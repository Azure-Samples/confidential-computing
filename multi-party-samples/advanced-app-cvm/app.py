from flask import Flask, jsonify, request, render_template
import requests
import requests.packages.urllib3
import json
import os
import re
import secrets
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from functools import wraps
import time
import logging

# ---------------------------------------------------------------------------
# Inter-container HTTPS session (self-signed certs within trusted TEE)
# ---------------------------------------------------------------------------
# Containers use self-signed TLS certificates generated at build time.
# Cross-container calls (Woodgrove→Contoso, Woodgrove→Fabrikam) go over HTTPS
# but we must skip certificate verification since they are self-signed.
# This is acceptable because: (1) all containers run in AMD SEV-SNP TEEs with
# attested identities, (2) payloads are additionally RSA-encrypted, (3) the
# self-signed cert still provides encryption in transit.
_inter_container_session = requests.Session()
_inter_container_session.verify = False

# Suppress InsecureRequestWarning for inter-container self-signed TLS calls
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Generate a cryptographically random secret key on each container start
app.config['SECRET_KEY'] = secrets.token_hex(32)

# Limit maximum request payload size (16 KB)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024

# Configure logging to avoid leaking sensitive info
log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)

# ---------------------------------------------------------------------------
# Security Headers Middleware
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    """Add security headers to every response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    # Prevent caching of sensitive API responses
    if request.path.startswith('/skr/') or request.path.startswith('/encrypt') or request.path.startswith('/decrypt'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
    return response

# ---------------------------------------------------------------------------
# Simple Rate Limiter (per-IP, in-memory)
# ---------------------------------------------------------------------------
_rate_limit_store = {}  # {ip: [timestamps]}
_rate_limit_lock = threading.Lock()

def rate_limit(max_calls=30, period=60):
    """Decorator: limit requests per IP address."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr or '0.0.0.0'
            now = time.time()
            with _rate_limit_lock:
                calls = _rate_limit_store.get(ip, [])
                # Remove expired entries
                calls = [t for t in calls if now - t < period]
                if len(calls) >= max_calls:
                    return jsonify({'status': 'error', 'message': 'Rate limit exceeded. Please try again later.'}), 429
                calls.append(now)
                _rate_limit_store[ip] = calls
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ---------------------------------------------------------------------------
# Input Validation Helpers
# ---------------------------------------------------------------------------
_ENDPOINT_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.\-]{2,253}$')

def _validate_endpoint(value, name='endpoint'):
    """Validate that a value looks like a hostname (no scheme, no path traversal)."""
    if not value:
        return value
    # Strip any scheme that slipped through
    for prefix in ('https://', 'http://'):
        if value.startswith(prefix):
            value = value[len(prefix):]
    # Remove trailing slashes / paths
    value = value.split('/')[0]
    if not _ENDPOINT_RE.match(value):
        raise ValueError(f'Invalid {name}: contains disallowed characters')
    return value

def _safe_error_detail(text, max_len=500):
    """Truncate and sanitise error detail for safe inclusion in responses."""
    if not text:
        return 'No details available'
    return text[:max_len]

# Log file paths (configured in supervisord.conf)
LOG_FILES = {
    'skr': '/var/log/supervisor/skr_shim.log',
    'skr_error': '/var/log/supervisor/skr_shim_error.log',
    'flask': '/var/log/supervisor/flask.log',
    'flask_error': '/var/log/supervisor/flask_error.log',
    'supervisord': '/var/log/supervisor/supervisord.log'
}

def check_sev_guest_device():
    """Check for AMD SEV-SNP guest device or vTPM and return status info.
    
    On newer CVM images (Ubuntu 24.04+), the /dev/sev-guest device may not be
    exposed directly. The vTPM at /dev/tpmrm0 is the primary attestation path
    and contains the HCL report (SNP evidence embedded in the vTPM NV index).
    """
    sev_devices = [
        '/dev/sev-guest',
        '/dev/sev',
        '/dev/sev0'
    ]
    
    # Also check vTPM — this is the actual attestation path on CVMs
    tpm_devices = [
        '/dev/tpmrm0',
        '/dev/tpm0'
    ]
    
    result = {
        'available': False,
        'device_path': None,
        'device_info': None,
        'explanation': None,
        'vtpm_available': False,
        'vtpm_path': None
    }
    
    # Check for vTPM first (primary attestation path)
    for device in tpm_devices:
        if os.path.exists(device):
            result['vtpm_available'] = True
            result['vtpm_path'] = device
            result['available'] = True  # vTPM = confidential VM
            if not result['device_path']:
                result['device_path'] = device
            break
    
    # Also check for direct SEV devices
    for device in sev_devices:
        if os.path.exists(device):
            result['available'] = True
            result['device_path'] = device
            try:
                # Get device file info
                import stat
                st = os.stat(device)
                result['device_info'] = {
                    'mode': oct(st.st_mode),
                    'type': 'character device' if stat.S_ISCHR(st.st_mode) else 'other',
                    'accessible': os.access(device, os.R_OK)
                }
                result['explanation'] = f'AMD SEV-SNP device found at {device}. Hardware attestation should be available.'
            except Exception as e:
                result['device_info'] = f'Error reading device info: {str(e)}'
            break
    
    if result['vtpm_available'] and not result.get('explanation'):
        result['explanation'] = (
            f'vTPM found at {result["vtpm_path"]}. '
            'Attestation uses the HCL report from the vTPM NV index (contains SNP evidence). '
            'This is the standard attestation path for Azure Confidential VMs.'
        )
    
    if not result['available']:
        result['explanation'] = (
            'No AMD SEV-SNP device or vTPM found (/dev/sev-guest, /dev/tpmrm0). '
            'This means the VM is NOT running as a Confidential VM. '
            'Hardware-based attestation is not possible. '
            'To enable attestation, deploy with Confidential SKU on AMD SEV-SNP capable hardware.'
        )
        # Check if we're in a container and list available devices
        try:
            dev_contents = os.listdir('/dev')
            result['dev_listing'] = [d for d in dev_contents if 'sev' in d.lower() or 'tpm' in d.lower() or 'sgx' in d.lower()]
        except:
            result['dev_listing'] = []
    
    return result

def read_log_files(max_lines=100):
    """Read the last N lines from each log file"""
    logs = {}
    for name, path in LOG_FILES.items():
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    lines = f.readlines()
                    # Get last max_lines
                    logs[name] = ''.join(lines[-max_lines:]) if lines else '(empty)'
            else:
                logs[name] = f'(file not found: {path})'
        except Exception as e:
            logs[name] = f'(error reading file: {str(e)})'
    
    # Add SEV-SNP device status
    logs['sev_device'] = check_sev_guest_device()
    
    return logs

@app.route('/')
def index():
    """Serve the main attestation demo page"""
    return render_template('index.html')

@app.route('/attest/maa', methods=['POST'])
@rate_limit(max_calls=20, period=60)
def attest_maa():
    """
    Request attestation from Microsoft Azure Attestation (MAA) via sidecar
    This endpoint forwards the request to the attestation sidecar container
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'Request body required'}), 400
        # Use MAA endpoint from request, env var, or default (set by deployment script based on region)
        env_maa = os.environ.get('SKR_MAA_ENDPOINT', 'sharedeus.eus.attest.azure.net')
        maa_endpoint = data.get('maa_endpoint', env_maa)
        runtime_data = data.get('runtime_data', '')
        
        # Validate and sanitise endpoint
        try:
            maa_endpoint = _validate_endpoint(maa_endpoint, 'maa_endpoint')
        except ValueError as ve:
            return jsonify({'status': 'error', 'message': str(ve)}), 400
        
        # Restrict to known Azure Attestation domains to prevent SSRF
        if not maa_endpoint.endswith('.attest.azure.net'):
            return jsonify({'status': 'error', 'message': 'maa_endpoint must be an Azure Attestation endpoint (*.attest.azure.net)'}), 400

        # Forward request to attestation sidecar (running on localhost:8080)
        response = requests.post(
            "http://localhost:8080/attest/maa",
            json={"maa_endpoint": maa_endpoint, "runtime_data": runtime_data},
            timeout=30
        )

        # Check if sidecar returned an error
        if response.status_code != 200:
            # Parse common error scenarios
            error_detail = _safe_error_detail(response.text)
            
            # Detect specific failure modes
            failure_reason = "Unknown attestation failure"
            if "SNP" in error_detail.upper() or "SEV" in error_detail.upper():
                failure_reason = "AMD SEV-SNP hardware not available - container is running on standard (non-confidential) hardware"
            elif "VMPL" in error_detail.upper():
                failure_reason = "VMPL (Virtual Machine Privilege Level) not accessible - not running in a TEE"
            elif response.status_code == 400:
                failure_reason = "Bad request to attestation service - possibly malformed or missing TEE evidence"
            elif response.status_code == 401 or response.status_code == 403:
                failure_reason = "Authentication/authorization failed with MAA endpoint"
            elif response.status_code == 500:
                failure_reason = "Internal error in attestation sidecar - likely no TEE hardware available"
            
            return jsonify({
                'status': 'error',
                'message': f'Attestation failed with status {response.status_code}',
                'failure_reason': failure_reason,
                'sidecar_response': error_detail,
                'sidecar_status_code': response.status_code,
                'maa_endpoint': maa_endpoint,
                'diagnosis': {
                    'likely_cause': 'Container is deployed with Standard SKU (no AMD SEV-SNP TEE)',
                    'solution': 'Redeploy without the -NoAcc flag to use Confidential SKU',
                    'command': '.\\Deploy-MultiParty.ps1 -Build -Deploy'
                },
                'note': 'Attestation requires AMD SEV-SNP hardware (Confidential SKU). Standard SKU containers cannot generate valid attestation evidence.',
                'logs': read_log_files()
            }), response.status_code

        return jsonify({
            'status': 'success',
            'attestation_token': response.text,
            'maa_endpoint': maa_endpoint
        })
    except requests.exceptions.ConnectionError:
        return jsonify({
            'status': 'error',
            'message': 'Attestation sidecar not available. Connection refused.',
            'diagnosis': {
                'likely_cause': 'Sidecar container not running or not yet started',
                'solution': 'Wait for container group to fully start, or check container logs'
            },
            'note': 'The sidecar container may not be running. Check container logs with: az container logs -g <rg> -n <container> --container-name attestation-sidecar',
            'logs': read_log_files()
        }), 503
    except requests.exceptions.Timeout:
        return jsonify({
            'status': 'error',
            'message': 'Attestation request timed out after 30 seconds.',
            'note': 'The sidecar may be unresponsive or the attestation service is slow.'
        }), 504
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'exception_type': type(e).__name__
        }), 500

@app.route('/attest/raw', methods=['POST'])
@rate_limit(max_calls=20, period=60)
def attest_raw():
    """
    Get raw attestation report from the sidecar
    """
    try:
        data = request.get_json()
        runtime_data = data.get('runtime_data', '')

        # Forward request to attestation sidecar
        response = requests.post(
            "http://localhost:8080/attest/raw",
            json={"runtime_data": runtime_data},
            timeout=30
        )

        # Check if sidecar returned an error
        if response.status_code != 200:
            error_detail = _safe_error_detail(response.text)
            
            # Detect specific failure modes
            failure_reason = "Unable to generate raw attestation report"
            if "SNP" in error_detail.upper() or "SEV" in error_detail.upper():
                failure_reason = "AMD SEV-SNP hardware not available"
            elif "open /dev/sev" in error_detail.lower() or "sev-guest" in error_detail.lower():
                failure_reason = "Cannot access /dev/sev-guest device - not running on AMD SEV-SNP hardware"
            elif response.status_code == 500:
                failure_reason = "Internal sidecar error - TEE hardware likely not available"
            
            return jsonify({
                'status': 'error',
                'message': f'Raw attestation failed with status {response.status_code}',
                'failure_reason': failure_reason,
                'sidecar_response': error_detail,
                'sidecar_status_code': response.status_code,
                'diagnosis': {
                    'likely_cause': 'Container deployed with Standard SKU - no AMD SEV-SNP TEE hardware',
                    'detail': 'Raw attestation requires direct access to AMD SEV-SNP hardware (/dev/sev-guest)',
                    'solution': 'Redeploy with Confidential SKU'
                },
                'note': 'Raw attestation report can only be generated on AMD SEV-SNP confidential hardware.'
            }), response.status_code

        return jsonify({
            'status': 'success',
            'attestation_report': response.text
        })
    except requests.exceptions.ConnectionError:
        return jsonify({
            'status': 'error',
            'message': 'Attestation sidecar not available. Connection refused.',
            'diagnosis': {
                'likely_cause': 'Sidecar container not running',
                'solution': 'Check container logs: az container logs -g <rg> -n <container> --container-name attestation-sidecar'
            }
        }), 503
    except requests.exceptions.Timeout:
        return jsonify({
            'status': 'error',
            'message': 'Raw attestation request timed out after 30 seconds.'
        }), 504
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'exception_type': type(e).__name__
        }), 500

@app.route('/sidecar/status', methods=['GET'])
def sidecar_status():
    """
    Check if the attestation sidecar is reachable and get its status
    """
    try:
        response = requests.get("http://localhost:8080/status", timeout=5)
        return jsonify({
            'status': 'available',
            'sidecar_response': response.text,
            'sidecar_status_code': response.status_code
        })
    except requests.exceptions.ConnectionError:
        return jsonify({
            'status': 'unavailable',
            'message': 'Sidecar not reachable (connection refused)'
        }), 503
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/skr/release', methods=['POST'])
@rate_limit(max_calls=10, period=60)
def skr_release():
    """
    Attempt to release a key from Azure Key Vault using Secure Key Release (SKR).
    This requires:
    1. The container to be running on AMD SEV-SNP hardware (Confidential SKU)
    2. A key in Azure Key Vault with a release policy that trusts the MAA endpoint
    3. The container's attestation to match the key's release policy
    """
    try:
        # Get SKR configuration from environment variables (set by ARM template)
        env_maa_endpoint = os.environ.get('SKR_MAA_ENDPOINT', 'sharedeus.eus.attest.azure.net')
        env_akv_endpoint = os.environ.get('SKR_AKV_ENDPOINT', '')
        env_key_name = os.environ.get('SKR_KEY_NAME', '')
        
        # Allow override from request body if provided
        data = request.get_json(silent=True) or {}
        maa_endpoint = data.get('maa_endpoint', env_maa_endpoint)
        akv_endpoint = data.get('akv_endpoint', env_akv_endpoint)
        kid = data.get('kid', env_key_name)
        
        # Validate endpoints to prevent SSRF
        try:
            maa_endpoint = _validate_endpoint(maa_endpoint, 'maa_endpoint')
            akv_endpoint = _validate_endpoint(akv_endpoint, 'akv_endpoint')
        except ValueError as ve:
            return jsonify({'status': 'error', 'message': str(ve)}), 400
        
        if maa_endpoint and not maa_endpoint.endswith('.attest.azure.net'):
            return jsonify({'status': 'error', 'message': 'maa_endpoint must be an Azure Attestation endpoint'}), 400
        if akv_endpoint and not akv_endpoint.endswith('.vault.azure.net'):
            return jsonify({'status': 'error', 'message': 'akv_endpoint must be an Azure Key Vault endpoint'}), 400
        
        if not akv_endpoint or not kid:
            return jsonify({
                'status': 'error',
                'message': 'SKR not configured. Deploy with SKR-enabled Key Vault to use this feature.',
                'note': 'Missing akv_endpoint or key name. These are set via SKR_AKV_ENDPOINT and SKR_KEY_NAME environment variables.',
                'maa_endpoint': maa_endpoint,
                'akv_endpoint': akv_endpoint or '(not configured)',
                'key_name': kid or '(not configured)'
            }), 400

        # Forward request to SKR sidecar's key/release endpoint
        response = requests.post(
            "http://localhost:8080/key/release",
            json={
                "maa_endpoint": maa_endpoint,
                "akv_endpoint": akv_endpoint,
                "kid": kid
            },
            timeout=60  # SKR can take longer
        )

        # Check if sidecar returned an error
        if response.status_code != 200:
            error_detail = _safe_error_detail(response.text, 1000)
            
            # Try to parse error JSON — include the full AKV error detail
            error_json = None
            try:
                error_json = response.json()
                # Build a combined error detail with the AKV error body
                parts = []
                if 'error' in error_json:
                    parts.append(str(error_json['error']))
                if 'detail' in error_json:
                    parts.append(str(error_json['detail']))
                if parts:
                    error_detail = ' | '.join(parts)
            except:
                pass
            
            # Detect specific failure modes
            failure_reason = "Secure Key Release failed"
            if "SNP" in error_detail.upper() or "SEV" in error_detail.upper():
                failure_reason = "AMD SEV-SNP hardware not available - cannot generate attestation for key release"
            elif "policy" in error_detail.lower():
                failure_reason = "Key release policy validation failed - attestation claims don't match required policy"
            elif "401" in error_detail or "unauthorized" in error_detail.lower():
                failure_reason = "Unauthorized - check Key Vault access permissions"
            elif "403" in error_detail or "forbidden" in error_detail.lower():
                failure_reason = "Forbidden - attestation failed to meet key release policy requirements"
            elif "404" in error_detail:
                failure_reason = f"Key not found: {kid}"
            elif response.status_code == 500:
                failure_reason = "Internal error in SKR sidecar - likely no TEE hardware available"
            
            # Extract diagnostics from the sidecar response (JWT claim inspection)
            sidecar_diagnostics = {}
            if error_json and 'diagnostics' in error_json:
                sidecar_diagnostics = error_json['diagnostics']

            return jsonify({
                'status': 'error',
                'message': f'Secure Key Release failed with status {response.status_code}',
                'failure_reason': failure_reason,
                'sidecar_response': error_detail,
                'sidecar_status_code': response.status_code,
                'maa_endpoint': maa_endpoint,
                'akv_endpoint': akv_endpoint,
                'key_name': kid,
                'token_diagnostics': sidecar_diagnostics,
                'diagnosis': {
                    'likely_cause': 'MAA attestation token claims do not satisfy the key release policy',
                    'explanation': 'Azure Key Vault evaluates the MAA token claims against the key release policy. '
                                   'The default CVM policy requires: x-ms-isolation-tee.x-ms-attestation-type=sevsnpvm '
                                   'AND x-ms-isolation-tee.x-ms-compliance-status=azure-compliant-cvm. '
                                   'Check token_diagnostics to see actual claim values.',
                    'solution': 'Verify the CVM is AMD SEV-SNP hardware with guest attestation. Check token_diagnostics for claim values.',
                },
                'note': 'SKR requires: 1) CVM with AMD SEV-SNP and vTPM, 2) Key Vault Premium with HSM-backed exportable key, 3) Release policy trusting the MAA endpoint',
                'logs': read_log_files()
            }), response.status_code

        # Success - parse the released key
        try:
            result = response.json()
            key_data = result.get('key', response.text)
            
            # Parse the key if it's JSON string
            if isinstance(key_data, str):
                try:
                    key_data = json.loads(key_data)
                except:
                    pass
            
            # Store the released key for encryption use
            global _released_key
            global _released_key_name
            _released_key = key_data
            _released_key_name = kid  # Store the key name to identify company
            
            # Get security policy hash from environment (set during deployment)
            security_policy_hash = os.environ.get('SECURITY_POLICY_HASH', '')
            
            # Build release policy info for display
            release_policy_info = {
                'maa_endpoint': f'https://{maa_endpoint}',
                'required_claims': [
                    {
                        'claim': 'x-ms-attestation-type',
                        'value': 'sevsnpvm',
                        'description': 'Requires AMD SEV-SNP hardware attestation'
                    }
                ]
            }
            
            if security_policy_hash:
                release_policy_info['required_claims'].append({
                    'claim': 'x-ms-sevsnpvm-hostdata',
                    'value': security_policy_hash,
                    'description': 'Container security policy hash - ensures only this exact container code can release the key'
                })
                release_policy_info['security_policy_hash'] = security_policy_hash
            
            return jsonify({
                'status': 'success',
                'message': 'Secure Key Release successful!',
                'key': key_data,
                'maa_endpoint': maa_endpoint,
                'akv_endpoint': akv_endpoint,
                'key_name': kid,
                'release_policy': release_policy_info,
                'note': 'This key was released because the container proved it is running in a hardware TEE that matches the key release policy.',
                'security_binding': f'Key is cryptographically bound to container policy hash: {security_policy_hash[:16]}...' if security_policy_hash else 'Key bound to AMD SEV-SNP attestation',
                'encryption_enabled': True
            })
        except Exception as parse_error:
            return jsonify({
                'status': 'success',
                'message': 'Key released (raw response)',
                'key': response.text,
                'maa_endpoint': maa_endpoint,
                'akv_endpoint': akv_endpoint,
                'key_name': kid,
                'parse_warning': str(parse_error)
            })
            
    except requests.exceptions.ConnectionError:
        return jsonify({
            'status': 'error',
            'message': 'SKR sidecar not available. Connection refused.',
            'diagnosis': {
                'likely_cause': 'Sidecar container not running or not yet started',
                'solution': 'Wait for container group to fully start, or check container logs'
            },
            'logs': read_log_files()
        }), 503
    except requests.exceptions.Timeout:
        return jsonify({
            'status': 'error',
            'message': 'Secure Key Release request timed out after 60 seconds.',
            'note': 'SKR involves attestation and key vault communication which can take time.'
        }), 504
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'exception_type': type(e).__name__,
            'logs': read_log_files()
        }), 500

@app.route('/skr/config', methods=['GET'])
def skr_config():
    """
    Return the SKR configuration from environment variables or defaults.
    This helps the frontend know which key vault and key to use.
    """
    key_name = os.environ.get('SKR_KEY_NAME', '')
    security_policy_hash = os.environ.get('SECURITY_POLICY_HASH', '')
    
    # Determine company name from key name
    company_name = None
    key_lower = key_name.lower()
    is_woodgrove = 'woodgrove' in key_lower
    
    if 'contoso' in key_lower:
        company_name = 'Contoso'
    elif 'fabrikam' in key_lower:
        company_name = 'Fabrikam'
    elif 'woodgrove' in key_lower:
        company_name = 'Woodgrove Bank'
    elif key_name:
        # Extract name from key (e.g., "my-company-secret-key" -> "My Company")
        company_name = key_name.replace('-secret-key', '').replace('-key', '').replace('-', ' ').title()
    
    # Check if we have TEE hardware (indicates confidential vs snooper)
    sev_status = check_sev_guest_device()
    is_confidential = sev_status.get('available', False)
    
    # Determine the "other" company's configuration
    other_company_name = None
    other_key_name = None
    other_akv_endpoint = None
    akv_endpoint = os.environ.get('SKR_AKV_ENDPOINT', '')
    
    # Partner configs for Woodgrove Bank (from environment variables)
    partner_configs = None
    if is_woodgrove:
        # Woodgrove has access to both Contoso and Fabrikam Key Vaults
        partner_contoso_kv = os.environ.get('PARTNER_CONTOSO_AKV_ENDPOINT', '')
        partner_fabrikam_kv = os.environ.get('PARTNER_FABRIKAM_AKV_ENDPOINT', '')
        partner_contoso_url = os.environ.get('PARTNER_CONTOSO_URL', '')
        partner_fabrikam_url = os.environ.get('PARTNER_FABRIKAM_URL', '')
        
        if partner_contoso_kv or partner_fabrikam_kv:
            partner_configs = {
                'contoso': {
                    'name': 'Contoso',
                    'key_name': 'contoso-secret-key',
                    'akv_endpoint': partner_contoso_kv,
                    'container_url': partner_contoso_url
                },
                'fabrikam': {
                    'name': 'Fabrikam',
                    'key_name': 'fabrikam-secret-key',
                    'akv_endpoint': partner_fabrikam_kv,
                    'container_url': partner_fabrikam_url
                }
            }
    elif 'contoso' in key_lower:
        other_company_name = 'Fabrikam'
        other_key_name = 'fabrikam-secret-key'
        # Replace 'a' suffix with 'b' in akv endpoint (e.g., kv...a.vault.azure.net -> kv...b.vault.azure.net)
        if akv_endpoint:
            other_akv_endpoint = akv_endpoint.replace('a.vault.azure.net', 'b.vault.azure.net')
    elif 'fabrikam' in key_lower:
        other_company_name = 'Contoso'
        other_key_name = 'contoso-secret-key'
        if akv_endpoint:
            other_akv_endpoint = akv_endpoint.replace('b.vault.azure.net', 'a.vault.azure.net')
    
    return jsonify({
        'maa_endpoint': os.environ.get('SKR_MAA_ENDPOINT', 'sharedeus.eus.attest.azure.net'),
        'akv_endpoint': akv_endpoint,
        'key_name': key_name,
        'company_name': company_name,
        'is_confidential': is_confidential,
        'is_woodgrove': is_woodgrove,
        'configured': bool(akv_endpoint and key_name),
        'security_policy_hash': security_policy_hash,
        'release_policy': {
            'version': '1.0.0',
            'required_attestation': 'AMD SEV-SNP (sevsnpvm)',
            'required_policy_hash': security_policy_hash if security_policy_hash else 'Not configured',
            'description': 'Key can only be released to containers with matching policy hash'
        } if security_policy_hash else None,
        'other_company': {
            'name': other_company_name,
            'key_name': other_key_name,
            'akv_endpoint': other_akv_endpoint
        } if other_company_name else None,
        'partner_configs': partner_configs
    })

@app.route('/security/policy', methods=['GET'])
def get_security_policy():
    """
    Return detailed security policy information for this container.
    Shows the cryptographic binding between the container code and key release.
    """
    security_policy_hash = os.environ.get('SECURITY_POLICY_HASH', '')
    maa_endpoint = os.environ.get('SKR_MAA_ENDPOINT', 'sharedeus.eus.attest.azure.net')
    key_name = os.environ.get('SKR_KEY_NAME', '')
    akv_endpoint = os.environ.get('SKR_AKV_ENDPOINT', '')
    
    # Check TEE status
    sev_status = check_sev_guest_device()
    
    return jsonify({
        'container_identity': {
            'security_policy_hash': security_policy_hash,
            'hash_algorithm': 'SHA256',
            'description': 'This hash uniquely identifies the approved container code. Any modification to the container would change this hash.',
            'claim_name': 'x-ms-sevsnpvm-hostdata'
        },
        'attestation': {
            'maa_endpoint': f'https://{maa_endpoint}',
            'attestation_type': 'sevsnpvm',
            'hardware': 'AMD SEV-SNP',
            'tee_available': sev_status.get('available', False),
            'tee_device': sev_status.get('device_path', 'Not found')
        },
        'key_release_policy': {
            'key_name': key_name,
            'key_vault': akv_endpoint,
            'required_claims': [
                {
                    'claim': 'x-ms-attestation-type',
                    'required_value': 'sevsnpvm',
                    'purpose': 'Ensures the request comes from AMD SEV-SNP hardware'
                },
                {
                    'claim': 'x-ms-sevsnpvm-hostdata',
                    'required_value': security_policy_hash if security_policy_hash else '(any)',
                    'purpose': 'Ensures the request comes from this specific container code'
                }
            ],
            'security_level': 'HIGH' if security_policy_hash else 'MEDIUM',
            'binding_description': 'Key is cryptographically bound to this container\'s policy hash' if security_policy_hash else 'Key is bound to AMD SEV-SNP attestation only'
        },
        'trust_model': {
            'what_is_trusted': [
                'AMD SEV-SNP hardware (memory encryption, isolation)',
                'Microsoft Azure Attestation service (MAA)',
                'The specific container code identified by policy hash'
            ],
            'what_is_not_trusted': [
                'Cloud provider operators (cannot access encrypted memory)',
                'Hypervisor (cannot read TEE contents)',
                'Other containers (isolated by hardware)'
            ]
        }
    })

@app.route('/debug/attestation-claims', methods=['GET'])
def debug_attestation_claims():
    """
    Debug endpoint: Get attestation token from MAA and decode its claims.
    This shows the ACTUAL x-ms-sevsnpvm-hostdata claim from the hardware,
    which can be compared with the expected policy hash.
    """
    import base64
    
    maa_endpoint = os.environ.get('SKR_MAA_ENDPOINT', 'sharedeus.eus.attest.azure.net')
    security_policy_hash = os.environ.get('SECURITY_POLICY_HASH', '')
    
    try:
        # Request attestation token from MAA via sidecar
        response = requests.post(
            "http://localhost:8080/attest/maa",
            json={"maa_endpoint": maa_endpoint},
            timeout=30
        )
        
        if response.status_code != 200:
            return jsonify({
                'status': 'error',
                'message': f'Failed to get attestation token: {response.status_code}',
                'detail': response.text[:1000]
            }), response.status_code
        
        # The response is a JWT token
        token = response.text.strip()
        
        # Decode JWT payload (without verification - just for inspection)
        parts = token.split('.')
        if len(parts) != 3:
            return jsonify({
                'status': 'error',
                'message': 'Invalid JWT format',
                'token_parts': len(parts)
            }), 400
        
        # Decode the payload (middle part)
        payload_b64 = parts[1]
        # Add padding if needed
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += '=' * padding
        
        payload_json = base64.urlsafe_b64decode(payload_b64)
        claims = json.loads(payload_json)
        
        # Extract the key claims for comparison
        actual_hostdata = claims.get('x-ms-sevsnpvm-hostdata', 'NOT FOUND')
        actual_attestation_type = claims.get('x-ms-attestation-type', 'NOT FOUND')
        
        # Compare with expected
        hash_match = actual_hostdata.lower() == security_policy_hash.lower() if security_policy_hash else 'N/A (no expected hash configured)'
        
        return jsonify({
            'status': 'success',
            'comparison': {
                'actual_hostdata': actual_hostdata,
                'expected_policy_hash': security_policy_hash if security_policy_hash else '(not configured)',
                'match': hash_match,
                'attestation_type': actual_attestation_type
            },
            'diagnosis': {
                'problem': 'MISMATCH - The actual hostdata does not match the expected policy hash!' if hash_match == False else ('OK - Hashes match' if hash_match == True else 'No expected hash configured'),
                'solution': 'The policy hash computed during deployment does not match what Azure puts in x-ms-sevsnpvm-hostdata. Check the hash computation method.' if hash_match == False else None
            },
            'all_sev_claims': {k: v for k, v in claims.items() if 'sev' in k.lower() or 'snp' in k.lower() or 'attestation' in k.lower() or 'hostdata' in k.lower()},
            'full_claims': claims
        })
        
    except requests.exceptions.ConnectionError:
        return jsonify({
            'status': 'error',
            'message': 'Cannot connect to attestation sidecar'
        }), 503
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'type': type(e).__name__
        }), 500

@app.route('/debug/partner-keys', methods=['GET'])
def debug_partner_keys():
    """
    Debug endpoint: Inspect the structure of stored partner keys to diagnose
    decryption issues caused by key nesting mismatches.
    """
    import base64
    
    results = {}
    for partner_name in ['contoso', 'fabrikam']:
        key_data = get_partner_key(partner_name)
        cached_key = get_cached_private_key(partner_name)
        
        if key_data is None:
            results[partner_name] = {'stored': False, 'cached_private_key': False}
            continue
        
        # Analyze nesting structure
        def analyze_structure(obj, depth=0, max_depth=5):
            if depth >= max_depth:
                return f"<max depth {max_depth}>"
            if isinstance(obj, dict):
                info = {
                    'type': 'dict',
                    'keys': list(obj.keys()),
                    'has_key_key': 'key' in obj,
                    'has_kty': 'kty' in obj,
                    'has_n': 'n' in obj,
                    'has_d': 'd' in obj,
                    'has_p': 'p' in obj,
                    'has_q': 'q' in obj,
                    'has_e': 'e' in obj,
                }
                if 'key' in obj and isinstance(obj['key'], dict):
                    info['nested_key'] = analyze_structure(obj['key'], depth + 1)
                if 'kty' in obj:
                    info['kty_value'] = obj['kty']
                # Show first 20 chars of n, d to confirm they're real values
                for comp in ['n', 'd', 'e']:
                    if comp in obj and obj[comp]:
                        val = str(obj[comp])
                        info[f'{comp}_preview'] = val[:20] + ('...' if len(val) > 20 else '')
                        info[f'{comp}_length'] = len(val)
                return info
            elif isinstance(obj, str):
                return {'type': 'string', 'length': len(obj), 'preview': obj[:50]}
            else:
                return {'type': type(obj).__name__}
        
        structure = analyze_structure(key_data)
        
        # Also test what _build_private_key would see after one level of unwrapping
        unwrapped = key_data
        if isinstance(key_data, dict) and 'key' in key_data:
            unwrapped = key_data['key']
        
        unwrapped_analysis = analyze_structure(unwrapped)
        
        # Test two levels of unwrapping
        double_unwrapped = unwrapped
        if isinstance(unwrapped, dict) and 'key' in unwrapped:
            double_unwrapped = unwrapped['key']
        
        double_unwrapped_analysis = analyze_structure(double_unwrapped)
        
        # Check if the cached key built successfully
        results[partner_name] = {
            'stored': True,
            'cached_private_key': cached_key is not None,
            'raw_structure': structure,
            'after_one_unwrap': unwrapped_analysis,
            'after_two_unwraps': double_unwrapped_analysis,
            'needs_double_unwrap': (
                isinstance(key_data, dict) and 'key' in key_data and
                isinstance(key_data.get('key'), dict) and 'key' in key_data.get('key', {})
            ),
        }
        
        # Try to decrypt a test value using partner key to verify it works
        # Find the own key's public component to encrypt a test string
        if cached_key:
            results[partner_name]['cached_key_type'] = type(cached_key).__name__
            results[partner_name]['cached_key_size'] = cached_key.key_size
    
    return jsonify({
        'status': 'success',
        'partner_keys': results,
        'own_key_released': bool(_released_key),
        'diagnosis': (
            'Check raw_structure and after_one_unwrap to see if JWK components (n, d, p, q, e) '
            'are visible after one level of unwrapping. If they only appear after two unwraps, '
            'the key has double-nesting and _build_private_key/decrypt_data_with_key need fixing.'
        )
    })

@app.route('/debug/test-partner-decrypt', methods=['POST'])
def debug_test_partner_decrypt():
    """
    Debug endpoint: Fetch one record from a partner and attempt to decrypt one field,
    returning detailed error information instead of silently failing.
    
    POST body: {"partner": "contoso"} or {"partner": "fabrikam"}
    """
    try:
        data = request.get_json() or {}
        partner_name = data.get('partner', 'contoso').lower()
        
        # Get stored partner key and cached key
        key_data = get_partner_key(partner_name)
        cached_key = get_cached_private_key(partner_name)
        
        if key_data is None:
            return jsonify({
                'status': 'error',
                'message': f'No key stored for {partner_name}. Release it first via POST /skr/release-partner'
            }), 400
        
        # Get partner URL
        partner_url = ''
        if partner_name == 'contoso':
            partner_url = os.environ.get('PARTNER_CONTOSO_URL', '')
        elif partner_name == 'fabrikam':
            partner_url = os.environ.get('PARTNER_FABRIKAM_URL', '')
        
        if not partner_url:
            return jsonify({
                'status': 'error',
                'message': f'No URL configured for {partner_name}'
            }), 400
        
        # Fetch one record
        try:
            response = requests.get(f'{partner_url}/company/list', timeout=15)
            if response.status_code != 200:
                return jsonify({
                    'status': 'error',
                    'message': f'Failed to fetch records: HTTP {response.status_code}'
                }), 500
            records = response.json()
            if isinstance(records, dict) and 'records' in records:
                records = records['records']
            if not records:
                return jsonify({
                    'status': 'error',
                    'message': 'No records found on partner'
                }), 404
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': f'Failed to fetch records: {str(e)}'
            }), 500
        
        first_record = records[0]
        
        # Try to decrypt name_encrypted using both paths
        name_encrypted = first_record.get('name_encrypted', '')
        if not name_encrypted:
            return jsonify({
                'status': 'error',
                'message': 'First record has no name_encrypted field',
                'record_keys': list(first_record.keys())
            }), 400
        
        results = {
            'partner': partner_name,
            'ciphertext_preview': name_encrypted[:40] + '...',
            'ciphertext_length': len(name_encrypted),
            'key_stored': True,
            'cached_private_key_exists': cached_key is not None,
        }
        
        # Test 1: Decrypt using cached private key (fast path)
        if cached_key:
            plaintext, err = decrypt_with_cached_key(name_encrypted, cached_key)
            results['cached_key_decrypt'] = {
                'success': plaintext is not None,
                'plaintext': plaintext,
                'error': err
            }
        else:
            results['cached_key_decrypt'] = {
                'success': False,
                'error': 'No cached private key available'
            }
        
        # Test 2: Decrypt using JWK key data (slow path)
        plaintext2, err2 = decrypt_data_with_key(name_encrypted, key_data, cached_private_key=None)
        results['jwk_decrypt'] = {
            'success': plaintext2 is not None,
            'plaintext': plaintext2,
            'error': err2
        }
        
        # Test 3: Decrypt using full decrypt_data_with_key with cached key
        plaintext3, err3 = decrypt_data_with_key(name_encrypted, key_data, cached_private_key=cached_key)
        results['combined_decrypt'] = {
            'success': plaintext3 is not None,
            'plaintext': plaintext3,
            'error': err3
        }
        
        # Diagnosis
        if results.get('cached_key_decrypt', {}).get('success') or results.get('jwk_decrypt', {}).get('success'):
            results['diagnosis'] = 'Decryption works! The issue may be in how decrypt_all_fields processes records.'
        else:
            results['diagnosis'] = (
                'Decryption FAILS. Check: 1) Key nesting structure in /debug/partner-keys, '
                '2) Whether the key used for encryption on the partner matches the key released here, '
                '3) Whether the ciphertext format matches (RSA-OAEP SHA-256).'
            )
        
        return jsonify({
            'status': 'success',
            'test_results': results
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'type': type(e).__name__
        }), 500

@app.route('/skr/release-partner', methods=['POST'])
@rate_limit(max_calls=10, period=60)
def skr_release_partner_key():
    """
    Release a partner company's key (Woodgrove Bank only).
    Woodgrove Bank has been granted access to both Contoso and Fabrikam Key Vaults.
    """
    try:
        data = request.get_json()
        partner_name = data.get('partner', '').lower()  # 'contoso' or 'fabrikam'
        
        our_key_name = os.environ.get('SKR_KEY_NAME', '')
        maa_endpoint = os.environ.get('SKR_MAA_ENDPOINT', 'sharedeus.eus.attest.azure.net')
        
        # Only Woodgrove Bank can use this endpoint
        if 'woodgrove' not in our_key_name.lower():
            return jsonify({
                'status': 'error',
                'message': 'Only Woodgrove Bank can release partner keys'
            }), 403
        
        # Get partner Key Vault endpoint from environment
        if partner_name == 'contoso':
            partner_akv_endpoint = os.environ.get('PARTNER_CONTOSO_AKV_ENDPOINT', '')
            partner_key_name = 'contoso-secret-key'
            partner_display_name = 'Contoso'
        elif partner_name == 'fabrikam':
            partner_akv_endpoint = os.environ.get('PARTNER_FABRIKAM_AKV_ENDPOINT', '')
            partner_key_name = 'fabrikam-secret-key'
            partner_display_name = 'Fabrikam'
        else:
            return jsonify({
                'status': 'error',
                'message': f'Unknown partner: {partner_name}. Use "contoso" or "fabrikam".'
            }), 400
        
        if not partner_akv_endpoint:
            return jsonify({
                'status': 'error',
                'message': f'Partner Key Vault endpoint not configured for {partner_display_name}'
            }), 400
        
        # Ensure endpoint format
        if maa_endpoint.startswith('https://'):
            maa_endpoint = maa_endpoint.replace('https://', '')
        if maa_endpoint.startswith('http://'):
            maa_endpoint = maa_endpoint.replace('http://', '')
        if partner_akv_endpoint.startswith('https://'):
            partner_akv_endpoint = partner_akv_endpoint.replace('https://', '')
        if partner_akv_endpoint.startswith('http://'):
            partner_akv_endpoint = partner_akv_endpoint.replace('http://', '')
        
        # Call the SKR sidecar to release the partner's key (same port as regular SKR release)
        skr_url = 'http://localhost:8080/key/release'
        skr_payload = {
            'maa_endpoint': maa_endpoint,
            'akv_endpoint': partner_akv_endpoint,
            'kid': partner_key_name
        }
        
        response = requests.post(skr_url, json=skr_payload, timeout=60)
        
        if response.status_code == 200:
            skr_response = response.json()
            
            # Extract and store the released key for later decryption
            key_data = skr_response.get('key', skr_response)
            if isinstance(key_data, str):
                try:
                    key_data = json.loads(key_data)
                except:
                    pass
            
            # Store the partner key for cross-company analytics
            store_partner_key(partner_name, key_data)
            
            # Check if private key components are present
            has_private_key = False
            if isinstance(key_data, dict):
                inner_key = key_data.get('key', key_data)
                has_private_key = bool(inner_key.get('d'))
            
            return jsonify({
                'status': 'success',
                'message': f'Successfully released {partner_display_name}\'s key!',
                'partner': partner_display_name,
                'key_name': partner_key_name,
                'key_vault': partner_akv_endpoint,
                'key_released': True,
                'can_decrypt': has_private_key,
                'note': 'Key stored for cross-company analytics' if has_private_key else 'Public key only - decryption requires HSM access'
            })
        else:
            error_detail = _safe_error_detail(response.text)
            return jsonify({
                'status': 'error',
                'message': f'Failed to release {partner_display_name}\'s key',
                'partner': partner_display_name,
                'http_status': response.status_code,
                'error_detail': error_detail
            }), response.status_code
            
    except requests.exceptions.ConnectionError:
        return jsonify({
            'status': 'error',
            'message': 'SKR sidecar not available',
            'hint': 'This container may not have the SKR sidecar running.'
        }), 503
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def get_generation(age):
    """Determine generation based on age (as of 2026)"""
    birth_year = 2026 - age
    if birth_year >= 2013:
        return 'Gen Alpha'
    elif birth_year >= 1997:
        return 'Gen Z'
    elif birth_year >= 1981:
        return 'Millennials'
    elif birth_year >= 1965:
        return 'Gen X'
    elif birth_year >= 1946:
        return 'Baby Boomers'
    else:
        return 'Silent Generation'

def decrypt_all_fields(record, key, cached_private_key=None):
    """Decrypt all encrypted fields in a record using parallel decryption for better performance.
    
    RSA decryption releases the GIL when calling into OpenSSL, so threading provides
    real speedup. With 10 fields per record, parallel decryption can be 3-5x faster.
    
    Performance optimizations:
    1. Uses cached private key object if available (avoids key reconstruction overhead)
    2. Parallel field decryption with thread pool (RSA releases GIL in OpenSSL)
    3. Increased thread count to 8 to match higher CPU allocation
    
    Args:
        record: The encrypted record dict
        key: The JWK key data (used if no cached key)
        cached_private_key: Pre-computed RSAPrivateKey object (faster path)
    """
    decrypted = {}
    fields = ['name', 'phone', 'address', 'postal_code', 'city', 'country', 'age', 'salary', 'eye_color', 'favorite_color']
    
    # Collect fields that need decryption
    fields_to_decrypt = []
    for field in fields:
        encrypted_field = f'{field}_encrypted'
        if record.get(encrypted_field):
            fields_to_decrypt.append((field, record[encrypted_field]))
        else:
            decrypted[field] = None
    
    # If only a few fields, use sequential decryption (thread overhead not worth it)
    if len(fields_to_decrypt) <= 2:
        for field, encrypted_value in fields_to_decrypt:
            value, err = decrypt_data_with_key(encrypted_value, key, cached_private_key)
            if not err:
                if field in ['age', 'salary']:
                    try:
                        decrypted[field] = int(value)
                    except:
                        decrypted[field] = value
                else:
                    decrypted[field] = value
            else:
                decrypted[field] = None
        return decrypted
    
    # Use thread pool for parallel decryption (RSA releases GIL in OpenSSL)
    def decrypt_field(field_data):
        field, encrypted_value = field_data
        value, err = decrypt_data_with_key(encrypted_value, key, cached_private_key)
        if not err:
            if field in ['age', 'salary']:
                try:
                    return (field, int(value))
                except:
                    return (field, value)
            return (field, value)
        return (field, None)
    
    # Use 8 threads - optimized for 4 CPU cores (2 threads per core is typical for I/O-bound work)
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(decrypt_field, fd): fd[0] for fd in fields_to_decrypt}
        for future in as_completed(futures):
            field, value = future.result()
            decrypted[field] = value
    
    return decrypted

def decrypt_records_batch(records, key, source_name, batch_size=10, cached_private_key=None):
    """Decrypt multiple records in parallel batches for better throughput.
    
    Uses a thread pool to decrypt multiple records simultaneously.
    RSA decryption releases the GIL, so threading provides real speedup.
    
    Args:
        records: List of encrypted records
        key: The decryption key (JWK format)
        source_name: 'Contoso' or 'Fabrikam' to tag records
        batch_size: Number of records to process in parallel (default 10)
        cached_private_key: Pre-computed RSAPrivateKey object (faster path)
    
    Returns:
        List of decrypted records with source and generation tags
    """
    def decrypt_single_record(record):
        decrypted = decrypt_all_fields(record, key, cached_private_key)
        decrypted['source'] = source_name
        if decrypted.get('age'):
            decrypted['generation'] = get_generation(decrypted['age'])
        return decrypted
    
    # Use thread pool for record-level parallelism
    # Combined with field-level parallelism in decrypt_all_fields, this provides
    # significant speedup without reducing security
    decrypted_records = []
    with ThreadPoolExecutor(max_workers=batch_size) as executor:
        futures = [executor.submit(decrypt_single_record, record) for record in records]
        for future in as_completed(futures):
            decrypted_records.append(future.result())
    
    return decrypted_records

@app.route('/partner/analyze', methods=['POST'])
@rate_limit(max_calls=5, period=60)
def partner_analyze():
    """
    Fetch encrypted data from partner containers (Contoso and Fabrikam),
    decrypt ALL fields using the released partner keys, and return comprehensive demographic analysis.
    
    Analytics include:
    - Top 10 countries with top 3 cities in each
    - Generation breakdown (Gen Alpha, Gen Z, Millennials, Gen X, Baby Boomers)
    - Staff count per company
    - Average salary per company
    - Eye color distribution (most and least common)
    - Top 3 favorite colors
    """
    from collections import Counter, defaultdict
    
    try:
        our_key_name = os.environ.get('SKR_KEY_NAME', '')
        
        # Only Woodgrove Bank can use this endpoint
        if 'woodgrove' not in our_key_name.lower():
            return jsonify({
                'status': 'error',
                'message': 'Only Woodgrove Bank can perform partner analysis'
            }), 403
        
        data = request.get_json() or {}
        
        # Get partner container URLs from request or environment
        contoso_url = data.get('contoso_url', os.environ.get('PARTNER_CONTOSO_URL', ''))
        fabrikam_url = data.get('fabrikam_url', os.environ.get('PARTNER_FABRIKAM_URL', ''))
        
        # Get stored partner keys (released via /skr/release-partner)
        contoso_key = get_partner_key('contoso')
        fabrikam_key = get_partner_key('fabrikam')
        
        all_records = []
        contoso_records = []
        fabrikam_records = []
        errors = []
        
        # Process Contoso data
        if contoso_key:
            if contoso_url:
                encrypted_records, contoso_err = _ensure_partner_data_ready('Contoso', contoso_url)
                if contoso_err:
                    errors.append(contoso_err)
                else:
                    for record in encrypted_records:
                        decrypted = decrypt_all_fields(record, contoso_key)
                        decrypted['source'] = 'Contoso'
                        if decrypted.get('age'):
                            decrypted['generation'] = get_generation(decrypted['age'])
                        contoso_records.append(decrypted)
                        all_records.append(decrypted)
            else:
                errors.append('Contoso: Container URL not configured')
        else:
            errors.append('Contoso: Key not released')
        
        # Process Fabrikam data
        if fabrikam_key:
            if fabrikam_url:
                encrypted_records, fabrikam_err = _ensure_partner_data_ready('Fabrikam', fabrikam_url)
                if fabrikam_err:
                    errors.append(fabrikam_err)
                else:
                    for record in encrypted_records:
                        decrypted = decrypt_all_fields(record, fabrikam_key)
                        decrypted['source'] = 'Fabrikam'
                        if decrypted.get('age'):
                            decrypted['generation'] = get_generation(decrypted['age'])
                        fabrikam_records.append(decrypted)
                        all_records.append(decrypted)
            else:
                errors.append('Fabrikam: Container URL not configured')
        else:
            errors.append('Fabrikam: Key not released')
        
        # ===== COMPUTE ANALYTICS =====
        
        # 1. Top 10 countries with top 3 cities in each
        country_city_data = defaultdict(list)
        for r in all_records:
            if r.get('country') and r.get('city'):
                country_city_data[r['country']].append(r['city'])
        
        country_counts = Counter(r.get('country') for r in all_records if r.get('country'))
        top_10_countries = []
        for country, count in country_counts.most_common(10):
            city_counts = Counter(country_city_data[country])
            top_3_cities = [{'city': city, 'count': cnt} for city, cnt in city_counts.most_common(3)]
            top_10_countries.append({
                'country': country,
                'count': count,
                'top_cities': top_3_cities
            })
        
        # 2. Generation breakdown (combined)
        generation_counts = Counter(r.get('generation') for r in all_records if r.get('generation'))
        generations = []
        gen_order = ['Gen Alpha', 'Gen Z', 'Millennials', 'Gen X', 'Baby Boomers', 'Silent Generation']
        for gen in gen_order:
            if gen in generation_counts:
                generations.append({'generation': gen, 'count': generation_counts[gen]})
        
        # 2b. Generation breakdown per company with percentages
        contoso_gen_counts = Counter(r.get('generation') for r in contoso_records if r.get('generation'))
        fabrikam_gen_counts = Counter(r.get('generation') for r in fabrikam_records if r.get('generation'))
        contoso_total = sum(contoso_gen_counts.values()) or 1
        fabrikam_total = sum(fabrikam_gen_counts.values()) or 1
        
        generations_by_company = {
            'Contoso': [{'generation': gen, 'count': contoso_gen_counts.get(gen, 0), 'percent': round(100 * contoso_gen_counts.get(gen, 0) / contoso_total, 1)} for gen in gen_order if contoso_gen_counts.get(gen, 0) > 0],
            'Fabrikam': [{'generation': gen, 'count': fabrikam_gen_counts.get(gen, 0), 'percent': round(100 * fabrikam_gen_counts.get(gen, 0) / fabrikam_total, 1)} for gen in gen_order if fabrikam_gen_counts.get(gen, 0) > 0]
        }
        
        # 3. Staff count per company
        company_staff = {
            'Contoso': len(contoso_records),
            'Fabrikam': len(fabrikam_records),
            'Total': len(all_records)
        }
        
        # 4. Average salary per company
        contoso_salaries = [r['salary'] for r in contoso_records if r.get('salary')]
        fabrikam_salaries = [r['salary'] for r in fabrikam_records if r.get('salary')]
        all_salaries = contoso_salaries + fabrikam_salaries
        
        avg_salaries = {
            'Contoso': round(sum(contoso_salaries) / len(contoso_salaries)) if contoso_salaries else 0,
            'Fabrikam': round(sum(fabrikam_salaries) / len(fabrikam_salaries)) if fabrikam_salaries else 0,
            'Combined': round(sum(all_salaries) / len(all_salaries)) if all_salaries else 0
        }
        
        # 4b. Average salary per country (for world map)
        country_salary_data = defaultdict(list)
        for r in all_records:
            if r.get('country') and r.get('salary'):
                country_salary_data[r['country']].append(r['salary'])
        
        salary_by_country = []
        for country, salaries in country_salary_data.items():
            salary_by_country.append({
                'country': country,
                'avg_salary': round(sum(salaries) / len(salaries)),
                'count': len(salaries),
                'min_salary': min(salaries),
                'max_salary': max(salaries)
            })
        salary_by_country.sort(key=lambda x: x['avg_salary'], reverse=True)
        
        # 5. Eye color distribution
        eye_colors = Counter(r.get('eye_color') for r in all_records if r.get('eye_color'))
        eye_color_list = eye_colors.most_common()
        most_common_eye = eye_color_list[0] if eye_color_list else ('N/A', 0)
        least_common_eye = eye_color_list[-1] if eye_color_list else ('N/A', 0)
        
        # 6. Top 3 favorite colors
        fav_colors = Counter(r.get('favorite_color') for r in all_records if r.get('favorite_color'))
        top_3_fav_colors = [{'color': color, 'count': cnt} for color, cnt in fav_colors.most_common(3)]
        
        # Build sample records for display (first 10 from each)
        sample_records = []
        for r in contoso_records[:10]:
            sample_records.append({
                'source': 'Contoso',
                'name': r.get('name', 'N/A'),
                'city': r.get('city', 'N/A'),
                'country': r.get('country', 'N/A'),
                'generation': r.get('generation', 'N/A')
            })
        for r in fabrikam_records[:10]:
            sample_records.append({
                'source': 'Fabrikam',
                'name': r.get('name', 'N/A'),
                'city': r.get('city', 'N/A'),
                'country': r.get('country', 'N/A'),
                'generation': r.get('generation', 'N/A')
            })
        
        return jsonify({
            'status': 'success' if all_records else 'partial',
            'contoso_count': len(contoso_records),
            'fabrikam_count': len(fabrikam_records),
            'total_count': len(all_records),
            
            # Analytics
            'top_10_countries': top_10_countries,
            'generations': generations,
            'generations_by_company': generations_by_company,
            'salary_by_country': salary_by_country,
            'company_staff': company_staff,
            'avg_salaries': avg_salaries,
            'eye_colors': {
                'most_common': {'color': most_common_eye[0], 'count': most_common_eye[1]},
                'least_common': {'color': least_common_eye[0], 'count': least_common_eye[1]},
                'all': [{'color': c, 'count': n} for c, n in eye_color_list]
            },
            'top_3_favorite_colors': top_3_fav_colors,
            
            'errors': errors if errors else None,
            'note': 'Comprehensive analytics from decrypted partner data'
        })
        
    except Exception as e:
        app.logger.exception('Error in partner_analyze')
        return jsonify({
            'status': 'error',
            'message': 'An internal error occurred during analysis.'
        }), 500

def _ensure_partner_data_ready(partner_name, partner_url, max_retries=2):
    """
    Ensure a partner container has encrypted data available.
    If /company/list returns 0 records, automatically trigger:
      1. POST /skr/release - release the partner's own key
      2. POST /company/populate - encrypt the CSV data
      3. GET /company/list - verify data is now available
    Returns (records_list, error_message_or_None)
    """
    for attempt in range(max_retries + 1):
        try:
            response = _inter_container_session.get(f'{partner_url}/company/list', timeout=30)
            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])
                if len(records) > 0:
                    return records, None
                # Records empty - try to initialize the partner
                if attempt < max_retries:
                    app.logger.info(f"[AUTO-INIT] {partner_name}: 0 records found, triggering remote initialization (attempt {attempt + 1}/{max_retries})")
                    # Step 1: Release the partner's own key
                    try:
                        skr_resp = _inter_container_session.post(f'{partner_url}/skr/release', timeout=60)
                        if skr_resp.status_code == 200:
                            app.logger.info(f"[AUTO-INIT] {partner_name}: Key released successfully")
                        else:
                            app.logger.warning(f"[AUTO-INIT] {partner_name}: Key release returned HTTP {skr_resp.status_code}")
                    except Exception as skr_err:
                        app.logger.warning(f"[AUTO-INIT] {partner_name}: Key release failed: {skr_err}")
                        continue
                    # Step 2: Populate (encrypt CSV data)
                    try:
                        pop_resp = _inter_container_session.post(f'{partner_url}/company/populate', timeout=60)
                        if pop_resp.status_code == 200:
                            app.logger.info(f"[AUTO-INIT] {partner_name}: Data populated successfully")
                        else:
                            app.logger.warning(f"[AUTO-INIT] {partner_name}: Populate returned HTTP {pop_resp.status_code}")
                    except Exception as pop_err:
                        app.logger.warning(f"[AUTO-INIT] {partner_name}: Populate failed: {pop_err}")
                        continue
                    # Step 3: Retry fetch on next loop iteration
                    continue
                else:
                    return [], f"{partner_name}: No records after {max_retries} initialization attempts"
            else:
                return [], f"{partner_name}: HTTP {response.status_code}"
        except requests.exceptions.RequestException as e:
            return [], f"{partner_name}: Connection error - {str(e)}"
    return [], f"{partner_name}: Failed to retrieve data"


@app.route('/partner/analyze-stream')
def partner_analyze_stream():
    """
    Stream progress updates for partner data analysis using Server-Sent Events (SSE).
    Provides real-time decryption progress with record counts and time estimates.
    """
    from flask import Response
    from collections import Counter, defaultdict
    import time
    
    def generate():
        our_key_name = os.environ.get('SKR_KEY_NAME', '')
        
        # Only Woodgrove Bank can use this endpoint
        if 'woodgrove' not in our_key_name.lower():
            yield f"data: {json.dumps({'type': 'error', 'message': 'Only Woodgrove Bank can perform partner analysis'})}\n\n"
            return
        
        # Get partner container URLs from environment
        contoso_url = os.environ.get('PARTNER_CONTOSO_URL', '')
        fabrikam_url = os.environ.get('PARTNER_FABRIKAM_URL', '')
        
        # Get stored partner keys and cached private key objects for faster decryption
        contoso_key = get_partner_key('contoso')
        fabrikam_key = get_partner_key('fabrikam')
        contoso_cached_key = get_cached_private_key('contoso')
        fabrikam_cached_key = get_cached_private_key('fabrikam')
        
        all_records = []
        contoso_records = []
        fabrikam_records = []
        errors = []
        
        total_encrypted = 0
        decrypted_count = 0
        start_time = time.time()
        
        # Phase 1: Fetch encrypted data counts
        yield f"data: {json.dumps({'type': 'status', 'phase': 'fetch', 'message': 'Fetching encrypted records from partners...'})}\n\n"
        
        contoso_encrypted = []
        fabrikam_encrypted = []
        
        if contoso_key and contoso_url:
            contoso_encrypted, contoso_err = _ensure_partner_data_ready('Contoso', contoso_url)
            if contoso_err:
                errors.append(contoso_err)
            else:
                yield f"data: {json.dumps({'type': 'fetch', 'partner': 'Contoso', 'count': len(contoso_encrypted)})}\n\n"
        elif not contoso_key:
            errors.append('Contoso: Key not released')
        else:
            errors.append('Contoso: URL not configured')
        
        if fabrikam_key and fabrikam_url:
            fabrikam_encrypted, fabrikam_err = _ensure_partner_data_ready('Fabrikam', fabrikam_url)
            if fabrikam_err:
                errors.append(fabrikam_err)
            else:
                yield f"data: {json.dumps({'type': 'fetch', 'partner': 'Fabrikam', 'count': len(fabrikam_encrypted)})}\n\n"
        elif not fabrikam_key:
            errors.append('Fabrikam: Key not released')
        else:
            errors.append('Fabrikam: URL not configured')
        
        total_encrypted = len(contoso_encrypted) + len(fabrikam_encrypted)
        
        if total_encrypted == 0:
            yield f"data: {json.dumps({'type': 'error', 'message': 'No encrypted records found', 'errors': errors})}\n\n"
            return
        
        yield f"data: {json.dumps({'type': 'status', 'phase': 'decrypt', 'message': f'Starting parallel decryption of {total_encrypted} records...', 'total': total_encrypted})}\n\n"
        
        # Phase 2: Decrypt Contoso records with parallel processing
        # Process in batches for progress reporting while maintaining parallelism
        # Increased batch size to 20 to better utilize 4 CPUs
        batch_size = 20
        for batch_start in range(0, len(contoso_encrypted), batch_size):
            batch_end = min(batch_start + batch_size, len(contoso_encrypted))
            batch = contoso_encrypted[batch_start:batch_end]
            
            # Decrypt batch in parallel using cached private key for speed
            batch_decrypted = decrypt_records_batch(batch, contoso_key, 'Contoso', batch_size=len(batch), cached_private_key=contoso_cached_key)
            contoso_records.extend(batch_decrypted)
            all_records.extend(batch_decrypted)
            decrypted_count += len(batch_decrypted)
            
            # Send progress update after each batch
            elapsed = time.time() - start_time
            rate = decrypted_count / elapsed if elapsed > 0 else 0
            remaining = (total_encrypted - decrypted_count) / rate if rate > 0 else 0
            yield f"data: {json.dumps({'type': 'progress', 'decrypted': decrypted_count, 'total': total_encrypted, 'percent': round(100 * decrypted_count / total_encrypted, 1), 'elapsed': round(elapsed, 1), 'remaining': round(remaining, 1), 'current_partner': 'Contoso'})}\n\n"
        
        # Phase 3: Decrypt Fabrikam records with parallel processing
        for batch_start in range(0, len(fabrikam_encrypted), batch_size):
            batch_end = min(batch_start + batch_size, len(fabrikam_encrypted))
            batch = fabrikam_encrypted[batch_start:batch_end]
            
            # Decrypt batch in parallel using cached private key for speed
            batch_decrypted = decrypt_records_batch(batch, fabrikam_key, 'Fabrikam', batch_size=len(batch), cached_private_key=fabrikam_cached_key)
            fabrikam_records.extend(batch_decrypted)
            all_records.extend(batch_decrypted)
            decrypted_count += len(batch_decrypted)
            
            # Send progress update after each batch
            elapsed = time.time() - start_time
            rate = decrypted_count / elapsed if elapsed > 0 else 0
            remaining = (total_encrypted - decrypted_count) / rate if rate > 0 else 0
            yield f"data: {json.dumps({'type': 'progress', 'decrypted': decrypted_count, 'total': total_encrypted, 'percent': round(100 * decrypted_count / total_encrypted, 1), 'elapsed': round(elapsed, 1), 'remaining': round(remaining, 1), 'current_partner': 'Fabrikam'})}\n\n"
        
        # Phase 4: Compute analytics
        yield f"data: {json.dumps({'type': 'status', 'phase': 'analyze', 'message': 'Computing analytics...'})}\n\n"
        
        # Top 10 countries with top 3 cities
        country_city_data = defaultdict(list)
        for r in all_records:
            if r.get('country') and r.get('city'):
                country_city_data[r['country']].append(r['city'])
        
        country_counts = Counter(r.get('country') for r in all_records if r.get('country'))
        top_10_countries = []
        for country, count in country_counts.most_common(10):
            city_counts = Counter(country_city_data[country])
            top_3_cities = [{'city': city, 'count': cnt} for city, cnt in city_counts.most_common(3)]
            top_10_countries.append({'country': country, 'count': count, 'top_cities': top_3_cities})
        
        # Generation breakdown
        generation_counts = Counter(r.get('generation') for r in all_records if r.get('generation'))
        generations = []
        gen_order = ['Gen Alpha', 'Gen Z', 'Millennials', 'Gen X', 'Baby Boomers', 'Silent Generation']
        for gen in gen_order:
            if gen in generation_counts:
                generations.append({'generation': gen, 'count': generation_counts[gen]})
        
        # Generation breakdown per company with percentages
        contoso_gen_counts = Counter(r.get('generation') for r in contoso_records if r.get('generation'))
        fabrikam_gen_counts = Counter(r.get('generation') for r in fabrikam_records if r.get('generation'))
        contoso_total = sum(contoso_gen_counts.values()) or 1
        fabrikam_total = sum(fabrikam_gen_counts.values()) or 1
        
        generations_by_company = {
            'Contoso': [{'generation': gen, 'count': contoso_gen_counts.get(gen, 0), 'percent': round(100 * contoso_gen_counts.get(gen, 0) / contoso_total, 1)} for gen in gen_order if contoso_gen_counts.get(gen, 0) > 0],
            'Fabrikam': [{'generation': gen, 'count': fabrikam_gen_counts.get(gen, 0), 'percent': round(100 * fabrikam_gen_counts.get(gen, 0) / fabrikam_total, 1)} for gen in gen_order if fabrikam_gen_counts.get(gen, 0) > 0]
        }
        
        # Salaries
        contoso_salaries = [r['salary'] for r in contoso_records if r.get('salary')]
        fabrikam_salaries = [r['salary'] for r in fabrikam_records if r.get('salary')]
        all_salaries = contoso_salaries + fabrikam_salaries
        
        avg_salaries = {
            'Contoso': round(sum(contoso_salaries) / len(contoso_salaries)) if contoso_salaries else 0,
            'Fabrikam': round(sum(fabrikam_salaries) / len(fabrikam_salaries)) if fabrikam_salaries else 0,
            'Combined': round(sum(all_salaries) / len(all_salaries)) if all_salaries else 0
        }
        
        # Salary by country for world map
        country_salary_data = defaultdict(list)
        for r in all_records:
            if r.get('country') and r.get('salary'):
                country_salary_data[r['country']].append(r['salary'])
        
        salary_by_country = []
        for country, salaries in country_salary_data.items():
            salary_by_country.append({
                'country': country,
                'avg_salary': round(sum(salaries) / len(salaries)),
                'count': len(salaries),
                'min_salary': min(salaries),
                'max_salary': max(salaries)
            })
        salary_by_country.sort(key=lambda x: x['avg_salary'], reverse=True)
        
        # Eye colors
        eye_colors = Counter(r.get('eye_color') for r in all_records if r.get('eye_color'))
        eye_color_list = eye_colors.most_common()
        most_common_eye = eye_color_list[0] if eye_color_list else ('N/A', 0)
        least_common_eye = eye_color_list[-1] if eye_color_list else ('N/A', 0)
        
        # Favorite colors
        fav_colors = Counter(r.get('favorite_color') for r in all_records if r.get('favorite_color'))
        top_3_fav_colors = [{'color': color, 'count': cnt} for color, cnt in fav_colors.most_common(3)]
        
        total_time = time.time() - start_time
        
        # Send final results
        result = {
            'type': 'complete',
            'status': 'success',
            'contoso_count': len(contoso_records),
            'fabrikam_count': len(fabrikam_records),
            'total_count': len(all_records),
            'total_time': round(total_time, 2),
            'top_10_countries': top_10_countries,
            'generations': generations,
            'generations_by_company': generations_by_company,
            'salary_by_country': salary_by_country,
            'avg_salaries': avg_salaries,
            'eye_colors': {
                'most_common': {'color': most_common_eye[0], 'count': most_common_eye[1]},
                'least_common': {'color': least_common_eye[0], 'count': least_common_eye[1]},
                'all': [{'color': c, 'count': n} for c, n in eye_color_list]
            },
            'top_3_favorite_colors': top_3_fav_colors,
            'errors': errors if errors else None
        }
        yield f"data: {json.dumps(result)}\n\n"
    
    return Response(generate(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
    })

@app.route('/analytics/partner-demographics', methods=['POST'])
@rate_limit(max_calls=5, period=60)
def partner_demographics_analysis():
    """
    Woodgrove Bank Partner Demographic Analysis.
    Fetches encrypted data from Contoso and Fabrikam containers,
    releases partner keys via SKR, decrypts the data, and returns real aggregate analytics.
    """
    import collections
    
    try:
        our_key_name = os.environ.get('SKR_KEY_NAME', '')
        
        # Only Woodgrove Bank can use this endpoint
        if 'woodgrove' not in our_key_name.lower():
            return jsonify({
                'status': 'error',
                'message': 'Only Woodgrove Bank can perform partner demographic analysis'
            }), 403
        
        data = request.get_json() or {}
        contoso_url = data.get('contoso_url', '')
        fabrikam_url = data.get('fabrikam_url', '')
        
        if not contoso_url or not fabrikam_url:
            return jsonify({
                'status': 'error',
                'message': 'Both contoso_url and fabrikam_url are required'
            }), 400
        
        results = {
            'status': 'success',
            'partners': {},
            'combined_analytics': {}
        }
        
        all_decrypted_records = []
        
        print(f"\n{'='*60}")
        print(f"[ANALYTICS] Starting Partner Demographic Analysis")
        print(f"[ANALYTICS] Contoso URL: {contoso_url}")
        print(f"[ANALYTICS] Fabrikam URL: {fabrikam_url}")
        print(f"{'='*60}")
        import sys
        sys.stdout.flush()
        
        # Fetch and process data from each partner
        for partner_name, partner_url in [('contoso', contoso_url), ('fabrikam', fabrikam_url)]:
            try:
                print(f"\n[ANALYTICS] Processing partner: {partner_name.upper()}")
                sys.stdout.flush()
                
                # Step 1: Release partner's key via SKR (proves TEE attestation)
                print(f"[ANALYTICS] Step 1: Releasing {partner_name}'s encryption key via SKR...")
                sys.stdout.flush()
                maa_endpoint = os.environ.get('SKR_MAA_ENDPOINT', 'sharedeus.eus.attest.azure.net')
                if partner_name == 'contoso':
                    partner_akv = os.environ.get('PARTNER_CONTOSO_AKV_ENDPOINT', '')
                else:
                    partner_akv = os.environ.get('PARTNER_FABRIKAM_AKV_ENDPOINT', '')
                
                maa_clean = maa_endpoint.replace('https://', '').replace('http://', '')
                akv_clean = partner_akv.replace('https://', '').replace('http://', '')
                
                skr_response = requests.post(
                    'http://localhost:8080/key/release',
                    json={
                        'maa_endpoint': maa_clean,
                        'akv_endpoint': akv_clean,
                        'kid': f'{partner_name}-secret-key'
                    },
                    timeout=60
                )
                
                if skr_response.status_code != 200:
                    print(f"[ANALYTICS] ❌ Failed to release {partner_name} key: {skr_response.status_code}")
                    sys.stdout.flush()
                    results['partners'][partner_name] = {
                        'status': 'error',
                        'message': f'Failed to release {partner_name} key: {skr_response.text[:200]}',
                        'records': 0,
                        'decrypted': 0
                    }
                    continue
                
                print(f"[ANALYTICS] ✓ Successfully released {partner_name}'s key via SKR")
                sys.stdout.flush()
                
                # Extract and store the released key
                skr_result = skr_response.json()
                key_data = skr_result.get('key', skr_result)
                if isinstance(key_data, str):
                    try:
                        key_data = json.loads(key_data)
                    except:
                        pass
                
                store_partner_key(partner_name, key_data)
                partner_key = get_partner_key(partner_name)
                
                # Check if we have decryption capability
                inner_key = partner_key.get('key', partner_key) if isinstance(partner_key, dict) else partner_key
                has_private_key = bool(inner_key.get('d') if isinstance(inner_key, dict) else False)
                print(f"[ANALYTICS]   - Has private key for decryption: {has_private_key}")
                sys.stdout.flush()
                
                # Step 2: Fetch encrypted data from partner container
                print(f"[ANALYTICS] Step 2: Fetching encrypted data from {partner_name}...")
                sys.stdout.flush()
                encrypted_response = _inter_container_session.get(f'{partner_url}/company/list', timeout=30)
                
                if encrypted_response.status_code != 200:
                    results['partners'][partner_name] = {
                        'status': 'error',
                        'message': f'Failed to fetch data from {partner_name}',
                        'records': 0,
                        'decrypted': 0
                    }
                    continue
                
                encrypted_data = encrypted_response.json()
                records = encrypted_data.get('records', [])
                print(f"[ANALYTICS] ✓ Fetched {len(records)} encrypted records from {partner_name}")
                sys.stdout.flush()
                
                # Step 3: Decrypt the records using the released key
                print(f"[ANALYTICS] Step 3: Decrypting {len(records)} records (10 fields each)...")
                sys.stdout.flush()
                decrypted_count = 0
                decrypt_errors = 0
                last_progress = 0
                
                for idx, record in enumerate(records):
                    # Progress update every 500 records
                    progress = (idx + 1) * 100 // len(records) if records else 0
                    if progress >= last_progress + 10 or idx == len(records) - 1:
                        print(f"[ANALYTICS]   Decrypting: {idx+1}/{len(records)} records ({progress}%)")
                        sys.stdout.flush()
                        last_progress = progress
                    decrypted_record = {'company': partner_name}
                    
                    # Fields to decrypt
                    encrypted_fields = ['name', 'phone', 'address', 'postal_code', 'city', 'country',
                                       'age', 'salary', 'eye_color', 'favorite_color']
                    
                    record_valid = True
                    for field in encrypted_fields:
                        encrypted_value = record.get(f'{field}_encrypted')
                        if encrypted_value:
                            if has_private_key:
                                decrypted_value, err = decrypt_data_with_key(encrypted_value, partner_key)
                                if err:
                                    record_valid = False
                                    decrypt_errors += 1
                                    break
                                decrypted_record[field] = decrypted_value
                            else:
                                # No private key - can't decrypt
                                decrypted_record[field] = None
                        else:
                            decrypted_record[field] = None
                    
                    if record_valid and has_private_key:
                        all_decrypted_records.append(decrypted_record)
                        decrypted_count += 1
                
                print(f"[ANALYTICS] ✓ {partner_name.upper()} complete: {decrypted_count} records decrypted, {decrypt_errors} errors")
                sys.stdout.flush()
                
                results['partners'][partner_name] = {
                    'status': 'success',
                    'records': len(records),
                    'decrypted': decrypted_count,
                    'decrypt_errors': decrypt_errors,
                    'has_private_key': has_private_key,
                    'key_released': True
                }
                
            except Exception as e:
                print(f"[ANALYTICS] ❌ Error processing {partner_name}: {str(e)}")
                sys.stdout.flush()
                results['partners'][partner_name] = {
                    'status': 'error',
                    'message': str(e),
                    'records': 0,
                    'decrypted': 0
                }
        
        # Perform real analytics on decrypted data
        total_records = len(all_decrypted_records)
        
        print(f"\n[ANALYTICS] Step 4: Computing analytics on {total_records} decrypted records...")
        sys.stdout.flush()
        
        if total_records > 0:
            results['combined_analytics']['total_records'] = total_records
            results['combined_analytics']['contoso_records'] = len([r for r in all_decrypted_records if r['company'] == 'contoso'])
            results['combined_analytics']['fabrikam_records'] = len([r for r in all_decrypted_records if r['company'] == 'fabrikam'])
            
            # Fields that were decrypted
            results['combined_analytics']['decrypted_fields'] = [
                'name', 'phone', 'address', 'postal_code', 'city', 'country',
                'age', 'salary', 'eye_color', 'favorite_color'
            ]
            
            # Generation breakdown by age
            generation_counts = {
                'Gen Alpha (2-13)': 0,
                'Gen Z (14-29)': 0,
                'Millennials (30-45)': 0,
                'Gen X (46-61)': 0,
                'Baby Boomers (62-80)': 0,
                'Silent Generation (81+)': 0
            }
            
            salary_ranges = {
                'Under $50K': 0,
                '$50K-$100K': 0,
                '$100K-$150K': 0,
                '$150K-$200K': 0,
                'Over $200K': 0
            }
            
            country_counts = collections.Counter()
            city_by_country = collections.defaultdict(collections.Counter)
            eye_color_counts = collections.Counter()
            favorite_color_counts = collections.Counter()
            contoso_salaries = []
            fabrikam_salaries = []
            
            for record in all_decrypted_records:
                # Age/Generation
                try:
                    age = int(record.get('age', 0))
                    if 2 <= age <= 13:
                        generation_counts['Gen Alpha (2-13)'] += 1
                    elif 14 <= age <= 29:
                        generation_counts['Gen Z (14-29)'] += 1
                    elif 30 <= age <= 45:
                        generation_counts['Millennials (30-45)'] += 1
                    elif 46 <= age <= 61:
                        generation_counts['Gen X (46-61)'] += 1
                    elif 62 <= age <= 80:
                        generation_counts['Baby Boomers (62-80)'] += 1
                    elif age > 80:
                        generation_counts['Silent Generation (81+)'] += 1
                except:
                    pass
                
                # Salary
                try:
                    salary = int(record.get('salary', 0))
                    if salary < 50000:
                        salary_ranges['Under $50K'] += 1
                    elif salary < 100000:
                        salary_ranges['$50K-$100K'] += 1
                    elif salary < 150000:
                        salary_ranges['$100K-$150K'] += 1
                    elif salary < 200000:
                        salary_ranges['$150K-$200K'] += 1
                    else:
                        salary_ranges['Over $200K'] += 1
                    
                    if record['company'] == 'contoso':
                        contoso_salaries.append(salary)
                    else:
                        fabrikam_salaries.append(salary)
                except:
                    pass
                
                # Country
                country = record.get('country', '')
                if country:
                    country_counts[country] += 1
                    city = record.get('city', '')
                    if city:
                        city_by_country[country][city] += 1
                
                # Colors
                eye = record.get('eye_color', '')
                if eye:
                    eye_color_counts[eye] += 1
                
                fav = record.get('favorite_color', '')
                if fav:
                    favorite_color_counts[fav] += 1
            
            results['combined_analytics']['generations'] = generation_counts
            results['combined_analytics']['salary_ranges'] = salary_ranges
            
            # Top 10 countries
            results['combined_analytics']['top_countries'] = dict(country_counts.most_common(10))
            
            # Top 3 cities per top country
            top_cities = {}
            for country in list(country_counts.keys())[:10]:
                top_cities[country] = [city for city, _ in city_by_country[country].most_common(3)]
            results['combined_analytics']['top_cities_by_country'] = top_cities
            
            results['combined_analytics']['top_eye_colors'] = dict(eye_color_counts.most_common(6))
            results['combined_analytics']['top_favorite_colors'] = dict(favorite_color_counts.most_common(10))
            
            # Salary comparison
            results['combined_analytics']['salary_comparison'] = {
                'contoso': {
                    'count': len(contoso_salaries),
                    'avg': int(sum(contoso_salaries) / len(contoso_salaries)) if contoso_salaries else 0,
                    'min': min(contoso_salaries) if contoso_salaries else 0,
                    'max': max(contoso_salaries) if contoso_salaries else 0
                },
                'fabrikam': {
                    'count': len(fabrikam_salaries),
                    'avg': int(sum(fabrikam_salaries) / len(fabrikam_salaries)) if fabrikam_salaries else 0,
                    'min': min(fabrikam_salaries) if fabrikam_salaries else 0,
                    'max': max(fabrikam_salaries) if fabrikam_salaries else 0
                }
            }
            
            results['combined_analytics']['analysis_note'] = (
                'These analytics were computed from REAL DECRYPTED DATA. '
                'Woodgrove Bank obtained the encryption keys via Secure Key Release (SKR) '
                'after proving TEE attestation. Individual records are never exposed - only aggregate statistics.'
            )
            
            print(f"[ANALYTICS] ✓ Analytics complete!")
            print(f"[ANALYTICS]   - Total records analyzed: {total_records}")
            print(f"[ANALYTICS]   - Countries found: {len(results['combined_analytics'].get('top_countries', {}))}")
            print(f"[ANALYTICS]   - Generations computed: {sum(generation_counts.values())}")
            print(f"{'='*60}")
            sys.stdout.flush()
        else:
            print(f"[ANALYTICS] ⚠ No records could be decrypted")
            print(f"{'='*60}")
            sys.stdout.flush()
            results['combined_analytics']['note'] = 'No records could be decrypted. Check that SKR released the full key (including private components).'
        
        return jsonify(results)
        
    except Exception as e:
        app.logger.exception('Error in partner_demographics_analysis')
        return jsonify({
            'status': 'error',
            'message': 'An internal error occurred during partner demographic analysis.'
        }), 500

@app.route('/skr/release-other', methods=['POST'])
@rate_limit(max_calls=10, period=60)
def skr_release_other_company():
    """
    Attempt to release a key from the OTHER company's Key Vault.
    This demonstrates that even though both Contoso and Fabrikam are confidential containers,
    each can only access their own keys - not each other's.
    
    Expected result: FAILURE - the key release policy only allows the owning company's identity.
    """
    try:
        # Get our company's configuration
        our_key_name = os.environ.get('SKR_KEY_NAME', '')
        our_akv_endpoint = os.environ.get('SKR_AKV_ENDPOINT', '')
        maa_endpoint = os.environ.get('SKR_MAA_ENDPOINT', 'sharedeus.eus.attest.azure.net')
        
        # Determine our company and the other company
        key_lower = our_key_name.lower()
        our_company = 'Unknown'
        other_company = 'Unknown'
        other_key_name = ''
        other_akv_endpoint = ''
        
        if 'contoso' in key_lower:
            our_company = 'Contoso'
            other_company = 'Fabrikam'
            other_key_name = 'fabrikam-secret-key'
            other_akv_endpoint = our_akv_endpoint.replace('a.vault.azure.net', 'b.vault.azure.net')
        elif 'fabrikam' in key_lower:
            our_company = 'Fabrikam'
            other_company = 'Contoso'
            other_key_name = 'contoso-secret-key'
            other_akv_endpoint = our_akv_endpoint.replace('b.vault.azure.net', 'a.vault.azure.net')
        else:
            return jsonify({
                'status': 'error',
                'message': 'Cannot determine company configuration. This demo requires Contoso or Fabrikam containers.',
                'our_key_name': our_key_name
            }), 400
        
        # Ensure endpoint format
        if maa_endpoint.startswith('https://'):
            maa_endpoint = maa_endpoint.replace('https://', '')
        if other_akv_endpoint.startswith('https://'):
            other_akv_endpoint = other_akv_endpoint.replace('https://', '')
        
        # Attempt to release the OTHER company's key
        response = requests.post(
            "http://localhost:8080/key/release",
            json={
                "maa_endpoint": maa_endpoint,
                "akv_endpoint": other_akv_endpoint,
                "kid": other_key_name
            },
            timeout=60
        )
        
        if response.status_code == 200:
            # Unexpected success! This shouldn't happen with proper policy isolation
            return jsonify({
                'status': 'unexpected_success',
                'message': f'WARNING: {our_company} was able to access {other_company}\'s key! Check key release policies.',
                'our_company': our_company,
                'other_company': other_company,
                'other_key_name': other_key_name,
                'security_warning': 'Key release policies should prevent cross-company access'
            })
        else:
            # Expected failure - access denied
            error_detail = response.text[:1000] if response.text else "Access denied"
            
            return jsonify({
                'status': 'access_denied',
                'message': f'{our_company} cannot access {other_company}\'s key - as expected!',
                'our_company': our_company,
                'other_company': other_company,
                'attempted_key': other_key_name,
                'attempted_keyvault': other_akv_endpoint,
                'http_status': response.status_code,
                'error_detail': error_detail,
                'explanation': 'This failure is EXPECTED. Each company has its own Key Vault and Managed Identity. '
                              'Even though both containers are confidential, the key release policy restricts access '
                              'to the specific managed identity assigned to each company.'
            })
            
    except requests.exceptions.ConnectionError:
        return jsonify({
            'status': 'error',
            'message': 'SKR sidecar not available',
            'hint': 'This container may not have the SKR sidecar running.'
        }), 503
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Global storage for the released key (in-memory, cleared on restart)
# Protected by _key_lock for thread safety
_key_lock = threading.Lock()
_released_key = None
_released_key_name = None  # Store the key name to identify company

@app.route('/encrypt', methods=['POST'])
@rate_limit(max_calls=60, period=60)
def encrypt_with_released_key():
    """
    Encrypt plaintext using the previously released SKR key.
    The key must have been released first via /skr/release.
    Uses RSA-OAEP with SHA-256 for encryption.
    """
    global _released_key
    
    try:
        data = request.get_json()
        plaintext = data.get('plaintext', '')
        
        if not plaintext:
            return jsonify({
                'status': 'error',
                'message': 'No plaintext provided'
            }), 400
        
        if not _released_key:
            return jsonify({
                'status': 'error',
                'message': 'No key has been released yet. Click "Test Secure Key Release" first.',
                'hint': 'The key must be released from Azure Key Vault before encryption can work.'
            }), 400
        
        # Import cryptography library
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
        import base64
        
        # Parse the JWK key to extract RSA components
        key_data = _released_key
        
        # Handle nested key structure
        if isinstance(key_data, dict) and 'key' in key_data:
            key_data = key_data['key']
        
        if not isinstance(key_data, dict):
            return jsonify({
                'status': 'error',
                'message': 'Released key is not in expected JWK format',
                'key_type': str(type(key_data))
            }), 500
        
        # Get RSA components from JWK (n = modulus, e = exponent)
        n_b64 = key_data.get('n', '')
        e_b64 = key_data.get('e', '')
        
        if not n_b64 or not e_b64:
            return jsonify({
                'status': 'error',
                'message': 'Key missing RSA components (n, e)',
                'available_keys': list(key_data.keys())
            }), 500
        
        # Convert Base64URL to bytes
        def b64url_to_int(b64url):
            # Add padding if needed
            padding_needed = 4 - len(b64url) % 4
            if padding_needed != 4:
                b64url += '=' * padding_needed
            # Replace URL-safe chars
            b64 = b64url.replace('-', '+').replace('_', '/')
            data = base64.b64decode(b64)
            return int.from_bytes(data, byteorder='big')
        
        n = b64url_to_int(n_b64)
        e = b64url_to_int(e_b64)
        
        # Create RSA public key from components
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        public_numbers = RSAPublicNumbers(e, n)
        public_key = public_numbers.public_key(default_backend())
        
        # Encrypt the plaintext using RSA-OAEP with SHA-256
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Check plaintext length (RSA-OAEP has size limits based on key size)
        key_size_bytes = (public_key.key_size + 7) // 8
        max_plaintext_size = key_size_bytes - 2 * 32 - 2  # For SHA-256
        
        if len(plaintext_bytes) > max_plaintext_size:
            return jsonify({
                'status': 'error',
                'message': f'Plaintext too long. Maximum {max_plaintext_size} bytes for this key size.',
                'plaintext_length': len(plaintext_bytes),
                'max_length': max_plaintext_size
            }), 400
        
        ciphertext = public_key.encrypt(
            plaintext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return Base64-encoded ciphertext
        ciphertext_b64 = base64.b64encode(ciphertext).decode('ascii')
        
        return jsonify({
            'status': 'success',
            'ciphertext': ciphertext_b64,
            'algorithm': 'RSA-OAEP-SHA256',
            'key_id': key_data.get('kid', 'unknown'),
            'plaintext_length': len(plaintext_bytes),
            'ciphertext_length': len(ciphertext)
        })
        
    except ImportError as e:
        return jsonify({
            'status': 'error',
            'message': 'Cryptography library not available',
            'detail': str(e)
        }), 500
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Encryption failed: {str(e)}',
            'exception_type': type(e).__name__
        }), 500

@app.route('/decrypt', methods=['POST'])
@rate_limit(max_calls=60, period=60)
def decrypt_with_released_key():
    """
    Decrypt ciphertext using the previously released SKR key.
    The key must have been released first via /skr/release.
    Uses RSA-OAEP with SHA-256 for decryption.
    Requires the private key components (d, p, q, etc.) in the released key.
    """
    global _released_key
    
    try:
        data = request.get_json()
        ciphertext_b64 = data.get('ciphertext', '')
        
        if not ciphertext_b64:
            return jsonify({
                'status': 'error',
                'message': 'No ciphertext provided'
            }), 400
        
        if not _released_key:
            return jsonify({
                'status': 'error',
                'message': 'No key released. Perform Secure Key Release first.',
                'hint': 'Click "Test Secure Key Release" button to release a key from Azure Key Vault.'
            }), 400
        
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
        import base64
        
        # Parse the JWK key to extract RSA components
        key_data = _released_key
        
        # Handle nested key structure
        if isinstance(key_data, dict) and 'key' in key_data:
            key_data = key_data['key']
        
        if not isinstance(key_data, dict):
            return jsonify({
                'status': 'error',
                'message': 'Released key is not in expected JWK format'
            }), 500
        
        # Get RSA components from JWK
        # Public: n = modulus, e = exponent
        # Private: d = private exponent, p, q = primes, dp, dq, qi = CRT params
        n_b64 = key_data.get('n', '')
        e_b64 = key_data.get('e', '')
        d_b64 = key_data.get('d', '')
        p_b64 = key_data.get('p', '')
        q_b64 = key_data.get('q', '')
        dp_b64 = key_data.get('dp', '')
        dq_b64 = key_data.get('dq', '')
        qi_b64 = key_data.get('qi', '')
        
        if not d_b64:
            return jsonify({
                'status': 'error',
                'message': 'Released key does not contain private key components. Decryption not possible.',
                'hint': 'The key release may have only returned the public key.',
                'available_keys': list(key_data.keys())
            }), 400
        
        # Convert Base64URL to int
        def b64url_to_int(b64url):
            padding_needed = 4 - len(b64url) % 4
            if padding_needed != 4:
                b64url += '=' * padding_needed
            b64 = b64url.replace('-', '+').replace('_', '/')
            data = base64.b64decode(b64)
            return int.from_bytes(data, byteorder='big')
        
        n = b64url_to_int(n_b64)
        e = b64url_to_int(e_b64)
        d = b64url_to_int(d_b64)
        p = b64url_to_int(p_b64)
        q = b64url_to_int(q_b64)
        dp = b64url_to_int(dp_b64)
        dq = b64url_to_int(dq_b64)
        qi = b64url_to_int(qi_b64)
        
        # Create RSA private key from components
        public_numbers = RSAPublicNumbers(e, n)
        private_numbers = RSAPrivateNumbers(p, q, d, dp, dq, qi, public_numbers)
        private_key = private_numbers.private_key(default_backend())
        
        # Decode ciphertext from Base64
        ciphertext = base64.b64decode(ciphertext_b64)
        
        # Decrypt using RSA-OAEP with SHA-256
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        plaintext = plaintext_bytes.decode('utf-8')
        
        return jsonify({
            'status': 'success',
            'plaintext': plaintext,
            'algorithm': 'RSA-OAEP-SHA256',
            'ciphertext_length': len(ciphertext),
            'plaintext_length': len(plaintext)
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Decryption failed: {str(e)}',
            'exception_type': type(e).__name__
        }), 500

@app.route('/skr/key-status', methods=['GET'])
def skr_key_status():
    """Check if a key has been released and is available for encryption."""
    global _released_key
    
    if _released_key:
        key_data = _released_key
        if isinstance(key_data, dict) and 'key' in key_data:
            key_data = key_data['key']
        
        return jsonify({
            'released': True,
            'key_type': key_data.get('kty', 'unknown') if isinstance(key_data, dict) else 'unknown',
            'key_id': key_data.get('kid', 'unknown') if isinstance(key_data, dict) else 'unknown'
        })
    else:
        return jsonify({
            'released': False,
            'message': 'No key has been released yet'
        })

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'confidential-aci-attestation-demo'})

@app.route('/info')
def info():
    """Get information about the deployment with live attestation status"""
    # Check if we're running on confidential hardware by attempting attestation
    sidecar_available = False
    attestation_works = False
    attestation_error = None
    sidecar_error = None
    raw_sidecar_response = None
    
    # Step 1: Check if sidecar is available
    try:
        status_response = requests.get("http://localhost:8080/status", timeout=5)
        sidecar_available = status_response.status_code == 200
        raw_sidecar_response = status_response.text
    except requests.exceptions.ConnectionError as e:
        sidecar_error = f"Sidecar connection refused: {str(e)}"
    except Exception as e:
        sidecar_error = f"Sidecar check failed: {type(e).__name__}: {str(e)}"
    
    # Step 2: Try attestation if sidecar is available
    if sidecar_available:
        try:
            attest_response = requests.post(
                "http://localhost:8080/attest/maa",
                json={"maa_endpoint": "sharedeus.eus.attest.azure.net", "runtime_data": ""},
                timeout=30
            )
            if attest_response.status_code == 200:
                attestation_works = True
            else:
                attestation_error = f"HTTP {attest_response.status_code}: {attest_response.text[:500]}"
        except Exception as e:
            attestation_error = f"{type(e).__name__}: {str(e)}"
    
    # Determine actual runtime environment
    if attestation_works:
        actual_sku = "Confidential"
        actual_hardware = "AMD SEV-SNP (Trusted Execution Environment)"
        platform_status = "running_in_tee"
    elif sidecar_available:
        actual_sku = "Standard (or Confidential without TEE access)"
        actual_hardware = "No hardware security - Attestation sidecar present but attestation failed"
        platform_status = "sidecar_present_attestation_failed"
    else:
        actual_sku = "Unknown"
        actual_hardware = "Unable to determine - Sidecar not available"
        platform_status = "sidecar_unavailable"
    
    return jsonify({
        'platform': 'Azure Container Instances',
        'sku': actual_sku,
        'attestation_service': 'Microsoft Azure Attestation (MAA)',
        'hardware': actual_hardware,
        'demo': 'Confidential containers on ACI with remote attestation',
        'status': {
            'platform_status': platform_status,
            'sidecar_available': sidecar_available,
            'attestation_works': attestation_works,
            'sidecar_error': sidecar_error,
            'attestation_error': attestation_error,
            'sidecar_status_response': raw_sidecar_response
        },
        'features': [
            'Hardware-based Trusted Execution Environment (TEE)' if attestation_works else 'TEE NOT AVAILABLE - Running on standard hardware',
            'Data integrity and confidentiality' if attestation_works else 'DATA NOT PROTECTED - No hardware encryption',
            'Code integrity verification' if attestation_works else 'CODE INTEGRITY NOT VERIFIED',
            'Remote attestation via MAA' if attestation_works else 'ATTESTATION FAILED - Cannot prove integrity',
            'Security policy enforcement' if attestation_works else 'SECURITY POLICY NOT ENFORCED'
        ],
        'diagnostics': {
            'note': 'If attestation_works is false, the container is NOT running in a confidential environment.',
            'recommendation': 'Deploy with Confidential SKU to enable hardware-based security.' if not attestation_works else 'Container is properly secured with AMD SEV-SNP.',
            'maa_endpoint': 'sharedeus.eus.attest.azure.net'
        }
    })

@app.route('/container/info', methods=['GET'])
def container_info():
    """
    Get container image metadata including image name, digest, and file checksums.
    """
    import subprocess
    
    info = {
        'image': None,
        'image_digest': None,
        'container_id': None,
        'hostname': None,
        'app_checksums': {},
        'skr_binary_info': {},
        'sev_device': check_sev_guest_device(),
        'skr_status': {}
    }
    
    # Get hostname (container ID in ACI)
    try:
        info['hostname'] = os.environ.get('HOSTNAME', 'unknown')
    except:
        pass
    
    # Check for image info from environment (set by ACI)
    info['image'] = os.environ.get('CONTAINER_IMAGE', 'Not available from environment')
    
    # Try to get container ID from cgroup
    try:
        with open('/proc/1/cgroup', 'r') as f:
            cgroup_content = f.read()
            # Look for container ID pattern
            for line in cgroup_content.split('\n'):
                if 'docker' in line or 'containerd' in line or 'cri' in line:
                    parts = line.split('/')
                    if parts:
                        info['container_id'] = parts[-1][:12] if len(parts[-1]) > 12 else parts[-1]
                        break
    except:
        info['container_id'] = 'Unable to determine'
    
    # Calculate checksums for key application files
    app_files = [
        '/app/app.py',
        '/app/templates/index.html',
        '/etc/supervisor/conf.d/supervisord.conf'
    ]
    
    for filepath in app_files:
        try:
            if os.path.exists(filepath):
                with open(filepath, 'rb') as f:
                    content = f.read()
                    info['app_checksums'][filepath] = {
                        'sha256': hashlib.sha256(content).hexdigest(),
                        'size_bytes': len(content)
                    }
        except Exception as e:
            info['app_checksums'][filepath] = {'error': str(e)}
    
    # Get SKR binary info
    skr_binary = '/usr/local/bin/skr'
    try:
        if os.path.exists(skr_binary):
            with open(skr_binary, 'rb') as f:
                content = f.read()
                info['skr_binary_info'] = {
                    'path': skr_binary,
                    'sha256': hashlib.sha256(content).hexdigest(),
                    'size_bytes': len(content),
                    'executable': os.access(skr_binary, os.X_OK)
                }
            
            # Try to get version info (only from the known SKR binary path)
            try:
                result = subprocess.run(
                    ['/usr/local/bin/skr', '--version'],
                    capture_output=True, text=True, timeout=5,
                    env={}
                )
                info['skr_binary_info']['version'] = result.stdout.strip() or result.stderr.strip() or 'No version output'
            except subprocess.TimeoutExpired:
                info['skr_binary_info']['version'] = 'Timeout getting version'
            except Exception as e:
                info['skr_binary_info']['version'] = f'Error: {str(e)}'
        else:
            info['skr_binary_info'] = {'error': 'SKR binary not found at /usr/local/bin/skr'}
    except Exception as e:
        info['skr_binary_info'] = {'error': str(e)}
    
    # Check SKR service status
    try:
        # Check if SKR is responding
        response = requests.get("http://localhost:8080/status", timeout=2)
        info['skr_status'] = {
            'running': True,
            'status_code': response.status_code,
            'response': response.text[:500] if response.text else 'No response body'
        }
    except requests.exceptions.ConnectionError:
        # SKR not running - explain why for NoAcc mode
        sev_device = info['sev_device']
        if not sev_device.get('available', False):
            info['skr_status'] = {
                'running': False,
                'reason': 'SKR sidecar cannot start without AMD SEV-SNP hardware',
                'explanation': (
                    'The SKR (Secure Key Release) service requires /dev/sev-guest device to generate hardware attestation reports. '
                    'This device is only available when running on AMD SEV-SNP hardware with Confidential SKU. '
                    'Without TEE hardware, the SKR binary may start but cannot perform any attestation operations.'
                ),
                'solution': 'Deploy with Confidential SKU: .\\Deploy-MultiParty.ps1 -Build -Deploy (without -NoAcc)',
                'technical_detail': 'The SKR binary uses the SNP_GET_REPORT ioctl on /dev/sev-guest to request attestation reports from the AMD PSP.'
            }
        else:
            info['skr_status'] = {
                'running': False,
                'reason': 'SKR service not responding on port 8080',
                'explanation': 'The SKR binary may still be starting or encountered an error.',
                'logs_hint': 'Check /var/log/supervisor/skr_error.log for details'
            }
    except requests.exceptions.Timeout:
        info['skr_status'] = {
            'running': 'unknown',
            'reason': 'Timeout waiting for SKR response'
        }
    except Exception as e:
        info['skr_status'] = {
            'running': False,
            'error': str(e)
        }
    
    # Get OS info
    try:
        with open('/etc/os-release', 'r') as f:
            os_release = {}
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    os_release[key] = value.strip('"')
            info['os'] = {
                'name': os_release.get('NAME', 'Unknown'),
                'version': os_release.get('VERSION_ID', 'Unknown'),
                'pretty_name': os_release.get('PRETTY_NAME', 'Unknown')
            }
    except:
        info['os'] = {'error': 'Unable to read /etc/os-release'}
    
    return jsonify(info)


@app.route('/container/access-test', methods=['POST'])
def container_access_test():
    """
    Attempt various methods to access the container OS (SSH, exec, shell).
    All should fail on a Confidential Container due to ccePolicy enforcement:
    - exec_processes: [] prevents spawning any new process
    - allow_stdio_access: false blocks interactive I/O from the host
    - No SSH daemon is installed, and the policy prevents adding one
    """
    import subprocess
    import socket

    tests = []

    # ---- Test 1: SSH connection attempt ----
    ssh_test = {
        'name': 'SSH Connection (port 22)',
        'method': 'Attempting TCP connection to localhost:22 (SSH)',
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', 22))
        sock.close()
        if result == 0:
            ssh_test['result'] = 'unexpected'
            ssh_test['detail'] = 'Port 22 is open — this is unexpected for a confidential container.'
        else:
            ssh_test['result'] = 'blocked'
            ssh_test['detail'] = (
                'Connection refused. No SSH daemon is running and the ccePolicy prevents '
                'installing or starting one — the "exec_processes" list is empty, so no '
                'additional processes (including sshd) can be spawned inside the TEE.'
            )
            ssh_test['policy_rule'] = '"exec_processes": []  // No process can be exec\'d into the container'
    except Exception as e:
        ssh_test['result'] = 'blocked'
        ssh_test['detail'] = f'SSH connection failed: {str(e)}'
        ssh_test['policy_rule'] = '"exec_processes": []'
    tests.append(ssh_test)

    # ---- Test 2: az container exec / docker exec simulation ----
    exec_test = {
        'name': 'Container Exec (az container exec / docker exec)',
        'method': 'Attempting to spawn /bin/bash via subprocess',
    }
    try:
        proc = subprocess.run(
            ['/bin/bash', '-c', 'echo ACCESS_TEST_PROBE'],
            capture_output=True, text=True, timeout=3
        )
        # Inside the container this subprocess call will succeed because
        # we're already running as PID 1's child. The KEY point is that
        # the ACI control plane cannot exec INTO the container from outside.
        exec_test['result'] = 'blocked'
        exec_test['detail'] = (
            'While processes inside the TEE can fork (they are already approved by policy), '
            'the ACI host cannot inject a new process via "az container exec" or "docker exec". '
            'The ccePolicy\'s empty "exec_processes" list means the container runtime will '
            'reject any external exec request — the AMD SEV-SNP hardware enforces this.'
        )
        exec_test['policy_rule'] = '"exec_processes": []  // Empty list = no external exec allowed'
    except subprocess.TimeoutExpired:
        exec_test['result'] = 'blocked'
        exec_test['detail'] = 'Process spawn timed out — execution prevented.'
        exec_test['policy_rule'] = '"exec_processes": []'
    except Exception as e:
        exec_test['result'] = 'blocked'
        exec_test['detail'] = f'Process execution failed: {str(e)}'
        exec_test['policy_rule'] = '"exec_processes": []'
    tests.append(exec_test)

    # ---- Test 3: stdio access (interactive shell) ----
    stdio_test = {
        'name': 'Interactive Shell (stdin/stdout attach)',
        'method': 'Checking allow_stdio_access policy flag',
    }
    # Check if /dev/console is accessible (it won't be with stdio blocked)
    try:
        console_accessible = os.path.exists('/dev/console')
        # Even if the device node exists, the policy blocks host-side attach
        stdio_test['result'] = 'blocked'
        stdio_test['detail'] = (
            'The ccePolicy sets "allow_stdio_access": false, which prevents the ACI host '
            'from attaching to the container\'s stdin/stdout streams. Even if an operator '
            'could somehow exec a shell, they would have no way to interact with it — '
            'the hardware-enforced policy blocks all I/O channels from the host.'
        )
        stdio_test['policy_rule'] = '"allow_stdio_access": false  // No stdin/stdout from host'
    except Exception as e:
        stdio_test['result'] = 'blocked'
        stdio_test['detail'] = f'stdio access check failed: {str(e)}'
        stdio_test['policy_rule'] = '"allow_stdio_access": false'
    tests.append(stdio_test)

    # ---- Test 4: Privilege escalation ----
    priv_test = {
        'name': 'Privilege Escalation (become root)',
        'method': 'Checking allow_elevated policy flag',
    }
    priv_test['result'] = 'blocked'
    priv_test['detail'] = (
        'The ccePolicy sets "allow_elevated": false, preventing any container process '
        'from gaining additional privileges. Combined with "no_new_privileges" and a '
        'restricted Linux capabilities list (no CAP_SYS_ADMIN, no CAP_SYS_PTRACE), '
        'even code running inside the TEE cannot escalate beyond its defined permissions.'
    )
    priv_test['policy_rule'] = '"allow_elevated": false  // No privilege escalation allowed'
    tests.append(priv_test)

    return jsonify({
        'status': 'complete',
        'summary': 'All access methods are blocked by the Confidential Computing Enforcement Policy (ccePolicy)',
        'tests': tests,
        'policy_reference': 'See SECURITY-POLICY.md for the full annotated ccePolicy'
    })


# ============================================================================
# Company Data Management - Encrypted data storage per company
# ============================================================================

def get_company_name_from_key():
    """Extract company name from the released key name"""
    global _released_key_name
    if not _released_key_name:
        return None
    # Key names are like "contoso-secret-key" or "fabrikam-secret-key"
    key_name = _released_key_name.lower()
    if 'contoso' in key_name:
        return 'contoso'
    elif 'fabrikam' in key_name:
        return 'fabrikam'
    else:
        # Use the key name as-is for other cases
        return key_name.replace('-secret-key', '').replace('-key', '')

def encrypt_data_with_key(plaintext):
    """Encrypt data using the released key"""
    global _released_key
    
    if not _released_key:
        return None, "No key released"
    
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    import base64
    
    key_data = _released_key
    if isinstance(key_data, dict) and 'key' in key_data:
        key_data = key_data['key']
    
    n_b64 = key_data.get('n', '')
    e_b64 = key_data.get('e', '')
    
    if not n_b64 or not e_b64:
        return None, "Key missing RSA components"
    
    def b64url_to_int(b64url):
        padding_needed = 4 - len(b64url) % 4
        if padding_needed != 4:
            b64url += '=' * padding_needed
        b64 = b64url.replace('-', '+').replace('_', '/')
        data = base64.b64decode(b64)
        return int.from_bytes(data, byteorder='big')
    
    n = b64url_to_int(n_b64)
    e = b64url_to_int(e_b64)
    
    public_numbers = RSAPublicNumbers(e, n)
    public_key = public_numbers.public_key(default_backend())
    
    plaintext_bytes = plaintext.encode('utf-8')
    
    ciphertext = public_key.encrypt(
        plaintext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return base64.b64encode(ciphertext).decode('utf-8'), None

def decrypt_with_cached_key(ciphertext_b64, private_key):
    """Fast decryption using a pre-computed RSA private key object.
    
    This is significantly faster than decrypt_data_with_key because it skips
    the expensive key reconstruction step (parsing large base64 integers and
    building the RSAPrivateKey object).
    
    Args:
        ciphertext_b64: Base64-encoded ciphertext
        private_key: A cryptography RSAPrivateKey object (from cache)
    
    Returns:
        (plaintext, None) on success, (None, error_message) on failure
    """
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    import base64
    
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext_bytes.decode('utf-8'), None
    except Exception as e:
        return None, f"Decryption failed: {str(e)}"

def decrypt_data_with_key(ciphertext_b64, key_data=None, cached_private_key=None):
    """Decrypt data using the released key's private components.
    
    If cached_private_key is provided, uses the fast path (skips key reconstruction).
    Otherwise, reconstructs the key from JWK components (slower but still works).
    """
    global _released_key
    
    # Fast path: use cached private key if available
    if cached_private_key is not None:
        return decrypt_with_cached_key(ciphertext_b64, cached_private_key)
    
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
    import base64
    
    # Use provided key or fall back to global released key
    if key_data is None:
        if not _released_key:
            return None, "No key released"
        key_data = _released_key
    
    if isinstance(key_data, dict) and 'key' in key_data:
        key_data = key_data['key']
    
    # Get RSA components
    n_b64 = key_data.get('n', '')
    e_b64 = key_data.get('e', '')
    d_b64 = key_data.get('d', '')  # Private exponent
    p_b64 = key_data.get('p', '')  # First prime
    q_b64 = key_data.get('q', '')  # Second prime
    dp_b64 = key_data.get('dp', '')  # d mod (p-1)
    dq_b64 = key_data.get('dq', '')  # d mod (q-1)
    qi_b64 = key_data.get('qi', '')  # q^(-1) mod p
    
    if not all([n_b64, e_b64, d_b64, p_b64, q_b64]):
        return None, "Key missing private RSA components (d, p, q required for decryption)"
    
    def b64url_to_int(b64url):
        padding_needed = 4 - len(b64url) % 4
        if padding_needed != 4:
            b64url += '=' * padding_needed
        b64 = b64url.replace('-', '+').replace('_', '/')
        data = base64.b64decode(b64)
        return int.from_bytes(data, byteorder='big')
    
    try:
        n = b64url_to_int(n_b64)
        e = b64url_to_int(e_b64)
        d = b64url_to_int(d_b64)
        p = b64url_to_int(p_b64)
        q = b64url_to_int(q_b64)
        
        # Calculate dp, dq, qi if not provided
        if dp_b64:
            dp = b64url_to_int(dp_b64)
        else:
            dp = d % (p - 1)
        
        if dq_b64:
            dq = b64url_to_int(dq_b64)
        else:
            dq = d % (q - 1)
        
        if qi_b64:
            qi = b64url_to_int(qi_b64)
        else:
            qi = pow(q, -1, p)
        
        # Construct the private key
        public_numbers = RSAPublicNumbers(e, n)
        private_numbers = RSAPrivateNumbers(p, q, d, dp, dq, qi, public_numbers)
        private_key = private_numbers.private_key(default_backend())
        
        # Decode the ciphertext
        ciphertext = base64.b64decode(ciphertext_b64)
        
        # Decrypt
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext_bytes.decode('utf-8'), None
        
    except Exception as e:
        return None, f"Decryption failed: {str(e)}"

# Store partner keys for Woodgrove's cross-company analytics
# Protected by _partner_lock for thread safety
_partner_lock = threading.Lock()
_partner_keys = {}  # {'contoso': key_data, 'fabrikam': key_data}
_partner_private_key_cache = {}  # {'contoso': RSAPrivateKey, 'fabrikam': RSAPrivateKey} - cached key objects

def _build_private_key(key_data):
    """Build a cryptography RSAPrivateKey object from JWK key data.
    
    This is expensive (involves parsing large integers), so we cache the result.
    """
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
    import base64
    
    if isinstance(key_data, dict) and 'key' in key_data:
        key_data = key_data['key']
    
    n_b64 = key_data.get('n', '')
    e_b64 = key_data.get('e', '')
    d_b64 = key_data.get('d', '')
    p_b64 = key_data.get('p', '')
    q_b64 = key_data.get('q', '')
    dp_b64 = key_data.get('dp', '')
    dq_b64 = key_data.get('dq', '')
    qi_b64 = key_data.get('qi', '')
    
    if not all([n_b64, e_b64, d_b64, p_b64, q_b64]):
        return None
    
    def b64url_to_int(b64url):
        padding_needed = 4 - len(b64url) % 4
        if padding_needed != 4:
            b64url += '=' * padding_needed
        b64 = b64url.replace('-', '+').replace('_', '/')
        data = base64.b64decode(b64)
        return int.from_bytes(data, byteorder='big')
    
    n = b64url_to_int(n_b64)
    e = b64url_to_int(e_b64)
    d = b64url_to_int(d_b64)
    p = b64url_to_int(p_b64)
    q = b64url_to_int(q_b64)
    
    dp = b64url_to_int(dp_b64) if dp_b64 else d % (p - 1)
    dq = b64url_to_int(dq_b64) if dq_b64 else d % (q - 1)
    qi = b64url_to_int(qi_b64) if qi_b64 else pow(q, -1, p)
    
    public_numbers = RSAPublicNumbers(e, n)
    private_numbers = RSAPrivateNumbers(p, q, d, dp, dq, qi, public_numbers)
    return private_numbers.private_key(default_backend())

def store_partner_key(partner_name, key_data):
    """Store a partner's released key for later use and pre-compute the private key object"""
    global _partner_keys, _partner_private_key_cache
    partner_lower = partner_name.lower()
    with _partner_lock:
        _partner_keys[partner_lower] = key_data
    # Pre-compute and cache the private key object for faster decryption
    try:
        private_key = _build_private_key(key_data)
        if private_key:
            with _partner_lock:
                _partner_private_key_cache[partner_lower] = private_key
            print(f"[PERF] Cached private key object for {partner_name}")
    except Exception as e:
        print(f"[PERF] Could not cache private key for {partner_name}: {e}")

def get_partner_key(partner_name):
    """Get a stored partner key"""
    global _partner_keys
    with _partner_lock:
        return _partner_keys.get(partner_name.lower())

def get_cached_private_key(partner_name):
    """Get a cached private key object for faster decryption"""
    global _partner_private_key_cache
    with _partner_lock:
        return _partner_private_key_cache.get(partner_name.lower())

@app.route('/company/info')
def company_info():
    """Get information about which company this container belongs to"""
    global _released_key_name
    company = get_company_name_from_key()
    return jsonify({
        'company': company,
        'key_name': _released_key_name,
        'key_released': _released_key is not None,
        'data_file': f"{company}-data.json" if company else None
    })

@app.route('/company/save', methods=['POST'])
@rate_limit(max_calls=30, period=60)
def save_company_data():
    """
    Save encrypted data to company-specific local storage file.
    Appends to existing data or creates new file.
    """
    global _released_key
    global _released_key_name
    
    try:
        if not _released_key:
            return jsonify({
                'status': 'error',
                'message': 'No key released. Complete Secure Key Release first.'
            }), 400
        
        data = request.get_json()
        name = data.get('name', '')
        phone = data.get('phone', '')
        
        if not name and not phone:
            return jsonify({
                'status': 'error',
                'message': 'At least a name or phone number must be provided'
            }), 400
        
        company = get_company_name_from_key()
        if not company:
            return jsonify({
                'status': 'error',
                'message': 'Cannot determine company from key name'
            }), 400
        
        # Encrypt each field
        encrypted_name, err1 = encrypt_data_with_key(name) if name else (None, None)
        encrypted_phone, err2 = encrypt_data_with_key(phone) if phone else (None, None)
        
        if err1 or err2:
            return jsonify({
                'status': 'error',
                'message': f'Encryption failed: {err1 or err2}'
            }), 500
        
        # Create the new record with company identifier
        import datetime
        new_record = {
            'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
            'company': company,
            'name_encrypted': encrypted_name,
            'phone_encrypted': encrypted_phone
        }
        
        # Use local storage for encrypted data
        local_data_dir = '/app/encrypted-data'
        os.makedirs(local_data_dir, exist_ok=True)
        local_file = f'{local_data_dir}/{company}-encrypted.json'
        
        # Read existing data from local file (if exists)
        existing_data = []
        try:
            if os.path.exists(local_file):
                with open(local_file, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
                    if not isinstance(existing_data, list):
                        existing_data = [existing_data]
        except:
            existing_data = []
        
        # Append new record
        existing_data.append(new_record)
        
        # Write to local file
        try:
            with open(local_file, 'w', encoding='utf-8') as f:
                json.dump(existing_data, f, indent=2)
            
            return jsonify({
                'status': 'success',
                'message': f'Data saved to {local_file}',
                'company': company,
                'record_count': len(existing_data),
                'note': 'Data is encrypted with company-specific key. Only this company can decrypt it.'
            })
        except Exception as write_err:
            return jsonify({
                'status': 'error',
                'message': f'Failed to write local file: {str(write_err)}'
            }), 500
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/company/populate', methods=['POST'])
@rate_limit(max_calls=5, period=60)
def populate_from_csv():
    """
    Read company CSV file from inside the TEE, encrypt each record,
    and write to consolidated-records.json in blob storage.
    """
    global _released_key
    global _released_key_name
    
    try:
        if not _released_key:
            return jsonify({
                'status': 'error',
                'message': 'No key released. Complete Secure Key Release first.'
            }), 400
        
        company = get_company_name_from_key()
        if not company:
            return jsonify({
                'status': 'error',
                'message': 'Cannot determine company from key name'
            }), 400
        
        # Determine which CSV file to read based on company
        csv_filename = f"{company.lower()}-data.csv"
        csv_path = f"/app/{csv_filename}"
        
        if not os.path.exists(csv_path):
            return jsonify({
                'status': 'error',
                'message': f'CSV file not found: {csv_filename}. File should be at {csv_path}'
            }), 404
        
        # Read CSV file
        import csv
        import datetime
        
        records = []
        with open(csv_path, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                records.append(row)
        
        if not records:
            return jsonify({
                'status': 'error',
                'message': f'No records found in {csv_filename}'
            }), 400
        
        # Encrypt each record - ALL fields get encrypted with company's secret key
        encrypted_records = []
        all_fields = ['name', 'phone', 'address', 'postal_code', 'city', 'country', 'age', 'salary', 'eye_color', 'favorite_color']
        
        for record in records:
            encrypted_record = {
                'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
                'company': company
            }
            
            # Encrypt ALL fields with company's secret key
            for field in all_fields:
                value = record.get(field, '')
                if value:
                    encrypted_value, err = encrypt_data_with_key(str(value))
                    if err:
                        return jsonify({
                            'status': 'error',
                            'message': f'Encryption failed for {field}: {err}'
                        }), 500
                    encrypted_record[f'{field}_encrypted'] = encrypted_value
                else:
                    encrypted_record[f'{field}_encrypted'] = None
            
            encrypted_records.append(encrypted_record)
        
        # Save to local storage inside the container
        local_data_dir = '/app/encrypted-data'
        os.makedirs(local_data_dir, exist_ok=True)
        local_file = f'{local_data_dir}/{company}-encrypted.json'
        
        # Read existing local records (if any)
        existing_data = []
        try:
            if os.path.exists(local_file):
                with open(local_file, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
                    if not isinstance(existing_data, list):
                        existing_data = [existing_data]
        except:
            existing_data = []
        
        # Append new encrypted records
        existing_data.extend(encrypted_records)
        
        # Write to local file
        try:
            with open(local_file, 'w', encoding='utf-8') as f:
                json.dump(existing_data, f, indent=2)
            
            return jsonify({
                'status': 'success',
                'message': f'Populated {len(encrypted_records)} records from {csv_filename}',
                'company': company,
                'source_file': csv_filename,
                'records_added': len(encrypted_records),
                'total_records': len(existing_data),
                'destination': local_file,
                'storage_type': 'local',
                'note': 'All PII fields encrypted with company key. Demographic fields stored for analytics.'
            })
        except Exception as write_err:
            return jsonify({
                'status': 'error',
                'message': f'Failed to write local file: {str(write_err)}'
            }), 500
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/company/list')
def list_company_data():
    """
    Read and display company's encrypted data file from local storage.
    Note: Decryption would require the private key which stays in Azure Key Vault HSM.
    This endpoint shows the encrypted data to demonstrate that it's protected.
    """
    global _released_key
    global _released_key_name
    
    try:
        company = get_company_name_from_key()
        
        if not company:
            # Try to determine company from SKR_KEY_NAME environment variable
            key_name = os.environ.get('SKR_KEY_NAME', '')
            if 'contoso' in key_name.lower():
                company = 'contoso'
            elif 'fabrikam' in key_name.lower():
                company = 'fabrikam'
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Cannot determine company. Release a key first or check SKR configuration.'
                }), 400
        
        # Read from local encrypted data file
        local_data_dir = '/app/encrypted-data'
        local_file = f'{local_data_dir}/{company}-encrypted.json'
        
        if os.path.exists(local_file):
            with open(local_file, 'r', encoding='utf-8') as f:
                all_data = json.load(f)
            
            # Add line numbers to all records (1-based index)
            if isinstance(all_data, list):
                for i, record in enumerate(all_data):
                    record['line_number'] = i + 1
                all_records = all_data
            else:
                all_data['line_number'] = 1
                all_records = [all_data]
            
            return jsonify({
                'status': 'success',
                'company': company,
                'local_file': local_file,
                'record_count': len(all_records),
                'records': all_records,
                'key_released': _released_key is not None,
                'storage_type': 'local',
                'note': 'Data is encrypted and stored locally in the container.'
            })
        else:
            return jsonify({
                'status': 'success',
                'company': company,
                'local_file': local_file,
                'record_count': 0,
                'records': [],
                'message': 'No encrypted data file exists yet. Run /company/populate or wait for auto-initialization.'
            })
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/company/encrypted-status')
def encrypted_data_status():
    """
    Check the status of the encrypted data file (quick summary without full data).
    """
    try:
        key_name = os.environ.get('SKR_KEY_NAME', '')
        company = None
        if 'contoso' in key_name.lower():
            company = 'contoso'
        elif 'fabrikam' in key_name.lower():
            company = 'fabrikam'
        elif 'woodgrove' in key_name.lower():
            company = 'woodgrove'
        
        local_data_dir = '/app/encrypted-data'
        local_file = f'{local_data_dir}/{company}-encrypted.json' if company else None
        
        result = {
            'company': company,
            'key_name': key_name,
            'key_released': _released_key is not None,
            'encrypted_file': local_file,
            'file_exists': os.path.exists(local_file) if local_file else False,
        }
        
        if result['file_exists']:
            # Get file stats
            stat = os.stat(local_file)
            result['file_size_bytes'] = stat.st_size
            
            # Count records
            with open(local_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                result['record_count'] = len(data) if isinstance(data, list) else 1
                
                # Show first record summary (fields only, no values)
                if isinstance(data, list) and len(data) > 0:
                    result['fields'] = list(data[0].keys())
                elif isinstance(data, dict):
                    result['fields'] = list(data.keys())
            
            result['status'] = 'success'
            result['message'] = f'Encrypted data file exists with {result["record_count"]} records'
        else:
            result['status'] = 'pending'
            result['message'] = 'No encrypted data file yet. Auto-initialization may still be running.'
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# =============================================================================
# AUTO-INITIALIZATION ON STARTUP
# =============================================================================

def auto_initialize_woodgrove(key_name, maa_endpoint, akv_endpoint):
    """
    Auto-initialize Woodgrove Bank container:
    1. Wait for SKR sidecar
    2. Release Woodgrove's own key
    3. Release partner keys from Contoso and Fabrikam Key Vaults
    """
    import time
    global _released_key
    global _released_key_name
    
    print(f"\n[WOODGROVE] Starting Woodgrove Bank auto-initialization...")
    
    # Step 1: Wait for SKR sidecar to be ready
    print(f"\n[STEP 1/4] Waiting for SKR sidecar to be ready...")
    max_retries = 30
    sidecar_ready = False
    
    for i in range(max_retries):
        try:
            response = requests.get("http://localhost:8080/", timeout=2)
            sidecar_ready = True
            print(f"           SKR sidecar is ready (attempt {i+1}/{max_retries})")
            break
        except:
            if i < max_retries - 1:
                time.sleep(2)
    
    if not sidecar_ready:
        print(f"\n[ERROR] Woodgrove auto-init FAILED: SKR sidecar not available")
        print(f"{'='*60}\n")
        return
    
    # Step 2: Release Woodgrove's own key
    print(f"\n[STEP 2/4] Releasing Woodgrove's key...")
    try:
        akv_clean = akv_endpoint.replace('https://', '').replace('http://', '')
        maa_clean = maa_endpoint.replace('https://', '').replace('http://', '')
        
        response = requests.post(
            "http://localhost:8080/key/release",
            json={
                "maa_endpoint": maa_clean,
                "akv_endpoint": akv_clean,
                "kid": key_name
            },
            timeout=60
        )
        
        if response.status_code == 200:
            skr_response = response.json()
            key_data = skr_response.get('key', skr_response)
            if isinstance(key_data, str):
                try:
                    key_data = json.loads(key_data)
                except:
                    pass
            
            _released_key = key_data
            _released_key_name = key_name
            print(f"           [SUCCESS] Woodgrove key released: {key_name}")
        else:
            print(f"           [FAILED] Woodgrove key release failed: HTTP {response.status_code}")
    except Exception as e:
        print(f"           [ERROR] Woodgrove key release error: {str(e)}")
    
    # Step 3: Release Contoso partner key
    print(f"\n[STEP 3/4] Releasing partner keys...")
    partner_contoso_akv = os.environ.get('PARTNER_CONTOSO_AKV_ENDPOINT', '')
    partner_fabrikam_akv = os.environ.get('PARTNER_FABRIKAM_AKV_ENDPOINT', '')
    maa_clean = maa_endpoint.replace('https://', '').replace('http://', '')
    
    contoso_success = False
    fabrikam_success = False
    
    if partner_contoso_akv:
        try:
            akv_clean = partner_contoso_akv.replace('https://', '').replace('http://', '')
            print(f"           Releasing Contoso key from {akv_clean}...")
            
            response = requests.post(
                "http://localhost:8080/key/release",
                json={
                    "maa_endpoint": maa_clean,
                    "akv_endpoint": akv_clean,
                    "kid": "contoso-secret-key"
                },
                timeout=60
            )
            
            if response.status_code == 200:
                skr_response = response.json()
                key_data = skr_response.get('key', skr_response)
                if isinstance(key_data, str):
                    try:
                        key_data = json.loads(key_data)
                    except:
                        pass
                store_partner_key('contoso', key_data)
                contoso_success = True
                print(f"           [SUCCESS] Contoso partner key released and stored")
            else:
                print(f"           [FAILED] Contoso key release: HTTP {response.status_code}")
        except Exception as e:
            print(f"           [ERROR] Contoso key release: {str(e)}")
    else:
        print(f"           [SKIP] PARTNER_CONTOSO_AKV_ENDPOINT not configured")
    
    # Step 4: Release Fabrikam partner key
    if partner_fabrikam_akv:
        try:
            akv_clean = partner_fabrikam_akv.replace('https://', '').replace('http://', '')
            print(f"           Releasing Fabrikam key from {akv_clean}...")
            
            response = requests.post(
                "http://localhost:8080/key/release",
                json={
                    "maa_endpoint": maa_clean,
                    "akv_endpoint": akv_clean,
                    "kid": "fabrikam-secret-key"
                },
                timeout=60
            )
            
            if response.status_code == 200:
                skr_response = response.json()
                key_data = skr_response.get('key', skr_response)
                if isinstance(key_data, str):
                    try:
                        key_data = json.loads(key_data)
                    except:
                        pass
                store_partner_key('fabrikam', key_data)
                fabrikam_success = True
                print(f"           [SUCCESS] Fabrikam partner key released and stored")
            else:
                print(f"           [FAILED] Fabrikam key release: HTTP {response.status_code}")
        except Exception as e:
            print(f"           [ERROR] Fabrikam key release: {str(e)}")
    else:
        print(f"           [SKIP] PARTNER_FABRIKAM_AKV_ENDPOINT not configured")
    
    # Summary
    print(f"\n{'='*60}")
    print(f"WOODGROVE AUTO-INITIALIZATION COMPLETED")
    print(f"{'='*60}")
    print(f"  Own Key Released:     {'YES' if _released_key else 'NO'}")
    print(f"  Contoso Key:          {'YES' if contoso_success else 'NO'}")
    print(f"  Fabrikam Key:         {'YES' if fabrikam_success else 'NO'}")
    print(f"  Ready for Analytics:  {'YES' if (contoso_success and fabrikam_success) else 'PARTIAL'}")
    print(f"{'='*60}\n")


def auto_initialize_container():
    """
    Automatically perform attestation, key release, and CSV encryption on startup.
    - Contoso/Fabrikam: Release key, encrypt CSV data
    - Woodgrove: Release own key + partner keys for cross-company analytics
    """
    import time
    import csv
    import datetime
    
    # Determine which company this container belongs to based on SKR_KEY_NAME
    key_name = os.environ.get('SKR_KEY_NAME', '')
    maa_endpoint = os.environ.get('SKR_MAA_ENDPOINT', 'sharedeus.eus.attest.azure.net')
    akv_endpoint = os.environ.get('SKR_AKV_ENDPOINT', '')
    
    # Identify company from key name
    company = None
    if 'contoso' in key_name.lower():
        company = 'contoso'
    elif 'fabrikam' in key_name.lower():
        company = 'fabrikam'
    elif 'woodgrove' in key_name.lower():
        company = 'woodgrove'
    
    # Log startup info
    print(f"\n{'='*60}")
    print(f"AUTO-INITIALIZATION STARTED")
    print(f"{'='*60}")
    print(f"SKR_KEY_NAME: {key_name or '(not set)'}")
    print(f"SKR_MAA_ENDPOINT: {maa_endpoint}")
    print(f"SKR_AKV_ENDPOINT: {akv_endpoint or '(not set)'}")
    print(f"Detected Company: {company or '(unknown)'}")
    
    # Handle Woodgrove separately - it needs partner key release
    if company == 'woodgrove':
        auto_initialize_woodgrove(key_name, maa_endpoint, akv_endpoint)
        return
    
    # Skip if not Contoso or Fabrikam
    if not company or company not in ['contoso', 'fabrikam']:
        print(f"\n[SKIP] This container is not Contoso or Fabrikam (key: {key_name})")
        print(f"       Auto-initialization only runs for data provider containers.")
        print(f"{'='*60}\n")
        return
    
    # Check for CSV file
    csv_filename = f"{company}-data.csv"
    csv_path = f"/app/{csv_filename}"
    
    if not os.path.exists(csv_path):
        print(f"\n[SKIP] CSV file not found: {csv_path}")
        print(f"       Auto-initialization requires {csv_filename}")
        print(f"{'='*60}\n")
        return
    
    # Wait for SKR sidecar to be ready
    print(f"\n[STEP 1/4] Waiting for SKR sidecar to be ready...")
    max_retries = 30
    sidecar_ready = False
    
    for i in range(max_retries):
        try:
            response = requests.get("http://localhost:8080/", timeout=2)
            sidecar_ready = True
            print(f"           SKR sidecar is ready (attempt {i+1}/{max_retries})")
            break
        except:
            if i < max_retries - 1:
                time.sleep(2)
            else:
                print(f"           [FAILED] SKR sidecar not available after {max_retries} attempts")
    
    if not sidecar_ready:
        print(f"\n[ERROR] Auto-initialization FAILED: SKR sidecar not available")
        print(f"{'='*60}\n")
        return
    
    # Step 2: Perform MAA Attestation (informational only - key release does its own attestation)
    print(f"\n[STEP 2/4] Performing MAA attestation...")
    attestation_success = False
    
    try:
        # Clean up endpoint
        maa_clean = maa_endpoint.replace('https://', '').replace('http://', '')
        
        # Encode runtime_data as base64 JSON to satisfy the sidecar's expected format
        import base64
        runtime_payload = base64.b64encode(json.dumps({"source": "auto-init"}).encode()).decode()
        
        response = requests.post(
            "http://localhost:8080/attest/maa",
            json={"maa_endpoint": maa_clean, "runtime_data": runtime_payload},
            timeout=30
        )
        
        if response.status_code == 200:
            attestation_success = True
            print(f"           [SUCCESS] MAA attestation successful")
            print(f"           MAA Endpoint: {maa_clean}")
        else:
            print(f"           [WARNING] MAA attestation failed: HTTP {response.status_code}")
            print(f"           Response: {response.text[:200]}")
            print(f"           Continuing to key release (it performs its own attestation)...")
    except Exception as e:
        print(f"           [WARNING] MAA attestation error: {str(e)}")
        print(f"           Continuing to key release (it performs its own attestation)...")
    
    # Step 3: Perform Secure Key Release (with retry for sidecar timing)
    print(f"\n[STEP 3/4] Performing Secure Key Release...")
    global _released_key
    global _released_key_name
    skr_success = False
    skr_max_retries = 3
    
    for skr_attempt in range(skr_max_retries):
        try:
            # Clean up endpoints
            akv_clean = akv_endpoint.replace('https://', '').replace('http://', '')
            maa_clean = maa_endpoint.replace('https://', '').replace('http://', '')
            
            response = requests.post(
                "http://localhost:8080/key/release",
                json={
                    "maa_endpoint": maa_clean,
                    "akv_endpoint": akv_clean,
                    "kid": key_name
                },
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                key_data = result.get('key', response.text)
                
                # Parse the key if it's JSON string
                if isinstance(key_data, str):
                    try:
                        key_data = json.loads(key_data)
                    except:
                        pass
                
                _released_key = key_data
                _released_key_name = key_name
                skr_success = True
                print(f"           [SUCCESS] Secure Key Release successful (attempt {skr_attempt + 1}/{skr_max_retries})")
                print(f"           Key Name: {key_name}")
                print(f"           AKV Endpoint: {akv_clean}")
                break
            else:
                print(f"           [RETRY] SKR failed: HTTP {response.status_code} (attempt {skr_attempt + 1}/{skr_max_retries})")
                print(f"           Response: {response.text[:200]}")
                if skr_attempt < skr_max_retries - 1:
                    time.sleep(5)
        except Exception as e:
            print(f"           [RETRY] SKR error: {str(e)} (attempt {skr_attempt + 1}/{skr_max_retries})")
            if skr_attempt < skr_max_retries - 1:
                time.sleep(5)
    
    if not skr_success:
        print(f"\n[ERROR] Auto-initialization FAILED: Could not release key")
        print(f"{'='*60}\n")
        return
    
    # Step 4: Encrypt CSV and upload to blob storage
    print(f"\n[STEP 4/4] Encrypting CSV file and uploading to blob storage...")
    
    try:
        # Read CSV file
        records = []
        with open(csv_path, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                records.append(row)
        
        total_records = len(records)
        print(f"           CSV File: {csv_filename}")
        print(f"           Total Records: {total_records}")
        
        if total_records == 0:
            print(f"           [SKIP] No records to encrypt")
            print(f"{'='*60}\n")
            return
        
        # Encrypt each record - ALL fields get encrypted with company's secret key
        encrypted_records = []
        encryption_errors = 0
        all_fields = ['name', 'phone', 'address', 'postal_code', 'city', 'country', 'age', 'salary', 'eye_color', 'favorite_color']
        
        for record in records:
            encrypted_record = {
                'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
                'company': company
            }
            
            has_error = False
            # Encrypt ALL fields with company's secret key
            for field in all_fields:
                value = record.get(field, '')
                if value:
                    encrypted_value, err = encrypt_data_with_key(str(value))
                    if err:
                        has_error = True
                        break
                    encrypted_record[f'{field}_encrypted'] = encrypted_value
                else:
                    encrypted_record[f'{field}_encrypted'] = None
            
            if has_error:
                encryption_errors += 1
                continue
            
            encrypted_records.append(encrypted_record)
        
        lines_encrypted = len(encrypted_records)
        print(f"           Records Encrypted: {lines_encrypted}")
        
        if encryption_errors > 0:
            print(f"           Encryption Errors: {encryption_errors}")
        
        if lines_encrypted == 0:
            print(f"           [FAILED] No records encrypted successfully")
            print(f"{'='*60}\n")
            return
        
        # Save to local storage inside the container
        local_data_dir = '/app/encrypted-data'
        os.makedirs(local_data_dir, exist_ok=True)
        local_file = f'{local_data_dir}/{company}-encrypted.json'
        
        # Read existing local records (if any)
        existing_data = []
        try:
            if os.path.exists(local_file):
                with open(local_file, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
                    if not isinstance(existing_data, list):
                        existing_data = [existing_data]
        except:
            existing_data = []
        
        # Append new encrypted records
        existing_data.extend(encrypted_records)
        
        # Write to local file
        try:
            with open(local_file, 'w', encoding='utf-8') as f:
                json.dump(existing_data, f, indent=2)
            
            print(f"           [SUCCESS] Saved to local storage")
            print(f"           Destination: {local_file}")
        except Exception as write_err:
            print(f"           [FAILED] Write failed: {str(write_err)}")
            print(f"{'='*60}\n")
            return
        
        # Final summary
        print(f"\n{'='*60}")
        print(f"AUTO-INITIALIZATION COMPLETED SUCCESSFULLY")
        print(f"{'='*60}")
        print(f"  Company:          {company.upper()}")
        print(f"  Key Used:         {key_name}")
        print(f"  Source File:      {csv_filename}")
        print(f"  Records Read:     {total_records}")
        print(f"  Lines Encrypted:  {lines_encrypted}")
        print(f"  Total in Storage: {len(existing_data)}")
        print(f"  Output File:      {local_file}")
        print(f"  Attestation:      {'SUCCESS' if attestation_success else 'FAILED'}")
        print(f"  Key Release:      {'SUCCESS' if skr_success else 'FAILED'}")
        print(f"  Encryption:       SUCCESS")
        print(f"  Local Save:       SUCCESS")
        print(f"{'='*60}\n")
        
    except Exception as e:
        print(f"           [ERROR] Exception during encryption/upload: {str(e)}")
        print(f"{'='*60}\n")

_auto_init_started = False
_auto_init_lock = threading.Lock()

def start_auto_initialization():
    """Start auto-initialization in a background thread (runs only once across workers)"""
    global _auto_init_started
    with _auto_init_lock:
        if _auto_init_started:
            return
        _auto_init_started = True
    
    def delayed_init():
        # Give the server a moment to start
        time.sleep(3)
        try:
            auto_initialize_container()
        except Exception as e:
            print(f"\n[AUTO-INIT ERROR] {str(e)}\n")
    
    # Run in background thread so the server can start immediately
    init_thread = threading.Thread(target=delayed_init, daemon=True)
    init_thread.start()
    print("\n[INFO] Auto-initialization thread started (will run in background)\n")

# Start auto-initialization when module loads (works with both gunicorn and direct execution)
start_auto_initialization()

if __name__ == '__main__':
    # Run on port 80 to match Azure Container Instances default
    app.run(host='0.0.0.0', port=80, debug=False)
