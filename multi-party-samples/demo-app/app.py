from flask import Flask, jsonify, request, render_template
import requests
import json
import os

app = Flask(__name__)

# Log file paths (configured in supervisord.conf)
LOG_FILES = {
    'skr': '/var/log/supervisor/skr.log',
    'skr_error': '/var/log/supervisor/skr_error.log',
    'flask': '/var/log/supervisor/flask.log',
    'flask_error': '/var/log/supervisor/flask_error.log',
    'supervisord': '/var/log/supervisor/supervisord.log'
}

def check_sev_guest_device():
    """Check for AMD SEV-SNP guest device and return status info"""
    sev_devices = [
        '/dev/sev-guest',
        '/dev/sev',
        '/dev/sev0'
    ]
    
    result = {
        'available': False,
        'device_path': None,
        'device_info': None,
        'explanation': None
    }
    
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
    
    if not result['available']:
        result['explanation'] = (
            'No AMD SEV-SNP device found (/dev/sev-guest, /dev/sev, /dev/sev0). '
            'This means the container is NOT running inside a Trusted Execution Environment (TEE). '
            'Hardware-based attestation is not possible. '
            'To enable attestation, deploy with Confidential SKU (without -NoAcc flag) on AMD SEV-SNP capable hardware.'
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
def attest_maa():
    """
    Request attestation from Microsoft Azure Attestation (MAA) via sidecar
    This endpoint forwards the request to the attestation sidecar container
    """
    try:
        data = request.get_json()
        # Use the shared MAA endpoint for East US
        maa_endpoint = data.get('maa_endpoint', 'sharedeus.eus.attest.azure.net')
        runtime_data = data.get('runtime_data', '')
        
        # Ensure the endpoint doesn't have https:// prefix - sidecar adds it
        if maa_endpoint.startswith('https://'):
            maa_endpoint = maa_endpoint.replace('https://', '')
        if maa_endpoint.startswith('http://'):
            maa_endpoint = maa_endpoint.replace('http://', '')

        # Forward request to attestation sidecar (running on localhost:8080)
        response = requests.post(
            "http://localhost:8080/attest/maa",
            json={"maa_endpoint": maa_endpoint, "runtime_data": runtime_data},
            timeout=30
        )

        # Check if sidecar returned an error
        if response.status_code != 200:
            # Parse common error scenarios
            error_detail = response.text[:1000] if response.text else "No response body"
            
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
                    'command': '.\\Deploy-AttestationDemo.ps1 -Build -Deploy'
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
            error_detail = response.text[:1000] if response.text else "No response body"
            
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
        
        if not akv_endpoint or not kid:
            return jsonify({
                'status': 'error',
                'message': 'SKR not configured. Deploy with SKR-enabled Key Vault to use this feature.',
                'note': 'Missing akv_endpoint or key name. These are set via SKR_AKV_ENDPOINT and SKR_KEY_NAME environment variables.',
                'maa_endpoint': maa_endpoint,
                'akv_endpoint': akv_endpoint or '(not configured)',
                'key_name': kid or '(not configured)'
            }), 400
        
        # Ensure endpoints don't have https:// prefix - sidecar adds it
        if maa_endpoint.startswith('https://'):
            maa_endpoint = maa_endpoint.replace('https://', '')
        if maa_endpoint.startswith('http://'):
            maa_endpoint = maa_endpoint.replace('http://', '')
        if akv_endpoint.startswith('https://'):
            akv_endpoint = akv_endpoint.replace('https://', '')
        if akv_endpoint.startswith('http://'):
            akv_endpoint = akv_endpoint.replace('http://', '')

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
            error_detail = response.text[:2000] if response.text else "No response body"
            
            # Try to parse error JSON
            error_json = None
            try:
                error_json = response.json()
                if 'error' in error_json:
                    error_detail = error_json['error']
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
            
            return jsonify({
                'status': 'error',
                'message': f'Secure Key Release failed with status {response.status_code}',
                'failure_reason': failure_reason,
                'sidecar_response': error_detail,
                'sidecar_status_code': response.status_code,
                'maa_endpoint': maa_endpoint,
                'akv_endpoint': akv_endpoint,
                'key_name': kid,
                'diagnosis': {
                    'likely_cause': 'Container is deployed with Standard SKU (no AMD SEV-SNP TEE)',
                    'explanation': 'Secure Key Release requires hardware attestation to prove the container is running in a TEE. Without AMD SEV-SNP, the attestation fails and the key cannot be released.',
                    'solution': 'Redeploy without the -NoAcc flag to use Confidential SKU',
                    'command': '.\\Deploy-AttestationDemo.ps1 -Build -Deploy'
                },
                'note': 'SKR requires: 1) Confidential SKU with AMD SEV-SNP, 2) Key Vault Premium with HSM-backed key, 3) Release policy trusting the MAA endpoint',
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
            
            return jsonify({
                'status': 'success',
                'message': 'Secure Key Release successful!',
                'key': key_data,
                'maa_endpoint': maa_endpoint,
                'akv_endpoint': akv_endpoint,
                'key_name': kid,
                'note': 'This key was released because the container proved it is running in a hardware TEE that matches the key release policy.',
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
    
    # Determine company name from key name
    company_name = None
    key_lower = key_name.lower()
    if 'contoso' in key_lower:
        company_name = 'Contoso'
    elif 'fabrikam' in key_lower:
        company_name = 'Fabrikam'
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
    
    if 'contoso' in key_lower:
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
        'configured': bool(akv_endpoint and key_name),
        'other_company': {
            'name': other_company_name,
            'key_name': other_key_name,
            'akv_endpoint': other_akv_endpoint
        } if other_company_name else None
    })

@app.route('/skr/release-other', methods=['POST'])
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
_released_key = None
_released_key_name = None  # Store the key name to identify company

@app.route('/encrypt', methods=['POST'])
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
    import hashlib
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
                        'md5': hashlib.md5(content).hexdigest(),
                        'sha256': hashlib.sha256(content).hexdigest()[:32] + '...',
                        'size_bytes': len(content)
                    }
        except Exception as e:
            info['app_checksums'][filepath] = {'error': str(e)}
    
    # Get SKR binary info
    skr_binary = '/app/skr'
    try:
        if os.path.exists(skr_binary):
            with open(skr_binary, 'rb') as f:
                content = f.read()
                info['skr_binary_info'] = {
                    'path': skr_binary,
                    'md5': hashlib.md5(content).hexdigest(),
                    'sha256': hashlib.sha256(content).hexdigest()[:32] + '...',
                    'size_bytes': len(content),
                    'executable': os.access(skr_binary, os.X_OK)
                }
            
            # Try to get version info
            try:
                result = subprocess.run([skr_binary, '--version'], capture_output=True, text=True, timeout=5)
                info['skr_binary_info']['version'] = result.stdout.strip() or result.stderr.strip() or 'No version output'
            except subprocess.TimeoutExpired:
                info['skr_binary_info']['version'] = 'Timeout getting version'
            except Exception as e:
                info['skr_binary_info']['version'] = f'Error: {str(e)}'
        else:
            info['skr_binary_info'] = {'error': 'SKR binary not found at /app/skr'}
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
                'solution': 'Deploy with Confidential SKU: .\\Deploy-AttestationDemo.ps1 -Build -Deploy (without -NoAcc)',
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

# ============================================================================
# External Storage Access - Demonstrates data access from blob storage
# ============================================================================

# Configuration for the external storage account (created by Create-StorageAccount.ps1)
# Connection string should be stored in environment variable AZURE_STORAGE_CONNECTION_STRING
# or in a .env file (which is gitignored)
EXTERNAL_STORAGE_ACCOUNT = "orangeappstorezspo861"
EXTERNAL_CONTAINER_NAME = "privateappdata"
EXTERNAL_BLOB_ENDPOINT = f"https://{EXTERNAL_STORAGE_ACCOUNT}.blob.core.windows.net"

def get_storage_sas_token():
    """Extract SAS token from connection string environment variable"""
    conn_str = os.environ.get('AZURE_STORAGE_CONNECTION_STRING', '')
    if not conn_str:
        return None
    # Parse the SAS token from connection string
    # Format: ...;SharedAccessSignature=sv=...
    if 'SharedAccessSignature=' in conn_str:
        sas_part = conn_str.split('SharedAccessSignature=')[-1]
        return sas_part
    return None

def get_sas_token_expiry():
    """Parse the SAS token to extract expiry date (se parameter)"""
    from urllib.parse import parse_qs
    from datetime import datetime, timezone
    
    sas_token = get_storage_sas_token()
    if not sas_token:
        return None
    
    try:
        # Parse the SAS token query parameters
        params = parse_qs(sas_token)
        
        # 'se' is the signed expiry parameter
        expiry_str = params.get('se', [None])[0]
        if not expiry_str:
            return None
        
        # Parse the ISO 8601 date format (e.g., 2026-02-10T00:00:00Z)
        expiry_dt = datetime.fromisoformat(expiry_str.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        
        # Calculate days remaining
        delta = expiry_dt - now
        days_remaining = delta.days
        
        return {
            'expiry_date': expiry_str,
            'expiry_formatted': expiry_dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'days_remaining': days_remaining,
            'is_expired': days_remaining < 0,
            'is_expiring_soon': 0 <= days_remaining <= 7
        }
    except Exception as e:
        return {'error': str(e)}

def get_storage_url_with_sas(base_url):
    """Append SAS token to URL if available"""
    sas_token = get_storage_sas_token()
    if sas_token:
        separator = '&' if '?' in base_url else '?'
        return f"{base_url}{separator}{sas_token}"
    return base_url

@app.route('/storage/config')
def storage_config():
    """Return the external storage configuration"""
    has_sas = get_storage_sas_token() is not None
    expiry_info = get_sas_token_expiry()
    return jsonify({
        'storage_account': EXTERNAL_STORAGE_ACCOUNT,
        'container_name': EXTERNAL_CONTAINER_NAME,
        'blob_endpoint': EXTERNAL_BLOB_ENDPOINT,
        'container_url': f"{EXTERNAL_BLOB_ENDPOINT}/{EXTERNAL_CONTAINER_NAME}",
        'authenticated': has_sas,
        'auth_method': 'SAS Token' if has_sas else 'Anonymous (public access only)',
        'sas_expiry': expiry_info
    })

@app.route('/storage/list')
def list_blobs():
    """
    List blobs in the external storage container.
    Uses SAS token from environment variable if available.
    """
    try:
        # Azure Blob Storage supports listing via REST API with restype=container&comp=list
        base_url = f"{EXTERNAL_BLOB_ENDPOINT}/{EXTERNAL_CONTAINER_NAME}?restype=container&comp=list"
        list_url = get_storage_url_with_sas(base_url)
        
        response = requests.get(list_url, timeout=10)
        
        if response.status_code == 200:
            # Parse the XML response
            import xml.etree.ElementTree as ET
            root = ET.fromstring(response.text)
            
            blobs = []
            for blob in root.findall('.//Blob'):
                blob_info = {
                    'name': blob.find('Name').text if blob.find('Name') is not None else 'Unknown',
                }
                # Get properties if available
                props = blob.find('Properties')
                if props is not None:
                    blob_info['size'] = props.find('Content-Length').text if props.find('Content-Length') is not None else '0'
                    blob_info['content_type'] = props.find('Content-Type').text if props.find('Content-Type') is not None else 'unknown'
                    blob_info['last_modified'] = props.find('Last-Modified').text if props.find('Last-Modified') is not None else 'unknown'
                    blob_info['url'] = f"{EXTERNAL_BLOB_ENDPOINT}/{EXTERNAL_CONTAINER_NAME}/{blob_info['name']}"
                blobs.append(blob_info)
            
            return jsonify({
                'status': 'success',
                'storage_account': EXTERNAL_STORAGE_ACCOUNT,
                'container': EXTERNAL_CONTAINER_NAME,
                'blob_count': len(blobs),
                'blobs': blobs,
                'message': 'Successfully listed blobs from external storage',
                'security_note': 'Data accessed using SAS token authentication' if get_storage_sas_token() else 'This data is publicly accessible - no attestation required!',
                'authenticated': get_storage_sas_token() is not None
            })
        elif response.status_code == 404:
            return jsonify({
                'status': 'error',
                'message': 'Container not found. The storage account or container may not exist yet.',
                'storage_account': EXTERNAL_STORAGE_ACCOUNT,
                'container': EXTERNAL_CONTAINER_NAME,
                'hint': 'Run Create-StorageAccount.ps1 to create the storage account and container.'
            }), 404
        elif response.status_code == 403:
            return jsonify({
                'status': 'error',
                'message': 'Access denied. The container may not have public access enabled.',
                'storage_account': EXTERNAL_STORAGE_ACCOUNT,
                'container': EXTERNAL_CONTAINER_NAME
            }), 403
        else:
            return jsonify({
                'status': 'error',
                'message': f'Unexpected response from storage: HTTP {response.status_code}',
                'response_text': response.text[:500]
            }), response.status_code
            
    except requests.exceptions.ConnectionError as e:
        return jsonify({
            'status': 'error',
            'message': 'Cannot connect to storage account. Network may be unavailable.',
            'error': str(e)
        }), 503
    except requests.exceptions.Timeout:
        return jsonify({
            'status': 'error',
            'message': 'Request to storage account timed out.'
        }), 504
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'exception_type': type(e).__name__
        }), 500

@app.route('/storage/download/<path:blob_name>')
def download_blob(blob_name):
    """
    Download a specific blob and return its contents.
    Uses SAS token from environment variable if available.
    """
    try:
        base_url = f"{EXTERNAL_BLOB_ENDPOINT}/{EXTERNAL_CONTAINER_NAME}/{blob_name}"
        blob_url = get_storage_url_with_sas(base_url)
        response = requests.get(blob_url, timeout=30)
        
        if response.status_code == 200:
            # Try to decode as text, fallback to base64 for binary
            try:
                content = response.text
                is_text = True
            except:
                import base64
                content = base64.b64encode(response.content).decode('utf-8')
                is_text = False
            
            return jsonify({
                'status': 'success',
                'blob_name': blob_name,
                'content': content,
                'is_text': is_text,
                'size': len(response.content),
                'content_type': response.headers.get('Content-Type', 'unknown'),
                'security_note': 'Data accessed using SAS token authentication' if get_storage_sas_token() else 'This data was accessed WITHOUT attestation - it is publicly readable!',
                'authenticated': get_storage_sas_token() is not None
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to download blob: HTTP {response.status_code}',
                'blob_name': blob_name
            }), response.status_code
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'blob_name': blob_name
        }), 500

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
def save_company_data():
    """
    Save encrypted data to company-specific blob storage file.
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
        
        # Read existing data from consolidated file (if exists)
        blob_name = "consolidated-records.json"
        existing_data = []
        
        try:
            base_url = f"{EXTERNAL_BLOB_ENDPOINT}/{EXTERNAL_CONTAINER_NAME}/{blob_name}"
            read_url = get_storage_url_with_sas(base_url)
            response = requests.get(read_url, timeout=10)
            if response.status_code == 200:
                existing_data = response.json()
                if not isinstance(existing_data, list):
                    existing_data = [existing_data]
        except:
            existing_data = []
        
        # Append new record
        existing_data.append(new_record)
        
        # Upload to blob storage
        sas_token = get_storage_sas_token()
        if not sas_token:
            return jsonify({
                'status': 'error',
                'message': 'No storage SAS token configured. Cannot save data.'
            }), 500
        
        upload_url = f"{EXTERNAL_BLOB_ENDPOINT}/{EXTERNAL_CONTAINER_NAME}/{blob_name}?{sas_token}"
        headers = {
            'Content-Type': 'application/json',
            'x-ms-blob-type': 'BlockBlob'
        }
        
        upload_response = requests.put(
            upload_url,
            data=json.dumps(existing_data, indent=2),
            headers=headers,
            timeout=30
        )
        
        if upload_response.status_code in [200, 201]:
            return jsonify({
                'status': 'success',
                'message': f'Data saved to {blob_name}',
                'company': company,
                'blob_name': blob_name,
                'record_count': len(existing_data),
                'note': 'Data is encrypted with company-specific key. Only this company can decrypt it.'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to upload: HTTP {upload_response.status_code}',
                'response': upload_response.text[:500]
            }), upload_response.status_code
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/company/populate', methods=['POST'])
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
        
        # Encrypt each record
        encrypted_records = []
        for record in records:
            name = record.get('name', '')
            phone = record.get('phone', '')
            
            encrypted_name, err1 = encrypt_data_with_key(name) if name else (None, None)
            encrypted_phone, err2 = encrypt_data_with_key(phone) if phone else (None, None)
            
            if err1 or err2:
                return jsonify({
                    'status': 'error',
                    'message': f'Encryption failed: {err1 or err2}'
                }), 500
            
            encrypted_records.append({
                'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
                'company': company,
                'name_encrypted': encrypted_name,
                'phone_encrypted': encrypted_phone
            })
        
        # Read existing consolidated records (if any)
        blob_name = "consolidated-records.json"
        existing_data = []
        
        try:
            base_url = f"{EXTERNAL_BLOB_ENDPOINT}/{EXTERNAL_CONTAINER_NAME}/{blob_name}"
            read_url = get_storage_url_with_sas(base_url)
            response = requests.get(read_url, timeout=10)
            if response.status_code == 200:
                existing_data = response.json()
                if not isinstance(existing_data, list):
                    existing_data = [existing_data]
        except:
            existing_data = []
        
        # Append new encrypted records
        existing_data.extend(encrypted_records)
        
        # Upload to blob storage
        sas_token = get_storage_sas_token()
        if not sas_token:
            return jsonify({
                'status': 'error',
                'message': 'No storage SAS token configured. Cannot save data.'
            }), 500
        
        upload_url = f"{EXTERNAL_BLOB_ENDPOINT}/{EXTERNAL_CONTAINER_NAME}/{blob_name}?{sas_token}"
        headers = {
            'Content-Type': 'application/json',
            'x-ms-blob-type': 'BlockBlob'
        }
        
        upload_response = requests.put(
            upload_url,
            data=json.dumps(existing_data, indent=2),
            headers=headers,
            timeout=30
        )
        
        if upload_response.status_code in [200, 201]:
            return jsonify({
                'status': 'success',
                'message': f'Populated {len(encrypted_records)} records from {csv_filename}',
                'company': company,
                'source_file': csv_filename,
                'records_added': len(encrypted_records),
                'total_records': len(existing_data),
                'destination': blob_name,
                'note': 'All records encrypted with company key before storage.'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to upload: HTTP {upload_response.status_code}',
                'response': upload_response.text[:500]
            }), upload_response.status_code
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/company/list')
def list_company_data():
    """
    Read and display company's encrypted data file.
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
        
        # Read from consolidated-records.json and filter by company
        blob_name = "consolidated-records.json"
        
        # Read from blob storage
        base_url = f"{EXTERNAL_BLOB_ENDPOINT}/{EXTERNAL_CONTAINER_NAME}/{blob_name}"
        read_url = get_storage_url_with_sas(base_url)
        
        response = requests.get(read_url, timeout=10)
        
        if response.status_code == 200:
            all_data = response.json()
            # Filter records by company
            if isinstance(all_data, list):
                company_records = [r for r in all_data if r.get('company', '').lower() == company.lower()]
            else:
                company_records = [all_data] if all_data.get('company', '').lower() == company.lower() else []
            
            return jsonify({
                'status': 'success',
                'company': company,
                'blob_name': blob_name,
                'record_count': len(company_records),
                'total_records_in_file': len(all_data) if isinstance(all_data, list) else 1,
                'records': company_records,
                'key_released': _released_key is not None,
                'note': 'Data is encrypted. The ciphertext can only be decrypted by the private key in Azure Key Vault HSM.'
            })
        elif response.status_code == 404:
            return jsonify({
                'status': 'success',
                'company': company,
                'blob_name': blob_name,
                'record_count': 0,
                'records': [],
                'message': 'No data file exists yet. Save some data first.'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to read blob: HTTP {response.status_code}',
                'company': company
            }), response.status_code
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    # Run on port 80 to match Azure Container Instances default
    app.run(host='0.0.0.0', port=80, debug=False)
