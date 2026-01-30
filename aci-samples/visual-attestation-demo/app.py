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

if __name__ == '__main__':
    # Run on port 80 to match Azure Container Instances default
    app.run(host='0.0.0.0', port=80, debug=False)
