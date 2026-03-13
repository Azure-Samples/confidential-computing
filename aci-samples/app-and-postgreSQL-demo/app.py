from flask import Flask, jsonify, request, render_template, Response
import requests
import json
import os
import re
import secrets
import threading
from functools import wraps
import time
import logging
import psycopg2
import psycopg2.pool

# ---------------------------------------------------------------------------
# Flask Application Setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024

log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)

# ---------------------------------------------------------------------------
# Database Connection Pool
# ---------------------------------------------------------------------------
_db_pool = None
_db_pool_lock = threading.Lock()


def _get_db_pool():
    """Lazy-initialize a thread-safe PostgreSQL connection pool."""
    global _db_pool
    if _db_pool is not None:
        return _db_pool
    with _db_pool_lock:
        if _db_pool is not None:
            return _db_pool
        db_host = os.environ.get('DB_HOST', '')
        db_name = os.environ.get('DB_NAME', 'financedemo')
        db_user = os.environ.get('DB_USER', '')
        db_password = os.environ.get('DB_PASSWORD', '')
        if not db_host or not db_user:
            return None
        _db_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=1, maxconn=5,
            host=db_host, dbname=db_name,
            user=db_user, password=db_password,
            port=5432, sslmode='require',
            connect_timeout=10,
        )
        return _db_pool


def _get_db_conn():
    """Get a connection from the pool."""
    pool = _get_db_pool()
    if pool is None:
        raise RuntimeError('Database not configured (DB_HOST / DB_USER missing)')
    return pool.getconn()


def _put_db_conn(conn):
    """Return a connection to the pool."""
    pool = _get_db_pool()
    if pool is not None:
        pool.putconn(conn)


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
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    if request.path.startswith('/skr/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
    return response


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------
_rate_limit_store = {}
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
                calls = [t for t in calls if now - t < period]
                if len(calls) >= max_calls:
                    return jsonify({'status': 'error', 'message': 'Rate limit exceeded.'}), 429
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
    """Validate that a value looks like a hostname."""
    if not value:
        return value
    for prefix in ('https://', 'http://'):
        if value.startswith(prefix):
            value = value[len(prefix):]
    value = value.split('/')[0]
    if not _ENDPOINT_RE.match(value):
        raise ValueError(f'Invalid {name}: contains disallowed characters')
    return value


def _safe_error_detail(text, max_len=500):
    """Truncate error detail for safe inclusion in responses."""
    if not text:
        return 'No details available'
    text = str(text)
    if len(text) > max_len:
        return text[:max_len] + '... (truncated)'
    return text


# ---------------------------------------------------------------------------
# Log file reader (for diagnostics)
# ---------------------------------------------------------------------------
def read_log_files():
    """Read recent log entries for diagnostics."""
    logs = {}
    log_files = {
        'skr': '/var/log/supervisor/skr_error.log',
        'flask': '/var/log/supervisor/flask_error.log',
        'supervisor': '/var/log/supervisor/supervisord.log',
    }
    for name, path in log_files.items():
        try:
            with open(path, 'r') as f:
                content = f.read()
                lines = content.strip().split('\n')
                logs[name] = lines[-20:] if len(lines) > 20 else lines
        except FileNotFoundError:
            logs[name] = [f'{path} not found']
        except Exception as e:
            logs[name] = [f'Error reading {path}: {str(e)}']
    return logs


# ---------------------------------------------------------------------------
# Global SKR key storage
# ---------------------------------------------------------------------------
_released_key = None
_released_key_name = None


# ============================================================================
# ROUTES
# ============================================================================

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    """Serve the financial analytics dashboard."""
    return render_template('index.html')


# ---------------------------------------------------------------------------
# Attestation Endpoints (MAA / Raw)
# ---------------------------------------------------------------------------
@app.route('/attest/maa', methods=['POST'])
@rate_limit(max_calls=20, period=60)
def attest_maa():
    """Request attestation from Microsoft Azure Attestation via sidecar."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'Request body required'}), 400

        env_maa = os.environ.get('SKR_MAA_ENDPOINT', 'sharedeus.eus.attest.azure.net')
        maa_endpoint = data.get('maa_endpoint', env_maa)
        runtime_data = data.get('runtime_data', '')

        try:
            maa_endpoint = _validate_endpoint(maa_endpoint, 'maa_endpoint')
        except ValueError as ve:
            return jsonify({'status': 'error', 'message': str(ve)}), 400

        if not maa_endpoint.endswith('.attest.azure.net'):
            return jsonify({'status': 'error', 'message': 'maa_endpoint must be *.attest.azure.net'}), 400

        response = requests.post(
            "http://localhost:8080/attest/maa",
            json={"maa_endpoint": maa_endpoint, "runtime_data": runtime_data},
            timeout=30
        )

        if response.status_code != 200:
            error_detail = _safe_error_detail(response.text)
            failure_reason = "Unknown attestation failure"
            if "SNP" in error_detail.upper() or "SEV" in error_detail.upper():
                failure_reason = "AMD SEV-SNP hardware not available"
            elif response.status_code == 500:
                failure_reason = "Internal error in attestation sidecar"

            return jsonify({
                'status': 'error',
                'message': f'Attestation failed with status {response.status_code}',
                'failure_reason': failure_reason,
                'sidecar_response': error_detail,
                'diagnosis': {
                    'likely_cause': 'Container deployed with Standard SKU (no TEE)',
                    'solution': 'Redeploy with Confidential SKU'
                },
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
            'message': 'Attestation sidecar not available.',
            'logs': read_log_files()
        }), 503
    except requests.exceptions.Timeout:
        return jsonify({'status': 'error', 'message': 'Attestation request timed out.'}), 504
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/attest/raw', methods=['POST'])
@rate_limit(max_calls=20, period=60)
def attest_raw():
    """Get raw attestation report from the sidecar."""
    try:
        data = request.get_json()
        runtime_data = data.get('runtime_data', '')

        response = requests.post(
            "http://localhost:8080/attest/raw",
            json={"runtime_data": runtime_data},
            timeout=30
        )

        if response.status_code != 200:
            error_detail = _safe_error_detail(response.text)
            return jsonify({
                'status': 'error',
                'message': f'Raw attestation failed with status {response.status_code}',
                'sidecar_response': error_detail,
            }), response.status_code

        return jsonify({
            'status': 'success',
            'attestation_report': response.text
        })
    except requests.exceptions.ConnectionError:
        return jsonify({'status': 'error', 'message': 'Sidecar not available.'}), 503
    except requests.exceptions.Timeout:
        return jsonify({'status': 'error', 'message': 'Timed out.'}), 504
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ---------------------------------------------------------------------------
# Sidecar Status
# ---------------------------------------------------------------------------
@app.route('/sidecar/status', methods=['GET'])
def sidecar_status():
    """Check if the attestation sidecar is reachable."""
    try:
        response = requests.get("http://localhost:8080/status", timeout=5)
        return jsonify({
            'status': 'available',
            'sidecar_response': response.text,
            'sidecar_status_code': response.status_code
        })
    except requests.exceptions.ConnectionError:
        return jsonify({'status': 'unavailable', 'message': 'Sidecar not reachable'}), 503
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ---------------------------------------------------------------------------
# Secure Key Release (SKR)
# ---------------------------------------------------------------------------
@app.route('/skr/release', methods=['POST'])
@rate_limit(max_calls=10, period=60)
def skr_release():
    """Release a key from Azure Key Vault using Secure Key Release."""
    try:
        env_maa_endpoint = os.environ.get('SKR_MAA_ENDPOINT', 'sharedeus.eus.attest.azure.net')
        env_akv_endpoint = os.environ.get('SKR_AKV_ENDPOINT', '')
        env_key_name = os.environ.get('SKR_KEY_NAME', '')

        data = request.get_json(silent=True) or {}
        maa_endpoint = data.get('maa_endpoint', env_maa_endpoint)
        akv_endpoint = data.get('akv_endpoint', env_akv_endpoint)
        kid = data.get('kid', env_key_name)

        try:
            maa_endpoint = _validate_endpoint(maa_endpoint, 'maa_endpoint')
            akv_endpoint = _validate_endpoint(akv_endpoint, 'akv_endpoint')
        except ValueError as ve:
            return jsonify({'status': 'error', 'message': str(ve)}), 400

        if maa_endpoint and not maa_endpoint.endswith('.attest.azure.net'):
            return jsonify({'status': 'error', 'message': 'maa_endpoint must be *.attest.azure.net'}), 400
        if akv_endpoint and not akv_endpoint.endswith('.vault.azure.net'):
            return jsonify({'status': 'error', 'message': 'akv_endpoint must be *.vault.azure.net'}), 400

        if not akv_endpoint or not kid:
            return jsonify({
                'status': 'error',
                'message': 'SKR not configured. Missing akv_endpoint or key name.',
            }), 400

        response = requests.post(
            "http://localhost:8080/key/release",
            json={"maa_endpoint": maa_endpoint, "akv_endpoint": akv_endpoint, "kid": kid},
            timeout=60
        )

        if response.status_code != 200:
            error_detail = _safe_error_detail(response.text, 1000)
            failure_reason = "Secure Key Release failed"
            if "SNP" in error_detail.upper() or "SEV" in error_detail.upper():
                failure_reason = "AMD SEV-SNP hardware not available"
            elif "policy" in error_detail.lower():
                failure_reason = "Key release policy validation failed"
            elif response.status_code == 500:
                failure_reason = "Internal SKR sidecar error"

            return jsonify({
                'status': 'error',
                'message': f'SKR failed with status {response.status_code}',
                'failure_reason': failure_reason,
                'sidecar_response': error_detail,
                'logs': read_log_files()
            }), response.status_code

        try:
            result = response.json()
            key_data = result.get('key', response.text)
            if isinstance(key_data, str):
                try:
                    key_data = json.loads(key_data)
                except Exception:
                    pass

            global _released_key, _released_key_name
            _released_key = key_data
            _released_key_name = kid

            security_policy_hash = os.environ.get('SECURITY_POLICY_HASH', '')
            release_policy_info = {
                'maa_endpoint': f'https://{maa_endpoint}',
                'required_claims': [
                    {
                        'claim': 'x-ms-attestation-type',
                        'value': 'sevsnpvm',
                        'description': 'Requires AMD SEV-SNP hardware attestation'
                    },
                    {
                        'claim': 'x-ms-sevsnpvm-hostdata',
                        'value': security_policy_hash,
                        'description': 'Container security policy hash must match — binds key to this specific container'
                    }
                ]
            }
            return jsonify({
                'status': 'success',
                'message': 'Secure Key Release successful!',
                'key': key_data,
                'key_name': kid,
                'maa_endpoint': maa_endpoint,
                'akv_endpoint': akv_endpoint,
                'security_policy_hash': security_policy_hash,
                'release_policy': release_policy_info,
            })
        except Exception as parse_error:
            return jsonify({
                'status': 'success',
                'message': 'Key released (raw)',
                'key_name': kid,
                'parse_warning': str(parse_error)
            })

    except requests.exceptions.ConnectionError:
        return jsonify({'status': 'error', 'message': 'SKR sidecar not available.', 'logs': read_log_files()}), 503
    except requests.exceptions.Timeout:
        return jsonify({'status': 'error', 'message': 'SKR request timed out.'}), 504
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e), 'logs': read_log_files()}), 500


@app.route('/skr/config', methods=['GET'])
def skr_config():
    """Return the SKR configuration."""
    return jsonify({
        'maa_endpoint': os.environ.get('SKR_MAA_ENDPOINT', ''),
        'akv_endpoint': os.environ.get('SKR_AKV_ENDPOINT', ''),
        'key_name': os.environ.get('SKR_KEY_NAME', ''),
        'key_released': _released_key is not None,
        'security_policy_hash': os.environ.get('SECURITY_POLICY_HASH', ''),
    })


# ---------------------------------------------------------------------------
# Security Policy
# ---------------------------------------------------------------------------
@app.route('/security/policy', methods=['GET'])
def security_policy():
    """Return security policy details."""
    tee_available = os.path.exists('/dev/sev-guest') or os.path.exists('/dev/sev') or os.path.exists('/dev/sev0')
    return jsonify({
        'container_type': 'Confidential' if tee_available else 'Standard',
        'tee_available': tee_available,
        'tee_type': 'AMD SEV-SNP' if tee_available else 'None',
        'security_policy_hash': os.environ.get('SECURITY_POLICY_HASH', ''),
        'skr_configured': bool(os.environ.get('SKR_AKV_ENDPOINT')),
        'db_configured': bool(os.environ.get('DB_HOST')),
    })


# ---------------------------------------------------------------------------
# Database Endpoints
# ---------------------------------------------------------------------------
@app.route('/db/status', methods=['GET'])
def db_status():
    """Check PostgreSQL connectivity and measure latency."""
    db_host = os.environ.get('DB_HOST', '')
    if not db_host:
        return jsonify({'status': 'not_configured', 'message': 'DB_HOST not set'}), 503

    conn = None
    try:
        start = time.time()
        conn = _get_db_conn()
        cur = conn.cursor()
        cur.execute('SELECT 1')
        cur.fetchone()
        latency_ms = round((time.time() - start) * 1000, 2)

        # Get row count
        cur.execute('SELECT COUNT(*) FROM transactions')
        row_count = cur.fetchone()[0]
        cur.close()

        return jsonify({
            'status': 'connected',
            'host': db_host,
            'database': os.environ.get('DB_NAME', 'financedemo'),
            'latency_ms': latency_ms,
            'transaction_count': row_count,
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'host': db_host,
            'message': _safe_error_detail(str(e)),
        }), 503
    finally:
        if conn:
            _put_db_conn(conn)


@app.route('/db/analytics', methods=['GET'])
@rate_limit(max_calls=20, period=60)
def db_analytics():
    """Run financial analytics queries against PostgreSQL and return results."""
    conn = None
    try:
        start = time.time()
        conn = _get_db_conn()
        cur = conn.cursor()

        # 1. Total count
        cur.execute('SELECT COUNT(*) FROM transactions')
        total_count = cur.fetchone()[0]

        # 2. Spend by category
        cur.execute("""
            SELECT merchant_category,
                   COUNT(*) AS txn_count,
                   ROUND(SUM(amount)::numeric, 2) AS total_spend,
                   ROUND(AVG(amount)::numeric, 2) AS avg_transaction
            FROM transactions
            GROUP BY merchant_category
            ORDER BY txn_count DESC
        """)
        spend_by_category = [
            {'category': r[0], 'transaction_count': r[1], 'total_spend': float(r[2]), 'avg_transaction': float(r[3])}
            for r in cur.fetchall()
        ]

        # 3. Transactions by hour of day
        cur.execute("""
            SELECT EXTRACT(HOUR FROM date_time)::int AS hour, COUNT(*) AS cnt
            FROM transactions GROUP BY hour ORDER BY hour
        """)
        hour_map = {r[0]: r[1] for r in cur.fetchall()}
        transactions_by_hour = [{'hour': h, 'count': hour_map.get(h, 0)} for h in range(24)]

        # 4. Grocery by hour
        cur.execute("""
            SELECT EXTRACT(HOUR FROM date_time)::int AS hour, COUNT(*) AS cnt
            FROM transactions WHERE merchant_category = 'Grocery Store'
            GROUP BY hour ORDER BY hour
        """)
        grocery_map = {r[0]: r[1] for r in cur.fetchall()}
        grocery_by_hour = [{'hour': h, 'count': grocery_map.get(h, 0)} for h in range(24)]
        peak_grocery_hour = max(grocery_map, key=grocery_map.get) if grocery_map else None

        # 5. Loan insights
        cur.execute("""
            SELECT merchant_category,
                   ROUND(AVG(amount)::numeric, 2) AS avg_payment,
                   COUNT(*) AS cnt
            FROM transactions
            WHERE merchant_category IN ('Mortgage', 'Car Loan', 'Student Loan Repayment')
            GROUP BY merchant_category
        """)
        loan_rows = {r[0]: {'avg': float(r[1]), 'count': r[2]} for r in cur.fetchall()}
        loan_insights = {
            'avg_mortgage_payment': loan_rows.get('Mortgage', {}).get('avg', 0),
            'avg_car_loan_payment': loan_rows.get('Car Loan', {}).get('avg', 0),
            'avg_student_loan_payment': loan_rows.get('Student Loan Repayment', {}).get('avg', 0),
            'mortgage_count': loan_rows.get('Mortgage', {}).get('count', 0),
            'car_loan_count': loan_rows.get('Car Loan', {}).get('count', 0),
            'student_loan_count': loan_rows.get('Student Loan Repayment', {}).get('count', 0),
        }

        # 6. Spending by country
        cur.execute("""
            SELECT customer_country,
                   COUNT(*) AS txn_count,
                   ROUND(SUM(amount)::numeric, 2) AS total_spend,
                   ROUND(AVG(amount)::numeric, 2) AS avg_transaction
            FROM transactions
            GROUP BY customer_country
            ORDER BY total_spend DESC
        """)
        spending_by_country = [
            {'country': r[0], 'transaction_count': r[1], 'total_spend': float(r[2]), 'avg_transaction': float(r[3])}
            for r in cur.fetchall()
        ]

        # 7. Age group spending
        cur.execute("""
            SELECT
                CASE
                    WHEN customer_age <= 25 THEN '18-25'
                    WHEN customer_age <= 35 THEN '26-35'
                    WHEN customer_age <= 45 THEN '36-45'
                    WHEN customer_age <= 55 THEN '46-55'
                    WHEN customer_age <= 65 THEN '56-65'
                    ELSE '65+'
                END AS age_group,
                COUNT(*) AS txn_count,
                ROUND(SUM(amount)::numeric, 2) AS total_spend,
                ROUND(AVG(amount)::numeric, 2) AS avg_transaction
            FROM transactions
            GROUP BY age_group
            ORDER BY age_group
        """)
        age_group_insights = [
            {'age_group': r[0], 'transaction_count': r[1], 'total_spend': float(r[2]), 'avg_transaction': float(r[3])}
            for r in cur.fetchall()
        ]

        # 8. Top 10 merchants
        cur.execute("""
            SELECT merchant_name,
                   COUNT(*) AS txn_count,
                   ROUND(SUM(amount)::numeric, 2) AS total_spend
            FROM transactions
            GROUP BY merchant_name
            ORDER BY txn_count DESC
            LIMIT 10
        """)
        top_merchants = [
            {'merchant': r[0], 'transaction_count': r[1], 'total_spend': float(r[2])}
            for r in cur.fetchall()
        ]

        # 9. Transactions by day of week
        cur.execute("""
            SELECT EXTRACT(DOW FROM date_time)::int AS dow, COUNT(*) AS cnt
            FROM transactions GROUP BY dow ORDER BY dow
        """)
        day_names = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
        dow_map = {r[0]: r[1] for r in cur.fetchall()}
        transactions_by_day = [{'day': day_names[i], 'count': dow_map.get(i, 0)} for i in range(7)]

        cur.close()
        query_time = round((time.time() - start) * 1000, 2)

        return jsonify({
            'status': 'success',
            'total_transactions': total_count,
            'query_time_ms': query_time,
            'spend_by_category': spend_by_category,
            'transactions_by_hour': transactions_by_hour,
            'grocery_by_hour': grocery_by_hour,
            'peak_grocery_hour': peak_grocery_hour,
            'loan_insights': loan_insights,
            'spending_by_country': spending_by_country,
            'age_group_insights': age_group_insights,
            'top_merchants': top_merchants,
            'transactions_by_day': transactions_by_day,
            'data_source': 'PostgreSQL (Confidential)',
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': _safe_error_detail(str(e))}), 500
    finally:
        if conn:
            _put_db_conn(conn)


@app.route('/db/analytics-stream')
@rate_limit(max_calls=10, period=60)
def db_analytics_stream():
    """SSE stream of analytics loading progress."""
    def generate():
        steps = [
            ('Connecting to PostgreSQL...', 5),
            ('Querying spend by category...', 15),
            ('Querying hourly transaction patterns...', 30),
            ('Querying grocery shopping patterns...', 40),
            ('Querying loan insights...', 50),
            ('Querying spending by country...', 60),
            ('Querying age group analytics...', 70),
            ('Querying top merchants...', 80),
            ('Querying day-of-week patterns...', 90),
            ('Finalizing analytics...', 95),
        ]
        for msg, pct in steps:
            yield f"data: {json.dumps({'phase': msg, 'progress': pct})}\n\n"
            time.sleep(0.1)

        # Now actually run the analytics
        conn = None
        try:
            conn = _get_db_conn()
            cur = conn.cursor()

            start = time.time()

            # Total count
            cur.execute('SELECT COUNT(*) FROM transactions')
            total_count = cur.fetchone()[0]

            # Spend by category
            cur.execute("""
                SELECT merchant_category, COUNT(*) AS txn_count,
                       ROUND(SUM(amount)::numeric, 2), ROUND(AVG(amount)::numeric, 2)
                FROM transactions GROUP BY merchant_category ORDER BY txn_count DESC
            """)
            spend_by_category = [
                {'category': r[0], 'transaction_count': r[1], 'total_spend': float(r[2]), 'avg_transaction': float(r[3])}
                for r in cur.fetchall()
            ]

            # Transactions by hour
            cur.execute("""
                SELECT EXTRACT(HOUR FROM date_time)::int, COUNT(*)
                FROM transactions GROUP BY 1 ORDER BY 1
            """)
            hour_map = {r[0]: r[1] for r in cur.fetchall()}
            transactions_by_hour = [{'hour': h, 'count': hour_map.get(h, 0)} for h in range(24)]

            # Grocery by hour
            cur.execute("""
                SELECT EXTRACT(HOUR FROM date_time)::int, COUNT(*)
                FROM transactions WHERE merchant_category = 'Grocery Store'
                GROUP BY 1 ORDER BY 1
            """)
            grocery_map = {r[0]: r[1] for r in cur.fetchall()}
            grocery_by_hour = [{'hour': h, 'count': grocery_map.get(h, 0)} for h in range(24)]
            peak_grocery_hour = max(grocery_map, key=grocery_map.get) if grocery_map else None

            # Loan insights
            cur.execute("""
                SELECT merchant_category, ROUND(AVG(amount)::numeric, 2), COUNT(*)
                FROM transactions
                WHERE merchant_category IN ('Mortgage', 'Car Loan', 'Student Loan Repayment')
                GROUP BY merchant_category
            """)
            loan_rows = {r[0]: {'avg': float(r[1]), 'count': r[2]} for r in cur.fetchall()}
            loan_insights = {
                'avg_mortgage_payment': loan_rows.get('Mortgage', {}).get('avg', 0),
                'avg_car_loan_payment': loan_rows.get('Car Loan', {}).get('avg', 0),
                'avg_student_loan_payment': loan_rows.get('Student Loan Repayment', {}).get('avg', 0),
                'mortgage_count': loan_rows.get('Mortgage', {}).get('count', 0),
                'car_loan_count': loan_rows.get('Car Loan', {}).get('count', 0),
                'student_loan_count': loan_rows.get('Student Loan Repayment', {}).get('count', 0),
            }

            # Spending by country
            cur.execute("""
                SELECT customer_country, COUNT(*), ROUND(SUM(amount)::numeric, 2), ROUND(AVG(amount)::numeric, 2)
                FROM transactions GROUP BY customer_country ORDER BY SUM(amount) DESC
            """)
            spending_by_country = [
                {'country': r[0], 'transaction_count': r[1], 'total_spend': float(r[2]), 'avg_transaction': float(r[3])}
                for r in cur.fetchall()
            ]

            # Age group
            cur.execute("""
                SELECT CASE
                    WHEN customer_age <= 25 THEN '18-25' WHEN customer_age <= 35 THEN '26-35'
                    WHEN customer_age <= 45 THEN '36-45' WHEN customer_age <= 55 THEN '46-55'
                    WHEN customer_age <= 65 THEN '56-65' ELSE '65+' END AS ag,
                    COUNT(*), ROUND(SUM(amount)::numeric, 2), ROUND(AVG(amount)::numeric, 2)
                FROM transactions GROUP BY ag ORDER BY ag
            """)
            age_group_insights = [
                {'age_group': r[0], 'transaction_count': r[1], 'total_spend': float(r[2]), 'avg_transaction': float(r[3])}
                for r in cur.fetchall()
            ]

            # Top merchants
            cur.execute("""
                SELECT merchant_name, COUNT(*), ROUND(SUM(amount)::numeric, 2)
                FROM transactions GROUP BY merchant_name ORDER BY COUNT(*) DESC LIMIT 10
            """)
            top_merchants = [
                {'merchant': r[0], 'transaction_count': r[1], 'total_spend': float(r[2])}
                for r in cur.fetchall()
            ]

            # Day of week
            cur.execute("""
                SELECT EXTRACT(DOW FROM date_time)::int, COUNT(*)
                FROM transactions GROUP BY 1 ORDER BY 1
            """)
            day_names = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
            dow_map = {r[0]: r[1] for r in cur.fetchall()}
            transactions_by_day = [{'day': day_names[i], 'count': dow_map.get(i, 0)} for i in range(7)]

            cur.close()
            query_time = round((time.time() - start) * 1000, 2)

            result = {
                'phase': 'complete',
                'progress': 100,
                'status': 'success',
                'total_transactions': total_count,
                'query_time_ms': query_time,
                'spend_by_category': spend_by_category,
                'transactions_by_hour': transactions_by_hour,
                'grocery_by_hour': grocery_by_hour,
                'peak_grocery_hour': peak_grocery_hour,
                'loan_insights': loan_insights,
                'spending_by_country': spending_by_country,
                'age_group_insights': age_group_insights,
                'top_merchants': top_merchants,
                'transactions_by_day': transactions_by_day,
                'data_source': 'PostgreSQL (Confidential)',
            }
            yield f"data: {json.dumps(result)}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'phase': 'error', 'progress': 0, 'error': _safe_error_detail(str(e))})}\n\n"
        finally:
            if conn:
                _put_db_conn(conn)

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


# ---------------------------------------------------------------------------
# Health Endpoints
# ---------------------------------------------------------------------------
@app.route('/health')
def health():
    """Simple health check for Application Gateway probes."""
    return jsonify({'status': 'healthy', 'timestamp': time.time()})


@app.route('/health/endpoints', methods=['GET'])
def health_endpoints():
    """Check all API endpoints and database connectivity with latency measurements."""
    results = {}

    # 1. Sidecar status
    try:
        start = time.time()
        resp = requests.get("http://localhost:8080/status", timeout=5)
        results['sidecar'] = {
            'status': 'ok' if resp.status_code == 200 else 'error',
            'latency_ms': round((time.time() - start) * 1000, 2),
            'status_code': resp.status_code,
        }
    except Exception as e:
        results['sidecar'] = {'status': 'error', 'message': _safe_error_detail(str(e))}

    # 2. Database connectivity
    db_host = os.environ.get('DB_HOST', '')
    if db_host:
        conn = None
        try:
            start = time.time()
            conn = _get_db_conn()
            cur = conn.cursor()
            cur.execute('SELECT COUNT(*) FROM transactions')
            row_count = cur.fetchone()[0]
            cur.close()
            results['database'] = {
                'status': 'ok',
                'latency_ms': round((time.time() - start) * 1000, 2),
                'host': db_host,
                'transaction_count': row_count,
            }
        except Exception as e:
            results['database'] = {'status': 'error', 'host': db_host, 'message': _safe_error_detail(str(e))}
        finally:
            if conn:
                _put_db_conn(conn)

        # 3. Database latency (average of 3 pings)
        latencies = []
        conn = None
        try:
            conn = _get_db_conn()
            cur = conn.cursor()
            for _ in range(3):
                start = time.time()
                cur.execute('SELECT 1')
                cur.fetchone()
                latencies.append(round((time.time() - start) * 1000, 2))
            cur.close()
            results['database_avg_latency_ms'] = round(sum(latencies) / len(latencies), 2)
        except Exception:
            pass
        finally:
            if conn:
                _put_db_conn(conn)
    else:
        results['database'] = {'status': 'not_configured'}

    # 4. SKR configuration
    results['skr'] = {
        'configured': bool(os.environ.get('SKR_AKV_ENDPOINT')),
        'key_released': _released_key is not None,
        'maa_endpoint': os.environ.get('SKR_MAA_ENDPOINT', ''),
    }

    # 5. TEE detection
    tee_available = os.path.exists('/dev/sev-guest') or os.path.exists('/dev/sev') or os.path.exists('/dev/sev0')
    results['tee'] = {
        'available': tee_available,
        'type': 'AMD SEV-SNP' if tee_available else 'None',
    }

    # 6. Internal API endpoints check
    api_checks = [
        ('GET', '/health', 'Health'),
        ('GET', '/skr/config', 'SKR Config'),
        ('GET', '/security/policy', 'Security Policy'),
        ('GET', '/db/status', 'Database Status'),
    ]
    api_results = []
    for method, path, name in api_checks:
        try:
            start = time.time()
            resp = requests.request(method, f'http://127.0.0.1:8000{path}', timeout=5)
            api_results.append({
                'name': name,
                'path': path,
                'status': 'ok' if resp.status_code == 200 else 'error',
                'status_code': resp.status_code,
                'latency_ms': round((time.time() - start) * 1000, 2),
            })
        except Exception as e:
            api_results.append({
                'name': name,
                'path': path,
                'status': 'error',
                'message': _safe_error_detail(str(e)),
            })
    results['api_endpoints'] = api_results

    return jsonify(results)


# ---------------------------------------------------------------------------
# Container Info
# ---------------------------------------------------------------------------
@app.route('/info')
def info():
    """Return container environment information."""
    tee_available = os.path.exists('/dev/sev-guest') or os.path.exists('/dev/sev') or os.path.exists('/dev/sev0')
    return jsonify({
        'container_type': 'Confidential ACI + PostgreSQL',
        'tee_available': tee_available,
        'tee_type': 'AMD SEV-SNP' if tee_available else 'None (Standard SKU)',
        'skr_key_name': os.environ.get('SKR_KEY_NAME', ''),
        'maa_endpoint': os.environ.get('SKR_MAA_ENDPOINT', ''),
        'db_host': os.environ.get('DB_HOST', ''),
        'db_name': os.environ.get('DB_NAME', ''),
        'security_policy_hash': os.environ.get('SECURITY_POLICY_HASH', ''),
        'deploy_script': 'Deploy-PostgreSQLDemo.ps1',
    })


# ---------------------------------------------------------------------------
# Run (development only — production uses gunicorn)
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
