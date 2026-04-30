from flask import Flask, jsonify, request, render_template, redirect, url_for
import os
import secrets
import struct
import threading
import pyodbc
from azure.identity import ManagedIdentityCredential, DefaultAzureCredential

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024

# ---------------------------------------------------------------------------
# SQL connectivity supports two modes:
# 1) SQL auth (DB_USER/DB_PASSWORD) for SQL Server on AMD CVM.
# 2) Azure AD token fallback for Azure SQL style deployments.
# ---------------------------------------------------------------------------
SQL_COPT_SS_ACCESS_TOKEN = 1256
_credential = None
_credential_lock = threading.Lock()


def _build_sql_auth_conn_str(server, database, user, password):
    return (
        f"Driver={{ODBC Driver 18 for SQL Server}};"
        f"Server=tcp:{server},1433;"
        f"Database={database};"
        f"UID={user};PWD={password};"
        "Encrypt=yes;TrustServerCertificate=yes;"
    )


def _bootstrap_demo_database(server, database, db_user, db_password):
    # Deployment-safe self-heal for demo environments:
    # when SQL init partially succeeds and the app hits 4060, recreate the
    # target DB/login/user mapping and retry the app login path.
    sa_password = os.environ.get('DB_SA_PASSWORD', '')
    if not sa_password:
        raise RuntimeError('DB_SA_PASSWORD env var is required for database bootstrap but is not set')
    admin_conn = pyodbc.connect(
        _build_sql_auth_conn_str(server, 'master', 'sa', sa_password),
        autocommit=True,
    )
    try:
        cur = admin_conn.cursor()
        cur.execute(f"IF DB_ID(N'{database}') IS NULL CREATE DATABASE [{database}]")
        cur.execute(
            f"IF SUSER_ID(N'{db_user}') IS NULL "
            f"CREATE LOGIN [{db_user}] WITH PASSWORD = '{db_password}' "
            f"ELSE ALTER LOGIN [{db_user}] WITH PASSWORD = '{db_password}'"
        )
        cur.execute(f"ALTER LOGIN [{db_user}] WITH DEFAULT_DATABASE = [{database}]")
        cur.execute(f"USE [{database}]")
        cur.execute(
            f"IF USER_ID(N'{db_user}') IS NULL CREATE USER [{db_user}] FOR LOGIN [{db_user}]"
        )
        cur.execute(f"ALTER USER [{db_user}] WITH LOGIN = [{db_user}]")
        cur.execute(
            f"IF IS_ROLEMEMBER('db_datareader', '{db_user}') <> 1 "
            f"ALTER ROLE db_datareader ADD MEMBER [{db_user}]"
        )
        cur.execute(
            f"IF IS_ROLEMEMBER('db_datawriter', '{db_user}') <> 1 "
            f"ALTER ROLE db_datawriter ADD MEMBER [{db_user}]"
        )
        cur.execute("""
            IF OBJECT_ID(N'dbo.citizen_registry', N'U') IS NULL
            BEGIN
                CREATE TABLE dbo.citizen_registry (
                    id INT IDENTITY(1,1) PRIMARY KEY,
                    national_id NVARCHAR(20) NOT NULL UNIQUE,
                    first_name NVARCHAR(100) NOT NULL,
                    last_name NVARCHAR(100) NOT NULL,
                    date_of_birth DATE NOT NULL,
                    sex NVARCHAR(10) NOT NULL,
                    region NVARCHAR(100) NOT NULL,
                    municipality NVARCHAR(100) NOT NULL,
                    address_line NVARCHAR(200),
                    postal_code NVARCHAR(10),
                    household_size INT DEFAULT 1,
                    marital_status NVARCHAR(20) DEFAULT N'Single',
                    employment_status NVARCHAR(30) DEFAULT N'Employed',
                    tax_bracket NVARCHAR(10) DEFAULT N'B',
                    registered_voter BIT DEFAULT 1
                )
            END
        """)
    finally:
        admin_conn.close()


def _get_credential():
    global _credential
    if _credential is not None:
        return _credential
    with _credential_lock:
        if _credential is not None:
            return _credential
        client_id = os.environ.get('AZURE_CLIENT_ID', '')
        if client_id:
            _credential = ManagedIdentityCredential(client_id=client_id)
        else:
            _credential = DefaultAzureCredential()
        return _credential


def _get_token_struct():
    credential = _get_credential()
    token = credential.get_token("https://database.windows.net/.default")
    token_bytes = token.token.encode("UTF-16-LE")
    return struct.pack(f'<I{len(token_bytes)}s', len(token_bytes), token_bytes)


def _get_db_conn():
    server = os.environ.get('DB_HOST', '')
    database = os.environ.get('DB_NAME', 'citizendb')
    db_user = os.environ.get('DB_USER', '')
    db_password = os.environ.get('DB_PASSWORD', '')
    if not server:
        raise RuntimeError('Database not configured (DB_HOST is empty)')

    # Prefer SQL auth for SQL Server on CVM.
    if db_user and db_password:
        conn_str = _build_sql_auth_conn_str(server, database, db_user, db_password)
        try:
            return pyodbc.connect(conn_str)
        except pyodbc.Error as primary_error:
            # Demo deployment fallback: if primary SQL auth is rejected or the
            # login cannot open the requested database, retry with SA.
            error_text = str(primary_error)
            if '28000' not in error_text and '4060' not in error_text:
                raise

            if '4060' in error_text:
                _bootstrap_demo_database(server, database, db_user, db_password)
                return pyodbc.connect(conn_str)

            sa_password = os.environ.get('DB_SA_PASSWORD', '')
            if not sa_password:
                raise  # No SA password available; re-raise the original error
            sa_conn_str = _build_sql_auth_conn_str(server, database, 'sa', sa_password)
            return pyodbc.connect(sa_conn_str)

    # Fallback path for managed identity / Azure AD token auth.
    conn_str = (
        f"Driver={{ODBC Driver 18 for SQL Server}};"
        f"Server=tcp:{server},1433;"
        f"Database={database};"
        f"Encrypt=yes;TrustServerCertificate=no;"
    )
    return pyodbc.connect(conn_str, attrs_before={SQL_COPT_SS_ACCESS_TOKEN: _get_token_struct()})


# ---------------------------------------------------------------------------
# Schema Initialization
# ---------------------------------------------------------------------------
_schema_ready = False
_schema_lock = threading.Lock()


def _init_schema():
    global _schema_ready
    if _schema_ready:
        return
    with _schema_lock:
        if _schema_ready:
            return
        conn = _get_db_conn()
        try:
            cur = conn.cursor()
            cur.execute("""
                IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES
                               WHERE TABLE_NAME = 'citizen_registry')
                CREATE TABLE citizen_registry (
                    id INT IDENTITY(1,1) PRIMARY KEY,
                    national_id NVARCHAR(20) NOT NULL UNIQUE,
                    first_name NVARCHAR(100) NOT NULL,
                    last_name NVARCHAR(100) NOT NULL,
                    date_of_birth DATE NOT NULL,
                    sex NVARCHAR(10) NOT NULL,
                    region NVARCHAR(100) NOT NULL,
                    municipality NVARCHAR(100) NOT NULL,
                    address_line NVARCHAR(200),
                    postal_code NVARCHAR(10),
                    household_size INT DEFAULT 1,
                    marital_status NVARCHAR(20) DEFAULT N'Single',
                    employment_status NVARCHAR(30) DEFAULT N'Employed',
                    tax_bracket NVARCHAR(10) DEFAULT N'B',
                    registered_voter BIT DEFAULT 1
                )
            """)
            conn.commit()
            _schema_ready = True
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Security Headers
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
ITEMS_PER_PAGE = 50


@app.route('/')
def index():
    _init_schema()
    page = max(1, request.args.get('page', 1, type=int))
    offset = (page - 1) * ITEMS_PER_PAGE
    conn = _get_db_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM citizen_registry")
        total = cur.fetchone()[0]
        cur.execute(
            "SELECT id, national_id, first_name, last_name, date_of_birth, sex, "
            "region, municipality, household_size, marital_status, employment_status, "
            "tax_bracket, registered_voter FROM citizen_registry ORDER BY id "
            "OFFSET ? ROWS FETCH NEXT ? ROWS ONLY",
            offset, ITEMS_PER_PAGE)
        rows = cur.fetchall()
    finally:
        conn.close()
    total_pages = max(1, (total + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE)
    return render_template('index.html', rows=rows, page=page, total_pages=total_pages, total=total)


@app.route('/citizen/new', methods=['GET', 'POST'])
def create_citizen():
    _init_schema()
    if request.method == 'POST':
        conn = _get_db_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO citizen_registry (national_id, first_name, last_name, date_of_birth, "
                "sex, region, municipality, address_line, postal_code, household_size, "
                "marital_status, employment_status, tax_bracket, registered_voter) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                request.form['national_id'], request.form['first_name'],
                request.form['last_name'], request.form['date_of_birth'],
                request.form['sex'], request.form['region'],
                request.form['municipality'], request.form.get('address_line', ''),
                request.form.get('postal_code', ''),
                int(request.form.get('household_size', 1)),
                request.form.get('marital_status', 'Single'),
                request.form.get('employment_status', 'Employed'),
                request.form.get('tax_bracket', 'B'),
                1 if request.form.get('registered_voter') == 'on' else 0)
            conn.commit()
        finally:
            conn.close()
        return redirect(url_for('index'))
    return render_template('citizen_form.html', citizen=None)


@app.route('/citizen/<int:cid>/edit', methods=['GET', 'POST'])
def edit_citizen(cid):
    _init_schema()
    conn = _get_db_conn()
    try:
        cur = conn.cursor()
        if request.method == 'POST':
            cur.execute(
                "UPDATE citizen_registry SET national_id=?, first_name=?, last_name=?, "
                "date_of_birth=?, sex=?, region=?, municipality=?, address_line=?, "
                "postal_code=?, household_size=?, marital_status=?, employment_status=?, "
                "tax_bracket=?, registered_voter=? WHERE id=?",
                request.form['national_id'], request.form['first_name'],
                request.form['last_name'], request.form['date_of_birth'],
                request.form['sex'], request.form['region'],
                request.form['municipality'], request.form.get('address_line', ''),
                request.form.get('postal_code', ''),
                int(request.form.get('household_size', 1)),
                request.form.get('marital_status', 'Single'),
                request.form.get('employment_status', 'Employed'),
                request.form.get('tax_bracket', 'B'),
                1 if request.form.get('registered_voter') == 'on' else 0,
                cid)
            conn.commit()
            return redirect(url_for('index'))
        cur.execute(
            "SELECT id, national_id, first_name, last_name, date_of_birth, sex, "
            "region, municipality, address_line, postal_code, household_size, "
            "marital_status, employment_status, tax_bracket, registered_voter "
            "FROM citizen_registry WHERE id=?", cid)
        row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        return redirect(url_for('index'))
    citizen = dict(zip(['id', 'national_id', 'first_name', 'last_name', 'date_of_birth',
                        'sex', 'region', 'municipality', 'address_line', 'postal_code',
                        'household_size', 'marital_status', 'employment_status',
                        'tax_bracket', 'registered_voter'], row))
    return render_template('citizen_form.html', citizen=citizen)


@app.route('/citizen/<int:cid>/delete', methods=['POST'])
def delete_citizen(cid):
    conn = _get_db_conn()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM citizen_registry WHERE id=?", cid)
        conn.commit()
    finally:
        conn.close()
    return redirect(url_for('index'))


@app.route('/health')
def health():
    return jsonify({'status': 'ok'})


@app.route('/db/status')
def db_status():
    try:
        conn = _get_db_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT 1")
        finally:
            conn.close()
        return jsonify({'status': 'connected'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
