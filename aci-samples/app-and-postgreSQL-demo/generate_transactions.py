#!/usr/bin/env python3
"""Generate 5000 realistic financial transactions as a PostgreSQL seed SQL file.

Uses the same merchant categories, amount ranges, and time-of-day patterns as the
advanced-app-finance-openAI multi-party sample to produce consistent demo data.

Usage:
    python generate_transactions.py
    # Produces seed-data.sql in the same directory
"""

import random
import os
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Data pools (matching the finance app's generate_data.py patterns)
# ---------------------------------------------------------------------------
first_names = [
    'James', 'Mary', 'John', 'Patricia', 'Robert', 'Jennifer', 'Michael', 'Linda',
    'William', 'Elizabeth', 'David', 'Barbara', 'Richard', 'Susan', 'Joseph', 'Jessica',
    'Thomas', 'Sarah', 'Charles', 'Karen', 'Mohammed', 'Fatima', 'Ali', 'Aisha',
    'Omar', 'Khadija', 'Ahmed', 'Maryam', 'Hassan', 'Zainab', 'Wei', 'Fang',
    'Min', 'Xiu', 'Jing', 'Li', 'Chen', 'Yan', 'Lei', 'Mei', 'Yuki', 'Hiroshi',
    'Sakura', 'Takeshi', 'Akiko', 'Kenji', 'Yuna', 'Ryu', 'Hana', 'Sota',
    'Carlos', 'Maria', 'Juan', 'Ana', 'Luis', 'Sofia', 'Miguel', 'Isabella',
    'Diego', 'Valentina', 'Pierre', 'Marie', 'Jean', 'Sophie', 'Luc', 'Camille',
    'Hans', 'Greta', 'Klaus', 'Ingrid', 'Franz', 'Heidi', 'Otto', 'Elsa',
    'Raj', 'Priya', 'Amit', 'Sunita', 'Vikram', 'Deepa', 'Arjun', 'Anita',
    'Amelia', 'Oliver', 'Charlotte', 'Noah', 'Ava', 'Liam', 'Mia', 'Lucas',
    'Rashid', 'Layla', 'Yusuf', 'Noor', 'Ibrahim', 'Sara', 'Khalid', 'Huda',
    'Tariq', 'Amira', 'Brian', 'Timothy', 'Daniel', 'Astrid', 'Michelle', 'Natasha',
]

last_names = [
    'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis',
    'Rodriguez', 'Martinez', 'Al-Rashid', 'Haddad', 'Khalil', 'Mansour', 'Abbas',
    'Wang', 'Li', 'Zhang', 'Chen', 'Liu', 'Yang', 'Huang', 'Wu', 'Zhou', 'Xu',
    'Tanaka', 'Yamamoto', 'Suzuki', 'Watanabe', 'Sato', 'Nakamura', 'Ito',
    'Silva', 'Santos', 'Oliveira', 'Souza', 'Pereira', 'Costa', 'Ferreira',
    'Martin', 'Bernard', 'Dubois', 'Thomas', 'Robert', 'Petit', 'Durand',
    'Mueller', 'Schmidt', 'Schneider', 'Fischer', 'Weber', 'Meyer', 'Wagner',
    'Sharma', 'Patel', 'Kumar', 'Singh', 'Gupta', 'Reddy', 'Verma', 'Rao',
    'Anderson', 'Taylor', 'Moore', 'Jackson', 'White', 'Harris', 'Clark', 'Lewis',
    'Persson', 'Lopez', 'Baker', 'Nelson', 'Kim', 'Park', 'Lee', 'Choi',
]

COUNTRIES = {
    'United States':  {'currency': 'USD', 'rate': 1.0,    'addresses': ['123 Main Street', '456 Oak Avenue', '789 Park Boulevard', '321 Lake Drive', '654 Cedar Lane', '987 Elm Court']},
    'United Kingdom': {'currency': 'GBP', 'rate': 0.79,   'addresses': ['12 High Street', '34 Church Road', '56 Victoria Lane', '78 King Street', '90 Oxford Road']},
    'Canada':         {'currency': 'CAD', 'rate': 1.36,   'addresses': ['100 Rue Sainte-Catherine', '200 Yonge Street', '300 Robson Street', '400 Jasper Avenue']},
    'Australia':      {'currency': 'AUD', 'rate': 1.53,   'addresses': ['1 George Street', '2 Collins Street', '3 Pitt Street', '4 Salamanca Place']},
    'Germany':        {'currency': 'EUR', 'rate': 0.92,   'addresses': ['Friedrichstrasse 100', 'Kurfuerstendamm 200', 'Marienplatz 5', 'Hauptstrasse 42']},
    'France':         {'currency': 'EUR', 'rate': 0.92,   'addresses': ['15 Rue de Rivoli', '25 Avenue des Champs-Elysees', '35 Boulevard Saint-Germain']},
    'Japan':          {'currency': 'JPY', 'rate': 149.50, 'addresses': ['1-2-3 Shibuya', '4-5-6 Shinjuku', '7-8-9 Ginza', '6-7-8 Ueno']},
    'India':          {'currency': 'INR', 'rate': 83.12,  'addresses': ['23 Anna Salai', 'MG Road 45', 'Park Street 67', 'Linking Road 89']},
    'Brazil':         {'currency': 'BRL', 'rate': 4.97,   'addresses': ['Avenida Paulista 1000', 'Rua Augusta 500', 'Copacabana 200']},
    'Mexico':         {'currency': 'MXN', 'rate': 17.15,  'addresses': ['Paseo de la Reforma 100', 'Avenida Insurgentes 200', 'Calle Madero 50']},
    'South Korea':    {'currency': 'KRW', 'rate': 1320.0, 'addresses': ['Gangnam-gu 123', 'Jongno-gu 456', 'Mapo-gu 789']},
    'Saudi Arabia':   {'currency': 'SAR', 'rate': 3.75,   'addresses': ['King Fahd Road 100', 'Olaya Street 200', 'Tahlia Street 50']},
    'UAE':            {'currency': 'AED', 'rate': 3.67,   'addresses': ['Sheikh Zayed Road 1', 'Jumeirah Beach Road 2', 'Corniche Road 3']},
    'South Africa':   {'currency': 'ZAR', 'rate': 18.50,  'addresses': ['Long Street 100', 'Sandton Drive 200', 'Durban Beachfront 50']},
    'Sweden':         {'currency': 'SEK', 'rate': 10.45,  'addresses': ['Drottninggatan 100', 'Kungsgatan 200', 'Storgatan 50']},
}

POSTAL_CODES = {
    'United States': lambda: f'{random.randint(10000, 99999)}',
    'United Kingdom': lambda: f'{random.choice(["SW1A","EC1A","W1D","SE1","N1","E1"])} {random.randint(1,9)}{random.choice("ABCDEFGHJKLMNPRSTUWXY")}{random.choice("ABCDEFGHJKLMNPRSTUWXY")}',
    'Canada': lambda: f'{random.choice("ABCEGHJKLMNPRSTVXY")}{random.randint(1,9)}{random.choice("ABCEGHJKLMNPRSTVWXYZ")} {random.randint(1,9)}{random.choice("ABCEGHJKLMNPRSTVWXYZ")}{random.randint(0,9)}',
    'Japan': lambda: f'{random.randint(100,999)}-{random.randint(1000,9999)}',
    'default': lambda: f'{random.randint(10000, 99999)}',
}

# Merchants with their categories (same as finance app)
MERCHANTS = [
    ('Fourth Coffee', 'Coffee Shop'), ('Contoso Coffee', 'Coffee Shop'),
    ('Alpine Bean Roasters', 'Coffee Shop'), ('Northwind Espresso', 'Coffee Shop'),
    ('Contoso Fuel', 'Petrol Station'), ('Northwind Petrol', 'Petrol Station'),
    ('Alpine Gas & Go', 'Petrol Station'),
    ('Fabrikam Life Insurance', 'Insurance'), ('Contoso Insurance Group', 'Insurance'),
    ('Woodgrove Insurance Partners', 'Insurance'),
    ('Contoso Bank ATM', 'Cash Withdrawal'), ('Fabrikam Bank ATM', 'Cash Withdrawal'),
    ('Woodgrove Bank ATM', 'Cash Withdrawal'),
    ('Contoso Electronics', 'Electronics Store'), ('Fabrikam Tech Store', 'Electronics Store'),
    ('Northwind Digital', 'Electronics Store'), ('Alpine Electronics', 'Electronics Store'),
    ('Contoso Fresh Market', 'Grocery Store'), ('Fabrikam Grocers', 'Grocery Store'),
    ('Northwind Organic', 'Grocery Store'), ('Alpine Supermarket', 'Grocery Store'),
    ('Golden Dragon', 'Restaurant - Chinese'), ('Sakura Garden', 'Restaurant - Japanese'),
    ('Chez Pierre', 'Restaurant - French'), ('Casa de Tacos', 'Restaurant - Mexican'),
    ('Spice Route', 'Restaurant - Indian'), ('La Trattoria', 'Restaurant - Italian'),
    ('Thai Orchid', 'Restaurant - Thai'), ('The American Grill', 'Restaurant - American'),
    ('Saigon Kitchen', 'Restaurant - Vietnamese'), ('Istanbul Kebab', 'Restaurant - Turkish'),
    ('Seoul BBQ House', 'Restaurant - Korean'),
    ('Contoso Burger', 'Fast Food'), ('Northwind Pizza', 'Fast Food'),
    ('Alpine Fried Chicken', 'Fast Food'), ('Fabrikam Subs', 'Fast Food'),
    ('Contoso Home Loans', 'Mortgage'), ('Woodgrove Mortgage Services', 'Mortgage'),
    ('Contoso Vehicle Loans', 'Car Loan'), ('Fabrikam Auto Finance', 'Car Loan'),
    ('Contoso Education Finance', 'Student Loan Repayment'),
    ('Woodgrove Student Lending', 'Student Loan Repayment'),
    ('Fabrikam Student Aid', 'Student Loan Repayment'),
]

# Amount ranges per category (in USD equivalent)
AMOUNT_RANGES = {
    'Coffee Shop': (3.50, 12.00),
    'Petrol Station': (25.00, 95.00),
    'Insurance': (150.00, 800.00),
    'Cash Withdrawal': (20.00, 500.00),
    'Electronics Store': (15.00, 2500.00),
    'Grocery Store': (12.00, 250.00),
    'Restaurant - Chinese': (15.00, 85.00),
    'Restaurant - Japanese': (20.00, 120.00),
    'Restaurant - French': (30.00, 150.00),
    'Restaurant - Mexican': (10.00, 65.00),
    'Restaurant - Indian': (12.00, 75.00),
    'Restaurant - Italian': (15.00, 95.00),
    'Restaurant - Thai': (12.00, 70.00),
    'Restaurant - American': (15.00, 95.00),
    'Restaurant - Vietnamese': (10.00, 60.00),
    'Restaurant - Turkish': (12.00, 70.00),
    'Restaurant - Korean': (15.00, 80.00),
    'Fast Food': (5.00, 25.00),
    'Mortgage': (800.00, 3500.00),
    'Car Loan': (250.00, 850.00),
    'Student Loan Repayment': (100.00, 600.00),
}

# Time-of-day weights by category (hour 0-23 → relative probability)
def _get_hour_for_category(category):
    """Return a realistic hour for a transaction based on merchant category."""
    if 'Coffee' in category:
        return random.choices(range(24), weights=[0,0,0,0,0,1,4,8,10,8,3,1,0,1,3,1,0,0,0,0,0,0,0,0])[0]
    elif 'Grocery' in category:
        return random.choices(range(24), weights=[0,0,0,0,0,0,0,0,1,3,5,5,3,1,3,5,6,5,4,2,1,0,0,0])[0]
    elif 'Restaurant' in category:
        return random.choices(range(24), weights=[0,0,0,0,0,0,0,0,0,0,1,4,6,3,1,0,0,1,4,7,5,2,0,0])[0]
    elif 'Fast Food' in category:
        return random.choices(range(24), weights=[0,0,0,0,0,0,0,0,0,0,1,4,6,3,2,1,0,2,4,5,4,2,1,0])[0]
    elif category in ('Mortgage', 'Car Loan', 'Student Loan Repayment', 'Insurance'):
        return random.choices(range(24), weights=[3,2,1,1,0,0,0,0,2,3,2,1,0,0,0,0,0,0,0,0,0,0,0,1])[0]
    elif 'Petrol' in category:
        return random.choices(range(24), weights=[0,0,0,0,0,0,1,3,5,4,3,3,3,3,3,3,3,3,2,1,0,0,0,0])[0]
    elif 'Cash' in category:
        return random.choices(range(24), weights=[0,0,0,0,0,0,0,1,2,3,4,4,5,4,3,3,3,3,4,3,2,1,0,0])[0]
    elif 'Electronics' in category:
        return random.choices(range(24), weights=[0,0,0,0,0,0,0,0,0,1,3,4,4,3,3,4,4,3,3,2,1,0,0,0])[0]
    else:
        return random.randint(8, 21)


def generate_customer_pool(seed_offset, count=200):
    """Generate a pool of unique customers."""
    rng = random.Random(20260313 + seed_offset)
    customers = []
    used_names = set()
    for _ in range(count * 2):
        name = f"{rng.choice(first_names)} {rng.choice(last_names)}"
        if name in used_names:
            continue
        used_names.add(name)
        country = rng.choice(list(COUNTRIES.keys()))
        info = COUNTRIES[country]
        age = rng.randint(19, 78)
        address = rng.choice(info['addresses'])
        postal_fn = POSTAL_CODES.get(country, POSTAL_CODES['default'])
        # Use the rng for deterministic postal codes
        old_state = random.getstate()
        random.setstate(rng.getstate())
        postal = postal_fn()
        rng.setstate(random.getstate())
        random.setstate(old_state)
        customers.append({
            'name': name, 'age': age, 'address': address,
            'postal_code': postal, 'country': country, 'currency': info['currency'],
            'rate': info['rate'],
        })
        if len(customers) >= count:
            break
    return customers


def generate_transactions(count=5000, seed=20260313):
    """Generate a list of financial transaction dicts."""
    random.seed(seed)
    customers = generate_customer_pool(0, 200)
    
    # Generate dates spread across Jan 2025 - Dec 2025
    start_date = datetime(2025, 1, 1)
    end_date = datetime(2025, 12, 31)
    total_days = (end_date - start_date).days

    transactions = []
    for i in range(count):
        txn_id = f"TXN-{random.randint(100000000, 999999999)}"
        
        # Pick a random day
        day_offset = random.randint(0, total_days)
        base_date = start_date + timedelta(days=day_offset)
        
        # Pick merchant and category
        merchant_name, category = random.choice(MERCHANTS)
        
        # Pick hour based on category
        hour = _get_hour_for_category(category)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        dt = base_date.replace(hour=hour, minute=minute, second=second)
        
        # Pick customer
        customer = random.choice(customers)
        
        # Generate amount in local currency
        low, high = AMOUNT_RANGES[category]
        usd_amount = round(random.uniform(low, high), 2)
        local_amount = round(usd_amount * customer['rate'], 2)
        
        transactions.append({
            'transaction_id': txn_id,
            'date_time': dt.strftime('%Y-%m-%d %H:%M:%S'),
            'customer_name': customer['name'],
            'customer_age': customer['age'],
            'customer_address': customer['address'],
            'customer_postal_code': customer['postal_code'],
            'customer_country': customer['country'],
            'merchant_name': merchant_name,
            'merchant_category': category,
            'amount': local_amount,
            'currency': customer['currency'],
        })
    
    # Sort by date
    transactions.sort(key=lambda t: t['date_time'])
    return transactions


def escape_sql(value):
    """Escape a string value for safe SQL insertion."""
    if value is None:
        return 'NULL'
    s = str(value)
    # Escape single quotes by doubling them
    s = s.replace("'", "''")
    return s


def generate_sql(transactions):
    """Generate SQL CREATE TABLE + INSERT statements."""
    lines = []
    lines.append("-- Auto-generated seed data for ACI + PostgreSQL Confidential Computing Demo")
    lines.append(f"-- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"-- Record count: {len(transactions)}")
    lines.append("")
    lines.append("-- Drop table if exists (idempotent)")
    lines.append("DROP TABLE IF EXISTS transactions;")
    lines.append("")
    lines.append("CREATE TABLE transactions (")
    lines.append("    id SERIAL PRIMARY KEY,")
    lines.append("    transaction_id VARCHAR(20) NOT NULL UNIQUE,")
    lines.append("    date_time TIMESTAMP NOT NULL,")
    lines.append("    customer_name VARCHAR(100) NOT NULL,")
    lines.append("    customer_age INTEGER NOT NULL,")
    lines.append("    customer_address VARCHAR(200) NOT NULL,")
    lines.append("    customer_postal_code VARCHAR(20) NOT NULL,")
    lines.append("    customer_country VARCHAR(50) NOT NULL,")
    lines.append("    merchant_name VARCHAR(100) NOT NULL,")
    lines.append("    merchant_category VARCHAR(50) NOT NULL,")
    lines.append("    amount DECIMAL(12,2) NOT NULL,")
    lines.append("    currency VARCHAR(3) NOT NULL")
    lines.append(");")
    lines.append("")
    lines.append("-- Create indexes for analytics queries")
    lines.append("CREATE INDEX idx_transactions_category ON transactions(merchant_category);")
    lines.append("CREATE INDEX idx_transactions_country ON transactions(customer_country);")
    lines.append("CREATE INDEX idx_transactions_date ON transactions(date_time);")
    lines.append("CREATE INDEX idx_transactions_merchant ON transactions(merchant_name);")
    lines.append("")
    lines.append(f"-- Insert {len(transactions)} transactions")
    
    # Batch inserts for efficiency (100 rows per INSERT)
    batch_size = 100
    for batch_start in range(0, len(transactions), batch_size):
        batch = transactions[batch_start:batch_start + batch_size]
        lines.append(f"INSERT INTO transactions (transaction_id, date_time, customer_name, customer_age, customer_address, customer_postal_code, customer_country, merchant_name, merchant_category, amount, currency) VALUES")
        
        value_lines = []
        for txn in batch:
            value_lines.append(
                f"('{escape_sql(txn['transaction_id'])}', "
                f"'{escape_sql(txn['date_time'])}', "
                f"'{escape_sql(txn['customer_name'])}', "
                f"{txn['customer_age']}, "
                f"'{escape_sql(txn['customer_address'])}', "
                f"'{escape_sql(txn['customer_postal_code'])}', "
                f"'{escape_sql(txn['customer_country'])}', "
                f"'{escape_sql(txn['merchant_name'])}', "
                f"'{escape_sql(txn['merchant_category'])}', "
                f"{txn['amount']}, "
                f"'{escape_sql(txn['currency'])}')"
            )
        
        lines.append(",\n".join(value_lines) + ";")
        lines.append("")
    
    lines.append("-- Verify row count")
    lines.append("SELECT COUNT(*) AS total_transactions FROM transactions;")
    lines.append("")
    return "\n".join(lines)


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    print("Generating 5000 financial transactions...")
    transactions = generate_transactions(5000)
    
    print("Generating SQL seed file...")
    sql = generate_sql(transactions)
    
    output_path = os.path.join(script_dir, 'seed-data.sql')
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(sql)
    
    print(f"Generated {len(transactions)} transactions -> {output_path}")
    print(f"File size: {os.path.getsize(output_path) / 1024:.1f} KB")
    
    # Print some stats
    categories = {}
    countries = {}
    for t in transactions:
        cat = t['merchant_category']
        categories[cat] = categories.get(cat, 0) + 1
        country = t['customer_country']
        countries[country] = countries.get(country, 0) + 1
    
    print(f"\nCategories: {len(categories)}")
    for cat, count in sorted(categories.items(), key=lambda x: -x[1])[:10]:
        print(f"  {cat}: {count}")
    
    print(f"\nCountries: {len(countries)}")
    for country, count in sorted(countries.items(), key=lambda x: -x[1])[:10]:
        print(f"  {country}: {count}")


if __name__ == '__main__':
    main()
