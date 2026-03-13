"""Generate contoso-data.csv and fabrikam-data.csv with 500 rows each of dummy credit card transaction data."""
import csv
import random
import os
from datetime import datetime, timedelta

random.seed(42)

# Microsoft-approved fictitious company names mapped to categories
MERCHANTS = [
    # Coffee Shops
    ("Fourth Coffee", "Coffee Shop"),
    ("Contoso Coffee", "Coffee Shop"),
    ("Alpine Bean Roasters", "Coffee Shop"),
    ("Northwind Espresso", "Coffee Shop"),
    # Petrol Stations
    ("Contoso Fuel", "Petrol Station"),
    ("Northwind Petrol", "Petrol Station"),
    ("Adventure Fuel Stop", "Petrol Station"),
    # Insurance
    ("Contoso Insurance", "Insurance"),
    ("Fabrikam Life Insurance", "Insurance"),
    ("Woodgrove Insurance Group", "Insurance"),
    # Cash Withdrawal
    ("Woodgrove Bank ATM", "Cash Withdrawal"),
    ("Contoso Bank ATM", "Cash Withdrawal"),
    # Electronics Store
    ("Adventure Works Electronics", "Electronics Store"),
    ("Fabrikam Tech Store", "Electronics Store"),
    ("Wingtip Electronics", "Electronics Store"),
    ("Litware Digital", "Electronics Store"),
    # Grocery Store
    ("Northwind Grocers", "Grocery Store"),
    ("Wide World Grocers", "Grocery Store"),
    ("Contoso Fresh Market", "Grocery Store"),
    ("Tailspin Grocery", "Grocery Store"),
    # Restaurant - various cuisines
    ("Proseware Thai Kitchen", "Restaurant - Thai"),
    ("Contoso Trattoria", "Restaurant - Italian"),
    ("Northwind Curry House", "Restaurant - Indian"),
    ("Adventure Cantina", "Restaurant - Mexican"),
    ("Fabrikam Sushi Bar", "Restaurant - Japanese"),
    ("Litware Dragon Palace", "Restaurant - Chinese"),
    ("Alpine Bistro", "Restaurant - French"),
    ("Trey Research Grill", "Restaurant - American"),
    ("Datum Steakhouse", "Restaurant - American"),
    ("Wingtip Noodle House", "Restaurant - Vietnamese"),
    ("Wide World Kebab", "Restaurant - Turkish"),
    ("Bellows Korean BBQ", "Restaurant - Korean"),
    # Fast Food
    ("Tailspin Burgers", "Fast Food"),
    ("Contoso Quick Bites", "Fast Food"),
    ("Northwind Fried Chicken", "Fast Food"),
    ("Fabrikam Pizza Express", "Fast Food"),
    # Mortgage
    ("Woodgrove Mortgage Services", "Mortgage"),
    ("Contoso Home Loans", "Mortgage"),
    # Car Loan
    ("Fabrikam Auto Finance", "Car Loan"),
    ("Contoso Vehicle Loans", "Car Loan"),
    # Student Loan Repayment
    ("Woodgrove Student Lending", "Student Loan Repayment"),
    ("Contoso Education Finance", "Student Loan Repayment"),
]

# Customer first names and last names
FIRST_NAMES = [
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda",
    "David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
    "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Lisa", "Daniel", "Nancy",
    "Matthew", "Betty", "Anthony", "Margaret", "Mark", "Sandra", "Donald", "Ashley",
    "Steven", "Kimberly", "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle",
    "Kenneth", "Dorothy", "Kevin", "Carol", "Brian", "Amanda", "George", "Melissa",
    "Timothy", "Deborah", "Ronald", "Stephanie", "Edward", "Rebecca", "Jason", "Sharon",
    "Aisha", "Yuki", "Chen", "Priya", "Omar", "Fatima", "Hiroshi", "Mei",
    "Raj", "Anya", "Diego", "Sofia", "Lars", "Ingrid", "Kofi", "Amara",
    "Liam", "Olivia", "Noah", "Emma", "Ethan", "Ava", "Lucas", "Mia",
    "Tariq", "Leila", "Hans", "Greta", "Paolo", "Giulia", "Kenji", "Sakura",
    "Ivan", "Natasha", "Sven", "Astrid", "Carlos", "Isabella", "Ahmed", "Zara",
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas",
    "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White",
    "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker", "Young",
    "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
    "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Patel", "Singh", "Kumar", "Khan", "Ahmed", "Ali", "Tanaka", "Suzuki",
    "Yamamoto", "Nakamura", "Chen", "Wang", "Li", "Zhang", "Liu", "Yang",
    "Muller", "Schmidt", "Fischer", "Weber", "Meyer", "Wagner", "Becker", "Schulz",
    "Johansson", "Eriksson", "Larsson", "Olsson", "Persson", "Svensson", "Nilsson",
    "Rossi", "Russo", "Ferrari", "Esposito", "Bianchi", "Romano", "Colombo",
    "Fernandez", "Santos", "Silva", "Costa", "Oliveira", "Souza",
]

# Addresses by country
COUNTRIES_DATA = {
    "United States": {
        "addresses": [
            ("123 Oak Street", "10001"), ("456 Maple Avenue", "90210"), ("789 Pine Road", "60601"),
            ("321 Elm Boulevard", "77001"), ("654 Cedar Lane", "85001"), ("987 Birch Drive", "33101"),
            ("111 Walnut Way", "02101"), ("222 Spruce Court", "98101"), ("333 Ash Place", "30301"),
            ("444 Poplar Circle", "94102"), ("555 Willow Trail", "75201"), ("666 Hazel Path", "48201"),
            ("777 Juniper Run", "55401"), ("888 Magnolia Bend", "80201"), ("999 Sequoia Ridge", "97201"),
        ],
    },
    "United Kingdom": {
        "addresses": [
            ("12 High Street", "SW1A 1AA"), ("34 King's Road", "EC1A 1BB"), ("56 Queen's Gate", "W1A 0AX"),
            ("78 Victoria Lane", "M1 1AA"), ("90 Oxford Terrace", "B1 1AA"), ("11 Cambridge Way", "LS1 1AA"),
            ("22 Windsor Close", "EH1 1AA"), ("33 Bristol Mews", "BS1 1AA"), ("44 York Place", "CF10 1AA"),
            ("55 Canterbury Drive", "NE1 1AA"), ("66 Durham Row", "G1 1AA"), ("77 Stratford Green", "BT1 1AA"),
        ],
    },
    "Germany": {
        "addresses": [
            ("Hauptstrasse 15", "10115"), ("Bahnhofstrasse 27", "80331"), ("Gartenweg 8", "20095"),
            ("Schulstrasse 42", "50667"), ("Bergstrasse 3", "70173"), ("Kirchweg 19", "60311"),
            ("Waldstrasse 55", "40210"), ("Marktplatz 6", "90402"), ("Lindenallee 31", "04109"),
            ("Rosenweg 12", "01067"),
        ],
    },
    "Japan": {
        "addresses": [
            ("1-2-3 Shibuya", "150-0002"), ("4-5-6 Shinjuku", "160-0022"), ("7-8-9 Ginza", "104-0061"),
            ("2-3-4 Akihabara", "101-0021"), ("5-6-7 Roppongi", "106-0032"), ("3-4-5 Ikebukuro", "170-0013"),
            ("6-7-8 Ueno", "110-0005"), ("1-1-1 Harajuku", "150-0001"),
        ],
    },
    "India": {
        "addresses": [
            ("42 MG Road", "400001"), ("15 Park Street", "700016"), ("88 Brigade Road", "560001"),
            ("23 Anna Salai", "600002"), ("67 Connaught Place", "110001"), ("9 Banjara Hills", "500034"),
            ("31 FC Road", "411001"), ("76 Civil Lines", "302001"),
        ],
    },
    "Brazil": {
        "addresses": [
            ("Rua Augusta 200", "01305-000"), ("Avenida Paulista 1000", "01310-100"),
            ("Rua das Flores 55", "80020-010"), ("Avenida Atlantica 300", "22021-001"),
            ("Rua XV de Novembro 88", "90020-080"), ("Avenida Brasil 450", "30130-000"),
        ],
    },
    "Australia": {
        "addresses": [
            ("42 George Street", "2000"), ("15 Collins Street", "3000"), ("88 Adelaide Street", "4000"),
            ("23 Hay Street", "6000"), ("67 King William Street", "5000"), ("9 Salamanca Place", "7000"),
        ],
    },
    "Canada": {
        "addresses": [
            ("123 Yonge Street", "M5B 2H1"), ("456 Rue Sainte-Catherine", "H3B 1A7"),
            ("789 Robson Street", "V6Z 1C2"), ("321 Jasper Avenue", "T5J 1S9"),
            ("654 Portage Avenue", "R3C 0G1"), ("987 Spring Garden Road", "B3J 3R4"),
        ],
    },
    "France": {
        "addresses": [
            ("15 Rue de Rivoli", "75001"), ("27 Avenue des Champs-Elysees", "75008"),
            ("8 Rue de la Republique", "69001"), ("42 Boulevard de la Liberte", "59000"),
            ("3 Place Bellecour", "69002"), ("19 Quai des Belges", "13001"),
        ],
    },
    "Mexico": {
        "addresses": [
            ("Avenida Reforma 200", "06600"), ("Calle Madero 55", "06000"),
            ("Paseo de Montejo 100", "97000"), ("Avenida Revolucion 300", "44100"),
            ("Boulevard Kukulcan 88", "77500"),
        ],
    },
}

CURRENCIES = {
    "United States": "USD", "United Kingdom": "GBP", "Germany": "EUR",
    "Japan": "JPY", "India": "INR", "Brazil": "BRL",
    "Australia": "AUD", "Canada": "CAD", "France": "EUR", "Mexico": "MXN",
}

# Amount ranges by category (in USD-equivalent, will be adjusted)
AMOUNT_RANGES = {
    "Coffee Shop": (3.50, 12.00),
    "Petrol Station": (25.00, 95.00),
    "Insurance": (150.00, 800.00),
    "Cash Withdrawal": (20.00, 500.00),
    "Electronics Store": (15.00, 2500.00),
    "Grocery Store": (12.00, 250.00),
    "Restaurant - Thai": (15.00, 85.00),
    "Restaurant - Italian": (20.00, 120.00),
    "Restaurant - Indian": (12.00, 75.00),
    "Restaurant - Mexican": (10.00, 65.00),
    "Restaurant - Japanese": (18.00, 150.00),
    "Restaurant - Chinese": (12.00, 70.00),
    "Restaurant - French": (25.00, 180.00),
    "Restaurant - American": (15.00, 95.00),
    "Restaurant - Vietnamese": (10.00, 55.00),
    "Restaurant - Turkish": (12.00, 65.00),
    "Restaurant - Korean": (15.00, 80.00),
    "Fast Food": (5.00, 25.00),
    "Mortgage": (800.00, 3500.00),
    "Car Loan": (250.00, 850.00),
    "Student Loan Repayment": (100.00, 600.00),
}


def generate_customer_pool(seed_offset, count=120):
    """Generate a pool of unique customers."""
    rng = random.Random(seed_offset)
    customers = []
    used_names = set()
    countries = list(COUNTRIES_DATA.keys())
    
    while len(customers) < count:
        first = rng.choice(FIRST_NAMES)
        last = rng.choice(LAST_NAMES)
        full_name = f"{first} {last}"
        if full_name in used_names:
            continue
        used_names.add(full_name)
        
        country = rng.choice(countries)
        addr_data = rng.choice(COUNTRIES_DATA[country]["addresses"])
        age = rng.randint(19, 78)
        
        customers.append({
            "name": full_name,
            "age": age,
            "address": addr_data[0],
            "postal_code": addr_data[1],
            "country": country,
        })
    
    return customers


def generate_csv(filename, seed, customer_seed_offset):
    """Generate a CSV file with 500 transaction rows."""
    rng = random.Random(seed)
    customers = generate_customer_pool(customer_seed_offset, count=120)
    
    # Time range: Jan 2025 to Dec 2025
    start_date = datetime(2025, 1, 1, 6, 0, 0)
    end_date = datetime(2025, 12, 31, 23, 59, 59)
    date_range_seconds = int((end_date - start_date).total_seconds())
    
    # Weight categories to make realistic distribution
    # More daily purchases, fewer mortgages/loans (those are monthly)
    category_weights = {
        "Coffee Shop": 12,
        "Petrol Station": 6,
        "Insurance": 2,
        "Cash Withdrawal": 5,
        "Electronics Store": 3,
        "Grocery Store": 15,
        "Restaurant - Thai": 2,
        "Restaurant - Italian": 3,
        "Restaurant - Indian": 2,
        "Restaurant - Mexican": 2,
        "Restaurant - Japanese": 2,
        "Restaurant - Chinese": 2,
        "Restaurant - French": 1,
        "Restaurant - American": 3,
        "Restaurant - Vietnamese": 1,
        "Restaurant - Turkish": 1,
        "Restaurant - Korean": 1,
        "Fast Food": 10,
        "Mortgage": 4,
        "Car Loan": 3,
        "Student Loan Repayment": 3,
    }
    
    # Build weighted merchant list
    weighted_merchants = []
    for merchant_name, category in MERCHANTS:
        weight = category_weights.get(category, 1)
        weighted_merchants.extend([(merchant_name, category)] * weight)
    
    rows = []
    for i in range(500):
        customer = rng.choice(customers)
        merchant_name, category = rng.choice(weighted_merchants)
        
        # Generate transaction timestamp with realistic time-of-day patterns
        random_seconds = rng.randint(0, date_range_seconds)
        tx_datetime = start_date + timedelta(seconds=random_seconds)
        
        # Adjust time of day based on category for realism
        if category == "Coffee Shop":
            hour = rng.choice([6, 7, 7, 8, 8, 8, 9, 9, 10, 14, 15])
        elif category == "Grocery Store":
            hour = rng.choice([9, 10, 11, 11, 12, 14, 15, 16, 17, 17, 18, 18, 19])
        elif category in ("Mortgage", "Car Loan", "Student Loan Repayment"):
            hour = rng.choice([0, 1, 2, 3, 8, 9, 10])  # Auto-debit early morning or midnight
            tx_datetime = tx_datetime.replace(day=rng.choice([1, 1, 1, 15, 15, 28]))  # 1st or 15th
        elif "Restaurant" in category:
            hour = rng.choice([11, 12, 12, 13, 18, 19, 19, 20, 20, 21])
        elif category == "Fast Food":
            hour = rng.choice([11, 12, 12, 13, 13, 17, 18, 19, 20, 21, 22])
        elif category == "Petrol Station":
            hour = rng.choice([7, 8, 9, 10, 14, 15, 16, 17, 18])
        elif category == "Cash Withdrawal":
            hour = rng.choice([9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20])
        elif category == "Insurance":
            hour = rng.choice([0, 1, 8, 9, 10])
            tx_datetime = tx_datetime.replace(day=rng.choice([1, 1, 5, 15]))
        else:
            hour = rng.randint(8, 21)
        
        minute = rng.randint(0, 59)
        second = rng.randint(0, 59)
        tx_datetime = tx_datetime.replace(hour=hour, minute=minute, second=second)
        
        # Generate amount
        min_amt, max_amt = AMOUNT_RANGES[category]
        amount = round(rng.uniform(min_amt, max_amt), 2)
        
        currency = CURRENCIES.get(customer["country"], "USD")
        
        # Transaction ID: anonymised hash-like
        tx_id = f"TXN-{rng.randint(100000000, 999999999)}"
        
        rows.append({
            "transaction_id": tx_id,
            "date_time": tx_datetime.strftime("%Y-%m-%d %H:%M:%S"),
            "customer_name": customer["name"],
            "customer_age": customer["age"],
            "customer_address": customer["address"],
            "customer_postal_code": customer["postal_code"],
            "customer_country": customer["country"],
            "merchant_name": merchant_name,
            "merchant_category": category,
            "amount": f"{amount:.2f}",
            "currency": currency,
        })
    
    # Sort by date for realism
    rows.sort(key=lambda r: r["date_time"])
    
    fieldnames = [
        "transaction_id", "date_time", "customer_name", "customer_age",
        "customer_address", "customer_postal_code", "customer_country",
        "merchant_name", "merchant_category", "amount", "currency",
    ]
    
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"Generated {filename} with {len(rows)} rows")


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    generate_csv(os.path.join(script_dir, "contoso-data.csv"), seed=1001, customer_seed_offset=100)
    generate_csv(os.path.join(script_dir, "fabrikam-data.csv"), seed=2002, customer_seed_offset=200)
    print("Done!")
