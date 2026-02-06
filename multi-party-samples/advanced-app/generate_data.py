#!/usr/bin/env python3
"""Generate realistic fake employee data for Contoso and Fabrikam CSV files."""

import csv
import random

# Data pools
first_names = ['James', 'Mary', 'John', 'Patricia', 'Robert', 'Jennifer', 'Michael', 'Linda', 'William', 'Elizabeth',
    'David', 'Barbara', 'Richard', 'Susan', 'Joseph', 'Jessica', 'Thomas', 'Sarah', 'Charles', 'Karen',
    'Mohammed', 'Fatima', 'Ali', 'Aisha', 'Omar', 'Khadija', 'Ahmed', 'Maryam', 'Hassan', 'Zainab',
    'Wei', 'Fang', 'Min', 'Xiu', 'Jing', 'Li', 'Chen', 'Yan', 'Lei', 'Mei',
    'Yuki', 'Hiroshi', 'Sakura', 'Takeshi', 'Akiko', 'Kenji', 'Yuna', 'Ryu', 'Hana', 'Sota',
    'Carlos', 'Maria', 'Juan', 'Ana', 'Luis', 'Sofia', 'Miguel', 'Isabella', 'Diego', 'Valentina',
    'Pierre', 'Marie', 'Jean', 'Sophie', 'Luc', 'Camille', 'Antoine', 'Emma', 'Hugo', 'Lea',
    'Hans', 'Greta', 'Klaus', 'Ingrid', 'Franz', 'Heidi', 'Otto', 'Elsa', 'Fritz', 'Anna',
    'Dmitri', 'Olga', 'Ivan', 'Natasha', 'Boris', 'Svetlana', 'Alexei', 'Elena', 'Nikolai', 'Irina',
    'Raj', 'Priya', 'Amit', 'Sunita', 'Vikram', 'Deepa', 'Arjun', 'Anita', 'Sanjay', 'Kavita',
    'Amelia', 'Oliver', 'Charlotte', 'Noah', 'Ava', 'Liam', 'Mia', 'Lucas', 'Harper', 'Ethan',
    'Rashid', 'Layla', 'Yusuf', 'Noor', 'Ibrahim', 'Sara', 'Khalid', 'Huda', 'Tariq', 'Amira']

last_names = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Rodriguez', 'Martinez',
    'Al-Rashid', 'Haddad', 'Khalil', 'Mansour', 'Abbas', 'Nasser', 'Bakhtiari', 'Hosseini', 'Ahmadi', 'Karimi',
    'Wang', 'Li', 'Zhang', 'Chen', 'Liu', 'Yang', 'Huang', 'Wu', 'Zhou', 'Xu',
    'Tanaka', 'Yamamoto', 'Suzuki', 'Watanabe', 'Sato', 'Nakamura', 'Ito', 'Kobayashi', 'Kimura', 'Hayashi',
    'Silva', 'Santos', 'Oliveira', 'Souza', 'Pereira', 'Costa', 'Ferreira', 'Rodrigues', 'Almeida', 'Lima',
    'Martin', 'Bernard', 'Dubois', 'Thomas', 'Robert', 'Richard', 'Petit', 'Durand', 'Leroy', 'Moreau',
    'Mueller', 'Schmidt', 'Schneider', 'Fischer', 'Weber', 'Meyer', 'Wagner', 'Becker', 'Schulz', 'Hoffmann',
    'Ivanov', 'Petrov', 'Smirnov', 'Kuznetsov', 'Popov', 'Sokolov', 'Lebedev', 'Kozlov', 'Novikov', 'Morozov',
    'Sharma', 'Patel', 'Kumar', 'Singh', 'Gupta', 'Reddy', 'Verma', 'Rao', 'Nair', 'Iyer',
    'Anderson', 'Taylor', 'Moore', 'Jackson', 'White', 'Harris', 'Clark', 'Lewis', 'Robinson', 'Walker',
    'Abubakar', 'Okonkwo', 'Mensah', 'Osei', 'Diallo', 'Traore', 'Nguyen', 'Tran', 'Pham', 'Nielsen']

countries = {
    'United States': {'code': '+1', 'cities': ['New York', 'Los Angeles', 'Chicago', 'Houston', 'Phoenix', 'Philadelphia', 'San Antonio', 'San Diego', 'Dallas', 'Seattle']},
    'United Kingdom': {'code': '+44', 'cities': ['London', 'Birmingham', 'Manchester', 'Glasgow', 'Liverpool', 'Leeds', 'Sheffield', 'Edinburgh', 'Bristol', 'Cardiff']},
    'Canada': {'code': '+1', 'cities': ['Toronto', 'Vancouver', 'Montreal', 'Calgary', 'Edmonton', 'Ottawa', 'Winnipeg', 'Quebec City', 'Hamilton', 'Halifax']},
    'Australia': {'code': '+61', 'cities': ['Sydney', 'Melbourne', 'Brisbane', 'Perth', 'Adelaide', 'Gold Coast', 'Canberra', 'Newcastle', 'Hobart', 'Darwin']},
    'Germany': {'code': '+49', 'cities': ['Berlin', 'Munich', 'Hamburg', 'Frankfurt', 'Cologne', 'Stuttgart', 'Dusseldorf', 'Leipzig', 'Dresden', 'Hanover']},
    'France': {'code': '+33', 'cities': ['Paris', 'Marseille', 'Lyon', 'Toulouse', 'Nice', 'Nantes', 'Strasbourg', 'Montpellier', 'Bordeaux', 'Lille']},
    'Italy': {'code': '+39', 'cities': ['Rome', 'Milan', 'Naples', 'Turin', 'Florence', 'Venice', 'Bologna', 'Genoa', 'Palermo', 'Verona']},
    'Spain': {'code': '+34', 'cities': ['Madrid', 'Barcelona', 'Valencia', 'Seville', 'Bilbao', 'Malaga', 'Zaragoza', 'Granada', 'Alicante', 'Cordoba']},
    'Netherlands': {'code': '+31', 'cities': ['Amsterdam', 'Rotterdam', 'The Hague', 'Utrecht', 'Eindhoven', 'Tilburg', 'Groningen', 'Breda', 'Nijmegen', 'Maastricht']},
    'Sweden': {'code': '+46', 'cities': ['Stockholm', 'Gothenburg', 'Malmo', 'Uppsala', 'Vasteras', 'Orebro', 'Linkoping', 'Helsingborg', 'Jonkoping', 'Norrkoping']},
    'Japan': {'code': '+81', 'cities': ['Tokyo', 'Osaka', 'Yokohama', 'Nagoya', 'Sapporo', 'Fukuoka', 'Kobe', 'Kyoto', 'Sendai', 'Hiroshima']},
    'China': {'code': '+86', 'cities': ['Beijing', 'Shanghai', 'Guangzhou', 'Shenzhen', 'Chengdu', 'Hangzhou', 'Wuhan', 'Xian', 'Nanjing', 'Tianjin']},
    'India': {'code': '+91', 'cities': ['Mumbai', 'Delhi', 'Bangalore', 'Hyderabad', 'Chennai', 'Kolkata', 'Pune', 'Ahmedabad', 'Jaipur', 'Lucknow']},
    'Brazil': {'code': '+55', 'cities': ['Sao Paulo', 'Rio de Janeiro', 'Brasilia', 'Salvador', 'Fortaleza', 'Belo Horizonte', 'Manaus', 'Curitiba', 'Recife', 'Porto Alegre']},
    'Mexico': {'code': '+52', 'cities': ['Mexico City', 'Guadalajara', 'Monterrey', 'Puebla', 'Tijuana', 'Leon', 'Juarez', 'Cancun', 'Merida', 'Queretaro']},
    'Nigeria': {'code': '+234', 'cities': ['Lagos', 'Kano', 'Ibadan', 'Abuja', 'Port Harcourt', 'Benin City', 'Warri', 'Kaduna', 'Enugu', 'Zaria']},
    'South Africa': {'code': '+27', 'cities': ['Johannesburg', 'Cape Town', 'Durban', 'Pretoria', 'Port Elizabeth', 'Bloemfontein', 'East London', 'Nelspruit', 'Polokwane', 'Kimberley']},
    'South Korea': {'code': '+82', 'cities': ['Seoul', 'Busan', 'Incheon', 'Daegu', 'Daejeon', 'Gwangju', 'Ulsan', 'Suwon', 'Changwon', 'Seongnam']},
    'Russia': {'code': '+7', 'cities': ['Moscow', 'Saint Petersburg', 'Novosibirsk', 'Yekaterinburg', 'Kazan', 'Nizhny Novgorod', 'Samara', 'Chelyabinsk', 'Omsk', 'Rostov']},
    'Saudi Arabia': {'code': '+966', 'cities': ['Riyadh', 'Jeddah', 'Mecca', 'Medina', 'Dammam', 'Khobar', 'Tabuk', 'Buraidah', 'Khamis Mushait', 'Abha']}
}

street_types = ['Street', 'Avenue', 'Road', 'Boulevard', 'Lane', 'Drive', 'Court', 'Place', 'Way', 'Circle']
street_names = ['Main', 'Oak', 'Maple', 'Cedar', 'Pine', 'Elm', 'Park', 'Lake', 'River', 'Forest', 
    'High', 'Church', 'Market', 'Bridge', 'Mill', 'Station', 'Victoria', 'King', 'Queen', 'Albert',
    'George', 'William', 'Oxford', 'Cambridge', 'York', 'Windsor', 'Wellington', 'Nelson', 'Churchill', 'Lincoln']

eye_colors = ['Brown', 'Blue', 'Green', 'Hazel', 'Gray', 'Amber']
eye_weights = [55, 20, 10, 8, 5, 2]  # Brown is most common globally

favorite_colors = ['Blue', 'Red', 'Green', 'Purple', 'Black', 'Pink', 'Orange', 'Yellow', 'White', 'Gray', 'Teal', 'Gold', 'Silver', 'Navy', 'Maroon']

uk_prefixes = ['AB', 'BA', 'BB', 'BD', 'BH', 'BL', 'BN', 'BR', 'BS', 'CA', 'CB', 'CF', 'CH', 'CM', 'CO', 'CR', 'CT', 'CV', 'CW', 'DA', 
    'DE', 'DH', 'DL', 'DN', 'DT', 'DY', 'EC', 'EH', 'EN', 'EX', 'FY', 'GL', 'GU', 'HA', 'HD', 'HG', 'HP', 'HR', 'HS', 'HU']
uk_suffixes = ['AA', 'AB', 'AD', 'AE', 'AF', 'AG', 'AH', 'AJ', 'AL', 'AN', 'AP', 'AR', 'AS', 'AT', 'AW', 'AX', 'AY', 'AZ',
    'BA', 'BB', 'BD', 'BE', 'BF', 'BG', 'BH', 'BJ', 'BL', 'BN', 'BP', 'BR', 'BS', 'BT', 'BW', 'BX', 'BY']

def generate_phone(country_code):
    return f'{country_code} {random.randint(100,999)}-{random.randint(100,999)}-{random.randint(1000,9999)}'

def generate_postal(country):
    if country == 'United Kingdom':
        return f'{random.choice(uk_prefixes)}{random.randint(1,99)} {random.randint(1,9)}{random.choice(uk_suffixes)}'
    elif country == 'Japan':
        return f'{random.randint(100,999)}-{random.randint(1000,9999)}'
    else:
        return str(random.randint(10000, 99999))

def generate_record():
    country = random.choice(list(countries.keys()))
    info = countries[country]
    name = f'{random.choice(first_names)} {random.choice(last_names)}'
    phone = generate_phone(info['code'])
    age = random.randint(18, 65)
    salary = random.randint(30000, 200000)
    eye_color = random.choices(eye_colors, weights=eye_weights)[0]
    fav_color = random.choice(favorite_colors)
    address = f'{random.randint(100, 9999)} {random.choice(street_names)} {random.choice(street_types)}'
    postal = generate_postal(country)
    city = random.choice(info['cities'])
    return [name, phone, age, salary, eye_color, fav_color, address, postal, city, country]

def main():
    import os
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Generate Contoso data with seed for reproducibility
    random.seed(20260206)
    contoso_path = os.path.join(script_dir, 'contoso-data.csv')
    with open(contoso_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['name', 'phone', 'age', 'salary', 'eye_color', 'favorite_color', 'address', 'postal_code', 'city', 'country'])
        for _ in range(800):
            writer.writerow(generate_record())
    print(f'Generated 800 records for contoso-data.csv')

    # Generate Fabrikam data with different seed
    random.seed(20260207)
    fabrikam_path = os.path.join(script_dir, 'fabrikam-data.csv')
    with open(fabrikam_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['name', 'phone', 'age', 'salary', 'eye_color', 'favorite_color', 'address', 'postal_code', 'city', 'country'])
        for _ in range(800):
            writer.writerow(generate_record())
    print(f'Generated 800 records for fabrikam-data.csv')

if __name__ == '__main__':
    main()
