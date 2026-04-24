"""Generate fictional citizen registry seed data for Republic of Norland (T-SQL)."""
import argparse
import random
import datetime

REGIONS = {
    "North Coast": ["Strandvik", "Havnsund", "Kystby"],
    "Central Plains": ["Slettemarka", "Midtfjord", "Akerby"],
    "Highland Province": ["Fjellstad", "Dalheim", "Bergvik"],
    "Eastern Corridor": ["Ostvik", "Grenseby", "Elvemo"],
    "Southern Delta": ["Sydport", "Solvik", "Deltastad"],
}

FIRST_NAMES_M = ["Erik", "Lars", "Bjorn", "Anders", "Olav", "Henrik", "Magnus", "Sigurd", "Tor", "Knut",
                  "Nils", "Gunnar", "Hakon", "Leif", "Rolf", "Arne", "Sven", "Dag", "Per", "Harald"]
FIRST_NAMES_F = ["Astrid", "Ingrid", "Sigrid", "Solveig", "Freya", "Karin", "Helga", "Liv", "Runa", "Maja",
                 "Greta", "Elsa", "Anja", "Thora", "Dagny", "Britt", "Eva", "Hilde", "Maren", "Ylva"]
LAST_NAMES = ["Nordberg", "Lindqvist", "Bakken", "Haugen", "Strand", "Dahl", "Vik", "Moen", "Solberg",
              "Berg", "Lund", "Fjeld", "Skog", "Sund", "Holm", "Aasen", "Brekke", "Foss", "Hagen", "Torp"]

MARITAL = ["Single", "Married", "Divorced", "Widowed"]
EMPLOYMENT = ["Employed", "Unemployed", "Retired", "Student", "Self-Employed"]
TAX_BRACKETS = ["A", "B", "C", "D", "E"]


def generate_sql(count, output_path):
    lines = []

    for i in range(1, count + 1):
        sex = random.choice(["Male", "Female"])
        first = random.choice(FIRST_NAMES_M if sex == "Male" else FIRST_NAMES_F)
        last = random.choice(LAST_NAMES)
        year = random.randint(1940, 2008)
        dob = datetime.date(year, random.randint(1, 12), random.randint(1, 28))
        region = random.choice(list(REGIONS.keys()))
        municipality = random.choice(REGIONS[region])
        nid = f"NOR-{year}-{i:06d}"
        addr = f"{random.randint(1, 300)} {municipality} Street"
        postal = f"{random.randint(10000, 99999)}"
        household = random.randint(1, 8)
        marital = random.choice(MARITAL)
        employ = random.choice(EMPLOYMENT)
        tax = random.choice(TAX_BRACKETS)
        voter = random.choice([1, 0])

        # Escape single quotes in names
        first_esc = first.replace("'", "''")
        last_esc = last.replace("'", "''")
        addr_esc = addr.replace("'", "''")

        lines.append(
            f"INSERT INTO citizen_registry (national_id, first_name, last_name, date_of_birth, sex, "
            f"region, municipality, address_line, postal_code, household_size, marital_status, "
            f"employment_status, tax_bracket, registered_voter) VALUES ("
            f"N'{nid}', N'{first_esc}', N'{last_esc}', '{dob}', N'{sex}', N'{region}', N'{municipality}', "
            f"N'{addr_esc}', N'{postal}', {household}, N'{marital}', N'{employ}', N'{tax}', {voter});"
        )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Generated {count} citizen records -> {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--output", default="seed-data.sql")
    args = parser.parse_args()
    generate_sql(args.count, args.output)
