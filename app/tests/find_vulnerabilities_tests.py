from app.src import normalizer
from app.src.find_devices import get_devices
from app.src.normalizer import load_mapping, normalize_vendor, normalize_product
from app.src.vuln_lookup import get_vulnerabilities
from find_vulnerabilities import find_all_vulnerabilities


def main():
    print("=== IoT Security Scanner ===")

    # Search for vulnerabilities for each device
    print("\nSearching for vulnerabilities...")
    find_all_vulnerabilities()
    print("Vulnerabilities synced to database.")

    print("\nDone.")


if __name__ == "__main__":
    main()
