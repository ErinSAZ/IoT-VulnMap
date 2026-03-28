from app.src import normalizer
from app.src.find_devices import *
from app.src.normalizer import *


def main():
    print("=== IoT Security Scanner ===")

    # Step 1: Discover and sync devices from Home Assistant
    print("\n[1/2] Scanning devices...")

    load_mapping()
    get_devices()
    normalize_vendor()
    normalize_product()
    normalizer.update_auditable_status()
    print("Devices synced to database.")

    # Step 2: Search for vulnerabilities for each device
    # print("\n[2/2] Searching for vulnerabilities...")
    # get_vulnerabilities()
    # print("Vulnerabilities synced to database.")

    print("\nDone.")


if __name__ == "__main__":
    main()
