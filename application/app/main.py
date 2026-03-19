from application.app.find_devices import get_devices
from application.db.connection import get_connection

def main():
    print("=== IoT Security Scanner ===")

    # Step 1: Discover and sync devices from Home Assistant
    print("\n[1/2] Scanning devices...")
    get_devices()
    print("Devices synced to database.")

    # Step 2: Search for vulnerabilities for each device
    # print("\n[2/2] Searching for vulnerabilities...")
    # get_vulnerabilities()
    # print("Vulnerabilities synced to database.")

    print("\nDone.")

if __name__ == "__main__":
    main()