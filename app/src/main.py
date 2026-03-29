"""
Entry point of IoT_VulnMap.
Orchestrates device discovery, normalization, vulnerability scanning and reporting.
"""
import normalizer
from database import get_devices_with_vulnerabilities
from find_devices import get_devices
from find_vulnerabilities import find_all_vulnerabilities
from normalizer import load_mapping, normalize_vendor, normalize_product


def print_separator(char="─", width=50):
    print(char * width)


def print_vulnerability_report():
    """
    Fetches and displays a summary table of devices and their vulnerabilities.
    """
    rows = get_devices_with_vulnerabilities()
    if not rows:
        print("  No auditable devices found.")
        return

    col_widths = [20, 16, 20, 16, 8, 8, 10]
    headers   = ["Device", "Vendor", "Product", "Firmware", "CVEs", "CVSS", "Severity"]

    print_separator(width=110)
    header_line = "  ".join(h.ljust(w) for h, w in zip(headers, col_widths))
    print(f"  {header_line}")
    print_separator(width=110)

    for row in rows:
        name, vendor, product, firmware, vuln_count, max_cvss, max_severity = row
        values = [
            (name     or "N/A")[:col_widths[0]],
            (vendor   or "N/A")[:col_widths[1]],
            (product  or "N/A")[:col_widths[2]],
            (firmware or "N/A")[:col_widths[3]],
            str(vuln_count or 0),
            str(max_cvss   or "-"),
            (max_severity  or "-"),
        ]
        line = "  ".join(v.ljust(w) for v, w in zip(values, col_widths))
        print(f"  {line}")

    print_separator(width=110)
    print(f"  {len(rows)} device(s) scanned.\n")


def main():
    print_separator("═")
    print("  IoT_VulnMap — IoT Vulnerability Scanner")
    print_separator("═")

    # Step 1: Load pre-established mappings
    print("\n[1/4] Loading mappings...")
    load_mapping()
    print("  Mappings loaded.")

    # Step 2: Discover and sync devices from Home Assistant
    print("\n[2/4] Discovering devices from Home Assistant...")
    get_devices()
    print("  Devices synced to database.")

    # Step 3: Normalize vendor and product names
    print("\n[3/4] Normalizing vendor and product names...")
    normalize_vendor()
    normalize_product()
    normalizer.update_auditable_status()
    print("  Normalization complete.")

    # Step 4: Scan for vulnerabilities
    print("\n[4/4] Scanning for vulnerabilities...")
    find_all_vulnerabilities()
    print("  Vulnerability scan complete.")

    # Report
    print("\n")
    print_separator("═")
    print("  VULNERABILITY REPORT")
    print_vulnerability_report()


if __name__ == "__main__":
    main()