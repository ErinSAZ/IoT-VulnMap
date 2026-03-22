"""
TODO
"""
import vuln_lookup
import database
from database import get_all_devices


def normalize_vendor():
    """
    Matches Home Assistant vendor names to Vulnerability Lookup vendor names,
    and updates device auditability status accordingly.
    """
    ha_vendors_list = database.get_vendors_without_vl()
    vl_vendors_list = vuln_lookup.get_vendors()

    for vendor_id, ha_vendor in ha_vendors_list:
        if ha_vendor == "N/A": # TODO retirer quand N/A ne sera plus ajouté dans la base
            continue

        if vuln_lookup.vendor_exists(ha_vendor, vl_vendors_list):
            database.update_vl_vendor(vendor_id,ha_vendor.lower())
        else :
            found_vl_vendor = vuln_lookup.find_closest_vendor(ha_vendor,vl_vendors_list)
            if found_vl_vendor:
                database.update_vl_vendor(vendor_id,found_vl_vendor.lower())


def update_auditable_status():
    # TODO
    devices_list = get_all_devices()

    for device in devices_list:
        vendor_id = device[5]

    pass

if __name__ == "__main__":
    devices_list = get_all_devices()
    print(devices_list)