"""
TODO
"""
import vuln_lookup
import database


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
    pass