"""
This module normalizes vendor names from Home Assistant to match those in Vulnerability Lookup.
"""

import database
import vuln_lookup
from database import get_all_devices


def normalize_vendor():
    """
    Matches Home Assistant vendor names to Vulnerability Lookup vendor names,
    and updates device auditability status accordingly.
    """
    ha_vendors_list = database.get_vendors_without_vl()
    vl_vendors_list = vuln_lookup.get_vendors()

    for vendor_id, ha_vendor in ha_vendors_list:
        if ha_vendor is None: continue

        if vuln_lookup.vendor_exists(ha_vendor, vl_vendors_list):
            database.update_vl_vendor(vendor_id, ha_vendor.lower())
        else:
            found_vl_vendor = vuln_lookup.find_closest_vendor(ha_vendor, vl_vendors_list)
            if found_vl_vendor:
                database.update_vl_vendor(vendor_id, found_vl_vendor.lower())


def update_auditable_status():
    """
    Updates device auditable status accordingly.
    :return:
    """
    devices_list = get_all_devices()

    for device_id, model, firmware, name_vl in devices_list:
        if (name_vl is not None  # vendor vl_name
                and model is not None  # device model
                and firmware is not None):  # device firmware
            database.update_auditable_status(device_id, True)
        else:
            database.update_auditable_status(device_id, False)
