"""
This module normalizes vendor names from Home Assistant to match those in Vulnerability Lookup.
"""
import json
import os

import database
import vuln_lookup
from database import get_all_devices

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAPPINGS_PATH = os.path.join(BASE_DIR, "data", "mappings.json")


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


def normalize_product():
    """
    Matches Home Assistant model names to Vulnerability Lookup model names,
    and updates device auditability status accordingly.
    """
    ha_devices_list = database.get_models_without_vl()
    for model_id, model_ha, vendor_vl in ha_devices_list:
        if vendor_vl is None or model_ha is None: continue

        if vuln_lookup.product_exists(model_ha, vendor_vl):
            database.update_vl_model(model_id, model_ha.lower())
        else:
            found_vl_model = vuln_lookup.find_closest_product(model_ha, vendor_vl)
            if found_vl_model:
                database.update_vl_model(model_id, found_vl_model.lower())


def update_auditable_status():
    """
    Updates device auditable status accordingly.
    :return:
    """
    devices_list = get_all_devices()

    for device_id, model_vl, firmware, vendor_vl in devices_list:
        if (vendor_vl is not None  # vendor vl_name
                and model_vl is not None  # device model
                and firmware is not None):  # device firmware
            database.update_auditable_status(device_id, True)
        else:
            database.update_auditable_status(device_id, False)


def load_mapping(path=MAPPINGS_PATH):
    """
    Loads vendor name mappings from a file and updates the database accordingly.
    :param path: Path to the mapping file (json)
    """
    with open(MAPPINGS_PATH, "r") as f:
        mappings = json.load(f)

        for vendor in mappings["vendors"]:
            # Add the vendor if it doesn't exist
            vendor_id = database.vendor_exists(vendor["ha_name"])
            if not vendor_id:
                vendor_id = database.add_vendor(vendor["ha_name"])
            # Update the vendor's VL name
            database.update_vl_vendor(vendor_id, vendor["vl_name"])

            for product in vendor["products"]:
                # Add the product if it doesn't exist
                model_id = database.model_exists(product["ha_name"])
                if not model_id:
                    model_id = database.add_model(product["ha_name"], vendor_id)
                # Update the product's VL name
                database.update_vl_model(model_id, product["vl_name"])
