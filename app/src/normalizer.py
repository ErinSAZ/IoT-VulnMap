"""
This module maps Home Assistant vendor and product names to their Vulnerability Lookup equivalents.
It also loads pre-established mappings from a JSON file and updates device auditability status.
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
    Matches Home Assistant vendor names to Vulnerability Lookup vendor names.
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
    Matches Home Assistant model names to Vulnerability Lookup model names.
    """
    ha_devices_list = database.get_products_without_vl()
    for product_id, product_ha, vendor_vl in ha_devices_list:
        if vendor_vl is None or product_ha is None: continue

        if vuln_lookup.product_exists(product_ha, vendor_vl):
            database.update_vl_product(product_id, product_ha.lower())
        else:
            found_vl_product = vuln_lookup.find_closest_product(product_ha, vendor_vl)
            if found_vl_product:
                database.update_vl_product(product_id, found_vl_product.lower())


def update_auditable_status():
    """
    Updates the auditable status of all devices in the database.
    A device is considered auditable if it has a mapped vendor name, a mapped product name and a firmware version.
    """
    devices_list = get_all_devices()

    for device_id, product_vl, firmware, vendor_vl in devices_list:
        if (vendor_vl is not None  # vendor vl_name
                and product_vl is not None  # device product
                and firmware is not None):  # device firmware
            database.update_device_auditable_status(device_id, True)
        else:
            database.update_device_auditable_status(device_id, False)


def load_mapping(path=MAPPINGS_PATH):
    """
    Loads pre-established vendor and product mappings from a JSON file
    and updates the database with their Vulnerability Lookup equivalents.
    :param path: path to the JSON file containing the mappings
    """
    with open(MAPPINGS_PATH, "r") as f:
        mappings = json.load(f)

        for vendor in mappings["vendors"]:
            existing = database.vendor_exists(vendor["ha_name"])
            if existing is None:
                vendor_id = database.add_vendor(vendor["ha_name"])
            else:
                vendor_id = existing[0]
            database.update_vl_vendor(vendor_id, vendor["vl_name"])

            for product in vendor["products"]:
                existing_product = database.product_exists(product["ha_name"])
                if existing_product is None:
                    product_id = database.add_product(product["ha_name"], vendor_id)
                else:
                    product_id = existing_product[0]
                database.update_vl_product(product_id, product["vl_name"])
