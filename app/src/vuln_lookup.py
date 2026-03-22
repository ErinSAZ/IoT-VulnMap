"""
This module contains functions for finding vulnerabilities in CIRCL's API.
"""

import json

import requests
from rapidfuzz.distance.metrics_cpp import levenshtein_distance

# CONSTANTS

FUZZY_THRESHOLD = 0.8
VL_INSTANCE_URL = "https://vulnerability.circl.lu/"


# API requests

def get_vendors():
    """
    Fetch the list of vendors from CIRCL's API.
    :return: list of vendors
    """
    try:
        content = requests.get(f"{VL_INSTANCE_URL}/api/browse")
        return json.loads(content.text)
    except requests.exceptions.RequestException:
        return []


def get_products(vendor):
    """
    Fetch the list of products of a given vendor from CIRCL's API.
    :param vendor: vendor name
    :return: list of products
    """
    try:
        content = requests.get(f"{VL_INSTANCE_URL}/api/browse/{vendor}")
        return json.loads(content.text)
    except requests.exceptions.RequestException:
        return []


def get_vulnerabilities(vendor, product):
    """
    Fetch the list of vulnerabilities for a given vendor and product from CIRCL's API.
    :param vendor: vendor name
    :param product: product name
    :return: list of vulnerabilities
    """
    try:
        content = requests.get(f"{VL_INSTANCE_URL}/api/search/{vendor}/{product}")
        return json.loads(content.text)
    except requests.exceptions.RequestException:
        return []


# Custom functions

def vendor_exists(searched_vendor, vendors=None):
    """
    Check if a given vendor exists in CIRCL's API.
    :param searched_vendor: vendor name
    :param vendors: list of vendors
    :return: True if the vendor exists, False otherwise
    """
    if searched_vendor is None:
        return False

    if vendors is None:
        vendors = get_vendors()

    low_vendor = searched_vendor.lower()

    for vendor in vendors:
        if low_vendor == vendor.lower():
            return True
    return False


def find_closest_vendor(searched_vendor, vendors=None):
    """
    Find the closest matching vendor name from the list of vendors using Levenshtein distance.
    :param searched_vendor: vendor name
    :param vendors: list of vendors
    :return: closest matching vendor name
    """
    if searched_vendor is None:
        return searched_vendor

    if vendors is None:
        vendors = get_vendors()

    best_match = None
    highest_score = 0

    low_vendor = searched_vendor.lower()
    # Use the first word of the input vendor name for matching
    pt1_vendor = low_vendor.split()[0]

    for vendor in vendors:
        if low_vendor == vendor.lower():
            return vendor
        score = 1 - (levenshtein_distance(pt1_vendor, vendor.lower()) / max(len(pt1_vendor), len(vendor)))
        if score > highest_score:
            highest_score = score
            best_match = vendor
    return best_match if highest_score > FUZZY_THRESHOLD else None


if __name__ == "__main__":
    # Tests
    vendors = get_vendors()
    print(vendors[0:5])
    print("\n")

    products = get_products(vendors[0])
    print(f"products of {vendors[0]}:")
    print(products[0:5])
    print("\n")

    vulnerabilities = get_vulnerabilities(vendors[0], products[0])
    print(f"vulnerabilities of {vendors[0]} and {products[0]}:")
    print(vulnerabilities)
    print("\n")

    test_vendors = ["Home Assistant", "IKEA of Sweden", "Google Inc.", "Apple", "Freebox", "Risco", "Ezviz", "Tuya",
                    "RandomBrand123"]
    for vendor in test_vendors:
        print(f"vendor: {vendor} exists in CIRCL's API : {vendor_exists(vendor)}")
        print(f"vendor: {vendor}, found_vendor: {find_closest_vendor(vendor, vendors)} ")
