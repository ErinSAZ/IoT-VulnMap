import json
import requests
from rapidfuzz.distance.metrics_cpp import levenshtein_distance

def get_vendors():
    """
    Fetch the list of vendors from CIRCL's API.
    :return: list of vendors
    """
    content = requests.get("https://vulnerability.circl.lu/api/browse")
    return json.loads(content.text)

def get_products(vendor):
    """
    Fetch the list of products of a given vendor from CIRCL's API.
    :param vendor: vendor name
    :return: list of products
    """
    content = requests.get(f"https://vulnerability.circl.lu/api/browse/{vendor}")
    return json.loads(content.text)

def get_vulnerabilities(vendor, product):
    """
    Fetch the list of vulnerabilities for a given vendor and product from CIRCL's API.
    :param vendor: vendor name
    :param product: product name
    :return: list of vulnerabilities
    """
    content = requests.get(f"https://vulnerability.circl.lu/api/search/{vendor}/{product}")
    return json.loads(content.text)

def find_closest_vendor(vendor_name, vendors):
    """
    Find the closest matching vendor name from the list of vendors using fuzzy matching.
    :param vendor_name: input vendor name
    :param vendors: list of available vendors
    :return: closest matching vendor name
    """
    best_match = None
    highest_score = 0

    # Use the first word of the input vendor name for matching
    pt1 = vendor_name.lower().split()[0]

    for vendor in vendors:
        score = 1 - (levenshtein_distance(pt1, vendor) / max(len(pt1), len(vendor)))
        if score > highest_score:
            highest_score = score
            best_match = vendor
    return best_match


if __name__ == "__main__":
    #Tests
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

    test_vendors = ["Home Assistant", "IKEA of Sweden", "Google Inc.", "Apple", "Freebox", "Risco", "Ezviz", "Tuya", "IKEA of Sweden"]
    for vendor in test_vendors:
        print(f"test_vendor: {vendor}, found_vendor: {find_closest_vendor(vendor, vendors)} ")
