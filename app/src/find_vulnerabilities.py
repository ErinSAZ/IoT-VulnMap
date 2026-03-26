
import requests
from datetime import date
from app.src.database import *

CIRCL_API_URL = "https://vulnerability.circl.lu/search"

def search_vulnerabilities(vendor, product):
    """
    Search for vulnerabilities for a given vendor and product using CIRCL's API.
    :param vendor: vendor name
    :param product: product name
    :return: list of vulnerabilities
    """
    try:
        response = requests.get(f"{CIRCL_API_URL}/{vendor}/{product}")
        return response.json()
    except requests.exceptions.RequestException:
        return []


def find_all_vulnerabilities():
    """
    For each device in the database, search for vulnerabilities using CIRCL's API,
    """
    # The devices in the list are auditable
    devices_list = get_auditable_devices()

    for device_id, model, firmware, name_vl in devices_list:
            vulnerabilities = search_vulnerabilities(name_vl, model)
            for vulnerability in vulnerabilities:
                add_vulnerability(
                    cve=vulnerability.get('id'),
                    cvss=vulnerability.get('cvss'),
                    descr=vulnerability.get('summary'),
                    severity=vulnerability.get('severity'),
                    date=vulnerability.get('Published'),
                    device_id=device_id
                )