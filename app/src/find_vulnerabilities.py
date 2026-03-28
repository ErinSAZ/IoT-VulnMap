"""
This module fetches vulnerabilities from CIRCL's Vulnerability Lookup API
for all auditable devices stored in the database and persists the results.
"""

from distutils.version import Version

from app.src.database import *
from vuln_lookup import get_vulnerabilities


def find_all_vulnerabilities():
    """
    Find all vulnerabilities for all auditable devices in the database and store them.
    """
    devices_list = get_auditable_devices()

    for device_id, product, firmware, name_vl in devices_list:
        firmware_version, firmware_date = firmware

        vulnerabilities = get_vulnerabilities(name_vl, product)
        for vulnerability in vulnerabilities:
            # Extract firmware information
            nvd_data = vulnerability.get('fkie_nvd', {})
            configurations = nvd_data.get('configurations', [])

            # Check if firmware version is affected by the vulnerability
            if configurations and not is_firmware_affected(firmware_version, configurations):
                continue

            # Skip CVEs published before the device firmware release date
            cve_date = nvd_data.get('published')
            if cve_date and cve_date < firmware_date:
                continue

            add_vulnerability(
                cve_id=nvd_data.get('id'),
                cvss=nvd_data.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('cvssData', {}).get('baseScore'),
                descr=next((d['value'] for d in nvd_data.get('descriptions', []) if d['lang'] == 'en'), None),
                severity=nvd_data.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('baseSeverity'),
                date=cve_date,
                device_id=device_id
            )


def extract_affected_versions_from_configurations(configurations: list) -> tuple[list, bool]:
    """
    Extracts affected versions from NVD-style configurations.
    :param configurations: list of configurations
    :return: tuple (list of affected versions, bool has_wildcard)
    """
    versions = []
    has_wildcard = False

    for config in configurations:
        for node in config.get('nodes', []):
            for cpe_match in node.get('cpeMatch', []):
                if not cpe_match.get('vulnerable', False):
                    continue

                criteria = cpe_match.get('criteria', '')
                parts = criteria.split(':')

                if len(parts) >= 6:
                    version = parts[5]
                    if version == '*':
                        has_wildcard = True
                    else:
                        versions.append(version)

    return versions, has_wildcard


def is_firmware_affected(firmware_version: str, configurations: list) -> bool:
    """
    Checks if the firmware version is in the affected versions or if a wildcard is present (all versions affected).
    :param firmware_version: firmware version to check
    :param configurations: list of configurations
    :return: True if the firmware version is affected, False otherwise
    """
    affected_versions, has_wildcard = extract_affected_versions_from_configurations(configurations)

    try:
        fw = Version(firmware_version)
        for v in affected_versions:
            status = v.get('status')
            if status != 'affected':
                continue

            less_than = v.get('lessThan')
            less_than_or_equal = v.get('lessThanOrEqual')
            exact = v.get('version')

            if less_than and fw < Version(less_than):
                return True
            if less_than_or_equal and fw <= Version(less_than_or_equal):
                return True
            if exact and exact != '0' and fw == Version(exact):
                return True

    except Exception as e:
        return False
