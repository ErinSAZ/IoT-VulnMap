"""
This module fetches vulnerabilities from CIRCL's Vulnerability Lookup API
for all auditable devices stored in the database and persists the results.
"""

from datetime import date
from packaging.version import Version, InvalidVersion

from database import add_vulnerability, get_auditable_devices
from vuln_lookup import get_vulnerabilities


def find_all_vulnerabilities():
    """
    For each auditable device in the database, fetch CVEs from CIRCL
    and store those affecting the device's firmware version.
    """
    devices = get_auditable_devices()

    for device_id, product_vl, firmware, vendor_vl in devices:
        if not product_vl or not vendor_vl or not firmware:
            continue

        response = get_vulnerabilities(vendor_vl, product_vl)
        entries = response.get('results', {}).get('nvd', [])

        for entry in entries:
            cve_id, cve_data = entry[0], entry[1]

            cve_metadata = cve_data.get('cveMetadata', {})
            containers = cve_data.get('containers', {})
            cna = containers.get('cna', {})
            adp_list = containers.get('adp', [])

            # Extract CVE ID
            cve_id = cve_metadata.get('cveId', cve_id).upper()

            # Extract published date
            published_raw = cve_metadata.get('datePublished')
            published_date = published_raw[:10] if published_raw else str(date.today())

            # Extract description (english)
            descriptions = cna.get('descriptions', [])
            description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), None)

            # Extract CVSS — try cna.metrics first, then adp.metrics
            cvss_score, severity = extract_cvss(cna.get('metrics', []), adp_list)

            # Extract affected versions
            affected_versions = []
            for affected in cna.get('affected', []):
                affected_versions.extend(affected.get('versions', []))

            # Check if firmware is affected — if no version info, include by default
            if affected_versions and not is_firmware_affected(firmware, affected_versions):
                continue

            try:
                add_vulnerability(
                    cve_id=cve_id,
                    cvss=cvss_score,
                    descr=description,
                    severity=severity,
                    date=published_date,
                    device_id=device_id
                )
            except Exception as e:
                continue


def extract_cvss(cna_metrics: list, adp_list: list) -> tuple:
    """
    Extracts CVSS score and severity from cna.metrics or adp.metrics.
    Tries cna first, then adp as fallback.
    :param cna_metrics: metrics list from cna container
    :param adp_list: list of adp containers
    :return: tuple (cvss_score, severity)
    """
    # Try cna metrics first
    for metric in cna_metrics:
        cvss_data = metric.get('cvssV3_1') or metric.get('cvssV3_0') or metric.get('cvssV2_0')
        if cvss_data:
            return cvss_data.get('baseScore'), cvss_data.get('baseSeverity')

    # Fallback to adp metrics
    for adp in adp_list:
        for metric in adp.get('metrics', []):
            cvss_data = metric.get('cvssV3_1') or metric.get('cvssV3_0') or metric.get('cvssV2_0')
            if cvss_data:
                return cvss_data.get('baseScore'), cvss_data.get('baseSeverity')

    return None, None


def is_firmware_affected(firmware_version: str, versions: list) -> bool:
    """
    Checks if the given firmware version is affected based on the CVE version ranges.
    :param firmware_version: firmware version string from the device
    :param versions: list of version dicts from CIRCL's API
    :return: True if the firmware is affected, False otherwise
    """
    try:
        fw = Version(firmware_version)
    except InvalidVersion:
        # If version cannot be parsed, assume affected to avoid missing vulnerabilities
        return True

    for v in versions:
        if v.get('status') != 'affected':
            continue

        less_than = v.get('lessThan')
        less_than_or_equal = v.get('lessThanOrEqual')
        exact = v.get('version')

        try:
            if less_than and fw < Version(less_than):
                return True
            if less_than_or_equal and fw <= Version(less_than_or_equal):
                return True
            if exact and exact not in ('0', '*') and fw == Version(exact):
                return True
        except InvalidVersion:
            # If range version cannot be parsed, include the CVE to be safe
            return True

    return False


if __name__ == "__main__":
    find_all_vulnerabilities()