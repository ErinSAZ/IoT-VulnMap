"""
This module provides functions to interact with the MySQL database.
It handles vendors, products, devices and vulnerabilities storage and retrieval.
"""
import os
from datetime import datetime

import pymysql
from dotenv import load_dotenv

load_dotenv()
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")


def get_connection():
    """
    Establish a connection to the MySQL database.
    """
    return pymysql.connections.Connection(
        host="localhost",
        port=3307,
        user=DB_USER,
        password=DB_PASSWORD,
        database="IoT_VulnMap",
        cursorclass=pymysql.cursors.Cursor
    )


# Vendors

def add_vendor(name_vendor_ha):
    """
    Adds a new vendor to the database.
    :param name_vendor_ha: new vendor name based on Home Assistant data
    :return: id of the new vendor
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("INSERT INTO Vendor (name_ha) values (%s)", (name_vendor_ha,))
    vendor_id = cursor.lastrowid
    connection.commit()
    cursor.close()
    connection.close()
    return vendor_id


def vendor_exists(name_vendor_ha):
    """
    Checks if a vendor exists in the database.
    :param name_vendor_ha: vendor name based on Home Assistant data
    :return: id of the vendor if it exists else None
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT id FROM Vendor WHERE name_ha = %s", (name_vendor_ha,))
    existing_vendor = cursor.fetchone()
    cursor.close()
    connection.close()
    return existing_vendor


def get_vendors_without_vl():
    """
    Retrieves all vendors without VulnerabilityLookup datas from the database.
    :return: list of tuples (id, name_ha) of vendors
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT id, name_ha FROM Vendor WHERE name_ha IS NOT NULL AND name_vl IS NULL")
    vendors_without_vl = list(cursor.fetchall())
    cursor.close()
    connection.close()
    return vendors_without_vl


def update_vl_vendor(vendor_id, vl_vendor):
    """
    Maps a vendor's Home Assistant name to its Vulnerability Lookup equivalent in the database.
    :param vendor_id: id of the vendor in the database
    :param vl_vendor: Vulnerability Lookup equivalent
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("UPDATE Vendor SET name_vl = %s WHERE id = %s", (vl_vendor, vendor_id))
    connection.commit()
    cursor.close()
    connection.close()


# Products

def add_product(name_product_ha, vendor_id):
    """
    Adds a new product to the database.
    :param name_product_ha: new product name based on Home Assistant data
    :param vendor_id: id of the vendor in the database
    :return: id of the new product
    """
    existing_product = product_exists(name_product_ha)
    if existing_product:
        return existing_product[0]
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("INSERT INTO Product (name_ha, vendor_id) values (%s, %s)", (name_product_ha, vendor_id))
    product_id = cursor.lastrowid
    connection.commit()
    cursor.close()
    connection.close()
    return product_id


def product_exists(name_product_ha):
    """
    Checks if a product exists in the database.
    :param name_product_ha: product name based on Home Assistant data
    :return: id of the product if it exists else None
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT id FROM Product WHERE name_ha = %s", (name_product_ha,))
    existing_product = cursor.fetchone()
    cursor.close()
    connection.close()
    return existing_product


def get_products_without_vl():
    """
    Retrieves all products without VulnerabilityLookup datas from the database.
    :return: list of tuples (id, name_ha) of products
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT Product.id, Product.name_ha, Vendor.name_vl FROM Product LEFT JOIN Vendor ON Product.vendor_id = Vendor.id WHERE Product.name_ha IS NOT NULL AND Product.name_vl IS NULL")
    products_without_vl = list(cursor.fetchall())
    cursor.close()
    connection.close()
    return products_without_vl


def update_vl_product(product_id, vl_product):
    """
    Maps a product's Home Assistant name to its Vulnerability Lookup equivalent in the database.
    :param product_id: id of the product in the database
    :param vl_product: Vulnerability Lookup equivalent
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("UPDATE Product SET name_vl = %s WHERE id = %s", (vl_product, product_id))
    connection.commit()
    cursor.close()
    connection.close()


# Devices

def get_all_devices():
    """
    Retrieves all devices from the database.
    :return: list of tuples (id, name_vl, firmware_version, vendor_name_vl) of devices
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT Device.id, Product.name_vl, Device.firmware_version, Vendor.name_vl FROM Device LEFT JOIN Product ON Device.product_id = Product.id LEFT JOIN Vendor ON Device.vendor_id = Vendor.id")
    all_devices = list(cursor.fetchall())
    cursor.close()
    connection.close()
    return all_devices


def get_auditable_devices():
    """
    Gets all auditable devices in the database.
    :return: list of tuples (id, product_name_vl, firmware_version, vendor_name_vl) of auditable devices
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT Device.id, Product.name_vl, Device.firmware_version, Vendor.name_vl "
                   "FROM Device LEFT JOIN Product ON Device.product_id = Product.id LEFT JOIN Vendor ON Device.vendor_id = Vendor.id "
                   "WHERE Device.is_auditable = TRUE")
    auditable_devices = list(cursor.fetchall())
    cursor.close()
    connection.close()
    return auditable_devices


def add_device(name, vendor_id, product_id, firmware):
    """
    Adds a new device to the database.
    :param name: Friendly name of the device
    :param vendor_id: id of the vendor in the database
    :param product_id: id of the product in the database
    :param firmware: firmware version of the device based on Home Assistant data
    :return: id of the new device
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO Device (name, firmware_version, vendor_id, product_id, is_auditable) values (%s,%s,%s,%s,%s)",
        (name, firmware, vendor_id, product_id, False))
    device_id = cursor.lastrowid
    connection.commit()
    cursor.close()
    connection.close()
    return device_id


def update_device(device_id, firmware):
    """
    Updates a device in the database.
    :param device_id: id of the device in the database
    :param name: Friendly name of the device
    :param firmware: firmware version of the device based on Home Assistant data
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "UPDATE Device SET firmware_version = %s WHERE id = %s",
        (firmware, device_id)
    )
    connection.commit()
    cursor.close()
    connection.close()


def device_already_scanned(name):
    """
    Checks if a device with the given name already exists in the database.
    :param name: Friendly name of the device
    :return: id of the device if it exists else None
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT id FROM Device WHERE name = %s", (name,)
    )
    device_already_scanned = cursor.fetchone()
    cursor.close()
    connection.close()
    if device_already_scanned is None:
        return None
    return device_already_scanned[0]


def device_exists(name, product):
    """
    Checks if a device exists in the database.
    :param name: Friendly name of the device
    :param product: id of the product in the database
    :return: id of the device if it exists else None
    """
    existing_product = product_exists(product)
    if existing_product is None:
        return None
    product_id = existing_product[0]
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT id FROM Device WHERE name = %s AND product_id = %s", (name, product_id))
    device = cursor.fetchone()
    cursor.close()
    connection.close()
    return device


def remove_device(id):
    """
    Removes a device from the database.
    :param id: id of the device in the database
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("DELETE FROM Device WHERE id = %s", (id,))
    connection.commit()
    cursor.close()
    connection.close()


def update_device_auditable_status(device_id, is_auditable):
    """
    Updates the auditable status of the device in the database.
    :param device_id: id of the device in the database
    :param is_auditable: boolean indicating if the device is auditable or not
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("UPDATE Device SET is_auditable = %s WHERE id = %s", (is_auditable, device_id))
    connection.commit()
    cursor.close()
    connection.close()


def get_devices_with_vulnerabilities():
    """
    Retrieves all devices with vulnerabilities.
    :return: list of devices with vulnerabilities
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
                   SELECT Device.name,
                          Vendor.name_ha,
                          Product.name_ha,
                          Device.firmware_version,
                          COUNT(Exposes.vulnerability_id) AS vuln_count,
                          MAX(Vulnerability.cvss_score)   AS max_cvss,
                          MAX(Vulnerability.severity)     AS max_severity
                   FROM Device
                            LEFT JOIN Vendor ON Device.vendor_id = Vendor.id
                            LEFT JOIN Product ON Device.product_id = Product.id
                            LEFT JOIN Exposes ON Device.id = Exposes.device_id
                            LEFT JOIN Vulnerability ON Exposes.vulnerability_id = Vulnerability.id
                   WHERE Device.is_auditable = TRUE
                   GROUP BY Device.id
                   ORDER BY max_cvss DESC
                   """)
    rows = cursor.fetchall()
    cursor.close()
    connection.close()
    return rows


# Vulnerabilities

def add_vulnerability(cve_id, cvss, descr, severity, date, device_id):
    """
    Adds a vulnerability to the database and links it to a device.
    :param cve_id: CVE identifier of the vulnerability
    :param cvss: CVSS of the vulnerability
    :param descr: Description of the vulnerability
    :param severity: Severity of the vulnerability
    :param date: Date of the vulnerability
    :param device_id: id of the device in the database
    :return:
    """
    connection = get_connection()
    cursor = connection.cursor()

    # Check if vulnerability already exists
    cursor.execute("SELECT id FROM Vulnerability WHERE cve_id = %s", (cve_id,))
    existing_vulnerability = cursor.fetchone()

    if existing_vulnerability is None:
        cursor.execute(
            "INSERT INTO Vulnerability (cve_id,cvss_score,description,severity,published_date) values (%s,%s,%s,%s,%s)",
            (cve_id, cvss, descr, severity, date))
        vulnerability_id = cursor.lastrowid
    else:
        vulnerability_id = existing_vulnerability[0]

    # Link vulnerability to device if not already linked
    cursor.execute(
        "INSERT INTO Exposes (device_id,vulnerability_id,detected_date) values (%s,%s,%s) ON DUPLICATE KEY UPDATE resolved_date = NULL",
        (device_id, vulnerability_id, datetime.now().date()))

    connection.commit()
    cursor.close()
    connection.close()


def get_active_vulnerabilities(device_id):
    """
    Retrieves all active vulnerabilities associated with a device.
    :param device_id: id of the device in the database
    :return: list of active vulnerabilities
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT cve_id FROM Exposes JOIN Vulnerability v ON Exposes.vulnerability_id = v.id WHERE Exposes.device_id = %s;",
        (device_id,))
    results = [row[0] for row in cursor.fetchall()]
    cursor.close()
    connection.close()
    return results


def resolve_vulnerability(device_id, cve_id):
    """
    Resolves a vulnerability from the database by setting the resolved_date.
    :param device_id: id of the device in the database
    :param cve_id: CVE identifier of the vulnerability
    """
    connection = get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("""
                       UPDATE Exposes
                       SET resolved_date = %s
                       WHERE device_id = %s
                         AND vulnerability_id = (SELECT id FROM Vulnerability WHERE cve_id = %s)
                         AND resolved_date IS NULL
                       """, (datetime.now().date(), device_id, cve_id))
        connection.commit()
    except Exception as e:
        connection.rollback()
        raise e
    finally:
        cursor.close()
        connection.close()


def add_exposes(device_id, vulnerability_id, date):
    """
    Adds an exposes to the database between device and vulnerability.
    :param device_id: id of the device in the database
    :param vulnerability_id: id of the vulnerability in the database
    :param date: date of the expose
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("INSERT INTO Exposes (device_id,vulnerability_id,detected_date) values (%s,%s,%s)",
                   (device_id, vulnerability_id, date))
    connection.commit()
    cursor.close()
    connection.close()
