import mysql.connector


def get_connection():
    return mysql.connector.connect(
        host="localhost",
        port=3307,
        user="user",
        password="password",
        database="IoT_VulnMap"
    )


def add_vendor(name_vendor_ha):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("INSERT INTO Vendor (name_ha) values (%s)", (name_vendor_ha,))
    vendor_id = cursor.lastrowid
    connection.commit()
    cursor.close()
    connection.close()
    return vendor_id


def vendor_exists(name_vendor_ha):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT id FROM Vendor WHERE name_ha = %s", (name_vendor_ha,))
    existing_vendor = cursor.fetchone()
    cursor.close()
    connection.close()
    return existing_vendor


def add_device(name, model, firmware, vendor_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("INSERT INTO Device (name,model,firmware_version,vendor_id) values (%s,%s,%s,%s)",
                   (name, model, firmware, vendor_id))
    connection.commit()
    cursor.close()
    connection.close()


def device_exists(name, model):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT id FROM Device WHERE name = %s AND model = %s", (name, model))
    device_exists = cursor.fetchone()
    cursor.close()
    connection.close()
    return device_exists


def remove_device(id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("DELETE FROM Device WHERE id = %s", (id,))
    connection.commit()


def add_vulnerability(cve, cvss, descr, severity, date):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO Vulnerability (cve_id,cvss_score,description,severity,published_date) values (%s,%s,%s,%s,%s)",
        (cve, cvss, descr, severity, date))
    connection.commit()
    cursor.close()
    connection.close()


def add_exposes(device_id, vulnerability_id, date):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("INSERT INTO Exposes (device_id,vulnerability_id,detected_date) values (%s,%s,%s)",
                   (device_id, vulnerability_id, date))
    connection.commit()
    cursor.close()
    connection.close()
