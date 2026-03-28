import pymysql


# ============================================
# Database access functions
# ============================================

# Established and return a connexion to the database
def get_connection():
    return pymysql.connections.Connection(
        host="localhost",
        port=3307,
        user="user",
        password="password",
        database="IoT_VulnMap",
        cursorclass=pymysql.cursors.Cursor
    )


# Add a new vendor to the database and return its ID
def add_vendor(name_vendor_ha):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("INSERT INTO Vendor (name_ha) values (%s)", (name_vendor_ha,))
    vendor_id = cursor.lastrowid
    connection.commit()
    cursor.close()
    connection.close()
    return vendor_id


# Check if a vendor with the given name_ha exists in the database and return its ID if found
def vendor_exists(name_vendor_ha):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT id FROM Vendor WHERE name_ha = %s", (name_vendor_ha,))
    existing_vendor = cursor.fetchone()
    cursor.close()
    connection.close()
    return existing_vendor


# Return all the vendors who don't have a name_vl in the database
def get_vendors_without_vl():
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT id, name_ha FROM Vendor WHERE name_ha IS NOT NULL AND name_vl IS NULL")
    vendors_without_vl = list(cursor.fetchall())
    cursor.close()
    connection.close()
    return vendors_without_vl


# Add a new model to the database and return its ID
def add_model(name_model_ha, vendor_id):
    # Check if model already exists
    existing_model = model_exists(name_model_ha)
    if existing_model:
        return existing_model[0]  # Return existing ID
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("INSERT INTO Models (name_ha, vendor_id) values (%s, %s)", (name_model_ha, vendor_id))
    model_id = cursor.lastrowid
    connection.commit()
    cursor.close()
    connection.close()
    return model_id


# Check if a model with the given name_ha exists in the database and return its ID if found
def model_exists(name_model_ha):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT id FROM Models WHERE name_ha = %s", (name_model_ha,))
    existing_model = cursor.fetchone()
    cursor.close()
    connection.close()
    return existing_model


# Return all the models who don't have a name_vl in the database
def get_models_without_vl():
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT Models.id, Models.name_ha, Vendor.name_vl FROM Models LEFT JOIN Vendor ON Models.vendor_id = Vendor.id WHERE Models.name_ha IS NOT NULL AND Models.name_vl IS NULL")
    models_without_vl = list(cursor.fetchall())
    cursor.close()
    connection.close()
    return models_without_vl


# Add a new device to the database
def add_device(name, vendor_id, model_id, firmware):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO Device (name, firmware_version, vendor_id, model_id, is_auditable) values (%s,%s,%s,%s,%s)",
        (name, firmware, vendor_id, model_id, False))
    connection.commit()
    cursor.close()
    connection.close()


# Check if a device with the given name and model exists in the database and return its ID if found
def device_exists(name, model):
    existing_model = model_exists(model)
    if existing_model is None:
        return None
    model_id = existing_model[0]
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT id FROM Device WHERE name = %s AND model_id = %s", (name, model_id))
    device = cursor.fetchone()
    cursor.close()
    connection.close()
    return device


def get_all_devices():
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT Device.id, Models.name_vl, Device.firmware_version, Vendor.name_vl FROM Device LEFT JOIN Models ON Device.model_id = Models.id LEFT JOIN Vendor ON Device.vendor_id = Vendor.id")
    all_devices = list(cursor.fetchall())
    cursor.close()
    connection.close()
    return all_devices


# Remove the device with the given id in the database
def remove_device(id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("DELETE FROM Device WHERE id = %s", (id,))
    connection.commit()
    cursor.close()
    connection.close()


# Add a new vulnerability to the database and link it with devices
def add_vulnerability(cve, cvss, descr, severity, date, device_id):
    connection = get_connection()
    cursor = connection.cursor()

    # Verify if vulnerability already exists
    cursor.execute("SELECT id FROM Vulnerability WHERE cve_id = %s", (cve,))
    existing_vulnerability = cursor.fetchone()

    if existing_vulnerability is None:
        cursor.execute(
            "INSERT INTO Vulnerability (cve_id,cvss_score,description,severity,published_date) values (%s,%s,%s,%s,%s)",
            (cve, cvss, descr, severity, date))
        vulnerability_id = cursor.lastrowid
    else:
        vulnerability_id = existing_vulnerability[0]

    # Link vulnerability to device if not already linked
    cursor.execute("INSERT INTO Exposes (device_id,vulnerability_id,detected_date) values (%s,%s,%s)",
                   (device_id, vulnerability_id, date))

    connection.commit()
    cursor.close()
    connection.close()


# Add a new exposes relation between a device and a vulnerability in the database
def add_exposes(device_id, vulnerability_id, date):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("INSERT INTO Exposes (device_id,vulnerability_id,detected_date) values (%s,%s,%s)",
                   (device_id, vulnerability_id, date))
    connection.commit()
    cursor.close()
    connection.close()


# Update the vulnerability lookup name of a vendor
def update_vl_vendor(vendor_id, vl_vendor):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("UPDATE Vendor SET name_vl = %s WHERE id = %s", (vl_vendor, vendor_id))
    connection.commit()
    cursor.close()
    connection.close()


# Update the vulnerability lookup name of a model
def update_vl_model(model_id, vl_model):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("UPDATE Models SET name_vl = %s WHERE id = %s", (vl_model, model_id))
    connection.commit()
    cursor.close()
    connection.close()


# Update the auditable status of a device
def update_auditable_status(device_id, is_auditable):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("UPDATE Device SET is_auditable = %s WHERE id = %s", (is_auditable, device_id))
    connection.commit()
    cursor.close()
    connection.close()


# Get all auditable devices with their model, firmware version and vulnerability lookup vendor name
def get_auditable_devices():
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT Device.id, Models.name_vl, Device.firmware_version, Vendor.name_vl "
                   "FROM Device LEFT JOIN Models ON Device.model_id = Models.id LEFT JOIN Vendor ON Device.vendor_id = Vendor.id "
                   "WHERE Device.is_auditable = TRUE")
    auditable_devices = list(cursor.fetchall())
    cursor.close()
    connection.close()
    return auditable_devices
