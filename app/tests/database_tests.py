import unittest

from app.src.database import *


class TestDatabase(unittest.TestCase):

    # =============================================
    # SETUP / TEARDOWN
    # =============================================

    def setUp(self):
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM Exposes")
        cursor.execute("DELETE FROM Device")
        cursor.execute("DELETE FROM Vulnerability")
        cursor.execute("DELETE FROM Products")
        cursor.execute("DELETE FROM Vendor")
        # Reset auto_increment counters
        cursor.execute("ALTER TABLE Exposes AUTO_INCREMENT = 1")
        cursor.execute("ALTER TABLE Device AUTO_INCREMENT = 1")
        cursor.execute("ALTER TABLE Vulnerability AUTO_INCREMENT = 1")
        cursor.execute("ALTER TABLE Products AUTO_INCREMENT = 1")
        cursor.execute("ALTER TABLE Vendor AUTO_INCREMENT = 1")
        conn.commit()
        cursor.close()
        conn.close()

    def test_get_connection(self):
        conn = get_connection()
        self.assertIsNotNone(conn)
        conn.close()

    def test_add_vendor(self):
        vendor_id = add_vendor("cisco")
        self.assertIsNotNone(vendor_id)
        self.assertIsInstance(vendor_id, int)

    def test_vendor_exists(self):
        add_vendor("cisco")
        result = vendor_exists("cisco")
        self.assertIsNotNone(result)

    def test_get_vendors_without_vl(self):
        add_vendor("cisco")
        vendors = get_vendors_without_vl()
        self.assertIsInstance(vendors, list)
        self.assertGreater(len(vendors), 0)
        self.assertEqual(vendors[0][1], "cisco")

    def test_add_product(self):
        vendor_id = add_vendor("cisco")
        product_id = add_product("RV340", vendor_id)
        self.assertIsNotNone(product_id)
        self.assertIsInstance(product_id, int)

    def test_product_exists(self):
        vendor_id = add_vendor("cisco")
        add_product("RV340", vendor_id)
        result = product_exists("RV340")
        self.assertIsNotNone(result)

    def test_get_products_without_vl(self):
        vendor_id = add_vendor("cisco")
        add_product("RV340", vendor_id)
        products = get_products_without_vl()
        self.assertIsInstance(products, list)
        self.assertGreater(len(products), 0)
        self.assertEqual(products[0][1], "RV340")

    def test_add_device(self):
        vendor_id = add_vendor("cisco")
        product_id = add_product("RV340", vendor_id)
        add_device("Router", vendor_id, product_id, "1.0.3")
        device = device_exists("Router", "RV340")
        self.assertIsNotNone(device)

    def test_device_exists(self):
        vendor_id = add_vendor("cisco")
        product_id = add_product("RV340", vendor_id)
        add_device("Router", vendor_id, product_id, "1.0.3")
        result = device_exists("Router", "RV340")
        self.assertIsNotNone(result)

    def test_get_all_devices(self):
        vendor_id = add_vendor("cisco")
        product_id = add_product("RV340", vendor_id)
        add_device("Router", vendor_id, product_id, "1.0.3")
        devices = get_all_devices()
        self.assertIsInstance(devices, list)
        self.assertGreater(len(devices), 0)

    def test_remove_device(self):
        vendor_id = add_vendor("cisco")
        product_id = add_product("RV340", vendor_id)
        add_device("Router", vendor_id, product_id, "1.0.3")
        device_id = device_exists("Router", "RV340")[0]
        remove_device(device_id)
        self.assertIsNone(device_exists("Router", "RV340"))

    def test_add_vulnerability(self):
        vendor_id = add_vendor("cisco")
        product_id = add_product("RV340", vendor_id)
        add_device("Router", vendor_id, product_id, "1.0.3")
        device_id = device_exists("Router", "RV340")[0]
        add_vulnerability("CVE-2024-1234", 9.8, "Buffer overflow", "CRITICAL", "2024-01-15", device_id)
        # Check if vulnerability exists
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM Vulnerability WHERE cve_id = %s", ("CVE-2024-1234",))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        self.assertIsNotNone(result)

    def test_add_exposes(self):
        vendor_id = add_vendor("cisco")
        product_id = add_product("RV340", vendor_id)
        add_device("Router", vendor_id, product_id, "1.0.3")
        device_id = device_exists("Router", "RV340")[0]
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO Vulnerability (cve_id, cvss_score, description, severity, published_date) VALUES (%s,%s,%s,%s,%s)",
            ("CVE-2024-5678", 7.5, "SQL Injection", "HIGH", "2024-03-01")
        )
        vuln_id = cursor.lastrowid
        conn.commit()
        cursor.close()
        conn.close()
        add_exposes(device_id, vuln_id, "2024-06-01")
        # Verify the link exists
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM Exposes WHERE device_id = %s AND vulnerability_id = %s",
            (device_id, vuln_id)
        )
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        self.assertIsNotNone(result)

    def test_update_vl_vendor(self):
        vendor_id = add_vendor("cisco")
        update_vl_vendor(vendor_id, "Cisco Systems")
        # Check update
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name_vl FROM Vendor WHERE id = %s", (vendor_id,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        self.assertEqual(result[0], "Cisco Systems")

    def test_update_vl_product(self):
        vendor_id = add_vendor("cisco")
        product_id = add_product("RV340", vendor_id)
        update_vl_product(product_id, "RV340W")
        # Check update
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name_vl FROM Products WHERE id = %s", (product_id,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        self.assertEqual(result[0], "RV340W")

    def test_update_auditable_status(self):
        vendor_id = add_vendor("cisco")
        product_id = add_product("RV340", vendor_id)
        add_device("Router", vendor_id, product_id, "1.0.3")
        device_id = device_exists("Router", "RV340")[0]
        update_device_auditable_status(device_id, True)
        # Check update
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT is_auditable FROM Device WHERE id = %s", (device_id,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        self.assertTrue(result[0])

    def test_get_auditable_devices(self):
        vendor_id = add_vendor("cisco")
        product_id = add_product("RV340", vendor_id)
        add_device("Router", vendor_id, product_id, "1.0.3")
        device_id = device_exists("Router", "RV340")[0]
        update_device_auditable_status(device_id, True)
        auditable = get_auditable_devices()
        self.assertIsInstance(auditable, list)
        self.assertGreater(len(auditable), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
