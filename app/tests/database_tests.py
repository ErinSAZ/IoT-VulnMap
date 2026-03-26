import unittest
import mysql.connector
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
        cursor.execute("DELETE FROM Vendor")
        # Reset auto_increment counters
        cursor.execute("ALTER TABLE Exposes AUTO_INCREMENT = 1")
        cursor.execute("ALTER TABLE Device AUTO_INCREMENT = 1")
        cursor.execute("ALTER TABLE Vulnerability AUTO_INCREMENT = 1")
        cursor.execute("ALTER TABLE Vendor AUTO_INCREMENT = 1")
        conn.commit()
        cursor.close()
        conn.close()

    # =============================================
    # TESTS VENDOR
    # =============================================

    def test_add_vendor_retourne_id(self):
        vendor_id = add_vendor("cisco")
        self.assertIsNotNone(vendor_id)
        self.assertIsInstance(vendor_id, int)

    def test_vendor_exists_trouve(self):
        add_vendor("cisco")
        result = vendor_exists("cisco")
        self.assertIsNotNone(result)

    def test_vendor_exists_introuvable(self):
        result = vendor_exists("nonexistent_vendor")
        self.assertIsNone(result)

    def test_vendor_exists_na(self):
        add_vendor("N/A")
        result = vendor_exists("N/A")
        self.assertIsNotNone(result)

    # =============================================
    # TESTS DEVICE
    # =============================================

    def _get_device_auditable(self, name, model):
        """Helper : get is_auditable from a device"""
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT is_auditable FROM Device WHERE name = %s AND model = %s",
            (name, model)
        )
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return result[0] if result else None

    def test_add_device_tout_valide_est_auditable(self):
        """All information → is_auditable must be TRUE"""
        vendor_id = add_vendor("cisco")
        add_device("Router", "RV340", "1.0.3", vendor_id)
        self.assertEqual(self._get_device_auditable("Router", "RV340"), 1)

    def test_add_device_modele_na_non_auditable(self):
        """Model N/A → is_auditable must be FALSE"""
        vendor_id = add_vendor("cisco")
        add_device("Router", "N/A", "1.0.3", vendor_id)
        self.assertEqual(self._get_device_auditable("Router", "N/A"), 0)

    def test_add_device_firmware_na_non_auditable(self):
        """Firmware N/A → is_auditable must be FALSE"""
        vendor_id = add_vendor("cisco")
        add_device("Router", "RV340", "N/A", vendor_id)
        self.assertEqual(self._get_device_auditable("Router", "RV340"), 0)

    def test_add_device_vendor_na_non_auditable(self):
        """Vendor N/A → is_auditable must be FALSE"""
        vendor_id = add_vendor("N/A")
        add_device("Router", "RV340", "1.0.3", vendor_id)
        self.assertEqual(self._get_device_auditable("Router", "RV340"), 0)

    def test_add_device_firmware_null_non_auditable(self):
        """Firmware NULL → is_auditable must be FALSE"""
        vendor_id = add_vendor("cisco")
        add_device("Router", "RV340", None, vendor_id)
        self.assertEqual(self._get_device_auditable("Router", "RV340"), 0)

    def test_device_exists_trouve(self):
        vendor_id = add_vendor("cisco")
        add_device("Router", "RV340", "1.0.3", vendor_id)
        result = device_exists("Router", "RV340")
        self.assertIsNotNone(result)

    def test_device_exists_introuvable(self):
        result = device_exists("Nonexistent device", "Nonexistent model")
        self.assertIsNone(result)

    def test_remove_device(self):
        vendor_id = add_vendor("cisco")
        add_device("Router", "RV340", "1.0.3", vendor_id)
        device_id = device_exists("Router", "RV340")[0]
        remove_device(device_id)
        self.assertIsNone(device_exists("Router", "RV340"))

    # =============================================
    # TESTS VULNERABILITY
    # =============================================

    def test_add_vulnerability_existe_en_bdd(self):
        """Vulnerability must be present in the database after insertion"""
        vendor_id = add_vendor("cisco")
        add_device("Router", "RV340", "1.0.3", vendor_id)
        device_id = device_exists("Router", "RV340")[0]

        add_vulnerability("CVE-2024-1234", 9.8, "Buffer overflow", "CRITICAL", "2024-01-15", device_id)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM Vulnerability WHERE cve_id = %s", ("CVE-2024-1234",))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        self.assertIsNotNone(result)

    def test_add_vulnerability_valeurs_correctes(self):
        """All fields must be stored correctly in the database"""
        vendor_id = add_vendor("cisco")
        add_device("Router", "RV340", "1.0.3", vendor_id)
        device_id = device_exists("Router", "RV340")[0]

        add_vulnerability("CVE-2024-1234", 9.8, "Buffer overflow", "CRITICAL", "2024-01-15", device_id)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT cve_id, cvss_score, description, severity FROM Vulnerability WHERE cve_id = %s",
                       ("CVE-2024-1234",))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        self.assertEqual(result[0], "CVE-2024-1234")
        self.assertEqual(float(result[1]), 9.8)
        self.assertEqual(result[2], "Buffer overflow")
        self.assertEqual(result[3], "CRITICAL")

    def test_add_vulnerability_lie_au_device(self):
        """Vulnerability must be linked to the device in Exposes table"""
        vendor_id = add_vendor("cisco")
        add_device("Router", "RV340", "1.0.3", vendor_id)
        device_id = device_exists("Router", "RV340")[0]

        add_vulnerability("CVE-2024-1234", 9.8, "Buffer overflow", "CRITICAL", "2024-01-15", device_id)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM Vulnerability WHERE cve_id = %s", ("CVE-2024-1234",))
        vuln_id = cursor.fetchone()[0]
        cursor.execute("SELECT * FROM Exposes WHERE device_id = %s AND vulnerability_id = %s", (device_id, vuln_id))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        self.assertIsNotNone(result)

    def test_add_vulnerability_meme_cve_deux_devices(self):
        """Same CVE on two different devices must create only one Vulnerability but two Exposes"""
        vendor_id = add_vendor("cisco")
        add_device("Router", "RV340", "1.0.3", vendor_id)
        add_device("Switch", "SG300", "2.0.0", vendor_id)
        device_id_1 = device_exists("Router", "RV340")[0]
        device_id_2 = device_exists("Switch", "SG300")[0]

        add_vulnerability("CVE-2024-1234", 9.8, "Buffer overflow", "CRITICAL", "2024-01-15", device_id_1)
        add_vulnerability("CVE-2024-1234", 9.8, "Buffer overflow", "CRITICAL", "2024-01-15", device_id_2)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM Vulnerability WHERE cve_id = %s", ("CVE-2024-1234",))
        vuln_count = cursor.fetchone()[0]
        cursor.execute("SELECT id FROM Vulnerability WHERE cve_id = %s", ("CVE-2024-1234",))
        vuln_id = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM Exposes WHERE vulnerability_id = %s", (vuln_id,))
        exposes_count = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        self.assertEqual(vuln_count, 1)  # only one CVE entry
        self.assertEqual(exposes_count, 2)  # but linked to two devices

    def test_add_vulnerability_cvss_null(self):
        """Vulnerability with NULL cvss must be inserted without error"""
        vendor_id = add_vendor("cisco")
        add_device("Router", "RV340", "1.0.3", vendor_id)
        device_id = device_exists("Router", "RV340")[0]

        add_vulnerability("CVE-2024-5678", None, "Unknown severity", None, "2024-01-15", device_id)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM Vulnerability WHERE cve_id = %s", ("CVE-2024-5678",))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        self.assertIsNotNone(result)

    # =============================================
    # TESTS VULNERABILITY
    # =============================================

    def test_add_vulnerability_existe_en_bdd(self):
        """Vulnerability must be present in the database after insertion"""
        vendor_id = add_vendor("cisco")
        add_device("Router", "RV340", "1.0.3", vendor_id)
        device_id = device_exists("Router", "RV340")[0]

        add_vulnerability("CVE-2024-1234", 9.8, "Buffer overflow", "CRITICAL", "2024-01-15", device_id)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM Vulnerability WHERE cve_id = %s", ("CVE-2024-1234",))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        self.assertIsNotNone(result)

    def test_add_vulnerability_valeurs_correctes(self):
        """All fields must be stored correctly in the database"""
        vendor_id = add_vendor("cisco")
        add_device("Router", "RV340", "1.0.3", vendor_id)
        device_id = device_exists("Router", "RV340")[0]

        add_vulnerability("CVE-2024-1234", 9.8, "Buffer overflow", "CRITICAL", "2024-01-15", device_id)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT cve_id, cvss_score, description, severity FROM Vulnerability WHERE cve_id = %s",
                       ("CVE-2024-1234",))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        self.assertEqual(result[0], "CVE-2024-1234")
        self.assertEqual(float(result[1]), 9.8)
        self.assertEqual(result[2], "Buffer overflow")
        self.assertEqual(result[3], "CRITICAL")

    def test_add_vulnerability_lie_au_device(self):
        """Vulnerability must be linked to the device in Exposes table"""
        vendor_id = add_vendor("cisco")
        add_device("Router", "RV340", "1.0.3", vendor_id)
        device_id = device_exists("Router", "RV340")[0]

        add_vulnerability("CVE-2024-1234", 9.8, "Buffer overflow", "CRITICAL", "2024-01-15", device_id)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM Vulnerability WHERE cve_id = %s", ("CVE-2024-1234",))
        vuln_id = cursor.fetchone()[0]
        cursor.execute("SELECT * FROM Exposes WHERE device_id = %s AND vulnerability_id = %s", (device_id, vuln_id))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        self.assertIsNotNone(result)

    def test_add_vulnerability_meme_cve_deux_devices(self):
        """Same CVE on two different devices must create only one Vulnerability but two Exposes"""
        vendor_id = add_vendor("cisco")
        add_device("Router", "RV340", "1.0.3", vendor_id)
        add_device("Switch", "SG300", "2.0.0", vendor_id)
        device_id_1 = device_exists("Router", "RV340")[0]
        device_id_2 = device_exists("Switch", "SG300")[0]

        add_vulnerability("CVE-2024-1234", 9.8, "Buffer overflow", "CRITICAL", "2024-01-15", device_id_1)
        add_vulnerability("CVE-2024-1234", 9.8, "Buffer overflow", "CRITICAL", "2024-01-15", device_id_2)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM Vulnerability WHERE cve_id = %s", ("CVE-2024-1234",))
        vuln_count = cursor.fetchone()[0]
        cursor.execute("SELECT id FROM Vulnerability WHERE cve_id = %s", ("CVE-2024-1234",))
        vuln_id = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM Exposes WHERE vulnerability_id = %s", (vuln_id,))
        exposes_count = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        self.assertEqual(vuln_count, 1)  # only one CVE entry
        self.assertEqual(exposes_count, 2)  # but linked to two devices

    def test_add_vulnerability_cvss_null(self):
        """Vulnerability with NULL cvss must be inserted without error"""
        vendor_id = add_vendor("cisco")
        add_device("Router", "RV340", "1.0.3", vendor_id)
        device_id = device_exists("Router", "RV340")[0]

        add_vulnerability("CVE-2024-5678", None, "Unknown severity", None, "2024-01-15", device_id)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM Vulnerability WHERE cve_id = %s", ("CVE-2024-5678",))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        self.assertIsNotNone(result)

    # =============================================
    # TESTS EXPOSES
    # =============================================

    def test_add_exposes(self):
        """add_exposes must return None and the link must exist in the database"""
        vendor_id = add_vendor("cisco")
        add_device("Router", "RV340", "1.0.3", vendor_id)
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

        # Call the method
        result = add_exposes(device_id, vuln_id, "2024-06-01")

        # Verify the link exists in the database
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT device_id, vulnerability_id, detected_date FROM Exposes WHERE device_id = %s AND vulnerability_id = %s",
            (device_id, vuln_id)
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], device_id)
        self.assertEqual(row[1], vuln_id)
        self.assertEqual(str(row[2]), "2024-06-01")  # compare detected_date

    def test_add_exposes_doublon_interdit(self):
        """The composite primary key must reject duplicates"""
        vendor_id = add_vendor("cisco")
        add_device("Router", "RV340", "1.0.3", vendor_id)
        device_id = device_exists("Router", "RV340")[0]

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO Vulnerability (cve_id, cvss_score, description, severity, published_date) VALUES (%s,%s,%s,%s,%s)",
            ("CVE-2024-9999", 5.0, "XSS", "MEDIUM", "2024-05-01")
        )
        vuln_id = cursor.lastrowid
        conn.commit()
        cursor.close()
        conn.close()

        # First insert must succeed
        add_exposes(device_id, vuln_id, "2024-06-01")

        # Second insert with same ids must raise an exception
        with self.assertRaises(Exception):
            add_exposes(device_id, vuln_id, "2024-06-01")


if __name__ == "__main__":
    unittest.main(verbosity=2)
