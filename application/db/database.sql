USE IoT_VulnMap;

CREATE TABLE Vendor(
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    name_vl VARCHAR(64),
    name_ha VARCHAR(64)
);

CREATE TABLE Vulnerability (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    cve_id VARCHAR(64),
    cvss_score FLOAT,
    description TEXT,
    severity VARCHAR(16),
    published_date DATE
);

CREATE TABLE Device (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(64),
    model VARCHAR(64),
    firmware_version VARCHAR(64),
    vendor_id INTEGER,
    is_auditable BOOLEAN,
    FOREIGN KEY (vendor_id) REFERENCES Vendor(id)
);

CREATE TABLE Exposes (
    device_id INTEGER,
    vulnerability_id INTEGER,
    detected_date DATE,
    PRIMARY KEY (device_id, vulnerability_id),
    FOREIGN KEY (device_id) REFERENCES Device(id),
    FOREIGN KEY (vulnerability_id) REFERENCES Vulnerability(id)
);

CREATE TRIGGER update_audit_device_status
BEFORE INSERT ON Device
    FOR EACH ROW
BEGIN
    DECLARE vendor VARCHAR(64);

    # Search vendor id
    SELECT name_ha INTO vendor
    FROM Vendor
    WHERE id = NEW.vendor_id;

    # Check if model, firmware version, and vendor are 'N/A'
    IF NEW.model = 'N/A' OR NEW.firmware_version = 'N/A' OR vendor = 'N/A' THEN
        SET NEW.is_auditable = FALSE;
    ELSE
        SET NEW.is_auditable = TRUE;
    END IF;
END;

