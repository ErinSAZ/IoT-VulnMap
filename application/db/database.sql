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
    os_version VARCHAR(64),
    vendor_id INTEGER,
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

