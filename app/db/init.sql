# Database schema for IoT_VulnMap
CREATE DATABASE IF NOT EXISTS IoT_VulnMap;
USE IoT_VulnMap;

# Drop existing tables if they exist
DROP TABLE IF EXISTS Exposes;
DROP TABLE IF EXISTS Device;
DROP TABLE IF EXISTS Vulnerability;
DROP TABLE IF EXISTS Products;
DROP TABLE IF EXISTS Vendor;

# Create tables
CREATE TABLE IF NOT EXISTS Vendor
(
    id      INTEGER PRIMARY KEY AUTO_INCREMENT,
    name_ha VARCHAR(64),
    name_vl VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS Products
(
    id        INTEGER PRIMARY KEY AUTO_INCREMENT,
    name_ha   VARCHAR(64),
    name_vl   VARCHAR(64),
    vendor_id INTEGER NULL,
    FOREIGN KEY (vendor_id) REFERENCES Vendor (id)
);

CREATE TABLE IF NOT EXISTS Vulnerability
(
    id             INTEGER PRIMARY KEY AUTO_INCREMENT,
    cve_id         VARCHAR(64),
    cvss_score     FLOAT,
    description    TEXT,
    severity       VARCHAR(16),
    published_date DATE
);

CREATE TABLE IF NOT EXISTS Device
(
    id               INTEGER PRIMARY KEY AUTO_INCREMENT,
    name             VARCHAR(64),
    firmware_version VARCHAR(64),
    vendor_id        INTEGER NULL,
    product_id       INTEGER NULL,
    is_auditable     BOOLEAN,
    FOREIGN KEY (vendor_id) REFERENCES Vendor (id),
    FOREIGN KEY (product_id) REFERENCES Products (id)
);

CREATE TABLE IF NOT EXISTS Exposes
(
    device_id        INTEGER,
    vulnerability_id INTEGER,
    detected_date    DATE,
    PRIMARY KEY (device_id, vulnerability_id),
    FOREIGN KEY (device_id) REFERENCES Device (id),
    FOREIGN KEY (vulnerability_id) REFERENCES Vulnerability (id)
);