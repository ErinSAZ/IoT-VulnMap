USE IoT_VulnMap;

INSERT INTO Vendor (name_ha, name_vl) VALUES ('Apple', 'apple');
INSERT INTO Vendor (name_ha, name_vl) VALUES ('Google', 'google');
INSERT INTO Vendor (name_ha, name_vl) VALUES ('Netgear', 'netgear');
INSERT INTO Vendor (name_ha, name_vl) VALUES ('Dlink', 'dlink');

INSERT INTO Product (name_ha,name_vl, vendor_id) VALUES ('iPhone', 'iOS and iPadOS', 1);
INSERT INTO Product (name_ha,name_vl, vendor_id) VALUES ('Nest Mini', 'nest_mini_firmware', 2);
INSERT INTO Product (name_ha,name_vl, vendor_id) VALUES ('firmware','r7000_firmware', 3);
INSERT INTO Product (name_ha,name_vl, vendor_id) VALUES ('firmware','dir-605l_firmware', 4);

INSERT INTO Device (name,firmware_version,vendor_id,product_id,is_auditable)
VALUES ('iPhone 12', '26.3', 1, 1,1);
INSERT INTO Device (name,firmware_version,vendor_id,product_id,is_auditable)
VALUES ('Nest Mini', '1.56.356012', 2, 2,1);
INSERT INTO Device (name,firmware_version,vendor_id,product_id,is_auditable)
VALUES ('Netgear R7000', '1.0.11.116', 3, 3,1);
INSERT INTO Device (name,firmware_version,vendor_id,product_id,is_auditable)
VALUES ('Dlink DIR-605L', '1.10', 4, 4,1);