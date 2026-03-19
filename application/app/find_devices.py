## COMMENTAIRES A FAIRE EN ANGLAIS pour description generale
## Boucle recherche appareils

import json
import os
import websocket
from application.db.connection import get_connection
from dotenv import load_dotenv

# Configurations
load_dotenv()
HA_HOST = os.getenv("HA_HOST")
HA_URL = "ws://" + HA_HOST + "/api/websocket"
HA_TOKEN = os.getenv("HA_TOKEN")

def get_devices():
    ws = websocket.create_connection(HA_URL)

    # Authentification
    auth_msg = json.loads(ws.recv())
    if auth_msg['type'] == 'auth_required':
        ws.send(json.dumps({
            "type": "auth",
            "access_token": HA_TOKEN
        }))

        auth_result = json.loads(ws.recv())
        if auth_result['type'] != 'auth_ok':
            print("Authentication failed")
            return []

    # Request to list devices
    device_msg = {
        "id": 1,
        "type": "config/device_registry/list"
    }
    ws.send(json.dumps(device_msg))

    response = json.loads(ws.recv())
    devices = response.get('result', [])
    ws.close()

    for device in devices :
        entry = {
            "manufacturer": device.get('manufacturer') or "N/A",
            "model": device.get('model') or "N/A",
            "sw_version": device.get('sw_version') or "N/A",
            "name": device.get('name_by_user') or device.get('name') or "N/A",
        }

        connection = get_connection()
        cursor = connection.cursor() # for send object to database

        # Insert vendor data into VENDOR database
        cursor.execute("SELECT id FROM Vendor WHERE name_ha = %s", (entry['manufacturer'], ))
        existing_vendor = cursor.fetchone()

        if existing_vendor is None:
            cursor.execute("INSERT INTO Vendor (name_ha) values (%s)", (entry['manufacturer'], ))
            vendor_id = cursor.lastrowid
        else:
            vendor_id = existing_vendor[0]

        # Insert device data into DEVICE database
        cursor.execute("SELECT id FROM Device WHERE name = %s AND model = %s", (entry['name'], entry['model']))
        existing_device = cursor.fetchone()

        if existing_device is None:
            cursor.execute("INSERT INTO Device   (name, model,os_version, vendor_id) values (%s, %s, %s, %s)",
                           (entry['name'], entry['model'], entry['sw_version'], vendor_id))


        connection.commit()
        cursor.close()
        connection.close()

    return None
