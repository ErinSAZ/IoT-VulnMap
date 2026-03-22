## COMMENTAIRES A FAIRE EN ANGLAIS pour description generale
## Boucle recherche appareils

import json
import os
import websocket
from database import *
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

    for device in devices:
        entry = {
            "manufacturer": device.get('manufacturer') or "N/A",
            "model": device.get('model') or "N/A",
            "sw_version": device.get('sw_version') or "N/A",
            "name": device.get('name_by_user') or device.get('name') or "N/A",
        }

        # Insert vendor data into VENDOR database
        existing_vendor = vendor_exists(entry['manufacturer'])
        if existing_vendor is None:
            vendor_id = add_vendor(entry['manufacturer'])
        else:
            vendor_id = existing_vendor[0]

        # Insert device data into DEVICE database
        existing_device = device_exists(entry['name'], entry['model'])

        if existing_device is None:
            add_device(entry['name'], entry['model'], entry['sw_version'], vendor_id)

    return None
