"""
This module connects to Home Assistant via WebSocket and retrieves the list of registered devices.
Retrieved devices are then stored in the database along with their vendor and product information.
"""

import json
import os

import websocket
from dotenv import load_dotenv

from database import add_device, add_product, add_vendor, device_exists, product_exists, vendor_exists

# Home Assistant configuration
load_dotenv()
HA_HOST = os.getenv("HA_HOST")
HA_URL = "ws://" + HA_HOST + "/api/websocket"
HA_TOKEN = os.getenv("HA_TOKEN")


def get_devices():
    """
    Gets the list of registered devices from a Home Assistant instance and stores them in the database.
    """
    ws = websocket.create_connection(HA_URL)

    # Authenticate with Home Assistant
    auth_msg = json.loads(ws.recv())
    if auth_msg['type'] == 'auth_required':
        ws.send(json.dumps({
            "type": "auth",
            "access_token": HA_TOKEN
        }))

        auth_result = json.loads(ws.recv())
        if auth_result['type'] != 'auth_ok':
            print("Authentication failed")
            return

    # Request the list of devices
    device_msg = {
        "id": 1,
        "type": "config/device_registry/list"
    }
    ws.send(json.dumps(device_msg))

    response = json.loads(ws.recv())
    devices = response.get('result', [])
    ws.close()

    # Extract and store vendor, product and device information for each retrieved device
    for device in devices:
        entry = {
            "manufacturer": device.get('manufacturer') or None,
            "model": device.get('model') or None,
            "sw_version": device.get('sw_version') or None,
            "name": device.get('name_by_user') or device.get('name') or None,
        }

        # Insert vendor into database if not already present
        vendor_id = None
        if entry['manufacturer'] is not None:
            existing_vendor = vendor_exists(entry['manufacturer'])
            if existing_vendor is None:
                vendor_id = add_vendor(entry['manufacturer'])
            else:
                vendor_id = existing_vendor[0]

        # Insert product into database if not already present
        product_id = None
        if entry['model'] is not None:
            existing_product = product_exists(entry['model'])
            if existing_product is None:
                product_id = add_product(entry['model'], vendor_id)
            else:
                product_id = existing_product[0]

        # Insert device into database if not already present
        existing_device = device_exists(entry['name'], entry['model'])
        if existing_device is None:
            add_device(entry['name'], vendor_id, product_id, entry['sw_version'])
