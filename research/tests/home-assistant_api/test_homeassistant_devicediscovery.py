import os
import websocket
import json
from datetime import datetime
from dotenv import load_dotenv

###############################DESCRIPTION###################################
# This script connects to the Home Assistant WebSocket API, retrieves the list
# of all connected devices, and displays relevant information
# (model, firmware, brand) for each device. Then it saves this data in a
# JSON file for later use.
############################################################################

# Configurations
load_dotenv()
HA_HOST = os.getenv("HA_HOST")
HA_URL = "ws://" + HA_HOST + "/api/websocket"
HA_TOKEN = os.getenv("HA_TOKEN")

# Output file
JSON_OUTPUT = "ha_devices.json"


def get_ha_devices():
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

    # Extract data
    extracted = []
    for device in devices:
        entry = {
            "manufacturer": device.get('manufacturer') or "N/A",
            "model": device.get('model') or "N/A",
            "sw_version": device.get('sw_version') or "N/A",
            "name": device.get('name_by_user') or device.get('name') or "N/A",
        }
        extracted.append(entry)

    # Display results in a table
    print(f"{'manufacturer':<20} | {'model / object':<30} | {'sw_version':<15} | {'Name'}")
    print("-" * 90)
    for e in extracted:
        print(f"{e['manufacturer']:<20} | {e['model']:<30} | {e['sw_version']:<15} | {e['name']}")

    # Save results to JSON
    output = {
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total": len(extracted),
        "devices": extracted
    }

    with open(JSON_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"\n{len(extracted)} devices saved in '{JSON_OUTPUT}'")
    return extracted


if __name__ == "__main__":
    get_ha_devices()
