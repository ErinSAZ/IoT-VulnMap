import mysql.connector

def get_connection():
    return mysql.connector.connect(
        host="localhost",
        port=3307,
        user="user",
        password="password",
        database="IoT_VulnMap"
    )