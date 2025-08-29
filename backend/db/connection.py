# connection.py
import pymysql

def get_db_connection():
    return pymysql.connect(
        host="localhost",
        port=3307,
        user="root",
        password="root123", 
        database="zta_security"
    )
