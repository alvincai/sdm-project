#! /usr/bin/python3

import mysql.connector
from mysql.connector import errorcode
import json

class Database:
    # Try to connect to database (sdmAssn1) with predefined username (sdm) and passwd (password)

    config1 = {
        'user': 'sdm',
        'password': 'password',
        'host': '127.0.0.1',
        'database': 'sdmAssn1',
        'raise_on_warnings': True,
    }

    def __init__(self):
        try:
            self.cnx = mysql.connector.connect(**self.config1)
            #self.cnx = mysql.connector.connect(user='sdm', password='password',
            #                                host='127.0.0.1', database='sdmAssn1')
            self.cursor = self.cnx.cursor()
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("Something is wrong with your user name or password")
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("Database does not exists")
            else:
                print(err)

    def insertRecord(self, ID, data):
        statement = (   "INSERT INTO HealthRecords"
                        "(PatientID, EncryptedData)"
                        "VALUES (%s, %s)")


        self.cursor.execute(statement, (ID, json.dumps(data)) )
        cnx.commit()


    def done(self):
        self.cursor.close()
        self.cnx.close()

def main():
    db = Database()


if __name__ == "__main__": main()
