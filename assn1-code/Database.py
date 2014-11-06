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
            self.cursor = self.cnx.cursor()

            # Delete all rows from HealthRecords!!
            statement = ("Truncate table HealthRecords")
            self.cursor.execute(statement)
            self.cnx.commit()

        # TODO: Probably want to reset all other tables as well

        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("Something is wrong with your user name or password")
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("Database does not exists")
            else:
                print(err)

    def insertRecord(self, ID, ctI, ctPg):
        statement = (   "INSERT INTO HealthRecords"
                        "(PatientID, EncryptedDataI, EncryptedDataPG)"
                        "VALUES (%s, %s, %s)")


        self.cursor.execute(statement, (ID, ctI, ctPg) )
        self.cnx.commit()

    def selectRecord(self, ID):
        statement = "SELECT EncryptedDataI, EncryptedDataPG from HealthRecords where PatientID = %s"
        self.cursor.execute(statement, (ID,))
        rows = self.cursor.fetchall()
        return rows
        #for (EncryptedDataI, EncryptedDataPG) in self.cursor:
            #print (EncryptedDataI)
            #print (EncryptedDataPG)

    def done(self):
        self.cursor.close()
        self.cnx.close()

def main():
    db = Database()
    db.insertRecord("Alice", "in", "Wonderland")
    db.selectRecord("Alice")

if __name__ == "__main__": main()
