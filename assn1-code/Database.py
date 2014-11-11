#! /usr/bin/python3

import mysql.connector
from mysql.connector import errorcode
import json
from charm.schemes.pksig import pksig_hess #for the signatures


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

        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("Something is wrong with your user name or password")
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("Database does not exists")
            else:
                print(err)

    def insertRecord(self, ID, ctI, ctPg, Signature, date, SignerID):
        statement = (   "INSERT INTO HealthRecords"
                        "(PatientID, EncryptedDataI, EncryptedDataPG, Signature, SignatureDate, SignerID)"
                        "VALUES (%s, %s, %s, %s, %s, %s)")
        try:
            self.cursor.execute(statement, (ID, ctI, ctPg, Signature, date, SignerID) )
            self.cnx.commit()
        except mysql.connector.Error as err:
            print(err)

    def insertSignKey(self, ID, pk):
        statement = (   "INSERT INTO SignKeys"
                        "(id, pubKey)"
                        "VALUES (%s, %s)" )
        try:
            self.cursor.execute(statement, (ID, pk) )
            self.cnx.commit()
        except mysql.connector.Error as err:
            print(err)
    
    # Returns objectToBytes() of the public key stored in the database for "ID"
    def getSignPubKey(self, ID):
        statement = ( "SELECT pubKey FROM SignKeys WHERE id = %s" )
        try:
            self.cursor.execute(statement, (ID,) )
            # self.cnx.commit()
            rows = self.cursor.fetchall()
            return rows
        except mysql.connector.Error as err:
            print(err)


    def selectRecord(self, ID):
        statement = ("SELECT EncryptedDataI, EncryptedDataPG, SignerID, Signature from HealthRecords where PatientID = %s")
        self.cursor.execute(statement, (ID,))
        rows = self.cursor.fetchall()
        return rows
        #for (EncryptedDataI, EncryptedDataPG) in self.cursor:
            #print (EncryptedDataI)
            #print (EncryptedDataPG)

    def reset(self):
        # Delete all rows from HealthRecords!!
        statement = ("Truncate table HealthRecords")
        self.cursor.execute(statement)
        self.cnx.commit()

        # Delete every public key, since we need to generate new ones on each run
        # Possible solution: Make the master key persistent somewhere
        statement = ("Truncate table SignKeys")
        self.cursor.execute(statement)
        self.cnx.commit()

        # TODO: Probably want to reset all other tables as well


    def done(self):
        self.cursor.close()
        self.cnx.close()

def main():
    db = Database()
    db.insertRecord("Alice", "in", "Wonderland")
    db.selectRecord("Alice")

if __name__ == "__main__": main()
