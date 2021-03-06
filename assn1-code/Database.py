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

    def getAuthorisedEntities(self, PatientID, HealthRecordType, date):
        statement = ("SELECT EntityID, DateStart, Signature FROM AuthorisedInsert WHERE HealthRecordType = %s AND PatientID= %s AND DateStart <= %s AND (DateEnd IS NULL OR DateEnd >= %s)")
        try:
            self.cursor.execute(statement, (HealthRecordType, PatientID, date, date,) )
            rows = self.cursor.fetchall()
            return rows # We return the result to the caller for further processing
        except mysql.connector.Error as err:
            print(err)

    def revokeAuthorisedEntity(self, PatientID, EntityID, HealthRecordType, DateEnd, Signature):
        statement = ("UPDATE AuthorisedInsert SET DateEnd = %s, Signature = %s WHERE HealthRecordType = %s AND PatientID = %s AND EntityID = %s")
        try:
            self.cursor.execute(statement, (DateEnd, Signature, HealthRecordType, PatientID, EntityID))
            self.cnx.commit()
        except mysql.connector.Error as err:
            print(err)

    #MD: This module should add an authorization for an EntityID (no DateEnd), and revoke the old one by settings DateEnd
    def insertAuthorisation(self, PatientID, EntityID, HealthRecordType, DateStart, Signature):
        # #First check if there is already an EntityID authorized to access this HealthRecordType for this PatientID
        # statement = ("SELECT EntityID FROM AuthorisedInsert WHERE HealthRecordType = %s AND PatientID = %s AND DateEnd IS NULL")
        # try:
        #     self.cursor.execute(statement, (HealthRecordType, PatientID) )
        #     # self.cnx.commit()
        #     rows = self.cursor.fetchall()
        #     if rows[0]:
        #         oldEntityID = rows[0][0] # Get the currently authorised entities
        #     else: oldEntityID = False
        # except mysql.connector.Error as err:
        #     print(err)

        #   Check the signature of the current tuple if it exists
        #       If it checks out, revoke access to this EntityID by setting the DateEnd to today and re-signing the new data
        # statement = ("UPDATE AuthorisedInsert SET DateEnd = %s, Signature = %s WHERE HealthRecordType = %s AND PatientID = %s AND EntityID = %s")

        #Create new tuple with newEntityID
        #   Check if it exists
        #       Generate newSignature
        #       Write new tuple to DB
        statement = ("INSERT INTO AuthorisedInsert (PatientID, EntityID, HealthRecordType, DateStart, Signature) VALUES (%s, %s, %s, %s, %s)")
        try:
            self.cursor.execute(statement, (PatientID, EntityID, HealthRecordType, DateStart, Signature) )
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
            PK_bytes = bytes(rows[0][0], 'utf-8')              # bytes of the first public key

            return PK_bytes # Return only the first hit as a byte array
        except mysql.connector.Error as err:
            print(err)


    def selectRecord(self, ID):
        statement = ("SELECT EncryptedDataI, EncryptedDataPG, SignerID, Signature, SignatureDate from HealthRecords where PatientID = %s")
        try:
            self.cursor.execute(statement, (ID,))
            rows = self.cursor.fetchall()
            return rows
        except mysql.connector.Error as err:
            print(err)


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

        # Delete all authorisations
        statement = ("Truncate table AuthorisedInsert")
        self.cursor.execute(statement)
        self.cnx.commit()

        # TODO: Probably want to reset all other tables as well


    def done(self):
        self.cursor.close()
        self.cnx.close()

# This only gets executed when calling the script directly, aka to test db connectivity
def main():
    db = Database()
    db.insertRecord("Alice", "in", "Wonderland")
    db.selectRecord("Alice")

if __name__ == "__main__": main()
