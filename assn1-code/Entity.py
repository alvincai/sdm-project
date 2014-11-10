#! /usr/bin/python3

from Database import *
from charm.toolbox.pairinggroup import PairingGroup,pc_element
from charm.schemes.pre_mg07 import *
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.core.math.integer import integer, serialize, deserialize


# Class for entities such as Hospitals, Doctors, Insurance and Health Clubs
class Entity:
    def __init__(self, ID, proxy):
        self.ID =  ID
        self.sk = proxy.keygen(self.ID)         # private key

        # public parameters of the proxy re-encryption
        self.pre = proxy.pre
        self.params = proxy.params
        self.group = proxy.group


    # Decrypts Patient Data from Database
    # 1. Check if re-encryption key exists for the request
    # 1. Read MySql Database to obtain string object
    # 2. Re-construct Ciphertext by converting it to a byte object, then call Charm's deSerialisation API
    # 3. Ask Proxy to re-encrypt reconstructed ciphertext with Entities' key
    # 4. Pass level2 ciphertext to dec2() function to get plaintext
    def read(self, ID1, recordType, proxy):

        if recordType.lower() == "general":
            ID1 = ID1 + "General"
        elif recordType.lower() == "medical":
            ID1 = ID1 + "Medical"
        elif recordType.lower() == "training":
            ID1 = ID1 + "Training"
        else:
            print("Please enter the correct record type")
            return

        keystring = ID1 + ":" + self.ID
        if keystring in proxy.listRk():

            db = Database()
            rows = db.selectRecord(ID1)
            for row in rows :
                ctI_bytes = bytes(row[0], 'utf-8')              # Integer element of CT
                ctI_Reconstruct = deserialize(ctI_bytes)
                ctPg_bytes = bytes(row[1], 'utf-8')             # PairingGroup element of CT
                ctReconstruct = bytesToObject(ctPg_bytes, self.group)
                ctReconstruct['C']['C'] = ctI_Reconstruct       # Complete Ciphertext from Integer and Pairing Group element

                ct2 = proxy.reEncrypt(ID1, self.ID, ctReconstruct)   # Pass CT to proxy for re-encrytion
                if (ct2 != "false"):
                    pt = self.dec2(ct2)
                    print (pt)
            db.done()

        else:
            print("Sorry, no Re-Encryption Key exists for this request!")
            return


    # Decrypt 2nd level ciphertext with own secret key
    # ciphertext here denotes to a '2nd-level' ciphertext which has been re-encrypted by the proxy.
    def dec2(self, ciphertext):
        return self.pre.decryptSecondLevel(self.params, self.sk, ciphertext['IDsrc'], self.ID, ciphertext)
        # Regarding the 3rd input variable ciphertext['IDsrc'], we use this because ciphertext is a python dictionary.
        # The idsrc can be extracted directly from it and does not need to be explicity stated.



    # Encrypts the msg (of type recordType) and stores it in Patient ID's Database
    # TODO: Include signature !
    def store(self, ID, recordType, msg):
        if recordType.lower() == "general":
            ID = ID + "General"
        elif recordType.lower() == "medical":
            ID = ID + "Medical"
        elif recordType.lower() == "training":
            ID = ID + "Training"
        else:
            print("Please enter the correct record type")
            return
        ct = self.pre.encrypt(self.params, ID, msg)

        # Serialise the ct for storage in MySql using appropriate charm API for each element type
        # Differentiate between the Integer element and the PairingGroup elements (Otherwise cannot seialise)
        # After serialisation, type is byte
        db = Database()
        ctI = serialize(ct['C']['C'])               # type of ctI is Integer. Use serialise API
        del ct['C']['C']
        ctPg = objectToBytes(ct, self.group)       # type of ctPG is PairingGroup. Use objectToBytes API
        db.insertRecord(ID, ctI, ctPg)
        db.done()
