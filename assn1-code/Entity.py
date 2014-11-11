#! /usr/bin/python3

from Database import *
from charm.toolbox.pairinggroup import PairingGroup,pc_element
from charm.schemes.pre_mg07 import *

from charm.core.engine.util import objectToBytes,bytesToObject
from charm.core.math.integer import integer, serialize, deserialize
import time


# Class for entities such as Hospitals, Doctors, Insurance and Health Clubs
class Entity:
    def __init__(self, ID, proxy, signK, signGroup, hess):
        self.ID =  ID
        self.sk = proxy.keygen(self.ID)         # private key
        self.signGroup = signGroup
        self.signK = bytesToObject(signK, self.signGroup)
        self.hess = hess

        #MD: Todo: Create/get signing key for the entity


        # public parameters of the proxy re-encryption
        self.pre = proxy.pre
        self.params = proxy.params
        self.group = proxy.group

    #MD: Todo: This should validate the signature and return True if it checks out, False if it doesnt
    # Should check the date too
    def verifySig(self, signerID, date, msg, signature):
        db = Database()
        rows = db.getSignPubKey("master")
        # for row in rows :
        mPK_bytes = bytes(rows[0][0], 'utf-8')              # bytes of the master public key
        mPK = bytesToObject(mPK_bytes, self.signGroup)  # de-serialize the key before usage
        # Now get the pubKey of the signerID
        rows = db.getSignPubKey(signerID)
        sPK_bytes = bytes(rows[0][0], 'utf-8')
        # print("Validating sig from: ", signerID, ": " , sPK_bytes, "\n")
        sPK = bytesToObject(sPK_bytes, self.signGroup)
        return(self.hess.verify(mPK, sPK, (msg, date), signature)) # True or False

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

        ###################
        #MD: Todo: Check signature of the data for each record that is being read
        # First need to make sure the sig is inserted below 
        ###################
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
                    signerID = row[2] # get the id of the signer

                    sig_bytes = bytes(row[3], 'utf-8') #MD: This has to change once we take the date into account!
                    signature = bytesToObject(sig_bytes, self.signGroup) # Got the actual signature
                    signdate = row[4] #Get the date of the signature (which is also signed by the same signature)
                    if self.verifySig(signerID, signdate, pt, signature): #check if the signature is valid
                        print("Verified record from ", signerID, ": ", pt, "\n")
                    else:
                        print("INVALID record from ", signerID, ": ", pt, "\n")
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

        ###################
        #MD: Todo: Add date to signature
        ######################
        # Get the mastser public key from the SignKeys table
        db = Database()
        rows = db.getSignPubKey("master")
        mPK_bytes = bytes(rows[0][0], 'utf-8')              # bytes of the master public key
        mPK = bytesToObject(mPK_bytes, self.signGroup)  # de-serialize the key before usage
        signature = objectToBytes(self.hess.sign(mPK, self.signK, msg), self.signGroup)
        
        # Serialise the ct for storage in MySql using appropriate charm API for each element type
        # Differentiate between the Integer element and the PairingGroup elements (Otherwise cannot seialise)
        # After serialisation, type is byte
        ctI = serialize(ct['C']['C'])               # type of ctI is Integer. Use serialise API
        del ct['C']['C']
        ctPg = objectToBytes(ct, self.group)       # type of ctPG is PairingGroup. Use objectToBytes API

        db.insertRecord(ID, ctI, ctPg, signature, "2012-01-01", self.ID)
        db.done()
