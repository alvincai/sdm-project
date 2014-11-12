#! /usr/bin/python3

from Database import *
from mysql.connector import errorcode
from charm.toolbox.pairinggroup import PairingGroup,pc_element
from charm.schemes.pre_mg07 import *
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.core.math.integer import integer, serialize, deserialize
import time

class Patient:
    def __init__(self, ID, proxy, signK, signGroup, hess):
        self.ID = ID
        #public parameters of the proxy re-encrpytion
        self.pre = proxy.pre
        self.params = proxy.params
        self.group = proxy.group

        self.signGroup = signGroup
        self.signK = bytesToObject(signK, self.signGroup)
        self.hess = hess

        # Three types of keys associated with General, Medical and Training type records
        # Each key is stored as a list in the structure [public ID, secret key]
        self.General = [ID + "General", proxy.keygen(ID + "General")]       # Age, blood type, birth date, weight
        self.Medical = [ID + "Medical", proxy.keygen(ID + "Medical")]       # medical service provider related
        self.Training = [ID + "Training", proxy.keygen(ID + "Training")]    # Training related


    # Encrypts the msg (of type recordType) and stores it in Database
    def store(self, recordType, msg):
        if recordType.lower() == "general":
            ID = self.General[0]
        elif recordType.lower() == "medical":
            ID = self.Medical[0]
        elif recordType.lower() == "training":
            ID = self.Training[0]
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

        ###################
        #MD: Todo: Add date to signature
        ######################
        # Get the mastser public key from the SignKeys table
        mPK_bytes = db.getSignPubKey("master")              # bytes of the master public key
        mPK = bytesToObject(mPK_bytes, self.signGroup)  # de-serialize the key before usage

        date = time.strftime("%Y-%m-%d %H:%M:%S")
        signature = objectToBytes(self.hess.sign(mPK, self.signK, (msg, date)), self.signGroup)

        db.insertRecord(ID, ctI, ctPg, signature, date, self.ID)
        db.done()

    #MD: Todo: Should check the date too
    def verifySig(self, signerID, date, msg, signature):
        db = Database()
        mPK_bytes = db.getSignPubKey("master")              # bytes of the master public key
        mPK = bytesToObject(mPK_bytes, self.signGroup)  # de-serialize the key before usage
        # Now get the pubKey of the signerID
        sPK_bytes = db.getSignPubKey(signerID)
        sPK = bytesToObject(sPK_bytes, self.signGroup)
        date = time.strftime("%Y-%m-%d %H:%M:%S")
        return(self.hess.verify(mPK, sPK, (msg, date), signature)) # True or False

    # Decrypts Data from Database of type "recordType"
    def read(self, recordType):
        if recordType.lower() == "general":
            ID = self.General[0]
        elif recordType.lower() == "medical":
            ID = self.Medical[0]
        elif recordType.lower() == "training":
            ID = self.Training[0]
        else:
            print("Please enter the correct record type")
            return

        # 1. Read MySql Database to obtain string object
        # 2. Re-construct Ciphertext by converting it to a byte object, then call Charm's deSerialisation API
        # 3. Pass reconstructed ciphertext to dec() function to get plaintext
        #####################
        #MD: Todo: Add date checking
        #####################
        db = Database()
        rows = db.selectRecord(ID) # Now fetch the ciphertexts and verify the signatures and print the result
        for row in rows :
            ctI_bytes = bytes(row[0], 'utf-8')              # Integer element of CT
            ctI_Reconstruct = deserialize(ctI_bytes)
            ctPg_bytes = bytes(row[1], 'utf-8')             # PairingGroup element of CT
            ctReconstruct = bytesToObject(ctPg_bytes, self.group)
            ctReconstruct['C']['C'] = ctI_Reconstruct       # Complete Ciphertext from Integer and Pairing Group element
            pt = self.dec(recordType, ctReconstruct) # Decrypt the Ciphertext
            signerID = row[2] # get the id of the signer
            sig_bytes = bytes(row[3], 'utf-8')
            signature = bytesToObject(sig_bytes, self.signGroup) # Got the actual signature
            signdate = row[4]

            if self.verifySig(signerID, signdate, pt, signature):
                # Signature is valid, now check if entity was authorised at this date
                # Dont check our own data since we know it's valid if the signature checks out (we are always allowed to write to our own HealthRecord)
                if signerID == self.ID:
                    print("Verified record from ", signerID, ": ", pt, "\n")
                else:
                    rows = db.getAuthorisedEntities(self.ID, recordType, signdate)
                    if rows:
                        for row in rows:
                            if signerID == row[0]:
                                print("Verified record from ", signerID, ": ", pt, "\n")
                            else:
                                print("INVALID record from ", signerID, ": ", pt, "\n")
                    else:
                        #There were no authorisations for this date
                        print("INVALID record from ", signerID, ": ", pt, "\n")
            else:
                print("INVALID signature from ", signerID, ": ", pt, "\n")

        db.done()

    #MD: Adds an authorisation for an entity to a patient for a specific HealthRecordType as of "today"
    def authoriseEntity(self, EntityID, HealthRecordType):
        db = Database()
        # Create the tuple and sign it
        mPK_bytes = db.getSignPubKey("master")              # bytes of the master public key
        mPK = bytesToObject(mPK_bytes, self.signGroup)  # de-serialize the key before usage
        date = time.strftime("%Y-%m-%d %H:%M:%S")
        signature = objectToBytes(self.hess.sign(mPK, self.signK, (self.ID, EntityID, HealthRecordType, date)), self.signGroup)
        db.insertAuthorisation(self.ID, EntityID, HealthRecordType, date, signature)
        db.done()

    #MD: A patient can revoke an entity access to parts of his/her healthrecord
    def revokeAuthorisedEntity(self, EntityID, HealthRecordType):
        # First check if this entity is authorised
        db = Database()
        rows = db.getAuthorisedEntities(self.ID, HealthRecordType, "2999-12-31 00:00:00") #Get all authorised entities that are authorised before the year 2999
        if rows:
            for row in rows:
                if EntityID == row[0]:
                    found = True
                    # Found the entity for this specific recordType. Check signature
                    DateStart = row[1]
                    signature = bytesToObject(bytes(row[2], 'utf-8'), self.signGroup)
                    if(self.verifySig(self.ID, DateStart, (self.ID, EntityID, HealthRecordType), signature)):
                        # Valid signature found, now revoke it by setting the DateEnd to today and re-signing
                        # First we need to wait 1 second otherwise the script is too fast!
                        time.sleep(1)
                        DateEnd = time.strftime("%Y-%m-%d %H:%M:%S")
                        mPK_bytes = db.getSignPubKey("master")              # bytes of the master public key
                        mPK = bytesToObject(mPK_bytes, self.signGroup)  # de-serialize the key before usage
                        signature = objectToBytes(self.hess.sign(mPK, self.signK, (self.ID, EntityID, HealthRecordType, DateEnd)), self.signGroup)
                        db.revokeAuthorisedEntity(self.ID, EntityID, HealthRecordType, DateEnd, signature)
                        print("Access for ", EntityID, " to write to ", HealthRecordType, " successfully revoked.")
                    else:
                        print("INVALID signature on authorisations")
            if found == False:
                print("Authorisation for ", EntityID, " to write to ", self.ID, "'s ", HealthRecordType, " data not found")
        else:
            print("Error: no authorisations found for ", self.ID, "'s ", HealthRecordType, " data!")
        db.done()


    # Each re-encryption key is for only one type of health record (recordType). The delegatee is ID2.
    # Proxy's re-encryption key should be generated by the Delegator (Patient) as it requires secret key input
    # After the Patient generates the re-encryption key, it is stored at the Proxy by calling Proxy.addKey
    def genRencryptionK(self, recordType, ID2, proxy):
        if recordType.lower() == "general":
            sk = self.General[1]
            ID = self.General[0]
        elif recordType.lower() == "medical":
            sk = self.Medical[1]
            ID = self.Medical[0]
        elif recordType.lower() == "training":
            sk = self.Training[1]
            ID = self.Training[0]
        else:
            print("Please enter the correct record type")
            return
        reEncryptionKey = self.pre.rkGen(self.params, sk, ID, ID2)
        proxy.addKey(ID, ID2, reEncryptionKey)  # store this key at the proxy


    # Remove the re-Encrpytion Key from the proxy for "recordType" and delegatee (ID2)
    def removeRencryptionK(self, recordType, ID2, proxy):
        if recordType.lower() == "general":
            ID = self.General[0]
        elif recordType.lower() == "medical":
            ID = self.Medical[0]
        elif recordType.lower() == "training":
            ID = self.Training[0]
        else:
            print("Please enter the correct record type")
            return

        keystring = ID + ":" + ID2
        if keystring in proxy.reEncryptionKeys:
            del proxy.reEncryptionKeys[keystring]
            print("Re-Encryption Key deleted")
        else:
            print("No such Re-Encryption Key exists")

    #called by read function
    def dec(self, recordType, ciphertext):
        if recordType.lower() == "general":
            sk = self.General[1]
            ID = self.General[0]
        elif recordType.lower() == "medical":
            sk = self.Medical[1]
            ID = self.Medical[0]
        elif recordType.lower() == "training":
            sk = self.Training[1]
            ID = self.Training[0]
        else:
            print("Please enter the correct record type")
            return

        return self.pre.decryptFirstLevel(self.params, sk, ciphertext, ID)
