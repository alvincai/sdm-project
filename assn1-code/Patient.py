#! /usr/bin/python3

from Database import *
from mysql.connector import errorcode
from charm.toolbox.pairinggroup import PairingGroup,pc_element
from charm.schemes.pre_mg07 import *
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.core.math.integer import integer, serialize, deserialize

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
        # db.insertRecord(ID, ctI, ctPg)
        db.done()

    #MD: Todo: This should validate the signature and return True if it checks out, False if it doesnt
    # Should check the date too
    def verifySig(self, Signer, date):
        return 0

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
        #MD: Todo: Check signature of the data for each record that is being read
        #print(hess.verify(master_public_key, public_key, msg, signature))
        #####################
        # But get the master key first
        db = Database()
        rows = db.getSignPubKey("master")
        # for row in rows :
        mPK_bytes = bytes(rows[0][0], 'utf-8')              # bytes of the master public key
        mPK = bytesToObject(mPK_bytes, self.signGroup)  # de-serialize the key before usage

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

            # Now get the pubKey of the signerID
            db2 = Database()
            rows = db2.getSignPubKey(signerID)
            sPK_bytes = bytes(rows[0][0], 'utf-8')
            sPK = bytesToObject(sPK_bytes, self.signGroup)

            if self.hess.verify(mPK, sPK, pt, signature):
                print(pt, " - Validated data from ", signerID, "\n")
            else:
                print("Signature mismatch for: ", pt, "\n")
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

