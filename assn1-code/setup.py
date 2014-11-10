#! /usr/bin/python3

from Database import *
from Patient import *
from Entity import *
from mysql.connector import errorcode
from charm.toolbox.pairinggroup import PairingGroup,pc_element
from charm.schemes.pre_mg07 import *
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.core.math.integer import integer, serialize, deserialize



class Proxy:
    def __init__(self):
        self.setup()
        self.reEncryptionKeys = dict()  #A dictionary of Re-Encryption Keys, stored at proxy

    def setup(self):
        self.group = PairingGroup('SS512', secparam=1024)
        self.pre = PreGA(self.group)
        (self.master_secret_key, self.params) = self.pre.setup()

    def keygen(self,ID):
        id_secret_key = self.pre.keyGen(self.master_secret_key, ID)
        return id_secret_key

    # This function stores the re-encryption key (provided by the Delegator, ID1)
    # to a dictionary of re-encryption keys, for future look-up.
    # note: ID1 should be the full ID string e.g. AliceGeneral
    def addKey(self, ID1, ID2, rk):
        keystring = ID1 + ":" + ID2
        self.reEncryptionKeys[keystring] = rk


    # This function performs re-encryption of first level CT encrypted for ID1
    # to second level CT encrypted for ID2
    # note: ID1 should be the full ID string e.g. AliceGeneral
    def reEncrypt(self, ID1, ID2, ciphertext):
        keystring = ID1 + ":" + ID2
        if keystring in self.reEncryptionKeys:
            rk = self.reEncryptionKeys[keystring]
            return self.pre.reEncrypt(self.params, ID1, rk, ciphertext)
        else:
            return "false"

    # List Re-Encryption Keys
    def listRk(self):
        return(self.reEncryptionKeys.keys())

def main():

    # Setup keys and clean Database
    db1 = Database()
    db1.reset()
    proxy = Proxy()
    id1 = "Alice"
    id2 = "AIG Insurance"           # Insurance
    id3 = "Fitness First"           # Health Club
    id4 = "Catherina Ziekenhuis"    # Hospital
    id4 = "Madison Gurkha"          # Employer
    id5 = "Doctor Frankenstein"     # Doctor
    Alice = Patient(id1, proxy)
    AIG = Entity(id2, proxy)
    FitnessFirst = Entity(id3, proxy)
    Ziekenhuis = Entity(id4, proxy)


    # Patient inserting (encrypted) information into her own Medical Record
    msg1 = "Blood Type A+"
    msg2 = "Height 1.75m"
    msg3 = "Weight 60 kg"
    msg4 = "Surgery to remove xxx on 16/05/2010"
    msg5 = "Yoga practice 1 hr on 24/10/2013"
    Alice.store("General", msg1)
    Alice.store("General", msg2)
    Alice.store("General", msg3)
    Alice.store("Medical", msg4)
    Alice.store("Training", msg5)


    # Patient can read her own Medical Records
    print("\nGeneral Health Records:")
    Alice.read("General")
    print("\nMedical Health Records:")
    Alice.read("Medical")
    print("\nTraining Health Records:")
    Alice.read("training")


    # Entity (Insurance) can read a Patient's records if assigned 'read' permission by patient
    reEncryptionKey = Alice.genRencryptionK("General", AIG.ID, proxy)
    print("\nRe-Encryption keys currently stored in proxy:")
    print(proxy.listRk())
    print("\nAIG tries to read General-type records of Alice:")
    AIG.read("Alice", "General", proxy)
    print("\nAIG tries to read Medical-type records of Alice:")
    AIG.read("Alice", "Medical", proxy)
    print("\nAIG tries to read Training-type records of Alice:")
    AIG.read("Alice", "Training", proxy)


    # Entity (Insurance) inserting data into Patient's record (Should not be allowed, but currently is)
    msgError = "This record should not be here"
    AIG.store("Alice", "Medical", msgError)
    print("\nMedical Health Records after an insert by AIG")
    Alice.read("Medical")

    return

if __name__ == "__main__": main()
