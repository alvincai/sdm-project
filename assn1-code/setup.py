#! /usr/bin/python3

from Database import *
from Patient import *
from mysql.connector import errorcode
from charm.toolbox.pairinggroup import PairingGroup,pc_element
from charm.schemes.pre_mg07 import *
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.core.math.integer import integer, serialize, deserialize
import copy


# Class for entities such as Hospitals, Doctors, Insurance and Health Clubs
class Entity:
    def __init__(self, ID, proxy):
        self.ID =  ID
        self.sk = proxy.keygen(self.ID)         # private key

        # public parameters of the proxy re-encryption
        self.pre = proxy.pre
        self.params = proxy.params
        self.group = proxy.group

    # ciphertext here denotes to a '2nd-level' ciphertext which has been re-encrypted by the proxy.
    def dec(self, ciphertext):
        return self.pre.decryptSecondLevel(self.params, self.sk, ciphertext['IDsrc'], self.ID, ciphertext)
        # Regarding the 3rd input variable ciphertext['IDsrc'], we use this because ciphertext is a python dictionary.
        # The idsrc can be extracted directly from it and does not need to be explicity stated.


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
            print("No re-Encryption Key exists for this request")
            return



def main():
    # Setup keys and clean Database
    db1 = Database()
    db1.reset()
    proxy = Proxy()
    id1 = "Alice"
    id2 = "AIG Insurance"
    Alice = Patient(id1, proxy)
    AIGinsurance = Entity(id2, proxy)


    # Demonstrate Encryption, Storage and Retrieval
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

    # Look in Database to observe ciphertext
    print("General Health Records:")
    Alice.read("General")
    print("Medical Health Records:")
    Alice.read("Medical")

    print("Training Health Records:")
    Alice.read("training")



    #reEncryptionKey = Alice.genRencryptionK("General", AIGinsurance.ID, proxy)
    #ct2 = proxy.reEncrypt(Alice.General[0], AIGinsurance.ID, ct)
    ##print(ct2)
    #pt2 = AIGinsurance.dec(ct2)
    ##print(pt2)

    ##print (proxy.reEncryptionKeys)
    #Alice.removeRencryptionK("General", AIGinsurance.ID, proxy)
    #print (proxy.reEncryptionKeys)


    return

if __name__ == "__main__": main()
