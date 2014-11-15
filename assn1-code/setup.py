from Database import *
from Patient import *
from Entity import *
from mysql.connector import errorcode
from charm.toolbox.pairinggroup import PairingGroup,pc_element
from charm.schemes.pre_mg07 import *
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.core.math.integer import integer, serialize, deserialize
import charm.schemes.pksig.pksig_waters as pksig_waters #for the signatures


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

# Generate Signing Keypair. Pass the waters object as we need to create the keys in the same context
#MD: I've put this in a function as we need to call it for every ID we have
def signKeyGen(ID, masterSK, masterPK, waters, db, group):
    sk = waters.keygen(masterPK, masterSK, ID) #generate keypair for this person
    return sk

def main():

    # Setup keys and clean Database
    db1 = Database()
    db1.reset()
    proxy = Proxy()
    signGroup = PairingGroup('SS512') #Possibly the same as for encryption
    waters = pksig_waters.WatersSig(signGroup)
    (masterPK, masterSK) = waters.setup(5) #master pub and priv keys for signing (other keys are deduced from the master secret key)

    # Insert the master public key to the db with SignKeys.id="master", it is needed for signing and verifying
    # masterSK (secret key) gets passed only to the signKeyGen function below
    # db1.insertSignKey("master", objectToBytes(masterPK, signGroup))

    # Create some identities (names). Do NOT use the same identity twice! It will destroy the signature scheme implementation.
    id1 = "Alice"
    id2 = "AIG Insurance"           # Insurance
    id3 = "Fitness First"           # Health Club
    id4 = "Catherina Ziekenhuis"    # Hospital
    id4 = "Madison Gurkha"          # Employer
    id5 = "Doctor Frankenstein"     # Doctor

    # Create keys for all id's and store the public part in the database under SignKeys.pubKey with the PatientID or EntityID in SignKeys.id
    id1_signK = signKeyGen(id1, masterSK, masterPK, waters, signGroup, db1)
    id2_signK = signKeyGen(id2, masterSK, masterPK, waters, signGroup, db1)
    id3_signK = signKeyGen(id3, masterSK, masterPK, waters, signGroup, db1)
    id4_signK = signKeyGen(id4, masterSK, masterPK, waters, signGroup, db1)
    id5_signK = signKeyGen(id5, masterSK, masterPK, waters, signGroup, db1)


    # Instantiate the patients and entities
    Alice = Patient(id1, proxy, id1_signK, signGroup, waters, masterPK)
    AIG = Entity(id2, proxy, id2_signK, signGroup, waters, masterPK)
    FitnessFirst = Entity(id3, proxy, id3_signK, signGroup, waters, masterPK)
    Ziekenhuis = Entity(id4, proxy, id4_signK, signGroup, waters, masterPK)
    Doctor = Entity(id5, proxy, id5_signK, signGroup, waters, masterPK)


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
    print("Patient reading her own health records:\n")
    print("\n\tGeneral Health Records:")
    Alice.read("General")
    print("\n\tMedical Health Records:")
    Alice.read("Medical")
    print("\n\tTraining Health Records:")
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

    # Authorise AIG to write to Alice's record
    print("\nAlice authorises Dr. Frankenstein to write to her Medical HealthRecord")
    Alice.authoriseEntity("Doctor Frankenstein", "Medical")
    print("\nDoctor Frankenstein stores data in Alice's Medical HealthRecord")
    Doctor.store("Alice", "Medical", "Patient reported diarhea on 01-November-2014")

    # Entity (Insurance) inserting data into Patient's record
    msg = "Estimated Time of Death: 11-November-2014"
    AIG.store("Alice", "Medical", msg)
    print("\nMedical Health Records after an (unauthorised) insert by AIG")
    Alice.read("Medical")

    #TODO: Change insurance company to VGZ
    print("\nAlice revokes access to Dr. Frankenstein (First we pause 1 second because time needs to pass...)")
    Alice.revokeAuthorisedEntity("Doctor Frankenstein", "Medical")

    time.sleep(1)

    Doctor.store("Alice", "Medical", "Patient died 02-November-2014")
    print("\nMedical Health Records after an (unauthorised) insert by Dr. F")
    Alice.read("Medical")

    # Entity (VGZ) inserting data into Alice's record
    # msg = "Alice is insured by VGZ as of today"
    # VGZ.store("Alice", "Medical", msg)
    # print("\nMedical Health Records after an (authorised) insert by VGZ")
    # Alice.read("Medical")

    #TODO: While VGZ is the insurance company, AIG should not be able to write anymore
    # msg = "Alice is a heavy smoker"
    # AIG.store("Alice", "Medical", msg)
    # print("\nMedical Health Records after an (illegal) insert by AIG")
    # Alice.read("Medical")

    return

if __name__ == "__main__": main()
