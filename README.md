sdm-project
===========

Assignment 1 of Secure Data Management Project
Implementing Cryptographic Access Control for Patient Health Records, to control both read and write access
Makes use of Charm functions:
    1. Proxy based re-encryption (Green)
    2. Identity based signatures (Waters)

To demo, open a python3 shell
>>> from setup import *
>>> proxy, Alice, AIG, FitnessFirst, Ziekenhuis, Doctor = setup()
