#!/usr/bin/python

from __future__ import print_function
import sys
import os
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


class Signature:
    pvt_key = ''
    filename = ''
    hash = SHA256.new()
    RSA_BITS = 2048

    def __init__(self, pvt, file):
        self.pvt_key = pvt
        self.filename = file

    def hashFile(self):
        fd = open(self.filename, 'r')
        self.hash.update(fd.read())
        return self.hash.digest()

    def signFile(self, hashed_file):
        fd = open(self.pvt_key, 'r')
        key = RSA.importKey(fd.read())
        signature = key.sign(self.hash.digest(), '')
        return hex(signature[0]).rstrip('L')

    def verifyFile(self, public, signature):
        s = open(signature, 'r')
        p = open(public, 'r')
        hashed = self.hashFile()
        pub_key = RSA.importKey(p.read())
        return pub_key.verify(hashed, (long(s.read(), 16), None))








if len(sys.argv) not in (4,5):
    print("Error: Possible Usages:\n"
          "./vault.py -s <path_to_file> <path_to_private_key>\n"
          "./vault.py -v <path_to_file> <path_to_public_key> <path_to_signature>\n"
          "./vault.py -e <path_to_file> <secret_key> <iv>\n"
          "./vault.py -d <path_to_file> <secret_key> <iv>")

file_path = sys.argv[2]

if sys.argv[1] == '-s':
    pvt_key = sys.argv[3]
    sign = Signature(pvt_key, file_path)
    hashed = sign.hashFile()
    signature = sign.signFile(hashed)
    print(signature)
elif sys.argv[1] == '-v':
    pub_key = sys.argv[3]
    signature = sys.argv[4]
    sign = Signature(None, file_path)
    print(sign.verifyFile(pub_key, signature)) #TODO: Return 0 if success or 1 if not...don't print bool
elif sys.argv[1] == '-e':
    secret_key = sys.argv[3]
    init_vector = sys.argv[4]
elif sys.argv[1] == '-d':
    secret_key = sys.argv[3]
    init_vector = sys.argv[4]
else:
    print("Error: Unknown Command!")

#TEST: #print(Signature.verifyFile(Signature.signFile(file_path, 'private.pem'), 'public.pem'))
