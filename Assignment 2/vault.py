#!/usr/bin/python

from __future__ import print_function
import sys
import os
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


class Signature:
    pvt_key = ''
    filename = ''
    BUF_SIZE = 65536
    hash = SHA256.new()
    RSA_BITS = 2048

    def __init__(self, pvt, file):
        self.pvt_key = pvt
        self.filename = file

    def hashFile(self, file):
        fd = os.open(file, os.O_RDONLY)
        while True:
            read_rv = os.read(fd, self.BUF_SIZE)
            if not read_rv:
                break
            else:
                self.hash.update(read_rv)
                #print(self.hash.hexdigest())
                #assert self.hash.hexdigest().upper() == ('F19630E34098A3498AA384EFA3E817F98DA382BEC862C51DA93E550A1B82CF19')
        return self.hash.digest()

    def signFile(self, hashed_file):
        fd = open(self.pvt_key, 'r')
        key = RSA.importKey(fd.read())
        #print key.exportKey(format='PEM')
        signature = key.sign(self.hash.digest(), '')
        #print(signature[0])
        #assert hex(signature[0]).rstrip('L') == ('0x8e9f3a50ce273afe4fdf905e9ca6542d80ddfba3fd95cc62e4d1e7a73fdf6f9b709f5763d66d7d6b962376e7bc4456652f85659fc3c4ac87e129cdf1070363f0535e10f876345af58e03edf7ef231f809949424ace6faeb0e8d2e9a7d9223d611cf4fbc7da531331dadd18cda0fa5ef84e475b074c1086389a23debe6c2eefb8')
        #print(hex(signature[0]).rstrip('L'))
        return hex(signature[0]).rstrip('L')

    def verifyFile(self, public, signature):
        s = open(signature, 'r')
        p = open(public, 'r')
        hashed = self.hashFile(self.filename)
        pub_key = RSA.importKey(p.read())
        #print(long(s.read(), 16))
        #s.seek(0)
        print(pub_key.verify(hashed, (long(s.read(), 16), None)))


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
    hashed = sign.hashFile(file_path)
    signature = sign.signFile(hashed)
    print(signature)
elif sys.argv[1] == '-v':
    pub_key = sys.argv[3]
    signature = sys.argv[4]
    sign = Signature(None, file_path)
    sign.verifyFile(pub_key, signature) #TODO: Return 0 if success or 1 if not...don't print bool
elif sys.argv[1] == '-e':
    secret_key = sys.argv[3]
    init_vector = sys.argv[4]
elif sys.argv[1] == '-d':
    secret_key = sys.argv[3]
    init_vector = sys.argv[4]
else:
    print("Error: Unknown Command!")

#TEST: #print(Signature.verifyFile(Signature.signFile(file_path, 'private.pem'), 'public.pem'))
