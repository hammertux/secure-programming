#!/usr/bin/python

from __future__ import print_function
import sys
import os
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import binascii
import base64


class Signature:
    pvt_key = ''
    filename = ''
    BUF_SIZE = 65536
    hash = SHA256.new()
    RSA_BITS = 2048

    def __init__(self, pvt, file):
        self.pvt_key = pvt
        self.filename = file

    def hashFile(self):
        fd = open(self.filename, 'r')
        self.hash.update(fd.read())
        #print(self.hash.hexdigest())
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

class Encryption:
    init_vector = ''
    filename = ''
    secret_key = ''
    padded = ''
    AES.block_size = 16

    def __init__(self, iv, file, key):
        self.filename = file
        self.init_vector = iv
        self.secret_key = SHA256.new(key).digest()


    def padPlain(self):
        fd = open(self.filename, 'rb')
        plain = fd.read()
        if len(plain) % 16 != 0:
            self.padded = plain + chr((AES.block_size - (len(plain) % AES.block_size))) * (AES.block_size - (len(plain) % AES.block_size))
        return self.padded

    def encrypt(self):
        cipher = AES.new(self.secret_key, AES.MODE_CBC, self.init_vector)
        encrypted = self.init_vector + cipher.encrypt(self.padPlain())
        return encrypted

    def decrypt(self, file):
        fd = open(file, 'rb')
        s = fd.read()
        self.init_vector = s[:AES.block_size]
        cipher = AES.new(self.secret_key, AES.MODE_CBC, self.init_vector)
        decrypted = cipher.decrypt(s[AES.block_size:])
        data = decrypted[:-ord(decrypted[-1:])]
        return data


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
    if sign.verifyFile(pub_key, signature) == True :
        sys.exit(0)
    else:
        sys.exit(1)
elif sys.argv[1] == '-e':
    if sys.argv[4][:2] == '0x':
        init_vector = binascii.unhexlify(sys.argv[4][2:])
    else:
        init_vector = binascii.unhexlify(sys.argv[4])
    secret_key = sys.argv[3]
    enc = Encryption(init_vector, file_path, secret_key)
    print(enc.encrypt(), end="")
elif sys.argv[1] == '-d':
    if sys.argv[4][:2] == '0x':
        init_vector = binascii.unhexlify(sys.argv[4][2:])
    else:
        init_vector = binascii.unhexlify(sys.argv[4])
    secret_key = sys.argv[3]
    dec = Encryption(init_vector, file_path, secret_key)
    print(dec.decrypt(file_path), end="")
else:
    print("Error: Unknown Command!")
