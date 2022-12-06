
from Crypto.Hash import SHA256
import hashlib
from Cryptodome.Cipher import AES
from Crypto.Random import get_random_bytes
import re


#encrypt the msg, using the session key and iv
def encrypt(msg, session_key_rec,iv):

    def hash_key(session_key):
    
        # get session key from user, the k-ab
        MD = session_key+iv  #computing hash with the key and initial vector  
        hash = bytes(hashlib.sha256(MD).hexdigest(), 'utf')
        print(hash)
        return hash
         
    def xor(var, key):
 
        return bytes(a ^ b for a, b in zip(var, key))


    hash_received=hash_key(session_key_rec)


    # ci is the xor of hash and the msg ci=pi xor bi
    ci=xor(hash_received,msg)
    return ci


#similar code for decryption
def decrypt(enc_msg, session_key_re,iv):
    def hash_key(session_key):
     
        
        MD = session_key+iv  #computing hash with the key and initial vector  
        hash = bytes(hashlib.sha256(MD).hexdigest(), 'utf')
        print(hash)
        return hash

    def xor(var, key):

        return bytes(a ^ b for a, b in zip(var, key))

    
    hash_received=hash_key(session_key_re)
    pi=xor(hash_received,enc_msg)
    # pi= bi xor ci
    return pi



