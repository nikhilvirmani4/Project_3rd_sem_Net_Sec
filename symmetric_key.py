from Crypto.Cipher import AES
import base64, os

from rsa import *
def send_ticket_msg(username1, username2, public_key1, public_key2):

    def generate_secret_key_for_AES_cipher():
        # AES key length must be either 16, 24, or 32 bytes long
        AES_key_length = 8 
        
        # this secret key will be used to create AES cipher for encryption/decryption
        secret_key = os.urandom(AES_key_length)
        # encode this secret key for storing safely in database
        encoded_secret_key = base64.b64encode(secret_key)
        return encoded_secret_key

# for key exchange we use the below mechanism


    kab=generate_secret_key_for_AES_cipher()
    print(kab)
    iv = os.urandom(16)
    
    str_to_encrypt= str(username1)+str(kab)+str(iv)
    print(len(str_to_encrypt))
    enc_msg_ticket,msg=get_encrypted_msg_2(public_key2, str_to_encrypt.encode())
    print(enc_msg_ticket)


    to_send_back_b= b"".join([username2.encode(), kab,iv,enc_msg_ticket])

    ### 256 bits + 3 other values

    print(len(to_send_back_b))
    print(to_send_back_b)
    
    to_send_back_encrypted,msg=get_encrypted_msg_2(public_key1, to_send_back_b)
    print(to_send_back_encrypted)

    return to_send_back_encrypted    
    ##################################
    # ticket=k2_public{client1, kab, iv}

    #server to client1
    #msg=k1_public{client-2, kab, iv, ticket}


def generate_secret_key():
        # AES key length must be either 16, 24, or 32 bytes long
        AES_key_length = 8 
        
        # this secret key will be used to create AES cipher for encryption/decryption
        secret_key = os.urandom(AES_key_length)
        # encode this secret key for storing safely in database
        encoded_secret_key = base64.b64encode(secret_key)
        return encoded_secret_key
