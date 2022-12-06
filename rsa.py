from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


# function to generate rsa public, pvt pair
# store the pvt key in client side only, and add the public key to the keys folder, send path of public key
def public_private_key(id):
    key = RSA.generate(2048)
    private_key = key.export_key()

    public_key = key.publickey().export_key()
    # print(public_key)
    public_key_file_path = f'keys/{id}public.pem'
    file_out = open(public_key_file_path, "wb")
    file_out.write(public_key)
    file_out.close()

    return public_key_file_path, private_key, key
  

# encrypt with public key
def get_encrypted_msg(public_key):
    pub_key = RSA.import_key(open(public_key).read())
        # generate random nonce
    nonce = get_random_bytes(16)

    print(f"randomly generated nonce {nonce}")
    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(pub_key)
    enc_nonce = cipher_rsa.encrypt(nonce)
    return enc_nonce, nonce

#encrypt msg with pubic key
def get_encrypted_msg_2(public_key,msg):
    pub_key = RSA.import_key(open(public_key).read())
        # generate random nonce
    nonce = get_random_bytes(2)

    print(f"randomly generated nonce {nonce}")
    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(pub_key)
    enc_nonce = cipher_rsa.encrypt(msg)
    #RSA is only able to encrypt data to a maximum amount equal to your key size (2048 bits = 256 bytes), minus any padding and header data (11 bytes for PKCS#1 v1.5 padding).

    return enc_nonce, msg