def get_count(dict_status):
    import json

    json_acceptable_string = dict_status.replace("'", "\"")
    d = json.loads(json_acceptable_string)
    no_of_idle = 0
    for key, val in d.items():  
        if val == 'idle':
            no_of_idle = no_of_idle+1

    print(no_of_idle)
    return (no_of_idle)


from Crypto.Cipher import AES
import base64, os
def generate_secret_key_for_AES_cipher():
    # AES key length must be either 16, 24, or 32 bytes long
    AES_key_length = 16 # use larger value in production
    # generate a random secret key with the decided key length
    # this secret key will be used to create AES cipher for encryption/decryption
    secret_key = os.urandom(AES_key_length)
    # encode this secret key for storing safely in database
    encoded_secret_key = base64.b64encode(secret_key)
    return encoded_secret_key