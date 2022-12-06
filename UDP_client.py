import socket

from rsa import *
from Util import *
from hash_key import *
from symmetric_key import *

# server address is stored here
serverAddressPort = ("127.0.0.1", 20001)
bufferSize = 1024

# Create a UDP socket at client side
UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# 1st comm
#######################
# Client is on, enter username after #
username = input("Enter your user name, followed by # :")
# generate rsa_key and share the public key path with server
# call function from rsa.py
public_key, private_key, key = public_private_key(username)

path_for_public_key = username + "," + public_key
UDPClientSocket.sendto(path_for_public_key.encode(), serverAddressPort)

# receive the encrypted nonce from the server, for auth
nonce_for_auth = UDPClientSocket.recvfrom(bufferSize)
nonce_for_auth = nonce_for_auth[0]
#print(f"nonce for auth {nonce_for_auth}")
#######################









# client side task
# decrypt the nonce, using pvt key of client
cipher_rsa = PKCS1_OAEP.new(key)
# print(f"cipher_rsa {cipher_rsa}")
decrypted_nonce = cipher_rsa.decrypt(nonce_for_auth)
print(f"decrypted_nonce for auth {decrypted_nonce}")












#2nd comm
##########################
#send to server auth msg, having the decrypted nonce
decrypted_nonce_auth = 'AUTH,' + str(decrypted_nonce)
print("Decrypted message: ", decrypted_nonce)
UDPClientSocket.sendto(decrypted_nonce_auth.encode(), serverAddressPort)


# post auth,msg received has list of clients with state, idle or busy
msgFromServer = UDPClientSocket.recvfrom(bufferSize)
msg1 = "Message from Server {}".format(msgFromServer[0].decode())
print(msg1)
#########################










# split received input and extract the dictionary
text, dict_from_server = msgFromServer[0].decode().split('!')
print(dict_from_server)

# get number of idle counts from get_count function in utils
no_of_idle_count = get_count(dict_from_server)










# if only the user who entered is idle, means no one is available to talk
# go to listen mode, wait for msg from other user
if (no_of_idle_count == 1):
    while True:

        #  msg received from client
        ###########################
        msgFromServer = UDPClientSocket.recvfrom(bufferSize)
        msg1 = "Message from {} - {}".format(
            msgFromServer[1], msgFromServer[0].decode())
        

        # decryption
        #key=generate_secret_key()
        #using key here, bcoz rsa had issues with ticket size
        ##RSA is only able to encrypt data to a maximum amount equal to your key size (2048 bits = 256 bytes), minus any padding and header data (11 bytes for PKCS#1 v1.5 padding).
        key=b'2Z+ybwi22Eg='
        iv=b'\xd3\xf3\xe4\x02\xc7\x80\xea\x92\x13A\xf2U\x02>^d\x9fD\xba\x04\xf5NG\xf2^\xb9\xdc\x00\x86\x88w\xbf'
        print('\n')
        print("enc msg=",msgFromServer[0])
        dec_msg=decrypt(msgFromServer[0],key,iv)
        print("\n")
        print("decrypted msg=",dec_msg)


        # send reply msg to other user, encrypted
        print("\n")
        send_msg = input("msg to reply to {} -".format(msgFromServer[1]))
        key=b'2Z+ybwi22Eg='
        iv=b'\xd3\xf3\xe4\x02\xc7\x80\xea\x92\x13A\xf2U\x02>^d\x9fD\xba\x04\xf5NG\xf2^\xb9\xdc\x00\x86\x88w\xbf'
        enc_msg=encrypt(send_msg.encode(),key,iv)
        print(enc_msg)
        UDPClientSocket.sendto(enc_msg, msgFromServer[1])

        ###########################
        # wait for exit key word, if yes then break the communication
        if (send_msg == 'exit'):
            break









# if there are users available, dont go to listen mode, send the username we want to talk to from the list
else:

    #send msg to server, username
    ############################
    send_msg = input("enter user you want to talk to ")
    UDPClientSocket.sendto(send_msg.encode(), serverAddressPort)

    # msg received status and client ip and port
    msgFromServer_status = UDPClientSocket.recvfrom(bufferSize)
    msg2 = "Message from Server {}".format(msgFromServer_status[0].decode())
    msg_addr_server = msgFromServer_status[1]
    print("status=", msg2)

    msgFromServer_ip = UDPClientSocket.recvfrom(bufferSize)
    msg2 = "Message from Server {}".format(msgFromServer_ip[0].decode())
    msg_addr_server = msgFromServer_ip[1]
    print(msg2)
    ############################

    addr_client = msgFromServer_ip[0]
    print(addr_client.decode())


    #once we got the ip and status list, we can start independent comm between the two clients on UDP
    # talk to the client on the port and ip received
    while True:

        # all are on localhost, so ip is same as below
        udp_ip = "127.0.0.1"
        addr_client_decoded = addr_client.decode()
        # extract port number from address ('127.0.0.1',port)
        udp_port = addr_client_decoded[addr_client_decoded.index(',')+1:-1]
        # print(udp_port)
        udp_port_int = int(udp_port)

    #  send first msg to other user
    ##########################
        print("\n")
        send_msg = input(
            "msg to send to requested user {} port {} - ".format(udp_ip, udp_port_int))

        # encryption 
        #key=generate_secret_key()
        key=b'2Z+ybwi22Eg='
        iv=b'\xd3\xf3\xe4\x02\xc7\x80\xea\x92\x13A\xf2U\x02>^d\x9fD\xba\x04\xf5NG\xf2^\xb9\xdc\x00\x86\x88w\xbf'
        enc_msg=encrypt(send_msg.encode(),key,iv)
        print(enc_msg)
        UDPClientSocket.sendto(enc_msg, (udp_ip, udp_port_int))

    # 2. reply received from other client
        msgFromServer = UDPClientSocket.recvfrom(bufferSize)
        msg1 = "Message from {} - {} ".format(
            msgFromServer[1], msgFromServer[0].decode())

        # decryption
        #key=generate_secret_key()
        key=b'2Z+ybwi22Eg='
        iv=b'\xd3\xf3\xe4\x02\xc7\x80\xea\x92\x13A\xf2U\x02>^d\x9fD\xba\x04\xf5NG\xf2^\xb9\xdc\x00\x86\x88w\xbf'
        print("enc msg=",msgFromServer[0])
        dec_msg=decrypt(msgFromServer[0],key,iv)
        print("\n")
        print("decrypted msg=",dec_msg)

    ##########################
        #send_msg = input("if you want to end type exit ")
        if (send_msg == 'exit'):
            break

    UDPClientSocket.close()


