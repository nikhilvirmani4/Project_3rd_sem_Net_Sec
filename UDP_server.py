import socket
from Util import *
from rsa import *
from symmetric_key import *

# username with ip mapping, username with status "idle" or "busy"
users_present_with_ip ={}
user_with_status = {}

# function to add username and ip
def add_user_ip(name, ip):
   users_present_with_ip[name] = ip

# function to add username and client status
def add_user_status(name, status):
    user_with_status[name] = status






##############################
# configure local ip and port numbers for UDP
localIP = "127.0.0.1"
localPort = 20001
bufferSize = 1024

# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
# Bind to address and ip
UDPServerSocket.bind((localIP, localPort))
print("UDP server up and listening")






# Listen for incoming datagrams
while (True):

    # 1. read the input from client
    rec_msg_from_client = UDPServerSocket.recvfrom(bufferSize)

    # udp has first msg as the byte message and second is the address of client
    message = rec_msg_from_client[0]
    address = rec_msg_from_client[1]

    # if msg starts with #, means it's for username auth
    if message.decode().startswith("#"):
        #############################
        msg_decoded = message.decode()
        user_name, public_key = msg_decoded.split(',')
        # user has sent his/her username and the path to public key file

        # add username and ip in dictionary
        add_user_ip(user_name[1:], address)
        # add username and status, make it idle, when user logs-in
        add_user_status(user_name[1:], 'idle')

        # get the public key from the path, for the client
        enc_nonce, nonce=get_encrypted_msg(public_key)
        UDPServerSocket.sendto(enc_nonce, address)
        ######################       

    # Authentication step here
    elif message.decode().startswith("AUTH"):
        ########################
        print("decrypted nonce from client",message.decode()[5:])

        # compare the nonce at server with the reply from client 
        if(str(message.decode()[5:])==str(nonce) ):
            print("matching nonce") 

        msg = "added your ip and username now find the list of users with status !" + \
        str(user_with_status)
        UDPServerSocket.sendto(msg.encode(), address)
        #########################

    
    # @ starting message is for the username which client wants to talk to
    elif message.decode().startswith("@"):
        #########################
        msg_decoded = message.decode()

        # make the client and the requested user as busy
        add_user_status(msg_decoded[1:], 'busy')
        add_user_status(user_name[1:], 'busy')

        # send status dictionary again, post updating the busy status for both
        msg = str(user_with_status)
        UDPServerSocket.sendto(msg.encode(), address)

        # find the ip of requested client, send back
        msg2 = str(users_present_with_ip.get(msg_decoded[1:]))
        #print(msg2)

        #before sending ip, send the ticket for symmetric key.
        id1="#"+msg_decoded[1:]
        id2="#"+user_name[1:]
        public_key_file_path_1 = f'keys/{id1}public.pem'
        public_key_file_path_2 = f'keys/{id2}public.pem'

        #received_msg= send_ticket_msg(msg_decoded[1:], user_name[1:],public_key_file_path_1,public_key_file_path_2 )
        ## server will send the above msg to client-1, from which the ticket will go to client-2

        #UDPServerSocket.sendto(msg2.encode(), address)

        UDPServerSocket.sendto(msg2.encode(), address)
        ##############################





