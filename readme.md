#### Library we used the following

RSA
SHA256
hashlib
Cryptodome
socket
json


#### Steps to run the code

cd to the folder
- python3 UDP_server.py

- python3 UDP_client.py
	
	Here you will be asked to enter the username with #

	Server will respond with the nonce, which the client will decrypt and reply

	Server matches the nonce, to authenticate

	Client will send the user he/she wants to talk to, enter @clientname-2

	Server will send the ip address of the clientname-2

	Messages will be encrypted here, terminal will show the enc msg

	Other client will decrypt the msg, decrypted msg is shown in terminal

	Freshness part is endusres via counter and nonce

	to exit the chat, just enter "exit"

All the client steps are pretty verbose, terminal prompts will help guide you.

Let us know if you face any issues.

Code directory
hash_key.py - for the keyed hash encryption and decryptin
rsa.py - for the public/pvt key rsa
symmetric_key.py - for the key exchange via the ticket mechanism, as described in the doc
UDP_client.py - client side socket program
UDP_server.py - server side socket program
freshness.py- for msg freshness, and replay attack
Util.py -  basic utility functions


