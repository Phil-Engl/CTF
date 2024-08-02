#!/usr/bin/env python3

import telnetlib
import json

##################################################################################################################################################
# To obtain the flag from the server, we have to correctly guess which secret_message from the 6 possibilities the server selected 64 times. 
# If we use the "encrypt" command of the server and provide a message, it will encrypt the (message + secret_message) and respond to us with the 
# prduced ciphertext and the used IV.
# For the encryption it uses AES in CBC mode, with a randomly selected key and a randomly selected IV. 
# The problem is that the randomness it uses to select the IV is predictable.
# The IV it will use for the first encryption comes from a small set, and all IV's for the following encryptions are deterministic depending 
# on the first IV.
#
# The IV gets XORed onto the first plaintext block before it is encrypted.
# Therfore setting the first block of the plaintext equal to the iv, will always result in the same cipherblock (encryption of a zero-block).
# If we then always append the same message to the IV, it will always result in the same ciphertext message.
# This script will abuse this fact to check wich message the server selected.
##################################################################################################################################################

def xor(x: bytes, y: bytes):
    return bytes(a ^ b for a, b in zip(x, y))

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")
DEBUG = 0
DEST = "0.0.0.0"

MESSAGES = [
    "Pad to the left",
    "Unpad it back now y'all",
    "Game hop this time",
    "Real world, let's stomp!",
    "Random world, let's stomp!",
    "AES real smooth~"
]

MESSAGES = [
    msg.ljust(32) for msg in MESSAGES
]


while(1):    
    tn = telnetlib.Telnet(DEST, 50402)
    ###############################################################################################################################
    # We first ask the server to encypt an empty message for us and we record the first IV it used.
    ###############################################################################################################################
    request = {"command": "encrypt", "msg": ""}
    json_send(request)
    response = json_recv()
    first_iv = response["iv"]
    ###############################################################################################################################
    # We repeatedly send the same request to record the IVs that will follow the first one.
    ###############################################################################################################################
    following_ivs = []
    for i in range(64 * 6):
        json_send(request)
        response = json_recv()
        following_ivs.append(response["iv"])
    #############################################################################################################################
    # We continously establish a new connection and ask him to encrypt the first_iv. The 2nd block of the returned ciphertext then 
    # contains an encryption first 16 bytes of the secret message XORed with the encryption of a zero-block.
    # We do so until the server re-uses the IV he used in the first response. This will allow us to predict the next IVs used.
    ##############################################################################################################################
    while(1):
        tn = telnetlib.Telnet(DEST, 50402)
        request = {"command": "encrypt", "msg": first_iv}
        json_send(request)
        response = json_recv()
        if response["iv"] == first_iv:
            encrypted_msg  = response["ctxt"][32:64]
            break

    index_iv = 0
    num_success = 0
    while num_success < 64:
        ##########################################################################################################################
        # For each of the possible messages msg, we ask the server to encrypt (next_IV + msg) for us. That way the first 16 bytes
        # of the msg will get XORed with the encryption of a zero-block and then encrypted.
        ###########################################################################################################################
        for msg in MESSAGES:
            chosen_plaintext = bytes.fromhex(following_ivs[index_iv]) + msg.encode()
            index_iv += 1
            request = {"command": "encrypt", "msg": chosen_plaintext.hex()}
            json_send(request)
            response = json_recv()
            ########################################################################################################################
            # If the second block of the recieved ciphertext is the same as our reference block, we know that the secret message of 
            # the server is the msg we just used in our request.
            ########################################################################################################################
            if response["ctxt"][32:64] == encrypted_msg:
                try:
                    request = {"command": "guess", "guess": msg}
                    json_send(request)
                    response = json_recv()
                    if response["result"] != "error":
                        num_success += 1
                        #################################################################################################################
                        # If we sucessfully obtained the flag, we update our reference block as before and start with the next iteration.
                        #################################################################################################################
                        request = {"command": "encrypt", "msg": following_ivs[index_iv]}
                        json_send(request)
                        response = json_recv()
                        encrypted_msg  = response["ctxt"][32:64]
                        index_iv += 1
                except:
                    pass    
    ###########################################################################################################################################
    # Once we guessed the secret message of the server correctly 64 times, we can simply use the "flag" command to get the flag from the server.
    # If this fails, we simply start over.
    ############################################################################################################################################
    request = {"command": "flag"}
    json_send(request)
    response = json_recv()
    try:
        flag = response["flag"]
        print(flag)
        break
    except:
        if DEBUG:
            print("failed... will start over...")

