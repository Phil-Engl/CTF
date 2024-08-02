#!/usr/bin/env python3

import telnetlib
import json
from string import ascii_letters

##################################################################################################################################################
# To obtain the flag from the server, we have to correctly guess the secret_message it has stored. If we use the "encrypt" command of the 
# server and provide a message, it will encrypt the (message + secret_message) and respond to us with the prduced ciphertext and the used IV.
# For the encryption it uses AES in CBC mode, with a randomly selected key and a randomly selected IV. 
# The problem is that the randomness it uses to select the IV is predictable.
# The IV it will use for the first encryption comes from a small set, and all IV's for the following encryptions are deterministic depending 
# on the first IV.
#
# The IV gets XORed onto the first plaintext block before it is encrypted.
# Therfore setting the first block of the plaintext equal to the iv, will always result in the same cipherblock (encryption of a zero-block).
# If we then always append the same message to the IV, it will always result in the same ciphertext message.
# This script will abuse this fact to obtain the secret message one byte at a time.
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



while(1):
    tn = telnetlib.Telnet(DEST, 50403)
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
    for i in range(3000):
        json_send(request)
        response = json_recv()
        following_ivs.append(response["iv"])

    zero_string = "00" * 31 
    zeros = bytes.fromhex(zero_string).hex()
    #############################################################################################################################
    # We continously establish a new connection and ask him to encrypt (first_iv + zeros). The 3rd block of the returned ciphertext then 
    # contains an encryption of (31*"00" + first byte of secret_message).
    # We do so until the server re-uses the IV he used in the first response. This will allow us to predict the next IVs used.
    ##############################################################################################################################
    while(1):
        tn = telnetlib.Telnet(DEST, 50403)
        request = {"command": "encrypt", "msg": first_iv + str(zeros)}
        json_send(request)
        response = json_recv()

        if response["iv"] == first_iv:
            encrypted_msg  = response["ctxt"][64:96]
            break
    ###################################################################################################################################
    # We reconstruct the secret message one byte at a time until we found all 32 bytes.
    ###################################################################################################################################
    secret_message = ""
    index_ivs = 0
    remaining = 31

    while remaining >= 0:
        ################################################################################################################################
        # c is our current guess for the next byte of the secret message. (we know the message only contains ascii letters).
        # For every possible c, we ask the server to encrypt a couple of zeros, followed by the already discovered bytes of the secret message,
        # followed by our current guess. We set the number of leading-zeros such that our guess gets encrypted as the last byte of the third block
        ################################################################################################################################
        for c in ascii_letters:
            zero_string = "00" * remaining 
            zeros = bytes.fromhex(zero_string).hex()
            request = {"command": "encrypt", "msg": following_ivs[index_ivs] + str(zeros) + str(secret_message.encode().hex()) + str(c.encode().hex())}
            index_ivs += 1
            json_send(request)
            response = json_recv()

            try:
                #####################################################################################################################################
                # If the third block of the obtained ciphertext is equal to the reference_block, we know that our current guess was correct and we can 
                # add it to the secret message.
                ######################################################################################################################################
                if response['ctxt'][64:96] == encrypted_msg:
                    secret_message = secret_message + c
                    if DEBUG:
                        print(secret_message)
                    remaining -= 1
                    #################################################################################################################################
                    # We then ask the server to encrypt a number of zeros for us to update our reference_block.
                    # We set the number of leading zeros such that the next unknown byte of the secret message is the last byte of the third block.
                    ##################################################################################################################################
                    zero_string = "00" * remaining
                    zeros = bytes.fromhex(zero_string).hex()
                    request = { "command": "encrypt", "msg": following_ivs[index_ivs] + str(zeros)}
                    index_ivs += 1
                    json_send(request)
                    response = json_recv()
                    encrypted_msg  = response["ctxt"][64:96]
                    break
            except:
                pass
    #################################################################################################################################################
    # Once we obtained all 32 bytes of the secret message, we simply use the "guess" command to obtain the flag from the server. If this fails,
    # we simply start over.
    #################################################################################################################################################
    request = {"command": "guess", "guess": secret_message}
    json_send(request)
    response = json_recv()
    try:
        flag = response["flag"]
        print(flag)
        break
    except:
        if DEBUG:
            print("failed... will start over...")


