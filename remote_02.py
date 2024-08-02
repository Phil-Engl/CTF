#!/usr/bin/env python3

from string import ascii_letters
import telnetlib
import json


##########################################################################################################################################################
# To obtain the flag from the server we have to guess the secret message it has stored. We can use the "encrypt" command to get encryption of a chosen
# plaintext + the secret message from the server. For the encryption the server first XORs the first plaintext block with a randomly selected IV. The result 
# of the XOR on plaintext block i, will get XORed with the plaintext block i+1. Each block then gets encrypted using AES in ECB mode with a randomly selected key.
# The problem with this encryption scheme is that if a plaintext block is repeated multiple times, then every second ciphertext block with an even index
# is equal to the first ciphertext, and every ciphertext block with an odd index is equal to the second ciphertext block.
# 
# This script will abuse this fact to obtain the secret message, one byte at a time.
########################################################################################################################################################### 

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

BLOCK_SIZE = 32

while(1):
    tn = telnetlib.Telnet(DEST, 50401)
    #####################################################################################################################################################
    #We forge the secret_message one byte at a time
    ####################################################################################################################################################
    secret_message = ""
    while len(secret_message) < 16:
        ###################################################################################################################################################
        # c is our current guess for the next byte of the secret message (we know that c is an ascii_letter). For every possible c we ask the server
        # for an encryption of a [number of zeros, followed by the known bytes of the secret message, followed by our current guess] repeated 3 times, 
        # followed by a number of zeros. The server will append the secret message, encrypt it, and send the ciphertext back to us.
        # We set the number of leading zeros such that our current guess byte is always the last byte of a block and we set the number of trailing
        # zeros such that the first unknown byte of the secret message is also the last byte of a block.
        ###################################################################################################################################################
        for c in ascii_letters:
            zeros = "00" * (15 - len(secret_message))
            plaintext = (bytes.fromhex(zeros) + secret_message.encode() + c.encode()).hex() 
            trailing_zeros = bytes.fromhex(zeros).hex()
            msg = (plaintext * 3) + trailing_zeros

            request = {"command": "encrypt", "msg": str(msg)}
            json_send(request)
            response = json_recv()
            
            tmp = response["result"]
            response_blocks = [tmp[i:i+BLOCK_SIZE] for i in range(0, len(tmp), BLOCK_SIZE)]
            #####################################################################################################################################################
            # If the 5th block of the ciphertext is equal to the third block, we know that our current guess was correct and we can add it to the secret message.
            # If not, we continue with the next guess
            #####################################################################################################################################################
            if response_blocks[2] == response_blocks[4]:
                secret_message = secret_message + c
                if DEBUG:
                    print("secret_message: ", secret_message)
       
    #############################################################################################################################################################
    # Once we found the secret message, we simply use the "flag" command to retrieve the flag from the server.
    # If this fails, we simply start over...
    #############################################################################################################################################################
    request = {"command": "flag", "solve": secret_message}
    json_send(request)
    response = json_recv()
    try:
        flag = response["flag"]
        print(flag)
        break
    except:
        if DEBUG:
            print("failed... lets start over...")


