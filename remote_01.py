#!/usr/bin/env python3

import telnetlib
import json


#################################################################################################################
# For the encryption, the server uses AES in ECB mode to encrypt the counter and then XORs the result
# with the current plaintext block to produce a ciphertext block. 
# So basically the server uses the counter and AES as a key generator for OTP encryption.
# The problem is the way the counter is implemented, since it won't get increased if we use the "encrypt"
# command and provide a plaintext that is smaller then the blocklength.
# If we ask the server to encrypt 15 bytes of zeros for us, the returned ciphertext will be the encryption 
# of the current counter and the counter will not be increased.
################################################################################################################

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


DEST = "0.0.0.0"


zeros  = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
succ = 0
while not succ:
    ################################################################################################################################
    # Establish new connection to the server
    ################################################################################################################################
    tn = telnetlib.Telnet(DEST , 50400)
    ################################################################################################################################
    # We first ask the server to encrypt a 15byte block of zeros for us. The first 15 bytes of the resulting ciphertext will be the
    # encrytion of the current counter. The counter will not get increased
    ################################################################################################################################
    request = {"command": "encrypt", "msg": zeros}
    json_send(request)
    response = json_recv()
    init_counter_enc = response["result"]
    #################################################################################################################################
    # We then ask the server to encrypt the secret for us. Since the server adds some leading- and trailing-characters, the secret message
    # corresponding ciphertext will be 2 blocks long. The first block will be the XORed with the encryption of the same counter as in our
    # first request. The second block will be XORed with the incremented counter.
    #################################################################################################################################
    request = {"command": "encrypt_secret"}
    json_send(request)
    response = json_recv()
    secret_encrypted = response["result"]
    #################################################################################################################################
    # We then ask the server again for an encryption of 15 bytes of zeros. This will give us the the first 15 bytes of the encrytion 
    # of the incremented counter
    #################################################################################################################################
    request = {"command": "encrypt","msg": zeros}
    json_send(request)
    response = json_recv()
    inc_counter_enc = response["result"]
    ##################################################################################################################################
    # If we now XOR the ciphertext of the secret with the concatenation of the encryption of the counter and the incremented counter, 
    # we should obtain the secret message.
    # The only problem is that we only know 15 bytes of the initial counter. But since the server allows us to try 1000 times to solve
    # the challenge, and the last byte can only take one of 256 values, we can simply brute force it.
    # Since the secret message only occupies the first 8 bytes of the second block, we dont need to brute force the last byte of the
    # incremented counter.
    ##################################################################################################################################
    for i in range(256):
        curr_guess = bytes.fromhex(init_counter_enc) + i.to_bytes(1, 'big') + bytes.fromhex(inc_counter_enc)
        try:
            secret_decrypted = (xor( bytes.fromhex(secret_encrypted) , curr_guess)).decode()
            request = {"command": "flag", "solve": secret_decrypted[8:24]}
            json_send(request)
            response = json_recv()
        except:
            pass
        try:
            #########################################################################################################################
            # If the response of the server contain the flag, we know that our guess was correct and we can terminate
            #########################################################################################################################
            flag = response["flag"]
            print(flag)
            succ = 1
            break
        except:
            #print(response)
            pass
            
