#!/usr/bin/env python3

import telnetlib
import json

import secrets
from string import ascii_letters


##########################################################################################################################################
# To obtain the flag from the backup server, we have to get the secret_file stored by the "admin".
# We can get simply use the "get" command to get the secret_file from the backup server, assuming we can get the server to decrypt
# a chosen ciphertext to the file_ID of the secret_file. The server will decrypt the message with the key of the admin, but we get to 
# chose the IV it will use. Since the server uses AES in CBC mode, flipping one bit in the IV results in the same bit flipped
# in the first block of the plaintext.
#
# The response messages of the server, especially the error messagaes of the "get" function, provide us a padding oracle.
# This script abuses this oracle to forge a an evil_IV which can get the server to decypt a chosen chiphermessage block to a
# plaintext block of all 0s.
# If we then XOR the evil_IV with a chosen plaintext, the decryption of the chosen ciphertext will result in that chosen plaintext.
# We will use the list command to get a destination plaintext (the file ID of the secret_file), and then get the server to 
# decrypt a randomly chose ciphertext, to said destination plaintext and respond with the flag.
############################################################################################################################################


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


DEBUG = 1
DEST = "0.0.0.0"

tn = telnetlib.Telnet(DEST, 50404)
num_success = 0
goal = 40
not_found = 'File not found!'


while num_success < goal:
    
    # Send list request to server to obtain the File_IDs of all files stored on the server
    request = {"command": "list", "user": "admin"}
    json_send(request)
    response = json_recv()

    if DEBUG:
        print("File_IDs: ", response)

    # Randomly select a ciphertext to use
    chosen_ciphertext = secrets.token_bytes(16)

    # Loop through all File_IDs and forge an evil_IV for each
    for file_ID in response["result"]:
        evil_IV = b""

        # We forge an evil_IV one byte at a time until we have 16 bytes 
        while(len(evil_IV) < 16):
            if DEBUG:
                print("evil_IV", evil_IV.hex())

            len_pad = 15 - len(evil_IV)
            padding = (b"\x00" * len_pad)
            n_padding = b"\xff" + b"\x00" * (len_pad - 1)

            # Loop through all possible guesses to add to the evil_IV
            for i in range(256):
                guess = i.to_bytes(1, "big")

                request = { "command": "get", "user": "admin", "ctxt": str(evil_IV.hex() + guess.hex() + padding.hex() + chosen_ciphertext.hex()) }
                json_send(request)
                response = json_recv()
                error_01 = response['error']
                #########################################################################################################################################
                # If the response message contains an error telling us that the file was not found, we know that the server decrypted our ciphertext to a 
                # plaintext with a valid padding. This can either mean that our "guess" produces "01" in the plaintext, or it produces "00" (followed by
                # zero or more "00"s and one "01").
                #########################################################################################################################################
                if error_01 == not_found:
                    #####################################################################################################################################
                    # If we are guessing the last bit of the evil_IV, it can only result in an "File not found error" if our guess produced an "01".
                    # We can therefore add guess XOR "01" to the evil_IV, since this will then produce "00" in the plaintext.
                    #####################################################################################################################################
                    if len(evil_IV) == 15:
                        evil_IV = evil_IV + xor(guess, b"\x01")
                        if DEBUG:
                            print("CASE 1")
                    else:
                        request = { "command": "get", "user": "admin", "ctxt": str(evil_IV.hex() + guess.hex() + n_padding.hex() + chosen_ciphertext.hex()) }
                        json_send(request)
                        response = json_recv()
                        error_02 = response['error']
                        ####################################################################################################################################
                        # If flipping all bits in the byte after our guess still results in a valid padding, we know that our guess must have resulted in 
                        # a "01" in the plaintext. We can therefore add (guess XOR "01") to the evil_IV, since this will then produce "00" in the plaintext
                        ####################################################################################################################################
                        if error_02 == not_found:
                            evil_IV = evil_IV + xor(guess, b"\x01")
                            if  DEBUG:
                                print("CASE 2")
                        ###################################################################################################################################
                        # If flipping all bits in the byte after our guess results in an invalid padding, we know that our guess must have resulted in
                        # a "00" in the plaintext. We can therefore add our guess to the evil_IV   
                        ###################################################################################################################################
                        else:
                            evil_IV = evil_IV + guess #xor(guess, b"\x01")
                            if DEBUG:
                                print("CASE 3")
        #####################################################################################################################################################
        # We construct the most_evil_IV by XORing the evil_IV (which produces all 0s in the plaintext for our chosen chiphertext) with
        # "01" followed by the 15-byte file_ID. Using this most_evil_IV to decrypt our chosen ciphertext will result in a plaintext with
        # a valid padding, followed by the file_ID of the secret_file. We can therefore send this to the "get" function of the backup server
        # and it should respond with the secret file
        ######################################################################################################################################################
        most_evil_IV = xor(evil_IV,  b"\x01" + bytes.fromhex(file_ID))

        request = { "command": "get", "user": "admin", "ctxt": str(most_evil_IV.hex() + chosen_ciphertext.hex())}
        json_send(request)
        response = json_recv()
        try:
            # Here we use the secret file to "solve the challenge". after 40 successful solves, the server will respond with the flag.
            secret_file = response["result"]
            request = { "command": "flag", "solve": secret_file}
            json_send(request)
            response = json_recv()
            num_success += 1
            print(response)
        except:
            if DEBUG:
                print("failed... will try again...")
            pass


#{'flag': 'flag{th3_pr00f_1s_1n_th3_p4dd1ng4f89b7416f67fa55f4a0365fb32766f7}'}