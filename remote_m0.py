#!/usr/bin/env python3

import telnetlib
import json
from Crypto.Hash import SHA256



def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

DEST = "0.0.0.0"


# If the k value used when signing 2 seperate messages with DSA is the same, the secret key x can be easily calculated.
# By the construction of the DSA, if the k value is repeated then the r value of both signatures are the same, 
# which makes it easy to detect.
# The server allows us to contribute to the randomness used for the generation of k. We will therfore select
# some "randomness" to contribute, such that the k value is repeated after only few signatures. We will then
# compute the secret key x from the two signatures which will allow us to correctly sign the required message
# to obtain the flag from the server.

while True:
    try:
        # Establish connection
        tn = telnetlib.Telnet(DEST , 51000)

        # Request parameters used for signing
        request = {"command": "get_params"}
        json_send(request)
        response = json_recv()

        q = response["q"]
        p = response["p"]
        g = response["g"]

        # Request parameters used for generating k values
        request = {"command": "get_rand_params"}
        json_send(request)
        response = json_recv()

        rand_q = response["q"]
        rand_p = response["p"]
        rand_g = response["g"]

        # The randomness for the k value is generated using the elements of the cyclic group (mod rand_p), of order rand_p-1
        # Since rand_q is a divisor of rand_p-1, one can use ((rand_p-1) / rand_q) as an exponent for a generator of a subgroup
        # of size rand_q, which is what this server does. 
        # But we are allowed to contribute some "randomness" which gets multiplied with the exponent selected by the server.
        # We want to select this randomness in such a way that the subgroub generated for the random value k becomes as
        # small as possible.
        # Since we know that rand_p is prime and therefore odd, we also know that (rand_p-1) must be divisible by 2.
        # Therefore we set the randomness contributed to the inverse of the one selected by the server, multiplied with 
        # (rand_p-1) / 2 to generate the smallest possible subgroup for the function generating k.
        # This will ensure that we get two signatures with the same k value after only few signing requests.
        inv = pow( (rand_p-1) // rand_q,-1, rand_p)
        dest = (rand_p-1) // 2
        evil_multiplier = inv * dest

        request = {"command": "contribute_randomness", "random": evil_multiplier}
        json_send(request)
        response = json_recv()

        # get signature of first message and calculate hash of the message
        msg1 = "aa"
        msg1_bytes = bytes.fromhex(msg1)
        h1 = int.from_bytes(SHA256.new(msg1_bytes).digest()[:28], 'big')
        request = {"command": "sign", "message": msg1}
        json_send(request)
        response = json_recv()
        signature = bytes.fromhex(response["signature"])
        r1, s1 = int.from_bytes(signature[:28], 'big'), int.from_bytes(signature[28:], 'big')

        # Repeatedly query server to sign second message until a signature with the same r value as the first message had 
        # is received. The same r value indicates the the k value from the first message was reused to generate the new signature
        msg2 = "bb"
        msg2_bytes= bytes.fromhex(msg2)
        h2 = int.from_bytes(SHA256.new(msg2_bytes).digest()[:28], 'big')
        request = {"command": "sign", "message": msg2}

        i = 0
        while i < 1000:
            json_send(request)
            response = json_recv()
            signature = bytes.fromhex(response["signature"])
            r2, s2 = int.from_bytes(signature[:28], 'big'), int.from_bytes(signature[28:], 'big')
            i+=1
            if r2 == r1:
                break

        # From the two signatures with the repeated k value we can easily compute the secret key x with some basic modular arithmetic
        k = ( (pow((s1-s2), -1, q) * (h1 - h2)  ) % q )
        r_inv = pow(r1, -1, q)
        x = (((s1 * k) - h1) * r_inv) % q
        print("x: ", x)

        # With the secret x value, we can simply sign the required message and send it to the server to obtain the flag
        final_msg_bytes= b"Mellon!"
        final_hash = int.from_bytes(SHA256.new(final_msg_bytes).digest()[:28], 'big')

        r_forged = pow(g, k, p) % q
        k_inv = pow(k, -1, q)
        s_forged = (k_inv * (final_hash + x * r_forged)) % q
        forged_signature = r_forged.to_bytes(28, 'big') + s_forged.to_bytes(28, 'big')

        request = {"command": "flag", "signature": str(forged_signature.hex())}
        json_send(request)
        response = json_recv()
        print(response["flag"])
        break
        
    except Exception as e:
        # If anything goes wrong, start over... 
        #print(e)
        pass
