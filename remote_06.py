#!/usr/bin/env python3

import secrets

import telnetlib
import json
from string import ascii_letters



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

tn = telnetlib.Telnet(DEST, 50405)

num_success = 0

zero_block = b"\x00" * 16


one = 1

one_b = one.to_bytes(4, "little")

test2 = one_b + ": don't forget that this is your secret AC login code.".encode() + b" " * 32


request = {
    "command": "register",
    "user": "Phil",
    "key": "ff"

    }

json_send(request)
response = json_recv()
print(response)



request = {
    "command": "backup",
    "user": "Phil",
    "ctxt": "ff"
    }

json_send(request)
response = json_recv()
print(response)


return

request = {
    "command": "list"
    }

json_send(request)
response = json_recv()
print(response)
found_hash = response["result"]



for i in range(10):
    test = f"{i}: don't forget that this is your secret AC login code.".encode() + b" " * 32
    tmp = test[:16]
    request = {
        #"command": "backup",
        #"user": "admin",
        #"ctxt": str(test.hex())
        "command": "check",
        "ctxt_start": "ff",
        "ctxt_hash": found_hash[0]
        }

    json_send(request)
    response = json_recv()
    print(response)




#for reps in range(40):
while num_success < 0:

    #tmp = secrets.randbelow(10000)
    #zero = 0
    test = f"{one}: don't forget that this is your secret AC login code.".encode() + b" " * 32
    
    
    #print(len(test))
    #print(len(test2))
    #print(tmp)

    request = {
        "command": "flag",
        "solve": str(test.hex())
        }

    json_send(request)
    response = json_recv()
    #print(response)

    try:
        response["error"] = "I don't like pudding."
        tn = telnetlib.Telnet(DEST, 50405)
    except:
        pass


    try:
        flag = response['flag']
        num_success = 1
    except:
        pass

    try:
        solved = response["result"]
        print("once...")
    #print("once...")
    except:
        pass




