#!/usr/bin/env python3
import math
import telnetlib
import json
from Crypto.Util.number import bytes_to_long, long_to_bytes


DEST = "0.0.0.0"


MESSAGES = [
    "We shall vote to excommunicate the student.",
    "Store your vote with the secret in the last message...",
    "...and that's to prevent tampering.",
    "And the only way this student will ever have freedom or peace, now or ever...",
    "...is in the end of this graded lab.",
    "I have served.",
    "I will be of service."
]


THE_HIGH_TABLE = [
    "kennyog",
    "neopt",
    "kientuong114",
    "dukeog",
    "mbackendal",
    "lahetz",
    "sveitch",
    "ffalzon",
    "lmarekova",
    "fguenther",
    "florian_tramer",
    "dennis",
    "ueli",
    "mia",
    "l0ssy_the_tr4pd00r_squ1rr3l",
    "spmerz",
    "r0gaway",
    "b0n3h"
]



msg_pow = []
num_participants = len(THE_HIGH_TABLE)
max_included = num_participants
used_exponent = 17


for msg in MESSAGES:
    tmp_msg = pow(bytes_to_long(msg.encode()), used_exponent)
    msg_pow.append(tmp_msg)

def most_frequent_element(arr):
    max_count = 0
    out = 0
    for i in range(len(arr)):
        ref = arr[i]
        count = 0
        for j in range(len(arr)):
            if arr[j] == ref and i != j:
                count += 1
        if count > max_count:
            max_count = count
            out = ref
    return out
    
def nth_root(num, n):    
    low, high = 0, num
    while low <= high:
        mid = (low + high) // 2
        power = mid**n
        if power < num:
            low = mid + 1
        elif power > num:
            high = mid - 1
        else:
            return mid
    return high 

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return abs(a)

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


# In this attack we have to present the votes of all participants of the HIGH TABLE to the adjunctor. The votes have to be encrypted with the public
# key of each participant (e = 17), and they must contain the shared secret.
# Since we know the plaintext of the first 7 messages sent to all participants and their corresponding ciphertexts, we can first compute the n used by
# each participant. Once we know the n's, we can use the 18 encryptions of the secret message that was sent to all pariticipants and the Chinese Remainder Theorem
# to compute the shared secret. Then we can fake and encrypt the votes for all participants, send them to the adjunctor and get to live another day....
while True:
    try:
        # Establish new connection
        tn = telnetlib.Telnet(DEST , 51001)

        # Request distribution of shared secret and encryption known messages
        request = {"command": "distribute_secret"}
        json_send(request)
        response = json_recv()
        enc_messages = response["outputs"]

        # We know the plaintext P_i of the first 7 messages from each person in the high table and we received the corresponding ciphertexts C_i. 
        # We know that C_i[name] = (P_i^17 mod n[name]) and therefore we know that P_i^17 - C_i[name] must be a multiple of n[name]
        # If we know take the GCD of (P_i^17 - C_i[name]) and (P_j^17 - C_j[name]) for i != j, we have a good change that it will give us n[name]
        # If we do not get the right n, one of the following steps will throw an exception and we start over until we calculated the right n 
        # for all names in the HIGH_TABLE. To increase our chances of selecting the right n's, we take the GCD of the differences of all possible 
        # message combinations, and assume that the correct n will be the most frequently occuring.
        n = []
        enc_sec_set = []
        for i in range(num_participants):
            candidate_set = []
            name = THE_HIGH_TABLE[i]
            diff1 = msg_pow[0] - response["outputs"][name][0]
            diff2 = msg_pow[1] - response["outputs"][name][1]
            diff3 = msg_pow[2] - response["outputs"][name][2]
            diff4 = msg_pow[3] - response["outputs"][name][3]
            diff5 = msg_pow[4] - response["outputs"][name][4]
            diff6 = msg_pow[5] - response["outputs"][name][5]
            diff7 = msg_pow[6] - response["outputs"][name][6]

            candidate_set.append(gcd(diff1, diff2))
            candidate_set.append(gcd(diff1, diff3))
            candidate_set.append(gcd(diff1, diff4))
            candidate_set.append(gcd(diff1, diff5))
            candidate_set.append(gcd(diff1, diff6))
            candidate_set.append(gcd(diff1, diff7))

            candidate_set.append(gcd(diff2, diff3))
            candidate_set.append(gcd(diff2, diff4))
            candidate_set.append(gcd(diff2, diff5))
            candidate_set.append(gcd(diff2, diff6))
            candidate_set.append(gcd(diff2, diff7))

            candidate_set.append(gcd(diff3, diff4))
            candidate_set.append(gcd(diff3, diff5))
            candidate_set.append(gcd(diff3, diff6))
            candidate_set.append(gcd(diff3, diff7))

            candidate_set.append(gcd(diff4, diff5))
            candidate_set.append(gcd(diff4, diff6))
            candidate_set.append(gcd(diff4, diff7))

            candidate_set.append(gcd(diff5, diff6))
            candidate_set.append(gcd(diff5, diff7))

            candidate_set.append(gcd(diff6, diff7))

            n_name = most_frequent_element(candidate_set)
            n.append(n_name)
            enc_sec_set.append(response["outputs"][name][-1])


        # The last encrypted message for all names in the HIGH_TABLE contains an encryption of the shared secret. We will use the n's we calculated in the last step
        # to calculate the secret, using the Chinese Remainder Theorem. The theorem states: 
        # Given pairwise coprime positive integers n1,n2,…,nk and arbitrary integers a_1,a_2,…,a_k, the system of simultaneous congruences
        #   x = a_1 (mod n1)
        #   x = a_2 (mod n2)
        #   ...
        #   x = a_k (mod nk)
        # has a solution, and the solution is unique modulo N = n1 * n2 * ... * nk.      
        # There is a general construction we are going to use to calculate the secret as follows:
        # (a_i is the encrypted shared secret of the i-th name in the HIGH_TABLE)

        # 1) Calculate N = n1 * n2 * ... * nk
        N = 1
        for i in range(max_included):
            N *= n[i]

        # 2) for each i=1..k, compute y_i = N / n_i
        # 3) for each i=1..k, compute z_i = y_i ^ (-1)  (mod n_i)
        # 4) The solution x is then sum( [a_i * y_i * z_i | i=1..k] ) % N
        x = 0
        for i in range(max_included):
            y_i = N // n[i]
            z_i = pow(y_i, -1, n[i])
            x += enc_sec_set[i] * y_i * z_i
        x_mod = x % N

        # The x we calculated is the shared secret raised to the power of 17.
        # The obtain the shared secret we simply have to take the 17-th root of x.
        secret_long = nth_root(x_mod, used_exponent)
        secret = long_to_bytes(secret_long).decode()
        print("sec: ", secret)


        # Let the people vote..! This is not strictly necessary but we cant call the adjudicator before we let the people vote
        # (Otherwise he would know that the votes aren't authentic :) )
        request = {"command": "vote"}
        json_send(request)
        response = json_recv()        
        votes = response["votes"]


        # We now know all the n[name], the used exponent = 17 and the shared secret. 
        # We can therefore simply craft the votes to not excommunicate us, encrypt them and send them to the adjudicator to obtain the flag
        my_votes = {}
        vote = json.dumps({"excommunicate": False, "secret": secret}).encode()

        for i in range(num_participants):
            enc_vote = pow(bytes_to_long(vote), used_exponent, n[i])
            my_votes[THE_HIGH_TABLE[i]] = enc_vote

        request = {"command": "adjudicator", "votes" : my_votes}
        json_send(request)

        response = json_recv()
        print(response["flag"])
        break
    except Exception as  e:
        # If anything goes wrong, we just start over...
        print(e)
        print("Next attempt...")
        


