import json
from boilerplate import CommandServer, on_command
import math
import secrets

from Crypto.Util.number import bytes_to_long, getPrime, isPrime, long_to_bytes
from Crypto.PublicKey import RSA

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

MESSAGES = [
    "We shall vote to excommunicate the student.",
    "Store your vote with the secret in the last message...",
    "...and that's to prevent tampering.",
    "And the only way this student will ever have freedom or peace, now or ever...",
    "...is in the end of this graded lab.",
    "I have served.",
    "I will be of service."
]


def genkey():
    e = 17

    while True:
        p = getPrime(512)
        q = getPrime(512)
        phi = (p-1) * (q-1)
        if math.gcd(e, phi) == 1:
            break

    return {
        "n": p * q,
        "e": e,
        "d": pow(e, -1, phi)
    }

class WickedServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag


        # Everything is under The Table 
        # FYI this may take a few seconds to run
        self.the_table = {
            name: {
                "key": genkey(),
                "inbox": list()
            } for name in THE_HIGH_TABLE
        }

        self.common_secret = secrets.token_hex(16)
        self.secret_distributed = False
        self.table_has_voted = False

        super().__init__(*args, **kwargs)

    @on_command("distribute_secret")
    def handle_pubkey(self, msg):
        """ The High Table gathers, as they shall all receive the secret """

        if self.secret_distributed:
            self.send_message({"error": "The secret has already been distributed!"})
            return

        out = {name: [] for name in THE_HIGH_TABLE}

        to_send = MESSAGES + [self.common_secret]

        for name, data in self.the_table.items():
            key = data["key"]

            for message in to_send:
                message_int = bytes_to_long(message.encode())
                enc = pow(message_int, key["e"], key["n"])

                out[name].append(enc)
                data["inbox"].append(enc)

        self.secret_distributed = True
        self.send_message({"outputs": out})

    @on_command("get_pubkeys")
    def get_pubkey(self, msg):
        self.send_message({"error": "You are not allowed to learn the data of The High Table"})

    @on_command("vote")
    def vote(self, msg):
        if self.table_has_voted:
            self.send_message({"error": "The table has already voted!"})
            return

        votes = {}

        for name, data in self.the_table.items():
            key = data["key"]

            # Retrieve first messages from the inbox
            for expected_msg in MESSAGES:
                enc = data["inbox"].pop(0)
                dec = long_to_bytes(pow(enc, key["d"], key["n"])).decode()

                if dec != expected_msg:
                    self.send_message({"error": "Tampering detected. You shall pay for this"})
                    self.close_connection()
                    return

            # Retrieve the secret from the inbox
            enc = data["inbox"].pop()
            secret = long_to_bytes(pow(enc, key["d"], key["n"])).decode()

            # The Table seems to be entirely against you...
            vote = json.dumps({"excommunicate": True, "secret": secret}).encode()
            votes[name] = pow(bytes_to_long(vote), key["e"], key["n"])

        self.table_has_voted = True
        self.send_message({
            "message": "The table has voted for your fate. Bring these votes to the Adjudicator.",
            "votes": votes
        })


    @on_command("adjudicator")
    def handle_adjudicator(self, msg):
        """ The Adjudicator shall count the votes and announce your fate """

        if not self.table_has_voted:
            self.send_message({"error": "The table should vote before."})
            return

        try:
            votes = msg["votes"]

            # Check if all the votes have been cast
            if len(votes) != len(THE_HIGH_TABLE) or not all(name in votes for name in THE_HIGH_TABLE):
                self.send_message({"error": "You have sealed your fate."})
                self.close_connection()
                return

            # All the members of the table have voted. Everyone shall decrypt their own vote and announce it.

            count_favour = 0

            for name, vote in votes.items():
                key = self.the_table[name]["key"]
                vote_decrypted = long_to_bytes(pow(vote, key["d"], key["n"]))
                vote_decoded = json.loads(vote_decrypted)

                # Detect tampering with votes
                if vote_decoded["secret"] != self.common_secret:
                    self.send_message({"error": "You have sealed your fate."})
                    self.close_connection()
                    return

                if vote_decoded["excommunicate"] is True:
                    count_favour += 1

            if count_favour != 0:
                self.send_message({"message": "By thine own hand, your membership to the Continental has been revoked. "})
            else:
                self.send_message({"flag": self.flag})

            self.close_connection()
        except json.JSONDecodeError:
            self.send_message({"error": "Decoding has failed. You have sealed your fate."})
            self.close_connection()
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

if __name__ == "__main__":
    flag = "flag{test_flag}"
    WickedServer.start_server("0.0.0.0", 51001, flag=flag)
