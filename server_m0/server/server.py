from random import randint
from boilerplate import CommandServer, on_command

from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

class DUAL_DL_DRBG():
    MODULUS_SIZE = 1024
    OUTPUT_SIZE = 128

    def __init__(self):
        rand_key = DSA.generate(self.MODULUS_SIZE)
        # This gives us parameters p, q, g for which the discrete logarithm problem is hard.
        # In particular, we get a 1024-bit p, and a 160-bit q!
        self.p, self.q, self.g = rand_key.p, rand_key.q, rand_key.g
        self.h = 0
        self.x = rand_key.x

    def add_client_rand(self, client_random):
        if client_random in [0, 1, self.p - 1]:
            raise ValueError("Bad Client Randomness!")

        # We need another generator for our super secure RNG
        e = (self.p - 1) // self.q
        # Use the randomness contribute from the client for extra security.
        e = (e * client_random) % self.p

        for _ in range(100):
            h = pow(randint(2, self.p), e, self.p)
            if h != 1:
                self.h = h
                break
        else:
            raise ValueError("Timeout, try different random value.")

    def randbytes(self) -> bytes:
        self.x = pow(self.g, self.x, self.p) % self.q
        r = pow(self.h, self.x, self.p)

        return r.to_bytes(self.MODULUS_SIZE // 8, 'big')[:self.OUTPUT_SIZE // 8]

    def randfunc(self, l: int) -> bytes:
        res = b""
        for _ in range(0, l, 16):
            res += self.randbytes()

        return res[:l]

class SigningServer(CommandServer):
    def __init__(self, flag: str, *args, **kwargs):
        self.flag = flag
        self.key = DSA.generate(2048)

        self.rng = DUAL_DL_DRBG()

        self.signer = None
        self.verifier = DSS.new(self.key, 'fips-186-3')
        super().__init__(*args, **kwargs)


    @on_command("get_params")
    def handle_get_params(self, _):
        self.send_message({"vfy_key": self.key.y, "g": self.key.g, "p": self.key.p, "q": self.key.q})

    @on_command("get_rand_params")
    def handle_get_rand_params(self, _):
        self.send_message({"g": self.rng.g, "p": self.rng.p, "q": self.rng.q, "h": self.rng.h})

    @on_command("contribute_randomness")
    def handle_contribute_randomness(self, msg):
        if self.signer != None:
            self.send_message({"error": "Randomness already contributed!"})
            return

        try:
            client_random = msg["random"]

            self.rng.add_client_rand(client_random)
            self.signer = DSS.new(self.key, 'fips-186-3', randfunc=self.rng.randfunc)
            self.send_message({"res": "ok"})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

    @on_command("sign")
    def handle_sign(self, msg):
        if self.signer == None:
            self.send_message({"error": "You need to first contribute randomness."})
            return

        try:
            message = bytes.fromhex(msg["message"])
            if message == b"Mellon!":
                raise ValueError("You shall not pass.")

            h = SHA256.new(message)
            signature = self.signer.sign(h)
            self.send_message({"signature": signature.hex()})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

    @on_command("flag")
    def handle_flag(self, msg):
        try:
            signature = bytes.fromhex(msg["signature"])

            h = SHA256.new(b"Mellon!")
            self.verifier.verify(h, signature)
            self.send_message({"flag": self.flag})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})
        self.close_connection()


if __name__ == "__main__":
    flag = "flag{test_flag}"
    SigningServer.start_server("0.0.0.0", 51000, flag=flag)
