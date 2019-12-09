from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
import argparse
import os
import json
from base64 import b64decode

def verify_client_signature(pub_key, username, hmac_message, signature):
        # SSL_DIR = os.environ['SSL_DIR']
        # CLIENT_PUB_KEY_SUBSTRING = '_public.pem'
        # key_name = SSL_DIR + username + CLIENT_PUB_KEY_SUBSTRING

        # with open(key_name, "r") as pub_key_file:
        #     pub_key = RSA.importKey(pub_key_file.read())

        # RECEIVE PUBLIC KEY FROM SERVER
        pub_key = RSA.importKey(pub_key)

        encoded_hmac = hmac_message.encode()
        hashed_hmac = SHA256.new()
        hashed_hmac.update(encoded_hmac)

        verifier = PKCS1_PSS.new(pub_key)
        try:
            verifier.verify(hashed_hmac, signature)
            print(True)
            # return "Good"
        except:
            print(False)
            # return "Bad"


parser = argparse.ArgumentParser(prog='verify_signature', description="verify a signature",
                                    usage="verify_signature config_file")
parser.add_argument('config', type=str)

if __name__ == '__main__':
    args = parser.parse_args()
    config_file = args.config
    with open(config_file, "r") as conf:
        config = json.loads(conf.read())
    
    verify_client_signature(b64decode(config['publicKey']), config['username'], config['hmac'], config['signature'])
