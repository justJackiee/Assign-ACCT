import requests
import json
import base64
import os
import time 
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

BASE_URL = "https://crypto-assignment.dangduongminhnhat2003.workers.dev"
USER_ID = "group-3"
ALGORITHM = "ecdh_3"

class SMCClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "x-user-id": USER_ID,
            "Content-Type": "application/json"
        })
        self.session_token = None
        self.aes_key = None
        
        # Identity Key Pair
        self.identity_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.identity_public_key = self.identity_private_key.public_key()

    def _safe_post(self, endpoint, payload):
        print(f"    [Wait] Sleeping 1.1s to respect rate limit...")
        time.sleep(1.1) 
        url = f"{BASE_URL}{endpoint}?userId={USER_ID}"
        return self.session.post(url, json=payload)

    def _get_public_key_json(self, pub_key):
        numbers = pub_key.public_numbers()
        return {
            "x": str(numbers.x),
            "y": str(numbers.y)
        }

    def _decode_signature(self, signature_bytes):
        r, s = asym_utils.decode_dss_signature(signature_bytes)
        return r, s

    def step_1_create_session(self):
        print(f"[*] Step 1: Creating session for {USER_ID}...")

        payload = {
            "algorithm": ALGORITHM,
            "curveParameters": {
                "p": "115792089210356248762697446949407573530086143415290314195533631308867097853951",
                "a": "-3",
                "b": "41058363725152142129326129780047268409114441015993725554835256314039467401291",
                "Gx": "48439561293906451759052585252797914202762949526041747995844080717082404635286",
                "Gy": "36134250956749795798585127919587881956611106672985015071877198253568414405109",
                "order": "115792089210356248762697446949407573529996955224135760342422259061068512044369"
            }
        }
        
        resp = self._safe_post("/session/create", payload)
        
        if resp.status_code != 200:
            raise Exception(f"Failed to create session: {resp.text}")
            
        data = resp.json()
        if not data.get("success"):
            raise Exception(f"Server error: {data}")

        self.session_token = data["sessionToken"]
        server_pub_json = data["serverPublicKey"]
        
        print(f"    [+] Session Token: {self.session_token[:20]}...")
        return server_pub_json

    def step_2_key_exchange(self, server_pub_json):
        print("[*] Step 2: Performing Key Exchange...")
        
        # Generate Ephemeral Key for this session
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_public_key = ephemeral_private_key.public_key()
        client_pub_json = self._get_public_key_json(ephemeral_public_key)

        # Compute Shared Secret
        server_pub_numbers = ec.EllipticCurvePublicNumbers(
            int(server_pub_json['x']), 
            int(server_pub_json['y']), 
            ec.SECP256R1()
        )
        server_pub_key = server_pub_numbers.public_key(default_backend())
        
        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), server_pub_key)
        
        salt = b'\x00' * 16 
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32, 
            salt=salt,
            iterations=1000,
            backend=default_backend()
        )
        self.aes_key = kdf.derive(shared_secret)
        print("    [+] AES Key Derived successfully")

        # Sign Client Public Key
        ephemeral_sig_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_sig_public = ephemeral_sig_private.public_key()
        
        message_to_sign = json.dumps(client_pub_json, separators=(',', ':')).encode()
        signature = ephemeral_sig_private.sign(
            message_to_sign,
            ec.ECDSA(hashes.SHA256())
        )
        r, s = self._decode_signature(signature)

        payload = {
            "sessionToken": self.session_token,
            "clientPublicKey": client_pub_json,
            "clientPublicKeySignature": {"r": str(r), "s": str(s)},
            "clientSignaturePublicKey": self._get_public_key_json(ephemeral_sig_public)
        }
        
        resp = self._safe_post("/session/exchange", payload)

        if resp.status_code != 200:
            raise Exception(f"Key exchange failed: {resp.text}")
            
        resp_data = resp.json()
        if "sessionToken" in resp_data:
            self.session_token = resp_data["sessionToken"]
            
        if resp_data.get("clientSignatureVerified") is True:
            print("    [+] Key Exchange Complete.")
        else:
            print("    [-] Warning: Server did not verify client signature.")

    def encrypt_message_cbc(self, plaintext):
        """Encrypts message and returns Base64 string (simulating client app behavior)"""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # PKCS7 Padding
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return Base64 of (IV + Ciphertext)
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    def send_message(self, message):
        print(f"[*] Sending message: '{message}'")
        encrypted_msg = self.encrypt_message_cbc(message)
        
        # Create a fresh ephemeral signature key (as per observed behavior)
        ephemeral_sig_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_sig_public = ephemeral_sig_private.public_key()
        
        signature = ephemeral_sig_private.sign(
            encrypted_msg.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        r, s = self._decode_signature(signature)

        payload = {
            "sessionToken": self.session_token,
            "encryptedMessage": encrypted_msg,
            "messageSignature": {"r": str(r), "s": str(s)},
            "clientSignaturePublicKey": self._get_public_key_json(ephemeral_sig_public)
        }
        
        resp = self._safe_post("/message/send", payload)
        
        if resp.status_code != 200:
            print(f"    [-] Send failed: {resp.text}")
            return {}
            
        result = resp.json()
        if "sessionToken" in result:
            self.session_token = result["sessionToken"]
        
        return result

def analyze_cipher_length(b64_cipher_from_json):
    """
    Analyzes the 'encryptedMessage' field from the JSON to determine plaintext length.
    """
    # Attacker sees the Base64 string length in the JSON
    base64_len = len(b64_cipher_from_json)
    
    # Attacker decodes to get raw bytes
    cipher_bytes = base64.b64decode(b64_cipher_from_json)
    raw_len = len(cipher_bytes)
    
    # Attacker calculates length based on AES-CBC PKCS7
    # Structure: IV (16 bytes) + Encrypted Blocks
    iv_len = 16
    payload_len = raw_len - iv_len
    
    # Logic: PKCS7 always adds padding (1 to 16 bytes).
    # Real_Length = Payload_Length - Padding
    # Since Padding is 1..16, Real_Length is between (Payload - 16) and (Payload - 1)
    
    min_real_len = payload_len - 16
    max_real_len = payload_len - 1
    
    if min_real_len < 0: min_real_len = 0
    
    return base64_len, raw_len, (min_real_len, max_real_len)

if __name__ == "__main__":
    try:
        # Initialize and Handshake
        client = SMCClient()
        server_pub = client.step_1_create_session()
        client.step_2_key_exchange(server_pub)
        
        test_messages = ["a", "Hello World", "This is a much longer message to force a new block"]
        
        for msg in test_messages:
            print(f"--- [Scenario] User sends: '{msg}' ---")
            
            # 1. Client creates encrypted payload 
            encrypted_b64 = client.encrypt_message_cbc(msg)
            
            # Send to server 
            client.send_message(msg)
            
            # ATTACKER ANALYSIS
            intercepted_field = encrypted_b64 
            
            b64_len, raw_len, (est_min, est_max) = analyze_cipher_length(intercepted_field)
            
            print(f"    [ATTACKER VIEW]")
            print(f"    Intercepted JSON Value: '{intercepted_field[:15]}...'")
            print(f"    Base64 String Length:   {b64_len} chars")  
            print(f"    Decoded Raw Length:     {raw_len} bytes")  
            print(f"    >> DEDUCTION: Real message is between {est_min} and {est_max} bytes.")
            
            # VERIFICATION
            if est_min <= len(msg) <= est_max:
                print(f"    [SUCCESS] Actual length {len(msg)} falls within attacker's estimated range!")
            else:
                print(f"    [FAIL] Analysis failed.")
            print("")

    except Exception as e:
        print(f"\nERROR: {e}")