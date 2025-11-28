import requests
import json
import base64
import os
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
        
        # Identity Key 
        self.identity_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.identity_public_key = self.identity_private_key.public_key()

    def _get_public_key_json(self, pub_key):
        """Convert Public Key to JSON format {x, y}"""
        numbers = pub_key.public_numbers()
        return {
            "x": str(numbers.x),
            "y": str(numbers.y)
        }

    def step_1_create_session(self):
        print(f"[*] Step 1: Creating session for {USER_ID} with {ALGORITHM}...")
        
        # For ecdh_3, we need to send curve parameters 
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
        
        resp = self.session.post(f"{BASE_URL}/session/create?userId={USER_ID}", json=payload)
        if resp.status_code != 200:
            raise Exception(f"Failed to create session: {resp.text}")
            
        data = resp.json()
        if not data.get("success"):
            raise Exception(f"Server error: {data}")

        self.session_token = data["sessionToken"]
        server_pub_json = data["serverPublicKey"]
        
        # Verify session signature 
        if "sessionSignature" in data and "serverSignaturePublicKey" in data:
            print("    [+] Session signature present (verification not implemented in this example)")
        
        print(f"    [+] Session Token: {self.session_token[:20]}...")
        return server_pub_json

    def step_2_key_exchange(self, server_pub_json):
        print("[*] Step 2: Performing Key Exchange...")
        
        # Generate EPHEMERAL Key (temporary key for this session)
        # Use NEW key for each session, not the identity key
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_public_key = ephemeral_private_key.public_key()
        client_pub_json = self._get_public_key_json(ephemeral_public_key)

        # Compute Shared Secret (ECDH)
        server_pub_numbers = ec.EllipticCurvePublicNumbers(
            int(server_pub_json['x']), 
            int(server_pub_json['y']), 
            ec.SECP256R1()
        )
        server_pub_key = server_pub_numbers.public_key(default_backend())
        
        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), server_pub_key)
        
        # Derive AES Key using PBKDF2 
        salt = b'\x00' * 16 
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256
            salt=salt,
            iterations=1000,
            backend=default_backend()
        )
        self.aes_key = kdf.derive(shared_secret)
        print("    [+] AES Key Derived successfully")

        # Sign Client Public Key with EPHEMERAL signature key
        # Create NEW ephemeral signature key pair
        ephemeral_sig_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_sig_public = ephemeral_sig_private.public_key()
        
        # Sign the client public key JSON 
        message_to_sign = json.dumps(client_pub_json, separators=(',', ':')).encode()
        signature = ephemeral_sig_private.sign(
            message_to_sign,
            ec.ECDSA(hashes.SHA256())
        )
        r, s = self._decode_signature(signature)

        # Send Exchange Request
        payload = {
            "sessionToken": self.session_token,
            "clientPublicKey": client_pub_json,
            "clientPublicKeySignature": {"r": str(r), "s": str(s)},
            "clientSignaturePublicKey": self._get_public_key_json(ephemeral_sig_public)
        }
        
        resp = self.session.post(f"{BASE_URL}/session/exchange?userId={USER_ID}", json=payload)
        if resp.status_code != 200:
            raise Exception(f"Key exchange failed: {resp.text}")
            
        resp_data = resp.json()
        
        # Update token if provided
        if "sessionToken" in resp_data:
            self.session_token = resp_data["sessionToken"]
            
        if resp_data.get("clientSignatureVerified") is True:
            print("    [+] Key Exchange Complete. Mutual Auth Success!")
        else:
            print("    [-] Warning: Server did not verify client signature.")
            if not resp_data.get("success"):
                raise Exception(f"Key exchange failed: {resp_data.get('error')}")

    def _decode_signature(self, signature_bytes):
        """Decode DER signature to r, s"""
        r, s = asym_utils.decode_dss_signature(signature_bytes)
        return r, s

    def encrypt_message_cbc(self, plaintext):
        """
        Encrypt using AES-CBC (for ecdh_3)
        Matches CryptoManager.java encryptCBC method
        """
        # Generate random IV (16 bytes)
        iv = os.urandom(16)
        
        cipher = Cipher(
            algorithms.AES(self.aes_key), 
            modes.CBC(iv), 
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # PKCS7 Padding 
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Result = IV + Ciphertext -> Base64
        final_bytes = iv + ciphertext
        return base64.b64encode(final_bytes).decode('utf-8')

    def decrypt_message_cbc(self, encrypted_b64):
        """Decrypt AES-CBC message"""
        data = base64.b64decode(encrypted_b64)
        iv = data[:16]
        ciphertext = data[16:]
        
        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext.decode('utf-8')

    def send_message(self, message):
        print(f"[*] Sending message: '{message}'")
        
        # Encrypt
        encrypted_msg = self.encrypt_message_cbc(message)
        print(f"    -> Encrypted Length (Base64): {len(encrypted_msg)}")
        
        # Sign with EPHEMERAL key 
        # Create new ephemeral signature key for each message
        ephemeral_sig_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_sig_public = ephemeral_sig_private.public_key()
        
        signature = ephemeral_sig_private.sign(
            encrypted_msg.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        r, s = self._decode_signature(signature)

        # 3. Send
        payload = {
            "sessionToken": self.session_token,
            "encryptedMessage": encrypted_msg,
            "messageSignature": {"r": str(r), "s": str(s)},
            "clientSignaturePublicKey": self._get_public_key_json(ephemeral_sig_public)
        }
        
        resp = self.session.post(f"{BASE_URL}/message/send?userId={USER_ID}", json=payload)
        
        if resp.status_code != 200:
            raise Exception(f"Send message failed: {resp.text}")
            
        result = resp.json()
        
        # Update session token if provided
        if "sessionToken" in result:
            self.session_token = result["sessionToken"]
        
        # Decrypt response if available
        if result.get("success") and "encryptedResponse" in result:
            try:
                decrypted = self.decrypt_message_cbc(result["encryptedResponse"])
                print(f"    <- Server Response: {decrypted}")
                result["decryptedResponse"] = decrypted
            except Exception as e:
                print(f"    [-] Failed to decrypt response: {e}")
        
        return result

if __name__ == "__main__":
    try:
        client = SMCClient()
        
        # Handshake
        server_pub = client.step_1_create_session()
        
        # Exchange Keys
        client.step_2_key_exchange(server_pub)
        
        print("\n--- TESTING METADATA LEAKAGE (TASK 3) ---")
        # Send messages with increasing lengths to visualize step pattern
        test_messages = ["a", "a"*5, "a"*15, "a"*16, "a"*32]
        
        for msg in test_messages:
            print(f"\n[Test] Message length: {len(msg)}")
            resp = client.send_message(msg)
            if not resp.get("success"):
                print(f"    [-] Error: {resp.get('error')}")
            
        print("\n--- Testing with actual questions ---")
        questions = ["name", "age", "location", "hobby"]
        for q in questions:
            print(f"\n[Question] {q}")
            resp = client.send_message(q)
            
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()