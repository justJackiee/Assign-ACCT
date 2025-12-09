# Secure Messaging Client (SMC) Assignment

This project implements a **Secure Messaging Client (SMC)** simulation in Python. It demonstrates key cryptographic concepts including ECDH key exchange, digital signatures, and AES-CBC encryption, as well as a side-channel analysis simulation.

### [Go to Problem 2 Implementation](https://github.com/justJackiee/Assign-ACCT/blob/main/Problem2/Problem2.py)
### [Go to SMC Client Implementation (smc.py)](https://github.com/justJackiee/Assign-ACCT/blob/main/smc.py)

## Overview

The `smc.py` script simulates a client communicating with a remote server (Crypto Assignment Server) to perform the following steps:

1.  **Session Creation**: The client registers a session with the server.
2.  **Key Exchange**:
    *   Generates an ephemeral ECDH key pair.
    *   Performs ECDH to derive a shared secret.
    *   Derives an AES session key using PBKDF2.
    *   Authenticates the exchange by signing the public key.
3.  **Secure Messaging**:
    *   Encrypts messages using AES-CBC with PKCS#7 padding.
    *   Signs the encrypted message for integrity and authenticity.
    *   Sends the message to the server.
4.  **Attacker Analysis (Simulation)**:
    *   The script locally simulates an attacker who intercepts the purely JSON/Base64 output.
    *   It attempts to deduce the length of the plaintext message based on the ciphertext length and padding rules.

## Prerequisites

*   **Python 3.6+**

## Installation

You need to install the required Python packages. It is recommended to use a virtual environment.

```bash
pip install -r requirements.txt
```

## Usage

Run the script directly using Python:

```bash
python smc.py
```

## How It Works

### Cryptography Details
*   **Curve**: SECP256R1 (NIST P-256)
*   **Key Exchange**: ECDH (Elliptic Curve Diffie-Hellman)
*   **KDF**: PBKDF2HMAC (SHA256, 1000 iterations, 32-byte key)
*   **Encryption**: AES-128/192/256 (derived from KDF) in CBC mode with PKCS7 padding.
*   **Signatures**: ECDSA (SHA256)

### Analysis Logic
The script includes an `analyze_cipher_length` function. This function demonstrates a passive side-channel attack where an eavesdropper can estimate the original message size by observing the length of the Base64-encoded ciphertext, knowing the block size (16 bytes) and padding scheme (PKCS7).

## Example Output

```text
[*] Step 1: Creating session for group-3...
    [+] Session Token: a1b2c3d4...
    [Wait] Sleeping 1.1s to respect rate limit...
[*] Step 2: Performing Key Exchange...
    [+] AES Key Derived successfully
    [+] Key Exchange Complete.
    [Wait] Sleeping 1.1s to respect rate limit...
--- [Scenario] User sends: 'Hello World' ---
[*] Sending message: 'Hello World'
    [Wait] Sleeping 1.1s to respect rate limit...
    [ATTACKER VIEW]
    Intercepted JSON Value: '...'
    Base64 String Length:   44 chars
    Decoded Raw Length:     32 bytes
    >> DEDUCTION: Real message is between 0 and 15 bytes.
    [SUCCESS] Actual length 11 falls within attacker's estimated range!
```

## Disclaimer
This code is for educational purposes as part of a cryptography assignment.

## Problem 2: Vigenère Cipher Analysis

This section deals with the cryptanalysis of a Vigenère Cipher. The solution is implemented in the `Problem2` directory.

### Description
The script `Problem2.py` provides an automated tool to break a Vigenère Cipher without knowing the key. It uses statistical analysis of English letter frequencies.

### How it Works
1.  **Key Length Determination**: Uses the **Index of Coincidence (IoC)**. It checks possible key lengths (up to 15) and selects the one where the average IoC of the column groups best matches the expected IoC of English text (~0.0667).
2.  **Key Recovery**: For each position in the key, it uses **Chi-squared analysis** to find the Caesar shift that minimizes the difference between the observed letter frequencies and standard English frequencies.
3.  **Decryption**: Once the key is recovered, it decrypts the ciphertext.

### Usage
Navigate to the `Problem2` directory and run the script:

```bash
cd Problem2
python Problem2.py
```



### Result

```text
 -> Do dai Key du doan: 10

TIM THAY KEY: HEAVENHELL
Giai ma voi Key 'HEAVENHELL'...

--- TOAN BO NOI DUNG DA GIAI MA ---
The concept of the afterlife has fascinated humanity for millennia, shaping cultures, religions, and philosophies across civilizations. At its core, the afterlife refers to the belief that some form of existence continues after physical death...

(Da luu ket qua vao file 'final_result.txt')
```
