# Secure Messaging Prototype  
**Course:** TIS 6200 / 8200 – Principles of Information Security and Privacy  
**Author:** JT Allen  
**Date:** 10/15/2025

## 📘 Overview
This project implements a prototype for **secure messaging** between two users — Alice and Bob.  
It demonstrates core cryptographic techniques that ensure **confidentiality**, **integrity**, and **authentication** in communication.  

The prototype uses **RSA digital signatures**, **Diffie-Hellman key exchange**, **SHA-256 key derivation**, **pseudo-random number generation**, and **AES encryption with HMAC authentication**.

---

## 🔐 Tasks Implemented

### **Task 1 – Digital Signature**
- Implemented RSA-style digital signatures.  
- Alice and Bob each generate public/private key pairs (`(e, n)` and `(d, n)`).  
- Each message is hashed and signed with the sender’s private key.  
- The receiver verifies the signature using the sender’s public key.  

🧩 **Purpose:** Prevents tampering and verifies authenticity.

---

### **Task 2 – Diffie-Hellman Key Exchange**
- Alice and Bob exchange public values (`A = g^a mod p`, `B = g^b mod p`) and compute a shared secret.  
- Signatures from Task 1 protect against man-in-the-middle attacks.  
- Both sides compute the same shared secret for later encryption.  

 **Purpose:** Securely establish a shared session key without revealing it publicly.

---

### **Task 3 – Key Derivation Function (KDF)**
- Converts the shared secret from Diffie-Hellman into a strong symmetric key.  
- Uses **SHA-256 hashing** repeated 10,000 times.  
- The final 256-bit hash is used as the encryption key.  

 **Purpose:** Ensures the session key is cryptographically strong and random.

---

### **Task 4 – Pseudo-Random Number Generator (PRNG)**
- Implements a simple **Linear Congruential Generator (LCG)** for pseudo-random number generation.  
- Features:
  - Seeding (using system time or a manual value)  
  - Deterministic output when seeded with the same value  
  - Reseeding for added randomness  
- Demonstrated random-like output and deterministic behavior.

 **Purpose:** Generates nonces or IVs for encryption modes like CBC or CTR.

---

### **Task 5 – Secure Message Exchange**
- Implements symmetric encryption using **AES (CBC mode)** and message authentication using **HMAC-SHA256**.  
- Uses the **Encrypt-then-MAC** structure for authenticated encryption.  
- The encryption key is derived from Task 3, and the IV is generated using Task 4.  
- Alice encrypts the message and attaches a MAC; Bob verifies integrity and decrypts the ciphertext.

 **Purpose:** Provides both **confidentiality** (encryption) and **integrity** (HMAC verification).

---

## How to Run

### 1️⃣ **Install Dependencies**
Make sure Python 3 and the required cryptography library are installed.  
Run this in your terminal (or VS Code terminal):

```bash
pip install cryptography

import random
import time
import hashlib
import hmac
from math import gcd

# cryptography (AES)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Task 1: Digital Signature
def key_generation():
    p = 61
    q = 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17
    d = pow(e, -1, phi)
    return (e, n), (d, n)

def hash_function(message):
    # Accept int or str; return small educational hash (fits tiny RSA n)
    if isinstance(message, int):
        message = str(message)
    return sum(ord(c) for c in message)

def sign(message, d, n):
    h = hash_function(message) % n
    return pow(h, d, n)

def verify(message, signature, e, n):
    h = hash_function(message) % n
    verified_hash = pow(signature, e, n)
    return verified_hash == h

# Pre-generate keys for Alice and Bob
alice_public, alice_private = key_generation()
bob_public, bob_private = key_generation()

# Task 2: Diffie–Hellman Exchange
def diffie_hellman_exchange(alice_keys, bob_keys):
    p = 23
    g = 5
    print(f"\nPublic parameters: p = {p}, g = {g}")

    a = random.randint(1, p-1)
    b = random.randint(1, p-1)
    print(f"Alice's secret a = {a}")
    print(f"Bob's secret b = {b}")

    A = pow(g, a, p)
    B = pow(g, b, p)
    print(f"Alice computes A = g^a mod p = {A}")
    print(f"Bob computes B = g^b mod p = {B}")

    alice_pub, alice_priv = alice_keys
    bob_pub, bob_priv = bob_keys

    # Sign the public DH values (convert to str inside sign is okay)
    alice_signature = sign(A, alice_priv[0], alice_priv[1])
    bob_signature = sign(B, bob_priv[0], bob_priv[1])
    print(f"Alice signs A -> Signature = {alice_signature}")
    print(f"Bob signs B -> Signature = {bob_signature}")

    # Verify
    verify_A = verify(A, alice_signature, alice_pub[0], alice_pub[1])
    verify_B = verify(B, bob_signature, bob_pub[0], bob_pub[1])
    print(f"Bob verifies Alice’s signature → {verify_A}")
    print(f"Alice verifies Bob’s signature → {verify_B}")

    alice_shared = pow(B, a, p)
    bob_shared = pow(A, b, p)
    print(f"\nAlice's computed shared secret = {alice_shared}")
    print(f"Bob's computed shared secret = {bob_shared}")

    if alice_shared == bob_shared:
        print("Shared secret successfully matched!")
    else:
        print("Shared secret mismatch")

    return alice_shared

shared_secret = diffie_hellman_exchange((alice_public, alice_private), (bob_public, bob_private))

# Task 3: KDF (iterated SHA-256)
def key_derivation(shared_secret, iterations):
    data = str(shared_secret).encode()
    for _ in range(iterations):
        data = hashlib.sha256(data).digest()
    return data.hex()  # hex string (64 chars => 32 bytes)

iterations = 10000
derived_key = key_derivation(shared_secret, iterations)
print(f"\nDerived Encryption Key after {iterations} iterations:")
print(derived_key)

# Task 4: Simple PRNG (LCG)
class SimplePRNG:
    def __init__(self, seed=None):
        self.seed(seed)

    def seed(self, value=None):
        if value is None:
            value = int(time.time() * 1000)
        self.state = value % (2**32)
        print(f"🔹 PRNG seeded with: {self.state}")

    def reseed(self, extra_value):
        print(f"🔹 PRNG reseeded with: {extra_value}")
        self.state = (self.state ^ extra_value) % (2**32)

    def generate(self):
        a = 1664525
        c = 1013904223
        m = 2**32
        self.state = (a * self.state + c) % m
        return self.state

# Create PRNG and produce a 16-byte IV
rng = SimplePRNG(12345)
iv = bytes([rng.generate() % 256 for _ in range(16)])
print(f"\nGenerated IV for AES (hex): {iv.hex()}")


#Task 5
def key_bytes_from_hex(hex_key):
    kb = bytes.fromhex(hex_key)
    if len(kb) >= 32:
        return kb[:32]
    return kb.ljust(32, b'\x00')

def sym_enc(message, key_hex, iv):
    key_bytes = key_bytes_from_hex(key_hex)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padding_len = 16 - (len(message) % 16)
    padded = message.encode() + bytes([padding_len] * padding_len)
    return encryptor.update(padded) + encryptor.finalize()

def sym_dec(ciphertext, key_hex, iv):
    key_bytes = key_bytes_from_hex(key_hex)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    padding_len = padded[-1]
    return padded[:-padding_len].decode()

def compute_hmac(key_hex, data):
    key_bytes = key_bytes_from_hex(key_hex)
    return hmac.new(key_bytes, data, hashlib.sha256).digest()

def encrypt_then_mac(message, key_hex, iv):
    ciphertext = sym_enc(message, key_hex, iv)
    mac = compute_hmac(key_hex, ciphertext)
    return ciphertext + mac

def decrypt_then_verify(ciphertext_mac, key_hex, iv):
    if len(ciphertext_mac) < 32:
        raise ValueError("ciphertext_mac too short")
    ciphertext = ciphertext_mac[:-32]
    mac_received = ciphertext_mac[-32:]
    mac_calc = compute_hmac(key_hex, ciphertext)
    if not hmac.compare_digest(mac_received, mac_calc):
        raise ValueError("HMAC verification failed!")
    return sym_dec(ciphertext, key_hex, iv)

#Alice sends a message
message = "Hello Bob, this is Alice."
encrypted_mac = encrypt_then_mac(message, derived_key, iv)
print(f"\nEncrypted + MAC (hex): {encrypted_mac.hex()}")

decrypted_msg = decrypt_then_verify(encrypted_mac, derived_key, iv)
print(f"Decrypted message at Bob's side: {decrypted_msg}")

# Task 6: Tampering experiment
def tamper_ciphertext(ciphertext_mac, flip_index=0, flip_mask=0x01):
    if len(ciphertext_mac) < 33:
        raise ValueError("ciphertext_mac too short to tamper")
    ciphertext = bytearray(ciphertext_mac[:-32]) 
    mac = ciphertext_mac[-32:]  

    flip_index = max(0, min(flip_index, len(ciphertext) - 1))
    ciphertext[flip_index] ^= (flip_mask & 0xFF) 

    return bytes(ciphertext) + mac

print("\n--- Tampering experiment ---")
print("Original encrypted+MAC (hex):")
print(encrypted_mac.hex())

tampered = tamper_ciphertext(encrypted_mac, flip_index=0, flip_mask=0xFF)
print("\nTampered encrypted+MAC (hex) (byte 0 flipped):")
print(tampered.hex())

#Bob tries to verify & decrypt 
try:
    print("\nBob attempts to verify and decrypt tampered message...")
    tampered_result = decrypt_then_verify(tampered, derived_key, iv)
    
    print("Unexpected: tampered message decrypted successfully:", tampered_result)
except Exception as e:
    print("Expected failure detected at Bob's side:")
    print(type(e).__name__ + ":", str(e))

