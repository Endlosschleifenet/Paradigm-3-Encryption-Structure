# PARATH_ENC.py

# Paradigm Software License Version 1.0 (2025)
# Copyright (c) 2025 Fenix T.
# https://github.com/Endlosschleifenet
#
# This file is part of the "Paradigm 3" project (codename: CLOAKER).
# Use, redistribution, and modification are subject to the terms of the
# Paradigm Software License Version 1.0, available in the LICENSE file.

"""
Encryption script with:
- Argon2id KDF
- Triple-layer encryption AES-GCM → Twofish-CBC → Serpent-CBC
- HMAC-SHA512 for integrity
- Plaintext length prefix + padding
- Encoding ciphertext as zero-width chars base-3 (3-char palette)
- Cover text for steganographic embedding
- Single compression: brotli before encryption
"""

import os
import importlib
import sys
import brotli
from Crypto.Cipher import AES
import pyserpent
from Crypto.Util.Padding import pad
import twofish
from argon2.low_level import hash_secret_raw, Type
from hmac import HMAC
import hashlib
import gc
import time

# ======== CONFIG ========
"""
Config should match in both ENC/DEC scripts.
"""
SALT_LEN    = 16
AES_KEY_LEN = 32
AES_IV_LEN  = 12
AES_TAG_LEN = 16
TF_KEY_LEN  = 32
TF_IV_LEN   = 16
SP_KEY_LEN  = 32
SP_IV_LEN   = 16
HMAC_KEY_LEN = 64

ARGON_MEM_COST = 2**18 # Measured in MB
ARGON_TIME_COST = 8
ARGON_PARALLELISM = min(os.cpu_count() or 1,8) # Automatically Detects how many threads to use, defaults to 1; maxes at 8
HASH_LEN = 64

PALETTE_3 = [
    '\u200B',  # ZERO WIDTH SPACE
    '\u200C',  # ZERO WIDTH NON-JOINER
    '\u200D',  # ZERO WIDTH JOINER
]
# ========================

def bytes_to_ternary_chars(data: bytes) -> str:
    ternary_digits = []
    num = int.from_bytes(data, 'big')
    if num == 0:
        ternary_digits.append(0)
    else:
        while num > 0:
            ternary_digits.append(num % 3)
            num //= 3
    ternary_digits.reverse()
    return ''.join(PALETTE_3[d] for d in ternary_digits)

def derive_keys(password: str, salt: bytes):
    total_key_len = AES_KEY_LEN + TF_KEY_LEN + SP_KEY_LEN + HMAC_KEY_LEN
    pwd_bytes = password.encode('utf-8')
    raw = hash_secret_raw(
        secret=pwd_bytes,
        salt=salt,
        time_cost=ARGON_TIME_COST,
        memory_cost=ARGON_MEM_COST,
        parallelism=ARGON_PARALLELISM,
        hash_len=total_key_len,
        type=Type.ID
    )
    aes_key = bytearray(raw[0:AES_KEY_LEN])
    tf_key = bytearray(raw[AES_KEY_LEN:AES_KEY_LEN + TF_KEY_LEN])
    sp_key = bytearray(raw[AES_KEY_LEN + TF_KEY_LEN:AES_KEY_LEN + TF_KEY_LEN + SP_KEY_LEN])
    hmac_key = bytearray(raw[-HMAC_KEY_LEN:])
    return aes_key, tf_key, sp_key, hmac_key

def twofish_encrypt(key: bytes, iv: bytes, data: bytes, block_size=16) -> bytes:
    key = bytes(key)
    data = pad(data, block_size)
    tf = twofish.Twofish(key)
    ciphertext = b""
    prev = iv
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        xored = bytes(a ^ b for a, b in zip(block, prev))
        enc = tf.encrypt(xored)
        ciphertext += enc
        prev = enc
    return ciphertext

def serpent_encrypt(key: bytes, iv: bytes, data: bytes, block_size=16) -> bytes:
    cipher = pyserpent.Serpent(key)
    data = pad(data, block_size)
    ciphertext = b""
    prev = iv
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        xored = bytes(a ^ b for a, b in zip(block, prev))
        enc = cipher.encrypt(xored)
        ciphertext += enc
        prev = enc
    return ciphertext

def aes_encrypt(key: bytes, iv: bytes, data: bytes) -> tuple[bytes, bytes]:
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, tag

# --- Brotli compression ---

def brotli_compress(data: bytes) -> bytes:
    return brotli.compress(data, quality=11)

def encrypt(secret: str, password: str, cover: str) -> str:
    salt = os.urandom(SALT_LEN)
    aes_key, tf_key, sp_key, hmac_key = derive_keys(password, salt)

    secret_bytes = secret.encode('utf-8')
    compressed = brotli_compress(secret_bytes)
    length_prefix = len(compressed).to_bytes(2, 'big')

    pad_len = os.urandom(1)[0] % 16
    padding = os.urandom(pad_len)

    secret_padded = length_prefix + compressed + padding

    print("Compressed length:", len(compressed))
    print("Padding length:", pad_len)
    print("Compressed + padded length:", len(secret_padded))

    aes_iv = os.urandom(AES_IV_LEN)
    ct1, tag1 = aes_encrypt(aes_key, aes_iv, secret_padded)
    print("AES ciphertext length:", len(ct1))

    tf_iv = os.urandom(TF_IV_LEN)
    ct2 = twofish_encrypt(tf_key, tf_iv, ct1)
    print("Twofish ciphertext length:", len(ct2))

    sp_iv = os.urandom(SP_IV_LEN)
    ct3 = serpent_encrypt(sp_key, sp_iv, ct2)
    print("Serpent ciphertext length:", len(ct3))

    blob = salt + aes_iv + tag1 + tf_iv + sp_iv + ct3

    hmac = HMAC(hmac_key, blob, hashlib.sha512)
    hmac_tag = hmac.digest()

    length_prefix = len(blob + hmac_tag).to_bytes(2, 'big')
    final_blob_with_length = length_prefix + blob + hmac_tag

    hidden = bytes_to_ternary_chars(final_blob_with_length)

    # Securely clear sensitive data
    for k in (aes_key, tf_key, sp_key, hmac_key):
        for i in range(len(k)):
            k[i] = 0

    del aes_key, tf_key, sp_key, hmac_key, salt, aes_iv, ct1, tag1, ct2, ct3, padding, secret_padded
    gc.collect()

    return cover + hidden

def import_decrypt_function(dec_file_path: str):
    module_name = "parath_decrypt"
    spec = importlib.util.spec_from_file_location(module_name, dec_file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module.decrypt

def is_ascii(s: str) -> bool:
    try:
        s.encode('ascii')
        return True
    except UnicodeEncodeError:
        return False

if __name__ == "__main__":
    print("\nWelcome to the Paradigm 3 Structured Encryption Program.")
    print("Designed by Fenix T. [@failstate]\n")

    while True:
        cover_text = input("Enter a cover (or leave blank): ")
        break

    # Check secret's input for non-ASCII characters
    while True:
        secret_text = input("Enter the secret: ")
        if not is_ascii(secret_text):
            print("\n[Warning] Secret contains non-ASCII characters, which will increase the size of the encrypted output.")
            time.sleep(2)
            yn = input("Do you want to continue? (y/n): ").strip().lower()
            if yn == 'y':
                break
            else:
                print("Please re-enter a new secret.")
        else:
            break

    # Check password's input for non-ASCII characters
    while True:
        password = input("Enter password: ")
        if not is_ascii(password):
            print("\n[Warning] Password contains non-ASCII characters, which will increase the size of the encrypted output.")
            time.sleep(2)
            yn = input("Do you want to continue? (y/n): ").strip().lower()
            if yn == 'y':
                break
            else:
                print("Please re-enter a new password.")
        else:
            break

    encrypted = encrypt(secret_text, password, cover_text)

    print("\nEncrypted Message:")
    print(encrypted)

    decrypt_path = os.path.join(os.path.dirname(__file__), "PARATH_DEC.py")
    decrypt = import_decrypt_function(decrypt_path)

    print("\nDecrypted Message:")
    decrypted = decrypt(encrypted, password)
    print(decrypted)
