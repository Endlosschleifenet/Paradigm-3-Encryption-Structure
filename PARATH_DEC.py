# PARATH_DEC.py

# Paradigm Software License Version 1.0 (2025)
# Copyright (c) 2025 Fenix T.
# https://github.com/Endlosschleifenet
#
# This file is part of the "Paradigm 3" project (codename: CLOAKER).
# Use, redistribution, and modification are subject to the terms of the
# Paradigm Software License Version 1.0, available in the LICENSE file.

"""
Decryption script with:
- Extraction of ternary zero-width encoded ciphertext (3 zero-width chars → base-3 → bytes)
- Argon2id KDF key derivation
- HMAC-SHA512 verification
- Triple-layer decryption: Serpent-CBC → Twofish-CBC → AES-GCM
- Removal of random padding using length prefix
- UTF-8 decoding
- Triple decompression: brotli after decryption
"""

import hashlib
import brotli
from hmac import compare_digest
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import pyserpent
import twofish
from argon2.low_level import hash_secret_raw, Type
import gc
import os
import binascii
import hmac

SALT_LEN    = 16
AES_KEY_LEN = 32
AES_IV_LEN  = 12
AES_TAG_LEN = 16
TF_KEY_LEN  = 32
TF_IV_LEN   = 16
SP_KEY_LEN  = 32
SP_IV_LEN   = 16
HMAC_KEY_LEN = 64

ARGON_MEM_COST = 2**21
ARGON_TIME_COST = 12
ARGON_PARALLELISM = min(os.cpu_count() or 1,8)
HASH_LEN = 64

PALETTE_3 = [
    '\u200B',  # ZERO WIDTH SPACE
    '\u200C',  # ZERO WIDTH NON-JOINER
    '\u200D',  # ZERO WIDTH JOINER
]

def ternary_chars_to_bytes(text: str) -> bytes:
    digits = []
    for c in text:
        if c not in PALETTE_3:
            continue
        digits.append(PALETTE_3.index(c))
    if not digits:
        return b''

    num = 0
    for d in digits:
        num = num * 3 + d

    import math
    bits = len(digits)*1.5849625
    length = math.ceil(bits/8)

    return num.to_bytes(length, 'big')

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

def twofish_decrypt_cbc(key: bytes, iv: bytes, data: bytes, block_size=16) -> bytes:
    key = bytes(key)
    tf = twofish.Twofish(key)
    prev = iv
    plaintext = b''
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        dec = tf.decrypt(block)
        xored = bytes(a ^ b for a, b in zip(dec, prev))
        plaintext += xored
        prev = block
    return unpad(plaintext, block_size)

def decrypt_cbc(cipher: pyserpent.Serpent, iv: bytes, data: bytes, block_size=16) -> bytes:
    prev = iv
    plaintext = b''
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        dec = cipher.decrypt(block)
        xored = bytes(a ^ b for a, b in zip(dec, prev))
        plaintext += xored
        prev = block
    return unpad(plaintext, block_size)

def constant_time_compare(val1: bytes, val2: bytes) -> bool:
    return compare_digest(val1, val2)

def decrypt(message: str, password: str) -> str:
    hidden = ''.join(c for c in message if c in PALETTE_3)
    if not hidden:
        return "[Error: No hidden data found]"

    try:
        data_with_length = ternary_chars_to_bytes(hidden)
    except Exception as e:
        return f"[Error decoding zero-width data]: {e}"

    if len(data_with_length) < 2:
        return "[Error: Data too short for length prefix]"

    expected_len = int.from_bytes(data_with_length[:2], 'big')

    if expected_len > len(data_with_length) - 2:
        return "[Error: Invalid length prefix]"

    data = data_with_length[2:2 + expected_len]

    min_len = SALT_LEN + AES_IV_LEN + AES_TAG_LEN + TF_IV_LEN + SP_IV_LEN + HMAC_KEY_LEN
    if len(data) < min_len:
        return "[Error: Data too short]"

    salt = data[:SALT_LEN]
    aes_iv = data[SALT_LEN:SALT_LEN + AES_IV_LEN]
    aes_tag = data[SALT_LEN + AES_IV_LEN:SALT_LEN + AES_IV_LEN + AES_TAG_LEN]
    tf_iv = data[SALT_LEN + AES_IV_LEN + AES_TAG_LEN:SALT_LEN + AES_IV_LEN + AES_TAG_LEN + TF_IV_LEN]
    sp_iv = data[SALT_LEN + AES_IV_LEN + AES_TAG_LEN + TF_IV_LEN:SALT_LEN + AES_IV_LEN + AES_TAG_LEN + TF_IV_LEN + SP_IV_LEN]
    hmac_tag = data[-HMAC_KEY_LEN:]
    ct3 = data[SALT_LEN + AES_IV_LEN + AES_TAG_LEN + TF_IV_LEN + SP_IV_LEN:-HMAC_KEY_LEN]

    aes_key, tf_key, sp_key, hmac_key = derive_keys(password, salt)

    blob_without_hmac = data[:-HMAC_KEY_LEN]
    expected_hmac = hmac.new(hmac_key, blob_without_hmac, hashlib.sha512).digest()

    print("Blob without HMAC length:", len(blob_without_hmac))
    print("Extracted HMAC:", binascii.hexlify(hmac_tag))
    print("Expected HMAC:", binascii.hexlify(expected_hmac))

    if not constant_time_compare(hmac_tag, expected_hmac):
        return "[Error: HMAC verification failed]"

    serpent = pyserpent.Serpent(sp_key)
    ct2 = decrypt_cbc(serpent, sp_iv, ct3)

    pt_aes_ciphertext = twofish_decrypt_cbc(tf_key, tf_iv, ct2)

    try:
        aes = AES.new(aes_key, AES.MODE_GCM, nonce=aes_iv)
        plaintext_padded = aes.decrypt_and_verify(pt_aes_ciphertext, aes_tag)
    except ValueError:
        return "[Error: AES-GCM tag verification failed]"

    if len(plaintext_padded) < 2:
        return "[Error: Decrypted data too short]"
    length = int.from_bytes(plaintext_padded[:2], 'big')
    if length > len(plaintext_padded) - 2:
        return "[Error: Invalid length prefix]"

    plaintext_bytes = plaintext_padded[2:2 + length]

    try:
        decompressed = brotli.decompress(plaintext_bytes)
        plaintext = decompressed.decode('utf-8')
    except Exception as e:
        return f"[Error decompressing or decoding plaintext]: {e}"

    # Securely clear sensitive data
    for k in (aes_key, tf_key, sp_key, hmac_key):
        for i in range(len(k)):
            k[i] = 0

    del aes_key, tf_key, sp_key, hmac_key, salt, aes_iv, aes_tag, tf_iv, sp_iv, hmac_tag, ct3, ct2, pt_aes_ciphertext, plaintext_padded, plaintext_bytes
    gc.collect()

    return plaintext

if __name__ == "__main__":
    print("\nWelcome to the Paradigm 3 Structured Decryption Program.")
    print("Designed by Fenix T. [@failstate]\n")
    message = input("Paste the encrypted message: ")
    password = input("Enter password: ")
    print("\nDecryption Result:")
    print(decrypt(message, password))
