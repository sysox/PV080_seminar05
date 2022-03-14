#!/usr/bin/env python3
import secrets
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from server_communication import rsa_encrypt, rsa_decrypt, aes_encrypt, aes_decrypt


def max_bytes_processed_encryption(num_bits):
    return num_bits // 16 - 33


def max_bytes_processed_decryption(num_bits):
    return num_bits // 8


def RSA_split_end_encrypt(key: rsa.RSAPublicKey, plaintext: bytes):
    block_size = max_bytes_processed_encryption(key.key_size)
    pt_len = len(plaintext)
    CT = b""
    idx = 0
    while idx < pt_len:
        new_block = rsa_encrypt(key, plaintext[idx : min(idx + block_size, pt_len)])
        CT += new_block
        idx += block_size
    return CT


def RSA_split_end_decrypt(key: rsa.RSAPrivateKey, ciphertext: bytes):
    block_size = max_bytes_processed_decryption(key.key_size)
    ct_len = len(ciphertext)
    PT = b""
    idx = 0
    while idx < ct_len:
        new_block = rsa_decrypt(key, ciphertext[idx : min(idx + block_size, ct_len)])
        PT += new_block
        idx += block_size
    return PT


def measure_aes_speed(key: bytes, message: bytes):
    start_encryption = time.time()
    ciphertext = aes_encrypt(key, message)
    print(f"AES encrypt {time.time() - start_encryption} sec")

    start_decryption = time.time()
    aes_decrypt(key, ciphertext)
    print(f"AES decrypt {time.time() - start_decryption} sec")


def measure_rsa_speed(key: rsa.RSAPrivateKey, message: bytes):
    public_key = key.public_key()

    start_encryption = time.time()
    ciphertext = RSA_split_end_encrypt(public_key, message)
    print(f"RSA encrypt {time.time() - start_encryption} sec")

    start_decryption = time.time()
    plaintext = RSA_split_end_decrypt(key, ciphertext)
    print(f"RSA decrypt {time.time() - start_decryption} sec")


if __name__ == "__main__":
    pass
