import secrets
import random

from server_communication import aes_encrypt, aes_decrypt
from server_communication import rsa_encrypt, rsa_decrypt
from server_communication import create_mac, verify_mac
from server_communication import create_signature, verify_signature
from cryptography.hazmat.primitives.asymmetric import rsa

import pytest


@pytest.mark.parametrize("key_size", [16, 24, 32])
def test_aes_encrypt_decrypt_roundtrip(key_size: int):
    for _ in range(10):
        # generate a random message of random length
        message_length = random.randint(0, 2 ** 16)
        message = secrets.token_bytes(message_length)

        key = secrets.token_bytes(key_size)
        # test encrypt/decrypt roundtrip
        ciphertext = aes_encrypt(key=key, message=message)
        plaintext = aes_decrypt(key=key, ciphertext=ciphertext)
        assert message == plaintext


@pytest.mark.parametrize(
    "public_exponent,key_size",
    [
        (3, 1024),
        (3, 2048),
        (65537, 1024),
        (65537, 2048),
    ],
)
def test_rsa_encrypt_decrypt_roundtrip(public_exponent: int, key_size: int):
    for _ in range(10):
        # generate a random message shorter than the key size
        message = secrets.token_bytes(key_size // 32)

        privkey = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size,
        )
        pubkey = privkey.public_key()

        ciphertext = rsa_encrypt(key=pubkey, plaintext=message)
        plaintext = rsa_decrypt(key=privkey, ciphertext=ciphertext)

        assert message == plaintext


@pytest.mark.parametrize("key_size", [16, 24, 32])
def test_mac_verification(key_size: int):
    for _ in range(10):
        key = secrets.token_bytes(key_size)
        length = random.randint(0, 2 ** 16)
        data = secrets.token_bytes(length)

        mac = create_mac(key=key, data=data)
        assert verify_mac(key=key, data=data, mac=mac)


@pytest.mark.parametrize(
    "public_exponent,key_size",
    [
        (3, 1024),
        (3, 2048),
        (65537, 1024),
        (65537, 2048),
    ],
)
def test_digital_signatures(public_exponent: int, key_size: int):
    for _ in range(10):
        length = random.randint(0, 2 ** 16)
        data = secrets.token_bytes(length)

        privkey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        pubkey = privkey.public_key()

        signature = create_signature(private_key=privkey, data=data)
        assert verify_signature(public_key=pubkey, data=data, signature=signature)
