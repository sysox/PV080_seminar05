#!/usr/bin/env python3
import hashlib
import requests
import secrets

from binascii import hexlify, unhexlify
from typing import Mapping, Union, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as padding_symmetric
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding as padding_asymmetric
from cryptography.hazmat.primitives import hashes

LOCALHOST = "http://127.0.0.1:5000"
SERVER_PATH = "https://pv080.fi.muni.cz"
SEMINAR_PATH = "s04"

SERVER_MESSAGE_PATH = f"{SERVER_PATH}/{SEMINAR_PATH}/message"
SERVER_KEY_PATH = f"{SERVER_PATH}/{SEMINAR_PATH}/key"


def send_message(uco_from: int, uco_to: int, content: bytes) -> str:
    """
    Sends the `content` to pv080.fi.muni.cz/s04 server, where it is readable by
    anyone on the internet.

    :param uco_from: the UCO of the sender
    :param uco_to: the UCO of the receiver
    :param content: the message encoded in bytes

    :return: the textual status of the result of this API call

    Example:
    >>> send_message(uco_from=408788, uco_to=408788, content=b"message")
    'overwritten'
    """
    data = {
        "from": uco_from,
        "to": uco_to,
        "content": hexlify(content).decode(),
    }

    resp = requests.post(
        SERVER_MESSAGE_PATH,
        json=data,
    )

    return resp.json()["status"]


def recv_message(uco: int) -> Mapping[str, Union[int, bytes]]:
    """
    Receive the messages that have been sent to `uco`.

    :param uco: the UCO of the addressee/receiver

    :return: a dictionar where keys are UCO of senders and values are their messages

    Example:
    >>> send_message(uco_from=408788, uco_to=408788, content=b"message")
    'overwritten'
    >>> messages = recv_message(uco=408788)
    >>> message_from_408788 = messages[408788]
    >>> assert message_from_408788 == messages[408788]
    """
    resp = requests.get(
        SERVER_MESSAGE_PATH,
        params={"uco": uco},
    )

    messages = {}
    if resp.status_code == 200:
        data = resp.json()
        for msg in data:
            # NOTE: at the moment there is only a single message per user
            # so no key collisions - apart from no auth/DoS that was there already
            messages[msg["from"]] = unhexlify(msg["content"])

    return messages


def publish_key(uco: int, key: rsa.RSAPublicKey) -> str:
    """
    Publishes the `key` under the `uco` to pv080.fi.muni.cz/s04 server, where it is
    readable by anyone on the internet.

    :param uco: the UCO of the owner of the key
    :param key: the RSA public key of the owner

    :return: the textual status of the result of this API call

    Example:
    >>> from cryptography.hazmat.primitives.asymmetric import rsa
    >>> private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    >>> public_key = private_key.public_key()
    >>> publish_key(uco=408788, key=public_key)
    'overwritten'
    """
    pem_key = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    resp = requests.post(
        SERVER_KEY_PATH,
        json={
            "uco": uco,
            "key": hexlify(pem_key).decode(),
        },
    )
    return resp.json()["status"]


def fetch_key(uco: int) -> Optional[rsa.RSAPublicKey]:
    """
    Fetches the public key associated with the `uco` from pv080.fi.muni.cz/s04.

    :param uco: the UCO of the party we want to communicate with

    Example:
    >>> from cryptography.hazmat.primitives.asymmetric import rsa
    >>> private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    >>> public_key = private_key.public_key()
    >>> publish_key(uco=408788, key=public_key)
    'overwritten'
    >>> assert isinstance(fetch_key(uco=408788), rsa.RSAPublicKey)
    """
    resp = requests.get(
        SERVER_KEY_PATH,
        params={"uco": uco},
    )
    key: Optional[rsa.RSAPublicKey] = None
    data = resp.json()
    if "key" in data:
        key_bytes = bytes.fromhex(data["key"])
        serialized_key = serialization.load_pem_public_key(key_bytes)
        if isinstance(serialized_key, rsa.RSAPublicKey):
            key = serialized_key

    return key


# FIXME 2023: unify key, message vs key, plaintext in RSA
def aes_encrypt(key: bytes, message: bytes) -> bytes:
    """
    Use AES-CBC to encrypt `message` using `key`.

    :param key: the bytes of the key (16, 24, 32 bytes sizes)
    :param message: the message bytes to be encrypted

    :return: the bytes of the ciphertext

    Example:
    >>> import secrets
    >>> key = secrets.token_bytes(16)
    >>> ciphertext = aes_encrypt(key=key, message=b"my message")
    """
    padder = padding_symmetric.PKCS7(128).padder()
    padded_msg = padder.update(message) + padder.finalize()

    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key=key), mode=modes.CBC(iv))
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded_msg) + encryptor.finalize()
    return iv + ciphertext


def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Use AES-CBC to decrypt `ciphertext` using `key`.

    :param key: the bytes of the key (16, 24, 32 bytes sizes)
    :param message: the ciphertext bytes to be decrypted

    :return: the bytes of the plaintext

    Example:
    >>> import secrets
    >>> key = secrets.token_bytes(16)
    >>> message = b"hello world"
    >>> ciphertext = aes_encrypt(key=key, message=message)
    >>> assert message == aes_decrypt(key=key, ciphertext=ciphertext)
    """
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key=key), mode=modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding_symmetric.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


# FIXME for 2023: return Optional[bytes] and return None on encryption failure?
def rsa_encrypt(key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    """
    Use RSA `key` to encrypt the `plaintext`.

    :param key: RSA public key to use for the encryption
    :param plaintext: the plaintext bytes to be encrypted

    :return: the ciphertext bytes

    Example:
    >>> from cryptography.hazmat.primitives.asymmetric import rsa
    >>> private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    >>> public_key = private_key.public_key()
    >>> ciphertext = rsa_encrypt(key=public_key, plaintext=b"hello world")
    """
    ciphertext = key.encrypt(
        plaintext,
        padding_asymmetric.OAEP(
            mgf=padding_asymmetric.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


# FIXME for 2023: return Optional[bytes] and return None on decrypt failure?
def rsa_decrypt(key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """
    Use RSA public `key` to decrypt the `ciphertext`.

    :param key: the RSA private key to use for the decryption
    :param ciphertext: the ciphertext bytes to be decrypted

    :return: the plaintext bytes

    Example:
    >>> from cryptography.hazmat.primitives.asymmetric import rsa
    >>> private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    >>> public_key = private_key.public_key()
    >>> ciphertext = rsa_encrypt(key=public_key, plaintext=b"hello world")
    >>> plaintext = rsa_decrypt(key=private_key, ciphertext=ciphertext)
    >>> assert b"hello world" == plaintext
    """
    plaintext = key.decrypt(
        ciphertext,
        padding_asymmetric.OAEP(
            mgf=padding_asymmetric.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext


def create_mac(key: bytes, data: bytes) -> bytes:
    """
    Calculate Message Authentication Code of `data` (using AES-CBC), i.e.
    encrypt `data` using `key` and AES-CBC with initialization vector
    equal to zero bytes.

    :param key: AES symmetric key
    :param data: the data that will be MAC'ed

    :return: 16 bytes long MAC value

    Example:
    >>> import secrets
    >>> key = secrets.token_bytes(32)
    >>> mac = create_mac(key=key, data=b"some data to MAC")
    """
    padder = padding_symmetric.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # the initialization vector is fixed to zero bytes
    iv = b"\x00" * 16
    cipher = Cipher(algorithms.AES(key=key), mode=modes.CBC(iv))

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # MAC is only the last block, i.e. 16 bytes
    mac = ciphertext[-16:]
    return mac


def verify_mac(key: bytes, data: bytes, mac: bytes) -> bool:
    """
    Verify that the MAC (using AES-CBC) of `data` matches `mac`.

    :param key: AES symmetric key
    :param data: the data that will be MAC'ed
    :param mac: the value against which we verify

    :return: True if the verification succeeds, False otherwise

    Example:
    >>> import secrets
    >>> key = secrets.token_bytes(32)
    >>> data=b"some data to MAC"
    >>> mac = create_mac(key=key, data=data)
    >>> assert verify_mac(key=key, data=data, mac=mac)
    """
    return mac == create_mac(key=key, data=data)


def create_signature(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Use RSA `private_key` to digitally sign of `data`.

    :param private_key: RSA private key
    :param data: the data to be signed

    :return: the bytes of the signature

    Example:
    >>> from cryptography.hazmat.primitives.asymmetric import rsa
    >>> private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    >>> public_key = private_key.public_key()
    >>> signature = create_signature(private_key=private_key, data=b"a contract contents")
    """
    prehashed_msg = hashlib.sha256(data).digest()
    signature = private_key.sign(
        prehashed_msg,
        padding_asymmetric.PSS(
            mgf=padding_asymmetric.MGF1(hashes.SHA256()),
            salt_length=padding_asymmetric.PSS.MAX_LENGTH,
        ),
        utils.Prehashed(hashes.SHA256()),
    )
    return signature


def verify_signature(
    public_key: rsa.RSAPublicKey, data: bytes, signature: bytes
) -> bool:
    """
    Verify that the `signature` of `data` was signed using the RSAPrivateKey
    corresponding to `public_key`.

    :param public_key: the RSAPublicKey to be used for the verification
    :param data: the data that were signed
    :param signature: the bytes of the signature

    Example:
    >>> from cryptography.hazmat.primitives.asymmetric import rsa
    >>> private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    >>> public_key = private_key.public_key()
    >>> data = b"the contract contents"
    >>> signature = create_signature(private_key=private_key, data=data)
    >>> assert verify_signature(public_key=public_key, data=data, signature=signature)
    """
    prehashed_msg = hashlib.sha256(data).digest()
    try:
        public_key.verify(
            signature,
            prehashed_msg,
            padding_asymmetric.PSS(
                mgf=padding_asymmetric.MGF1(hashes.SHA256()),
                salt_length=padding_asymmetric.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(hashes.SHA256()),
        )
        return True
    except:
        return False
