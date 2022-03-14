# ---
# jupyter:
#   jupytext:
#     formats: ipynb,py:light
#     text_representation:
#       extension: .py
#       format_name: light
#       format_version: '1.5'
#       jupytext_version: 1.13.7
#   kernelspec:
#     display_name: Python 3 (ipykernel)
#     language: python
#     name: python3
# ---

# + [markdown] heading_collapsed=true
# # Necessary imports
# Run this cell to have all the necessary imports for this seminar.

# + hidden=true
import secrets

from cryptography.hazmat.primitives.asymmetric import rsa

# the API from the previous seminar
from server_communication import aes_encrypt, aes_decrypt, rsa_encrypt, rsa_decrypt
from server_communication import send_message, recv_message, publish_key, fetch_key

# new API functions for this seminar
from server_communication import create_mac, verify_mac
from server_communication import create_signature, verify_signature
from utils import flip_random_bit
from measurements import measure_aes_speed, measure_rsa_speed
# -


# # Part 1: Hybrid encryption - combining RSA and AES

# + [markdown] heading_collapsed=true
# ## Motivation

# + [markdown] hidden=true
# The speed of AES and RSA algorithms differs. While RSA can be used to **share
# a key** publicly, it is not that practical for **large** messages.
#
# RSA works over integers modulo $N$. Therefore larger values have to be
# split into parts and processed separately. Maximal message length is:
#  - 223 bytes for 4096bit RSA key.
#  - 95 bytes for 2048bit RSA key.
#  - 31 bytes for 1024bit RSA key.
#
# We can test the encryption/decryption speed by encrypting messages of
# different sizes. AES encrypts much larger messages in *rougly the same time*.

# + hidden=true
symmetric_key = secrets.token_bytes(16)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

# TODO: play with the length of the message
message_aes = b"\x00" * 10000000
message_rsa = b"\x00" * 20000
print(f"AES message is {len(message_aes)/len(message_rsa) } times larger than RSA.\n")

measure_aes_speed(symmetric_key, message_aes)
measure_rsa_speed(private_key, message_rsa)
# -

# ## Task 1: <font color='gray'>Hybrid communication between a bank and a customer</font>

# Replicate the worked-out paper diagram in front of you. **Decide**, who
# represents which party (we have **the bank** and **the customer**).
#
# Then carry out **the following communication** between the bank and the customer:
#  - The bank publishes an RSA public key.
#  - Use RSA encryption to share a symmetric key.
#  - Use AES to exchange the following messages:
#
# *Bank*: `"What amount do you want to transfer?"`</br>
# *Customer*: `"amount: 000000100.00 USD"`

# TODO: Fill in your and your classmate's UCOs after you've picked
#       your roles (the bank, the customer).
bank_uco = __TODO__
customer_uco = __TODO__

# ### The API and key generation functions

# API functions' signatures:
# ```python
# aes_encrypt(key: bytes, message: bytes) -> bytes
# aes_decrypt(key: bytes, ciphertext: bytes) -> bytes
# rsa_encrypt(key: rsa.RSAPublicKey, plaintext: bytes) -> bytes
# rsa_decrypt(key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes
#
# send_message(uco_from: int, uco_to: int, content: bytes) -> str
# recv_message(uco: int) -> Mapping[str, Union[int, bytes]]
# publish_key(uco: int, key: rsa.RSAPublicKey) -> str
# fetch_key(uco: int) -> Optional[rsa.RSAPublicKey]
# ```
#
# Key generation functions' signatures:
# ```python
# secrets.token_bytes(nbytes:int) -> bytes
# rsa.generate_private_key(public_exponent:int, key_size:int) -> rsa.RSAPrivateKey
# rsa.RSAPrivateKey.public_key() -> rsa.RSAPublicKey
# ```

# ### Bank's point of view

# +
# TODO: Generate a private/public key pair.

# +
# TODO: Publish your public key.

# +
# ...wait.. for the customer's AES key encrypted using your RSA public key
# TODO: Use RSA to decrypt the AES key from the customer and **save** it.


# +
# TODO: Send an AES encrypted question: "What amount do you want to transfer?"

# +
# ...wait.. for the customer's response
# TODO: Use AES to decrypt the response.
# -

# ### Customer's point of view

# +
# ...wait.. for the bank's public key
# TODO: Fetch the bank's public key and save it.

# +
# TODO: Securely generate a new AES key.

# +
# TODO: Encrypt the AES key using bank's public RSA key.
# TODO: Send the encrypted key to the bank.

# +
# ...wait.. for the bank to send you the question
# TODO: Decrypt the bank's question.

# +
# TODO: Send the amount you want to transfer to the bank.
# -

# ## Task 2: <font color='gray'>Issue with message integrity</font>

# Now you will work with the ciphertext corresponding to the encrypted **amount**
# the customer wishes to send. Use `flip_random_bit` to change a single
# bit in the ciphertext and then try to decrypt it. What happens?
#

# +
from utils import flip_random_bit

help(flip_random_bit)
# -

# TODO: Use the encrypted message "amount:..." as the ciphertext
ciphertext = __TODO__
# TODO: Use flip_random_bit to change the original ciphertext and try
#       to decrypt it with the symmetric key. Execute this cell multiple times.
altered_ciphertext = __TODO__
altered_plaintext = aes_decrypt(__TODO__, altered_ciphertext)
# TODO: Compare the expected plaintext and the one you get.

# # Part 2: Message Authentication & Integrity

# ## Task 3: <font color='gray'>Solution #1 Message Authentication Code (MAC)</gray>

# To check the integrity of a message we can **use also the MAC**, concatenated to the **ciphertext**.
# We apply **Encrypt-then-MAC** scheme, i.e. we MAC **the ciphertext** to ensure its integrity.
# Use additional functions:
# ```python
# create_mac(key: bytes, data: bytes) -> bytes
# verify_mac(key: bytes, data: bytes, mac: bytes) -> bool
# ```
#
# **Note:** In a real-world use case we must use a different key for the MAC. Here, we reuse the symmetric key for simplicity.

# +
# [OPTIONAL TODO]: Check the source code of the `create_mac` function. Is it familiar?
import inspect

print(inspect.getsource(create_mac))
# -

# **Task:** Try sending the message with the "amount: ..." again, but this time **include the MAC**

# ### Customer's point of view

# +
# TODO: Encrypt the "amount: ... " message.

# +
# TODO: Create the MAC value.

# +
# TODO: Send `mac + ciphertext` to the bank.
# -

# ### Bank's point of view

# +
# TODO: Receive the new encrypted message with the MAC prefixed.

# +
# TODO: The MAC is a single block of data prepended to the ciphertext.
#       Therefore you need to split the message into 16B `mac` and the ciphertext,
#       which is the rest of the data.
# TODO: Verify the MAC using `verify_mac`
# TODO: Only if the MAC verifies, decrypt the ciphertext using the symmetric key.
# -

# ## Task 4: <font color='gray'>Solution #2 Digital Signature</gray>

# Instead of sending a MAC of the message, the sender (the customer in our example)
# can **digitally sign** the message and the receiver (the bank) can **verify the signature**.
# Use additional functions `create_signature` and `verify_signature`:
# ```python
# create_signature(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes
# verify_signature(
#     public_key: rsa.RSAPublicKey, data: bytes, signature: bytes
# ) -> bool
# ```

# **Task:** Try sending the message with the "amount: ..." again, but this time **include the digital signature**

# ### Customer's point of view

# +
# TODO: Generate an RSA private/public keypair for signing.

# +
# TODO: Publish your public RSA key.

# +
# TODO: Create a signature of the encrypted message with the "amount: ...".
# TODO: Send both the `signature + ciphertext`.
# -

# ### Bank's point of view

# TODO: Fetch customer's public key.
customer_public_key = __TODO__
# TODO: Receive customers signature and message.
# TODO: Split the received data into the signature,
#       which is `customer_key.key_size // 8` bytes long and
#       into the actual ciphertext, which is the rest.
signature_byte_size = customer_public_key.key_size // 8
# TODO: Only if the signature verifies, you may decrypt the ciphertext.
