from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import binascii

def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return private_key

def get_public_key_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

def load_public_key(public_key_bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_bytes)

def encrypt_AES_GCM(data, key):
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return (ciphertext, iv, encryptor.tag)

def decrypt_AES_GCM(ciphertext, key, iv, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def encrypt_ECC(data, public_key):
    private_key = generate_key_pair()
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    ciphertext, iv, tag = encrypt_AES_GCM(data, key)
    return (ciphertext, iv, tag, get_public_key_bytes(private_key.public_key()))

def decrypt_ECC(encrypted_data, private_key):
    (ciphertext, iv, tag, public_key_bytes) = encrypted_data
    public_key = load_public_key(public_key_bytes)
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    return decrypt_AES_GCM(ciphertext, key, iv, tag)
