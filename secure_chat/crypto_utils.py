from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, HMAC
from Crypto.Signature import pkcs1_15

def generate_rsa_keypair():
    key = RSA.generate(2048)
    return key, key.publickey()

def encrypt_with_rsa(public_key, data):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)

def decrypt_with_rsa(private_key, data):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(data)

def generate_aes_key():
    return get_random_bytes(16)

def encrypt_aes(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext

def decrypt_aes(key, combined):
    nonce = combined[:16]
    tag = combined[16:32]
    ciphertext = combined[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def generate_hmac(key, data):
    h = HMAC.new(key, data, digestmod=SHA256)
    return h.digest()

def verify_hmac(key, data, mac):
    h = HMAC.new(key, data, digestmod=SHA256)
    h.verify(mac)

def sign_data(private_key, data):
    h = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(public_key, data, signature):
    h = SHA256.new(data)
    pkcs1_15.new(public_key).verify(h, signature)
