from crypto_utils import encrypt_aes, decrypt_aes, generate_hmac, verify_hmac
from crypto_utils import sign_data, verify_signature

def prepare_secure_message(aes_key, plaintext, private_key):
    ciphertext = encrypt_aes(aes_key, plaintext)
    mac = generate_hmac(aes_key, ciphertext)
    signature = sign_data(private_key, ciphertext)
    return ciphertext + mac + signature

def read_secure_message(aes_key, data, public_key):
    ciphertext = data[:-32-256]
    mac = data[-32-256:-256]
    signature = data[-256:]

    verify_hmac(aes_key, ciphertext, mac)
    verify_signature(public_key, ciphertext, signature)

    return decrypt_aes(aes_key, ciphertext)
