import socket
from config import HOST, PORT
from key_exchange import *
from crypto_utils import generate_aes_key, generate_rsa_keypair
from protocol import prepare_secure_message
from Crypto.PublicKey import RSA

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# Geração de chaves
private_key, public_key = generate_rsa_keypair()

server_pub = RSA.import_key(receive_public_key(client))
aes_key = generate_aes_key()
send_encrypted_aes_key(client, server_pub, aes_key)

print("[✓] Chave simétrica enviada")

# Envia a chave pública do cliente para autenticação
client.send(public_key.export_key())
print("[✓] Chave pública enviada")

while True:
    msg = input("Você: ").encode()
    secure_data = prepare_secure_message(aes_key, msg, private_key)
    client.send(secure_data)
