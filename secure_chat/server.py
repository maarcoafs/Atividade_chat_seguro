import socket, threading
from config import HOST, PORT
from key_exchange import *
from crypto_utils import generate_rsa_keypair
from protocol import read_secure_message
from Crypto.PublicKey import RSA

private_key, public_key = generate_rsa_keypair()

def handle_client(conn):
    print("[+] Cliente conectado")
    send_public_key(conn, public_key)

    symmetric_key = receive_encrypted_aes_key(conn, private_key)
    print("[✓] Chave simétrica recebida")

    client_pub_data = conn.recv(1024)
    client_public_key = RSA.import_key(client_pub_data)
    print("[✓] Chave pública do cliente recebida")

    while True:
        try:
            data = conn.recv(2048)
            if not data:
                break
            plaintext = read_secure_message(symmetric_key, data, client_public_key)
            print("Cliente:", plaintext.decode())
        except Exception as e:
            print("[!] Erro:", e)
            break

    conn.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

print(f"[+] Servidor escutando em {HOST}:{PORT}")
while True:
    conn, _ = server.accept()
    threading.Thread(target=handle_client, args=(conn,)).start()
