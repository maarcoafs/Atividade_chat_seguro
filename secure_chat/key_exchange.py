from crypto_utils import generate_rsa_keypair, encrypt_with_rsa, decrypt_with_rsa

def send_public_key(socket, public_key):
    socket.send(public_key.export_key())

def receive_public_key(socket):
    return socket.recv(1024)

def send_encrypted_aes_key(socket, server_public_key, aes_key):
    encrypted_key = encrypt_with_rsa(server_public_key, aes_key)
    socket.send(encrypted_key)

def receive_encrypted_aes_key(socket, private_key):
    encrypted_key = socket.recv(256)
    return decrypt_with_rsa(private_key, encrypted_key)
