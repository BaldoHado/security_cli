import math
import click
import socket
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from functools import lru_cache
import json
import base64

PRINTABLE_CHARS = {
    "capital_letters": {chr(printable_idx) for printable_idx in range(65, 91)},
    "lowercase_letters": {chr(printable_idx) for printable_idx in range(97, 123)},
    "special_characters": {
        *({chr(printable_idx) for printable_idx in range(32, 48)}),
        *({chr(printable_idx) for printable_idx in range(58, 65)}),
        *({chr(printable_idx) for printable_idx in range(91, 97)}),
        *({chr(printable_idx) for printable_idx in range(123, 128)}),
    },
    "numbers": {chr(printable_idx) for printable_idx in range(48, 58)},
}

MAX_PRINTABLE_CHARS = 128 - 32


ADDRESS = "127.0.0.1"
PORT_NUMBER = 6868


def calculate_password_entropy(password: str):
    character_set = {
        "capital_letters": 0,
        "lowercase_letters": 0,
        "special_characters": 0,
        "numbers": 0,
    }
    for letter in password:
        if all(character_set.values()):
            break
        for name, chars in PRINTABLE_CHARS.items():
            if letter in chars:
                character_set[name] = len(chars)
    return math.floor(math.log2((sum(character_set.values()) ** len(password))))


@click.group()
def cli():
    pass


@click.command()
def password_entropy():
    input_pass = input("Enter Password: ")
    entropy = calculate_password_entropy(input_pass)

    print(f"Password Entropy: {entropy} bits")


@click.command()
def SMA():
    session_password = input(f"Enter your shared password: ")
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((ADDRESS, PORT_NUMBER))
        server.listen()
        print("Waiting for connection...")
        conn, _ = server.accept()
        user_one(conn, session_password)
        server.close()
    except socket.error:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ADDRESS, PORT_NUMBER))
        print("Connected.")
        user_two(client, session_password)


def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key


@lru_cache
def generate_shared_key(shared_password: str, salt: bytes):
    return PBKDF2(shared_password, salt, 32, count=10000, hmac_hash_module=SHA256)


def rsa_encrypt_message(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message)


def rsa_decrypt_message(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)


def user_one(conn, shared_password):

    user_one_private_key, user_one_public_key = generate_rsa_keys()
    cbc_iv = get_random_bytes(16)
    public_data = {
        "public_key": base64.b64encode(user_one_public_key.export_key()).decode(),
        "cbc_iv": base64.b64encode(cbc_iv).decode(),
    }

    print(f"Sending public key data and initialization vector AES CBC Encryption...")
    conn.sendall(json.dumps(public_data).encode())

    shared_key = rsa_decrypt_message(user_one_private_key, conn.recv(1024))

    aes_cipher_en = AES.new(shared_key, AES.MODE_CBC, cbc_iv)
    aes_cipher_de = AES.new(shared_key, AES.MODE_CBC, cbc_iv)

    while True:
        msg = input("You: ")
        if msg.lower() == "exit":
            break
        conn.sendall(aes_cipher_en.encrypt(pad(msg.encode(), 16)))
        received_message = unpad(aes_cipher_de.decrypt(conn.recv(1024)), 16).decode()
        if not received_message:
            break
        print(f"Them: {received_message}")

    conn.close()


def user_two(conn, shared_password):

    user_one_public_data = json.loads(conn.recv(1024).decode())

    user_one_public_key, cbc_iv = (
        base64.b64decode(user_one_public_data["public_key"]),
        base64.b64decode(user_one_public_data["cbc_iv"]),
    )
    salt = get_random_bytes(16)
    shared_key = generate_shared_key(shared_password, salt)
    conn.sendall(rsa_encrypt_message(RSA.import_key(user_one_public_key), shared_key))

    aes_cipher_en = AES.new(shared_key, AES.MODE_CBC, cbc_iv)
    aes_cipher_de = AES.new(shared_key, AES.MODE_CBC, cbc_iv)

    while True:
        received_message = unpad(aes_cipher_de.decrypt(conn.recv(1024)), 16).decode()
        if not received_message:
            break
        print(f"Them: {received_message}")
        msg = input("You: ")
        if msg.lower() == "exit":
            break
        conn.sendall(aes_cipher_en.encrypt(pad(msg.encode(), 16)))

    conn.close()


cli.add_command(password_entropy)
cli.add_command(SMA)


if __name__ == "__main__":
    cli()
