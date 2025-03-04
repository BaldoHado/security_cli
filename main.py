import math
import click
import socket
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import sys
import json
import base64
import threading


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


@click.command(help="Password entropy checking tool")
def pe():
    input_pass = input("Enter Password: ")
    entropy = calculate_password_entropy(input_pass)

    print(f"Password Entropy: {entropy} bits")


@click.command(help="Secure messaging tool")
def sm():
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


def generate_shared_key(shared_password: str):
    sha_256 = SHA256.new()
    sha_256.update(shared_password.encode())
    return sha_256.digest()


def rsa_encrypt_message(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message)


def rsa_decrypt_message(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)


def receive_messages(conn, aes_cipher_de):
    while True:
        try:
            encrypted_message = conn.recv(1024)
            if not encrypted_message:
                break
            message = unpad(aes_cipher_de.decrypt(encrypted_message), 16).decode()
            print(f"\nThem: {message}\nYou: ", end="", flush=True)
        except Exception as e:
            print(f"Error receiving message: {e}")
            break


def send_messages(conn, aes_cipher_en):
    while True:
        try:
            msg = input("You: ")
            if msg.lower() == "exit":
                conn.close()
                sys.exit(0)
            conn.sendall(aes_cipher_en.encrypt(pad(msg.encode(), 16)))
        except Exception as e:
            print(f"Error sending message: {e}")
            break


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
    if shared_key != generate_shared_key(shared_password):
        print(f"Shared passwords do not match. Exiting...")
        sys.exit(1)

    aes_cipher_en = AES.new(shared_key, AES.MODE_CBC, cbc_iv)
    aes_cipher_de = AES.new(shared_key, AES.MODE_CBC, cbc_iv)

    recv_thread = threading.Thread(
        target=receive_messages, args=(conn, aes_cipher_de), daemon=True
    )
    send_thread = threading.Thread(
        target=send_messages, args=(conn, aes_cipher_en), daemon=True
    )

    recv_thread.start()
    send_thread.start()

    send_thread.join()


def user_two(conn, shared_password):

    user_one_public_data = json.loads(conn.recv(1024).decode())

    user_one_public_key, cbc_iv = (
        base64.b64decode(user_one_public_data["public_key"]),
        base64.b64decode(user_one_public_data["cbc_iv"]),
    )
    shared_key = generate_shared_key(shared_password)
    conn.sendall(rsa_encrypt_message(RSA.import_key(user_one_public_key), shared_key))

    aes_cipher_en = AES.new(shared_key, AES.MODE_CBC, cbc_iv)
    aes_cipher_de = AES.new(shared_key, AES.MODE_CBC, cbc_iv)

    recv_thread = threading.Thread(
        target=receive_messages, args=(conn, aes_cipher_de), daemon=True
    )
    send_thread = threading.Thread(
        target=send_messages, args=(conn, aes_cipher_en), daemon=True
    )

    recv_thread.start()
    send_thread.start()

    send_thread.join()


cli.add_command(pe)
cli.add_command(sm)


if __name__ == "__main__":
    cli()
