import math
import click
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

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
def secure_messaging_app():
    session_password = input(f"Enter your shared password: ")


def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode("utf-8")
    public_key = key.publickey().export_key().decode("utf-8")
    return private_key, public_key


def generate_shared_key():
    iv = get_random_bytes(16)
    aes_key = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    


def encrypt_message(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message.encode("utf-8"))


def decrypt_message(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext).decode("utf-8")


def user_one():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ADDRESS, PORT_NUMBER))
    print("Waiting for connection...")
    conn, addr = server.accept()
    print(f"Connection established.")

    while True:
        msg = input("You: ")
        if msg.lower() == "exit":
            break
        conn.sendall(msg.encode())
        data = conn.recv(1024).decode()
        if not data:
            break
        print(f"Friend: {data}")

    conn.close()
    server.close()


def user_two():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ADDRESS, PORT_NUMBER))
    print("Connected.")
    while True:
        data = client.recv(1024).decode()
        if not data:
            break
        print(f"Friend: {data}")
        msg = input("You: ")
        if msg.lower() == "exit":
            break
        client.sendall(msg.encode())

    client.close()


cli.add_command(password_entropy)
cli.add_command(secure_messaging_app)


if __name__ == "__main__":
    cli()
