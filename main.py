import math
import click
import socket
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
import sys
import json
import base64
import threading
from typing import Tuple
from textwrap import dedent
from loguru import logger


CHARACTER_SETS = {
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

WELCOME_MESSAGE = """Welcome to the secure messaging application. 
Start typing below to send messages. 
Messages received will be red."""


@click.group()
def cli():
    pass


@click.command(help="Password entropy checking tool")
def pe():
    """
    CLI Function for processing the pe (password entropy) subcommand.
    """
    input_pass = input("Enter Password: ")
    entropy = calculate_password_entropy(input_pass)

    logger.info(f"Password Entropy: {entropy} bits")


@click.command(help="Secure messaging tool")
def sm():
    """
    CLI Function for processing the sm (secure messaging) subcommand.
    """
    session_password = input(f"Enter your shared password: ")
    if (entropy_bits := calculate_password_entropy(session_password)) < 75:
        logger.error(
            f"Your password is too weak! Requires at least 75 bits of entropy. The input password had {entropy_bits} bits of entropy."
        )
        sys.exit(1)
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((ADDRESS, PORT_NUMBER))
        server.listen()
        logger.info("Waiting for connection...")
        conn, _ = server.accept()
        user_one(conn, session_password)
        server.close()
    except socket.error:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ADDRESS, PORT_NUMBER))
        logger.info("Connected.")
        user_two(client, session_password)


def calculate_password_entropy(password: str):
    """
    Main function for calculating password entropy.
    Entropy is calculated with the formula: log2(R^L)

    Args:
        password (str): The password to evaluate.
    """
    character_set = {
        "capital_letters": 0,
        "lowercase_letters": 0,
        "special_characters": 0,
        "numbers": 0,
    }
    for letter in password:
        if all(character_set.values()):
            break
        for name, chars in CHARACTER_SETS.items():
            if letter in chars:
                character_set[name] = len(chars)
    return math.floor(math.log2((sum(character_set.values()) ** len(password))))


def generate_rsa_keys() -> Tuple[RSA.RsaKey, RSA.RsaKey]:
    """
    Generates public and private RSA keys.
    """
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key


def calculate_sha256_hash(message: str) -> bytes:
    """
    Calculates the SHA256 hash of a message.

    Args:
        message (str): The message to hash.
    """
    sha_256 = SHA256.new()
    sha_256.update(message.encode())
    return sha_256.digest()


def calculate_sha256_hash_object(message: str) -> bytes:
    """
    Calculates the SHA256 hash of a message.

    Args:
        message (str): The message to hash.
    """
    return SHA256.new(message.encode())


def rsa_encrypt_message(public_key: RSA.RsaKey, message: str) -> bytes:
    """
    Uses RSA to encrypt a plaintext message.

    Args:
        public_key (RsaKey): The public key to use for encryption.
        message (str): The message to encrypt.
    """
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message)


def rsa_decrypt_message(private_key: RSA.RsaKey, ciphertext: bytes):
    """
    Uses RSA to decrypt a hidden message.

    Args:
        private_key (RsaKey): The private key to use for decryption.
        ciphertext (bytes): The ciphertext to decrypt.
    """
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)


def receive_messages(
    conn: socket.socket,
    aes_cipher_de: AES,
    rsa_public_key: RSA.RsaKey,
    terminate_event: threading.Event,
):
    """
    Receives messages, decrypts and unpads them with a shared key and prints to stdout.

    Args:
        conn (socket): The socket connection to receive messages from.
        aes_cipher_de (AES): The decrypt cipher to use for AES decryption.
        rsa_public_key (RsaKey): The other user's RSA public key for verifying the digital signature.
    """
    while True:
        try:
            encrypted_message = conn.recv(1024)
            if not encrypted_message:
                break
            message = json.loads(
                unpad(aes_cipher_de.decrypt(encrypted_message), 16).decode()
            )
            plaintext = base64.b64decode(message["message"]).decode()
            signature = base64.b64decode(message["signature"])
            try:
                pkcs1_15.new(rsa_public_key).verify(
                    calculate_sha256_hash_object(plaintext), signature
                )
            except (ValueError, TypeError):
                logger.error("Invalid Signature! Exiting...")
                sys.exit(1)
            click.echo(click.style(plaintext, fg="bright_red"))
            sys.stdout.flush()
        except Exception as e:
            terminate_event.set()
            sys.exit(0)


def send_messages(
    conn: socket.socket,
    aes_cipher_en: AES,
    rsa_private_key: RSA.RsaKey,
    terminate_event: threading.Event,
):
    """
    Pads and encrypts a message using AES and sends it through the connection provided.

    Args:
        conn (socket): The socket connection to send messages to.
        aes_cipher_en (AES): The encrypt cipher to use for AES encryption.
        rsa_private_key (RsaKey): The sending user's private key to sign the digital signature.
    """
    while True:
        try:
            msg = input()
            if terminate_event.is_set():
                logger.info("The other user disconnected. Exiting...")
                conn.close()
                terminate_event.set()
                sys.exit(0)
            if msg.lower() == "exit":
                logger.info("Exiting...")
                conn.close()
                terminate_event.set()
                sys.exit(0)
            payload = {
                "message": base64.b64encode(msg.encode()).decode(),
                "signature": base64.b64encode(
                    pkcs1_15.new(rsa_private_key).sign(
                        calculate_sha256_hash_object(msg)
                    )
                ).decode(),
            }
            conn.sendall(aes_cipher_en.encrypt(pad(json.dumps(payload).encode(), 16)))
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            break


def user_one(conn: socket.socket, shared_password: str):
    """
    Workflow for first user to establish a shared password over an insecure channel.

    Args:
        conn (socket): The connection to send/receive messages from.
        shared_password (str): The shared password that user one inputted.
    """
    user_one_private_key, user_one_public_key = generate_rsa_keys()
    cbc_iv = get_random_bytes(16)
    public_data = {
        "public_key": base64.b64encode(user_one_public_key.export_key()).decode(),
        "cbc_iv": base64.b64encode(cbc_iv).decode(),
    }

    logger.info(f"Sending RSA public key and IV...")
    conn.sendall(json.dumps(public_data).encode())

    user_two_public_key = RSA.import_key(
        base64.b64decode(json.loads(conn.recv(1024).decode())["public_key"])
    )
    logger.info(f"Received other user's public key.")

    shared_key = rsa_decrypt_message(user_one_private_key, conn.recv(1024))
    if shared_key != calculate_sha256_hash(shared_password):
        logger.error("Passwords do not match. Exiting...")
        conn.sendall(b"TERMINATE")
        conn.close()
        sys.exit(1)
    else:
        conn.sendall(b"CONTINUE")
    logger.info(f"Secure communication established with other user.")
    aes_cipher_en = AES.new(shared_key, AES.MODE_CBC, cbc_iv)
    aes_cipher_de = AES.new(shared_key, AES.MODE_CBC, cbc_iv)
    click.echo(
        click.style(
            dedent(WELCOME_MESSAGE),
            fg="cyan",
        )
    )
    terminate_event = threading.Event()
    recv_thread = threading.Thread(
        target=receive_messages,
        args=(conn, aes_cipher_de, user_two_public_key, terminate_event),
        daemon=True,
    )
    send_thread = threading.Thread(
        target=send_messages,
        args=(conn, aes_cipher_en, user_one_private_key, terminate_event),
        daemon=True,
    )

    recv_thread.start()
    send_thread.start()

    send_thread.join()


def user_two(conn: socket.socket, shared_password: str):
    """
    Workflow for second user to establish a shared password over an insecure channel.

    Args:
        conn (socket): The connection to send/receive messages from.
        shared_password (str): The shared password that user two inputted.
    """
    user_two_private_key, user_two_public_key = generate_rsa_keys()
    user_one_public_data = json.loads(conn.recv(1024).decode())
    logger.info(f"Received other user's public key and IV.")
    user_one_public_key, cbc_iv = (
        RSA.import_key(base64.b64decode(user_one_public_data["public_key"])),
        base64.b64decode(user_one_public_data["cbc_iv"]),
    )

    public_data = {
        "public_key": base64.b64encode(user_two_public_key.export_key()).decode(),
    }

    logger.info(f"Sending RSA public key...")
    conn.sendall(json.dumps(public_data).encode())

    shared_key = calculate_sha256_hash(shared_password)
    conn.sendall(rsa_encrypt_message(user_one_public_key, shared_key))
    if conn.recv(1024).decode() == "TERMINATE":
        logger.error("Passwords do not match. Exiting...")
        conn.close()
        sys.exit(1)
    logger.info(f"Secure communication established with other user.")
    aes_cipher_en = AES.new(shared_key, AES.MODE_CBC, cbc_iv)
    aes_cipher_de = AES.new(shared_key, AES.MODE_CBC, cbc_iv)
    click.echo(
        click.style(
            dedent(WELCOME_MESSAGE),
            fg="cyan",
        )
    )
    terminate_event = threading.Event()
    recv_thread = threading.Thread(
        target=receive_messages,
        args=(conn, aes_cipher_de, user_one_public_key, terminate_event),
        daemon=True,
    )
    send_thread = threading.Thread(
        target=send_messages,
        args=(conn, aes_cipher_en, user_two_private_key, terminate_event),
        daemon=True,
    )

    recv_thread.start()
    send_thread.start()

    send_thread.join()


cli.add_command(pe)
cli.add_command(sm)


if __name__ == "__main__":
    cli()
