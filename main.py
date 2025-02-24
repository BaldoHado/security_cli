import math
import sys
import click

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
    pass


cli.add_command(password_entropy)
cli.add_command(secure_messaging_app)


if __name__ == "__main__":
    cli()
