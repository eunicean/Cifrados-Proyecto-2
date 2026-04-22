from dataclasses import dataclass
from base64 import b64encode
from math import gcd, lcm
import secrets
import textwrap
from typing import Dict

@dataclass
class User:

    id: int
    name: str
    email: str
    password: str
    public_key_pem: str
    private_key_pem: str

users_by_email: Dict[str, User] = {}
next_user_id: int = 1

RSA_KEY_SIZE_BITS = 2048
RSA_PUBLIC_EXPONENT = 65537


def is_probable_prime(number: int, rounds: int = 40) -> bool:

    if number < 2:
        return False

    small_primes = (
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
        31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    )

    for prime in small_primes:
        if number == prime:
            return True
        if number % prime == 0:
            return False

    s = 0
    d = number - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(number - 3) + 2
        x = pow(a, d, number)

        if x == 1 or x == number - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, number)
            if x == number - 1:
                break
        else:
            return False

    return True


def generate_large_prime(bits: int, public_exponent: int) -> int:

    while True:
        candidate = secrets.randbits(bits)

        candidate |= (1 << (bits - 1))
        candidate |= 1

        if gcd(public_exponent, candidate - 1) != 1:
            continue

        if is_probable_prime(candidate):
            return candidate


def der_length(length: int) -> bytes:

    if length < 128:
        return bytes([length])

    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(length_bytes)]) + length_bytes


def der_integer(value: int) -> bytes:

    value_bytes = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if value_bytes[0] & 0x80:
        value_bytes = b"\x00" + value_bytes

    return b"\x02" + der_length(len(value_bytes)) + value_bytes


def der_sequence(*items: bytes) -> bytes:

    content = b"".join(items)
    return b"\x30" + der_length(len(content)) + content


def pem_block(label: str, der_bytes: bytes) -> str:

    base64_text = b64encode(der_bytes).decode("ascii")
    wrapped = "\n".join(textwrap.wrap(base64_text, 64))
    return f"-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----\n"


def rsa_public_key_to_pem(n: int, e: int) -> str:

    der = der_sequence(der_integer(n), der_integer(e))
    return pem_block("RSA PUBLIC KEY", der)


def rsa_private_key_to_pem(
    n: int,
    e: int,
    d: int,
    p: int,
    q: int,
    dmp1: int,
    dmq1: int,
    iqmp: int,
) -> str:

    der = der_sequence(
        der_integer(0),
        der_integer(n),
        der_integer(e),
        der_integer(d),
        der_integer(p),
        der_integer(q),
        der_integer(dmp1),
        der_integer(dmq1),
        der_integer(iqmp),
    )
    return pem_block("RSA PRIVATE KEY", der)

def generate_rsa_keypair_pem() -> tuple[str, str]:

    prime_bits = RSA_KEY_SIZE_BITS // 2
    e = RSA_PUBLIC_EXPONENT

    p = generate_large_prime(prime_bits, e)
    q = generate_large_prime(prime_bits, e)
    while p == q:
        q = generate_large_prime(prime_bits, e)

    n = p * q
    lambda_n = lcm(p - 1, q - 1)
    d = pow(e, -1, lambda_n)

    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = pow(q, -1, p)

    public_key_pem = rsa_public_key_to_pem(n, e)
    private_key_pem = rsa_private_key_to_pem(n, e, d, p, q, dmp1, dmq1, iqmp)

    return public_key_pem, private_key_pem

def register_user(name: str, email: str, password: str) -> User:

    global next_user_id

    normalized_email = email.strip().lower()

    if normalized_email in users_by_email:
        raise ValueError("El correo ya esta registrado.")

    public_key_pem, private_key_pem = generate_rsa_keypair_pem()

    user = User(
        id=next_user_id,
        name=name.strip(),
        email=normalized_email,
        password=password,
        public_key_pem=public_key_pem,
        private_key_pem=private_key_pem,
    )

    users_by_email[normalized_email] = user
    next_user_id += 1

    return user


if __name__ == "__main__":
    try:
        new_user = register_user(
            name="Ana Torres",
            email="ana@example.com",
            password="MiPasswordTemporal123",
        )

    except ValueError as exc:
        print(f"Error en registro: {exc}")
