import random


def mod_exp(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent //= 2
        base = (base * base) % modulus
    return result


def generate_keys():
    # Step 1: Choose a large prime number
    p = int(input("Enter a large prime number (p): "))

    # Step 2: Choose a primitive root modulo p
    g = int(input("Enter a primitive root modulo p (g): "))

    # Step 3: Choose a private key (a)
    a = random.randint(2, p - 2)

    # Step 4: Calculate the public key (A)
    A = mod_exp(g, a, p)

    return p, g, a, A


def encrypt(message, p, g, A):
    # Step 1: Choose a random number (k)
    k = random.randint(2, p - 2)

    # Step 2: Calculate the temporary public key (B)
    B = mod_exp(g, k, p)

    # Step 3: Calculate the shared secret (s)
    s = mod_exp(A, k, p)

    # Step 4: Convert the message to a number (m)
    m = int.from_bytes(message.encode(), 'big')

    # Step 5: Calculate the ciphertext
    c1 = mod_exp(g, k, p)
    c2 = (m * s) % p

    return (c1, c2)


def decrypt(ciphertext, p, a):
    # Step 1: Extract the components of the ciphertext
    c1, c2 = ciphertext

    # Step 2: Calculate the shared secret (s)
    s = mod_exp(c1, a, p)

    # Step 3: Calculate the modular inverse of s
    s_inv = pow(s, -1, p)

    # Step 4: Calculate the plaintext
    m = (c2 * s_inv) % p

    # Step 5: Convert the plaintext to a string
    message = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()

    return message


def main():
    p, g, a, A = generate_keys()

    print(f"Public Key (p, g, A): ({p}, {g}, {A})")
    print(f"Private Key (a): {a}")

    message = input("Enter the message to encrypt: ")

    # Encryption
    ciphertext = encrypt(message, p, g, A)
    print(f"Ciphertext: {ciphertext}")

    # Decryption
    decrypted_message = decrypt(ciphertext, p, a)
    print(f"Decrypted Message: {decrypted_message}")


if __name__ == "__main__":
    main()
