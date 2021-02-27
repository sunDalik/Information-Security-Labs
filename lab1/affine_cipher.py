import argparse
import math

# Affine Cipher is a generalization of Caesar Cipher
# Caesar Cipher encryption looks like this j1 = (j + b) % n
# While Affine Cipher encryption looks like j1 = (a * j + b) % n
# So Caesar Cipher is Affine Cipher with a = 1

alphabet = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
            'V', 'W', 'X', 'Y', 'Z']

# Size of the alphabet
n = len(alphabet)


def are_coprime_integers(a, b):
    # Integers are considered coprime if their only common denominator is 1
    return math.gcd(a, b) == 1


def encrypt_char(c, a, b):
    j = alphabet.index(c)
    # Multiply char index by [a] and shift it by [b]
    return alphabet[(a * j + b) % n]


def decrypt_char(c, a, b):
    j = alphabet.index(c)
    # [a2] is a modular multiplicative inverse of [a] by modulo [n]
    a2 = pow(a, -1, n)
    return alphabet[((j - b + n) * a2) % n]


def main():
    # Encrypt the message in file [filename] by default, use -d if you wish to decrypt instead
    # Outputs result message to stdout
    # Affine cipher uses two keys: [a] and [b]
    usage = 'affine_cipher.py filename a b [-d]'
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument('filename', action='store')
    parser.add_argument("a", action="store", type=int)
    parser.add_argument("b", action="store", type=int)
    parser.add_argument("-d", '--decrypt', action="store_true", dest="decrypt", default=False)
    args = parser.parse_args()

    # [a] and [n] MUST be coprime for modular multiplicative inverse of [a] to exist
    if not are_coprime_integers(args.a, n):
        print("a and n must be coprime integers!")
        return

    new_message = ''
    with open(args.filename) as message:
        while True:
            # Process text file char by char
            c = message.read(1)

            # Stop reading file when it ends
            if not c:
                break

            # Do not encode a character if it's not in the alphabet
            if c not in alphabet:
                new_message += c
                continue

            # Encrypt / decrypt character
            if args.decrypt:
                new_message += decrypt_char(c, args.a, args.b)
            else:
                new_message += encrypt_char(c, args.a, args.b)

    print(new_message)


main()
