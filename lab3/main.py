import math

# RSA cryptanalysis using Fermat factorization
# This cryptanalysis is possible if [p] and [q] are "too close" to each other

# To decrypt a message we need to know encrypted message, [N] and [e]
N = 81177745546021
e = 2711039
encrypted_blocks = [61553353723258,
                    11339642237403,
                    55951185642146,
                    38561524032018,
                    34517298669793,
                    33641624424571,
                    78428225355946,
                    50176820404544,
                    68017840453091,
                    5507834749606,
                    26675763943141,
                    47457759065088]

# Fermat's factorization method is based on representation of an odd integer as the difference of two squares
# N = a^2 - b^2
# We need to try many different [a]s hoping to make this equation true
# a^2 - N = b^2 where [b] is a square of an integer

# Start the search with sqrt(N), the least possible [a] where a^2 - N >= 0
a = math.ceil(math.sqrt(N)) + 1

# b^2 = a^2 - N; b = sqrt(a^2 - N)
b = math.sqrt(pow(a, 2) - N)

while not b.is_integer():
    # Try out next [a]
    a += 1
    b = math.sqrt(pow(a, 2) - N)

# N = a^2 - b^2 -> N = (a - b)(a + b)
p = a + b
q = a - b

# Calculating Euler's totient function
phi_n = (p - 1) * (q - 1)

# Decryption key is a modular multiplicative inverse of [e] by modulo [phi]
d = pow(int(e), -1, int(phi_n))

for block in encrypted_blocks:
    # Once you know [d] decryption is simple
    # decrypted block = encrypted_block^d mod N
    res = pow(block, d, N)

    # Split decrypted block into 4 bytes
    result_bytes = bytearray([(res >> 24) & 0xFF, (res >> 16) & 0xFF, (res >> 8) & 0xFF, res & 0xFF])

    # Decode decrypted bytes via WINDOWS-1251
    print(result_bytes.decode("WINDOWS-1251"))
