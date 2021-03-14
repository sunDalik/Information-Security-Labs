# RSA cryptanalysis when you have 2 messages with the same [N] and different [e]s

N = 392117053283
e1 = 744721
e2 = 1297633
encrypted_blocks_1 = [188779427301,
                      142624237358,
                      222856552604,
                      64779987640,
                      184552630472,
                      357891671735,
                      159800573947,
                      320365191568,
                      53704108470,
                      29809614757,
                      236651896578,
                      5185872557,
                      374026260505
                      ]

encrypted_blocks_2 = [330155414629,
                      183843269790,
                      113231290101,
                      381735803560,
                      115846890704,
                      117837936469,
                      188064551177,
                      241636957582,
                      253908524873,
                      219235963059,
                      333424804843,
                      278400905892,
                      254102728294]


# Solve equation r*a + s*b = 1
def solve_rs(a, b):
    # Simply brute-force it by trying all [r]s
    r = 0
    while True:
        # r*a + s*b = 1 -> s = (1 - r*a)/b
        s = (1 - r * a) / b

        # [r] and [s] must be integer
        if s.is_integer():
            return int(r), int(s)
        r += 1


# Solve r*e1 + s*e2 = 1
r, s = solve_rs(e1, e2)

for i in range(len(encrypted_blocks_1)):
    # Decrypted block x = y_1^r * y_2^s
    res = (pow(encrypted_blocks_1[i], r, N) * pow(encrypted_blocks_2[i], int(s), N)) % N

    # Split decrypted block into 4 bytes and decode using WINDOWS-1251 encoding
    result_bytes = bytearray([(res >> 24) & 0xFF, (res >> 16) & 0xFF, (res >> 8) & 0xFF, res & 0xFF])
    print(result_bytes.decode("WINDOWS-1251"), end="")
