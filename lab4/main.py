# RSA cryptanalysis via re-encryption

N = 290716329017
e = 497729
encrypted_blocks = [1135414239,
                    169213008965,
                    175441050863,
                    109545918774,
                    123669279758,
                    149542889269,
                    43068653151,
                    32806195453,
                    285151390718,
                    137668394392,
                    140567677417,
                    176736386447,
                    218957656245]

for block in encrypted_blocks:
    # First, take the encrypted block. We are then going to encrypt it multiple times until we eventually decrypt it
    prev_y = block
    res = 0

    while True:
        # y_i = y_(i-1)^e mod N
        y = pow(prev_y, e, N)

        # Once we found [y_i] that is equal to encrypted block we can say that [y_(i-1)] is the decrypted block
        if y == block:
            res = prev_y

            # Split decrypted block into 4 bytes and decode using WINDOWS-1251 encoding
            result_bytes = bytearray([(res >> 24) & 0xFF, (res >> 16) & 0xFF, (res >> 8) & 0xFF, res & 0xFF])
            print(result_bytes.decode("WINDOWS-1251"), end="")
            break
        else:
            # Otherwise calculate next [y] and use current [y] as the previous [y]
            prev_y = y
