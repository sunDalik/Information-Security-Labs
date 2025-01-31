# RSA cryptanalysis via Chinese remainder theorem
# This cryptanalysis is possible when multiple users have the same [e] and different relatively prime [N]s

N1 = 431972773933
N2 = 432558060211
N3 = 434276528083
e = 3
encrypted_blocks_1 = [43268974598,
                      302331913599,
                      47134049761,
                      126642563008,
                      165827503054,
                      232086597542,
                      31465887151,
                      30373336865,
                      284998624093,
                      89084365158,
                      322533676789,
                      383736009455,
                      108545189851]

encrypted_blocks_2 = [330701159000,
                      104807592171,
                      45038416117,
                      81063981859,
                      427734601871,
                      27505991527,
                      81910363197,
                      190166502949,
                      116404011104,
                      249933949107,
                      90486698466,
                      206265723002,
                      276536042468]

encrypted_blocks_3 = [269237460393,
                      165034165638,
                      207280715083,
                      151936477226,
                      7495879547,
                      141105308724,
                      316939568874,
                      360819196331,
                      46940627813,
                      137301580237,
                      168518778628,
                      113124777920,
                      282998095133]

for i in range(len(encrypted_blocks_1)):
    M0 = N1 * N2 * N3

    m1 = N2 * N3
    m2 = N1 * N3
    m3 = N1 * N2

    n1 = pow(m1, -1, N1)
    n2 = pow(m2, -1, N2)
    n3 = pow(m3, -1, N3)

    # S = y1*n1*m1 + y2*n2*m2
    S = encrypted_blocks_1[i] * n1 * m1 + encrypted_blocks_2[i] * n2 * m2 + encrypted_blocks_3[i] * n3 * m3

    # Decrypted block x = (s mod M0)^(1/e)
    res = round(pow(S % M0, 1 / e))

    # Split decrypted block into 4 bytes and decode using WINDOWS-1251 encoding
    result_bytes = bytearray([(res >> 24) & 0xFF, (res >> 16) & 0xFF, (res >> 8) & 0xFF, res & 0xFF])
    print(result_bytes.decode("WINDOWS-1251"), end="")
