# IDEA algorithm uses 3 basic operations: mul, add and xor

# mul is basically (a * b) % (2^16 + 1)
# However all-zero inputs are interpreted as 2^16 and 2^16 output is interpreted as 0
def idea_mul(a, b):
    if a == 0:
        a = pow(2, 16)
    if b == 0:
        b = pow(2, 16)
    val = (a * b) % (pow(2, 16) + 1)
    if val == pow(2, 16):
        val = 0
    return val


def idea_add(a, b):
    return (a + b) % pow(2, 16)


def idea_xor(a, b):
    return a ^ b


# This method returns 9 sets of keys with 6 keys in each set. Last set has only 4 keys. Total keys generated = 52
def generate_encryption_round_keys(key):
    round_keys = [[0 for i in range(6)] for j in range(9)]
    next_key_id = 0
    next_round_id = 0
    keys_generated = 0
    while True:
        for i in range(8):
            # Since key is a 128-bit value we can get 8 16-bit subkeys from it from left to right
            # Example: on the first iteration we will get these subkeys K1(1) K2(1) K3(1) K4(1) K5(1) K6(1) K1(2) K2(2)
            round_keys[next_round_id][next_key_id] = (key >> (16 * (7 - i))) & 0xFFFF

            # Stop after generating enough keys (52)
            keys_generated += 1
            if keys_generated >= 52:
                return round_keys

            # Each round has 6 keys at most
            next_key_id += 1
            if next_key_id == 6:
                next_key_id = 0
                next_round_id += 1

        # Cyclic shift of key to the left by 25 bits
        bit_amount = 25
        key = (key << bit_amount) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF | key >> (128 - bit_amount)


# Decryption keys are encryption keys but with modifications
# Common modification for all keys is that we swap all keys of round 1 with keys of round 8/9,
# all round 2 keys with round 7/8 keys and so on
def generate_decryption_round_keys(key):
    encrypt_keys = generate_encryption_round_keys(key)
    decrypt_keys = [[0 for i in range(6)] for j in range(9)]

    # Returns modular multiplicative inverse of key by index i,j by module 2^16+1
    def mul_invert(i, j):
        if encrypt_keys[8 - i][j] == 0:
            return 0
        else:
            return pow(encrypt_keys[8 - i][j], -1, pow(2, 16) + 1)

    # Basically returns -K value of K taken from encrypt_keys[i][j] by module 2^16
    def add_invert(i, j):
        return (pow(2, 16) - encrypt_keys[8 - i][j]) % pow(2, 16)

    for i in range(9):
        # 1 / K1
        decrypt_keys[i][0] = mul_invert(i, 0)

        # -K2, -K3
        if i == 0 or i == 8:
            decrypt_keys[i][1] = add_invert(i, 1)
            decrypt_keys[i][2] = add_invert(i, 2)
        else:
            # In all rounds except first and last K2 and K3 also swap places with each other
            decrypt_keys[i][1] = add_invert(i, 2)
            decrypt_keys[i][2] = add_invert(i, 1)

        # 1 / K4
        decrypt_keys[i][3] = mul_invert(i, 3)

        # 5th and 6th keys are only swapped
        decrypt_keys[i][4] = encrypt_keys[7 - i][4]
        decrypt_keys[i][5] = encrypt_keys[7 - i][5]
    return decrypt_keys


def encrypt(data_block, key, to_decrypt=False):
    # Split 64-bit data blocks into 4 16-bit values: db_0, db_1, db_2 and db_3
    global db_0, db_1, db_2, db_3
    db_0 = (data_block >> 48) & 0xFFFF
    db_1 = (data_block >> 32) & 0xFFFF
    db_2 = (data_block >> 16) & 0xFFFF
    db_3 = data_block & 0xFFFF

    # Generate 9 sets of encryption/decryption keys with 6 keys in each round (4 in last)
    round_keys = generate_decryption_round_keys(key) if to_decrypt else generate_encryption_round_keys(key)

    for i in range(8):
        # A = db_0 * K1
        # B = db_1 * K2
        # C = db_2 * K3
        # D = db_3 * K4
        a = idea_mul(db_0, round_keys[i][0])
        b = idea_add(db_1, round_keys[i][1])
        c = idea_add(db_2, round_keys[i][2])
        d = idea_mul(db_3, round_keys[i][3])

        # E = A ^ C
        # F = B ^ D
        e = idea_xor(a, c)
        f = idea_xor(b, d)

        # db_0 = A ^ ((F + E * K5) * K6)
        # db_1 = C ^ ((F + E * K5) * K6)
        # db_2 = B ^ (E * K5 + (F + E * K5) * K6)
        # db_3 = D ^ (E * K5 + (F + E * K5) * K6)
        db_0 = idea_xor(a, idea_mul(idea_add(f, idea_mul(e, round_keys[i][4])), round_keys[i][5]))
        db_1 = idea_xor(c, idea_mul(idea_add(f, idea_mul(e, round_keys[i][4])), round_keys[i][5]))
        db_2 = idea_xor(b, idea_add(idea_mul(e, round_keys[i][4]),
                                    idea_mul(round_keys[i][5], idea_add(f, idea_mul(e, round_keys[i][4])))))
        db_3 = idea_xor(d, idea_add(idea_mul(e, round_keys[i][4]),
                                    idea_mul(round_keys[i][5], idea_add(f, idea_mul(e, round_keys[i][4])))))

    # We skip xor phase in the 9th round and just assign A - D to db_0 - db_4
    db_0 = idea_mul(db_0, round_keys[8][0])
    temp_db_1 = db_1
    db_1 = idea_add(db_2, round_keys[8][1])
    db_2 = idea_add(temp_db_1, round_keys[8][2])
    db_3 = idea_mul(db_3, round_keys[8][3])

    # Debug
    # print(hex(db_0), hex(db_1), hex(db_2), hex(db_3))

    # Combine data 16-bit miniblocks into full 64-bit data block
    db_0 <<= 48
    db_1 <<= 32
    db_2 <<= 16
    encrypted_data = db_0 | db_1 | db_2 | db_3

    # Debug
    # print(hex(encrypted_data))
    return encrypted_data


def decrypt(data_block, key):
    return encrypt(data_block, key, True)


def test():
    key = 0x00010002000300040005000600070008
    data_block = 0x0000000100020003
    # Encrypted data block
    # data_block = 0x11fbed2b01986de5
    encrypt(encrypt(data_block, key), key)
