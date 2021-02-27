import secrets


# secrets_storage is an object where .key, .init_vector and .size will be stored
def encrypt_data(data, encryption_algorithm, secrets_storage):
    # Generate 128-bit key used in encryption_algorithm and Initialization Vector used in PCBC encryption
    key = secrets.randbits(128)
    init_vector = secrets.randbits(64)

    # Offset in data
    offset = 0

    # (plain data ^ encrypted data) of the previous block. Equals to Initialization Vector at the start
    prev_block = init_vector

    # Size of the original data
    # We must remember original size because encrypted data will be padded with zeroes to be a multiple of 64
    size = len(data)

    encrypted_data = bytearray()

    while True:
        # Block size is 64 bits or 8 bytes
        block_size = 8

        # Last block size might be lesser than 64 bits and if that's the case we add padding
        data_block_size = min(block_size, len(data) - offset)
        # Amount of padding bytes to add
        padding_needed = block_size - data_block_size

        # Extract 64-bit block from data by offset
        block = int.from_bytes(data[offset: offset + block_size], byteorder="big")
        block <<= 8 * padding_needed

        # Xor with prev_block before encryption
        encrypted_block = encryption_algorithm(block ^ prev_block, key)

        # Write all bytes of the encrypted block to the output data
        encrypted_data.append((encrypted_block >> 56) & 0xFF)
        encrypted_data.append((encrypted_block >> 48) & 0xFF)
        encrypted_data.append((encrypted_block >> 40) & 0xFF)
        encrypted_data.append((encrypted_block >> 32) & 0xFF)
        encrypted_data.append((encrypted_block >> 24) & 0xFF)
        encrypted_data.append((encrypted_block >> 16) & 0xFF)
        encrypted_data.append((encrypted_block >> 8) & 0xFF)
        encrypted_data.append(encrypted_block & 0xFF)

        # Plain data ^ encrypted data
        prev_block = block ^ encrypted_block

        # Move offset to the next block. Stop encryption if we reached the end of the data.
        offset += block_size
        if offset >= len(data):
            break

    # Store generated secrets in the provided object
    secrets_storage.key = key
    secrets_storage.init_vector = init_vector
    secrets_storage.size = size

    return encrypted_data


def decrypt_data(data, decryption_algorithm, key, init_vector, size):
    offset = 0
    prev_block = init_vector
    decrypted_data = bytearray()

    while True:
        block_size = 8

        # Extract 64-bit block from data by offset
        encrypted_block = int.from_bytes(data[offset: offset + block_size], byteorder="big")

        decrypted_block = decryption_algorithm(encrypted_block, key)
        # To fully decrypt the block xor the decrypted block with prev_block
        plain_data = decrypted_block ^ prev_block

        # Write all bytes of the decrypted block to the output data
        decrypted_data.append((plain_data >> 56) & 0xFF)
        decrypted_data.append((plain_data >> 48) & 0xFF)
        decrypted_data.append((plain_data >> 40) & 0xFF)
        decrypted_data.append((plain_data >> 32) & 0xFF)
        decrypted_data.append((plain_data >> 24) & 0xFF)
        decrypted_data.append((plain_data >> 16) & 0xFF)
        decrypted_data.append((plain_data >> 8) & 0xFF)
        decrypted_data.append(plain_data & 0xFF)

        # Plain data ^ encrypted data
        prev_block = plain_data ^ encrypted_block

        # Move offset to the next block. Stop encryption if we reached the end of the data.
        offset += block_size
        if offset >= len(data):
            break

    # After decryption is complete we can remove padding according to the original size
    return decrypted_data[0:size]
