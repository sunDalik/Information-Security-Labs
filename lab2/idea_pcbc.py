import argparse
import pcbc_mode
import idea_cipher


def main():
    # Two usages are possible
    # To encrypt a file simply provide input and output files
    # To decrypt a file use -d option and provide key (-k), initialization vector(-i) and size of the original file (-s)
    usage = 'idea_pcbc.py file_in file_out [-d] [-k] [-i] [-s]'
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument('file_in', action='store')
    parser.add_argument('file_out', action='store')
    parser.add_argument("-d", '--decrypt', action="store_true", dest="decrypt", default=False)
    parser.add_argument("-k", '--key', action="store", type=int, dest="key", default=0)
    parser.add_argument("-i", '--init_vector', action="store", type=int, dest="init_vector", default=0)
    parser.add_argument("-s", '--size', action="store", type=int, dest="size", default=0)
    args = parser.parse_args()

    with open(args.file_in, "rb") as f:
        file_data = f.read()
        # If -d is enabled then decrypt file using provided key, init vector and size
        # Else encrypt this file
        data = pcbc_mode.decrypt_data(file_data, idea_cipher.decrypt, args.key, args.init_vector, args.size) \
            if args.decrypt \
            else pcbc_mode.encrypt_data(file_data, idea_cipher.encrypt, args)

        with open(args.file_out, "wb") as f2:
            # After encrypting / decrypting write resulting data to output file
            # If file was encrypted, output key, init vector and size necessary for decryption
            f2.write(data)
            if args.decrypt:
                print("File decrypted!")
            else:
                print("File encrypted!")
                print("Key = " + str(args.key))
                print("Init Vector = " + str(args.init_vector))
                print("Size = " + str(args.size))


main()
