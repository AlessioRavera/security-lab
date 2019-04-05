#! /usr/bin/env python3
import argparse
import Crypto.Cipher.AES as AES
import os
import pickle

BLOCK_SIZE = AES.block_size
FORGERY_FILE_EXTENSION = os.extsep + "dat"

def pad(data, block_size=BLOCK_SIZE):
    data += b'\xff'
    missing_bytes = block_size - (len(data) % block_size)
    return data + b'\0' * missing_bytes

def read_block(filename):
    data: bytes = b''
    with open(filename, mode="rb") as f:
        while True:
            b = f.read(BLOCK_SIZE)
            l = len(b)
            if l < BLOCK_SIZE:
                data += pad(b)
                return data
            else:
                data += b

def tag_filename(filename):
    return os.path.splitext(filename)[0]+FORGERY_FILE_EXTENSION

def main():
    parser = argparse.ArgumentParser(description="Perform existential forgery attack")
    parser.add_argument("filename_one", type=str, help="Input file used to forge second file or himself")
    parser.add_argument("tag_filename_one", type=str, help="Input tag-file one")
    parser.add_argument("filename_two", type=str, nargs='?', help="Input file to forge")
    args = parser.parse_args()

    if args.filename_two is not None:
        filename = args.filename_two
    else:
        filename = args.filename_one

    try:
        with open(args.tag_filename_one, "rb") as inFile:
            stored_mac = pickle.load(inFile)
        if not isinstance(stored_mac, bytes) or len(stored_mac) != AES.block_size:
            print("I don't understand the format of the tag-file!")
            raise SystemExit(-1)
    except Exception as e:
        print("Cannot read the tag-file, error={}".format(e))
        raise SystemExit(-1)

    try:
        output_file = tag_filename(filename)
        with open(output_file, mode='wb') as outfile:
            outfile.write(read_block(args.filename_one))
            with open(filename, mode="rb") as f2:
                b = f2.read(BLOCK_SIZE)
                for i in range(BLOCK_SIZE):
                    outfile.write((b[i] ^ stored_mac[i]).to_bytes(1,"little"))
                outfile.write(f2.read())
    except Exception as e:
        print("Cannot write {}, error={}".format(output_file, e))


if __name__ == "__main__":
    main()
