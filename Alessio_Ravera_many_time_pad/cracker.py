#!/usr/bin/env python3

import binascii
import argparse

SPACE = ord(' ')


def extractKey(cts):
    keys = set()
    keytoinsert = set()
    for i in range(len(cts)):
        for j in range(i, len(cts)):
            xor = chr(cts[i] ^ cts[j])
            if xor.isalpha():
                keytoinsert.clear()
                if xor.isupper():
                    keytoinsert.add(ord(xor.lower()) ^ cts[i])
                else:
                    keytoinsert.add(ord(xor.upper()) ^ cts[i])
                keytoinsert.add(SPACE ^ cts[i])
                if len(keys) == 0:
                    keys.update(keytoinsert)
                else:
                    keys.intersection_update(keytoinsert)
                    if len(keys) == 1:
                        return keys
    return keys


def chooseKey(possibleKeys, k):
    if not possibleKeys:
        print("[+]The key in position " + str(k) + " has not been found")
        return None
    key = possibleKeys.pop()
    if possibleKeys:
        print("[+]The key in position " + str(k) + " can also be: " + hex(possibleKeys.pop()) + "\n")
    return key


def decript(cleartexts, ciphertexts, keystream):
    for i in range(len(cleartexts)):
        for j in range(len(cleartexts[i])):
            if keystream[j] is None:
                cleartexts[i][j] = ord('*')
            else:
                cleartexts[i][j] = ciphertexts[i][j] ^ keystream[j]


def main():
    parser = argparse.ArgumentParser(description="Many-time Pad Cracker")
    parser.add_argument("--filename", type=str,
                        help="Name of the file containing the ciphertexts (default: ciphertexts.txt)",
                        default="ciphertexts.txt")
    args = parser.parse_args()
    try:
        with open(args.filename) as f:
            ciphertexts = [binascii.unhexlify(line.rstrip()) for line in f]
        cleartexts = [bytearray(b'?' * len(c)) for c in ciphertexts]
    except Exception as e:
        print("Cannot crack {} --- {}".format(args.filename, e))
        raise SystemExit(-1)
    '''for k in range(max(len(c) for c in ciphertexts)):
        cts = [c for c in ciphertexts if len(c) > k]'''
    # TODO
    keystream = list()

    for k in range(max(len(c) for c in ciphertexts)):
        cts = [c[k] for c in ciphertexts if len(c) > k]
        possibleKeys = extractKey(cts)
        keystream.append(chooseKey(possibleKeys, k))

    decript(cleartexts, ciphertexts, keystream)

    print("\n".join(c.decode('ascii') for c in cleartexts))


if __name__ == "__main__":
    main()
