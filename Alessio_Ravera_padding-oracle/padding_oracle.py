from oracle import encrypt, is_padding_ok, BLOCK_SIZE


def get_pad_len(encrypted_msg):
    array = bytearray(encrypted_msg)
    pad_len = 16
    while True:
        array[-(pad_len + BLOCK_SIZE)] ^= 1
        if not is_padding_ok(bytes(array)):
            return pad_len
        pad_len -= 1


def decrypt_block(array, pad_len):
    cleartext = bytearray()
    for current_pl in range(pad_len, BLOCK_SIZE):
        new_pl = current_pl + 1
        for i in range(1, new_pl):
            value = current_pl ^ new_pl
            array[-(i + BLOCK_SIZE)] = array[-(i + BLOCK_SIZE)] ^ value
        c = array[-(new_pl + BLOCK_SIZE)]
        for byte in range(0, 256):
            array[-(new_pl + BLOCK_SIZE)] = byte
            if is_padding_ok(bytes(array)):
                cleartext.append(c ^ new_pl ^ byte)
                break
    return cleartext[::-1]


def attack(encrypted_msg):
    pad_len = get_pad_len(encrypted_msg)
    array = bytearray(encrypted_msg)
    msg = bytearray()
    i = 1
    while len(array) > BLOCK_SIZE:
        msg = (decrypt_block(array, pad_len)) + msg
        array = bytearray(encrypted_msg[:-BLOCK_SIZE*i])
        i += 1
        pad_len = 0
    return bytes(msg)


def test_the_attack():
    messages = (b'Attack at dawn', b'', b'Giovanni',
                b"In symmetric cryptography, the padding oracle attack can be applied to the CBC mode of operation," +
                b"where the \"oracle\" (usually a server) leaks data about whether the padding of an encrypted " +
                b"message is correct or not. Such data can allow attackers to decrypt (and sometimes encrypt) " +
                b"messages through the oracle using the oracle's key, without knowing the encryption key")
    for msg in messages:
        print('Testing:', msg)
        cracked_ct = attack(encrypt(msg))
        assert cracked_ct == msg


if __name__ == '__main__':
    test_the_attack()
