import hashlib
from typing import Union

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


def _encode_entries(salt: bytes, nonce: bytes, tag: bytes, cipher_text: bytes):
    salt_len = str(len(salt)).encode("utf-8")
    nonce_len = str(len(nonce)+len(salt)).encode("utf-8")
    tag_len = str(len(tag)+len(nonce)+len(salt)).encode("utf-8")
    return b";".join([salt_len, nonce_len, tag_len])+b"/"+salt+nonce+tag+cipher_text


def _decode_entries(data: bytes):
    len_sector, data_sector = data.split(b"/", 1)
    salt_len, nonce_len, tag_len = map(int, len_sector.split(b";"))
    salt = data_sector[0: salt_len]
    nonce = data_sector[salt_len: nonce_len]
    tag = data_sector[nonce_len: tag_len]
    data = data_sector[tag_len:]
    return (salt, nonce, tag), data


def encrypt(message: Union[bytes, str], password: Union[bytes, str]):
    if isinstance(message, str):
        message = message.encode('utf-8')
    if isinstance(password, str):
        password = password.encode('utf-8')

    # generate a random salt

    salt = get_random_bytes(AES.block_size)

    # use the SCrypt KDF to get a private key from the password

    private_key = hashlib.scrypt(
        password,
        salt=salt,
        n=2 ** 14,
        r=8,
        p=1,
        dklen=32,
        )

    # create cipher config

    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text

    (cipher_text, tag) = cipher_config.encrypt_and_digest(message)

    encrypted_string = _encode_entries(salt, cipher_config.nonce, tag, cipher_text)
    return encrypted_string


def decrypt(encrypted_data: bytes, password: Union[str, bytes]):
    # decode the dictionary entries from base64

    (salt, nonce, tag), cipher_text = _decode_entries(encrypted_data)
    # generate the private key from the password and salt

    private_key = hashlib.scrypt(
        password.encode() if isinstance(password, str) else password,
        salt=salt,
        n=2 ** 14,
        r=8,
        p=1,
        dklen=32,
        )

    # create the cipher config

    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text

    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted
