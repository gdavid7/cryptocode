from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
def encrypt(message , password):
    plain_text = message

    # generate a random salt

    salt = get_random_bytes(AES.block_size)

    # use the Scrypt KDF to get a private key from the password

    private_key = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=2 ** 14,
        r=8,
        p=1,
        dklen=32,
        )

    # create cipher config

    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text

    (cipher_text, tag) = \
        cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    encryptedDict = {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8'),
        }
    encryptedString = encryptedDict['cipher_text'] + '*' \
        + encryptedDict['salt'] + '*' + encryptedDict['nonce'] + '*' \
        + encryptedDict['tag']
    return encryptedString


def decrypt(enc_dict, password):
    """Decrypt a string; return False for malformed or unauthentic tokens.

    Both arguments must be strings. Runtime and dependency errors propagate.
    """
    if not isinstance(enc_dict, str) or not isinstance(password, str):
        raise TypeError("ciphertext and password must be strings")
    fields = enc_dict.split('*')
    if len(fields) != 4:
        return False
    try:
        cipher_text, salt, nonce, tag = (
            b64decode(field, validate=True) for field in fields
        )
    except ValueError:
        return False
    if any(len(value) != AES.block_size for value in (salt, nonce, tag)):
        return False

    # Keep the original parameters so existing ciphertext remains readable.
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32
    )
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)
    try:
        decrypted = cipher.decrypt_and_verify(cipher_text, tag)
    except ValueError:
        return False
    try:
        return decrypted.decode('utf-8')
    except UnicodeDecodeError:
        return False
