import base64
import hashlib
import unittest
from unittest.mock import patch

import cryptocode
from Cryptodome.Cipher import AES

LEGACY = ('M+Wykmlub0z7FhEdmA==*PvAbXRNx0SiSDHHxLsKZ5w=='
          '*ihQM/fdkgrX3G+yOItyAUQ==*QFNDmuUP1ysgo01/P2MNpg==')


class CryptocodeTests(unittest.TestCase):
    def test_round_trips(self):
        for message, password in [('I like trains', 'password123'),
                                  ('你好 🌍 café שלום', '🔑pässword'),
                                  ('', 'pw'), ('message', ''),
                                  ('a\x00b\nc', 'pw'), ('x' * 1048576, 'pw')]:
            with self.subTest(length=len(message), password=password):
                self.assertEqual(cryptocode.decrypt(
                    cryptocode.encrypt(message, password), password), message)

    def test_legacy_ciphertext(self):
        self.assertEqual(cryptocode.decrypt(LEGACY, 'password123'), 'I like trains')

    def test_wrong_password(self):
        self.assertIs(cryptocode.decrypt(LEGACY, 'wrong'), False)

    def test_random_salts_and_nonces(self):
        tokens = [cryptocode.encrypt('hello', 'pw').split('*') for _ in range(10)]
        for index in (1, 2):
            self.assertEqual(len({token[index] for token in tokens}), 10)

    def test_tampering(self):
        for index in range(4):
            with self.subTest(field=index):
                fields = LEGACY.split('*')
                raw = bytearray(base64.b64decode(fields[index]))
                raw[0] ^= 1
                fields[index] = base64.b64encode(raw).decode()
                self.assertIs(cryptocode.decrypt('*'.join(fields), 'password123'), False)

    def test_malformed_tokens(self):
        tokens = ['', 'garbage', 'a*b*c', '***', LEGACY + '*extra']
        for index in range(4):
            for invalid in ['!', '\n', 'é']:
                fields = LEGACY.split('*')
                fields[index] = invalid + fields[index]
                tokens.append('*'.join(fields))
        for token in tokens:
            with self.subTest(token=token):
                self.assertIs(cryptocode.decrypt(token, 'password123'), False)

    def test_invalid_lengths_rejected_before_kdf(self):
        for index in (1, 2, 3):
            for length in (0, 1, 15, 17, 32):
                fields = LEGACY.split('*')
                fields[index] = base64.b64encode(b'x' * length).decode()
                with self.subTest(field=index, length=length):
                    with patch('cryptocode.hashlib.scrypt') as kdf:
                        self.assertIs(cryptocode.decrypt('*'.join(fields), 'pw'), False)
                        kdf.assert_not_called()

    def test_argument_types(self):
        for value in (None, b'bytes', 42, [], {}):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    cryptocode.decrypt(value, 'pw')
                with self.assertRaises(TypeError):
                    cryptocode.decrypt(LEGACY, value)

    def test_runtime_failures_propagate(self):
        for error in (ValueError('memory limit exceeded'), RuntimeError('backend'),
                      MemoryError(), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                with patch('cryptocode.hashlib.scrypt', side_effect=error):
                    with self.assertRaises(type(error)):
                        cryptocode.decrypt(LEGACY, 'password123')
        with patch('cryptocode.AES.new', side_effect=RuntimeError('backend')):
            with self.assertRaises(RuntimeError):
                cryptocode.decrypt(LEGACY, 'password123')

    def test_authenticated_non_utf8_returns_false(self):
        salt = b's' * 16
        key = hashlib.scrypt(b'pw', salt=salt, n=2**14, r=8, p=1, dklen=32)
        cipher = AES.new(key, AES.MODE_GCM)
        data, tag = cipher.encrypt_and_digest(b'\xff')
        token = '*'.join(base64.b64encode(v).decode()
                         for v in (data, salt, cipher.nonce, tag))
        self.assertIs(cryptocode.decrypt(token, 'pw'), False)


if __name__ == '__main__':
    unittest.main()
