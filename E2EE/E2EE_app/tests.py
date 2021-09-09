import json
import unittest

from Crypto.Cipher import AES
from django.test import TestCase

from E2EE.E2EE_app.views import get_random_bytes, sym_enc


class TestSym(unittest.TestCase):

    def test_sym_enc(self):
        data = {"name": "ardy", "key": "somekey"}
        key = get_random_bytes(AES.block_size)
        iv = get_random_bytes(AES.block_size)
        output = sym_enc(key, iv, data)
        self.assertIsInstance(output, dict)




if __name__ == '__main__':
    unittest.main()