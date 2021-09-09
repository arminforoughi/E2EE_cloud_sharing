import json
import unittest

from Crypto.Cipher import AES
from django.test import TestCase

from E2EE.E2EE_app.views import get_random_bytes, sym_enc


class TestSym(unittest.TestCase):
    def setUp(self):
        self.data = {"name": "ardy", "key": "somekey"}
        self.key = get_random_bytes(AES.block_size)
        self.iv = get_random_bytes(AES.block_size)
        self.output = sym_enc(self.key, self.iv, self.data)


    def test_sym_enc(self):
        self.assertIsInstance(self.output, dict)




if __name__ == '__main__':
    unittest.main()