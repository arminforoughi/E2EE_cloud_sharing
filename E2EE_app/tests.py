
from django.test import TestCase

from Cryptodome.Cipher import AES

from .views import get_random_bytes, sym_enc, sym_dec


class TestSym(TestCase):
    def setUp(self):
        self.data = {"name": "ardy", "key": "somekey"}
        self.key = get_random_bytes(AES.block_size)
        self.iv = get_random_bytes(AES.block_size)
        self.output = sym_enc(self.key, self.iv, self.data)     # output is a dict
        self.output_dec = sym_dec(self.key, self.output)


    def test_sym_enc(self):
        self.assertIsInstance(self.output, dict)

    def test_sym_enc_output(self):
        m = "output is the same as input"
        self.assertNotEqual(self.output, self.data, m)

    def test_sym_enc(self):
        m = "D(E(a)) is not equal to a "
        self.assertDictEqual(self.data,self.output_dec, m)


# class TestHmac(unittest.TestCase):
#     def setUp(self):
#
#
#
#     def test_sym_enc(self):
#         self.assertIsInstance(self.output, dict)

