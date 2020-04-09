# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import unittest

from swh.model.exceptions import ValidationError
from swh.model.fields import hashes


class ValidateHashes(unittest.TestCase):
    def setUp(self):
        self.valid_byte_hashes = {
            "sha1": b"\xf1\xd2\xd2\xf9\x24\xe9\x86\xac\x86\xfd\xf7\xb3\x6c\x94"
            b"\xbc\xdf\x32\xbe\xec\x15",
            "sha1_git": b"\x25\x7c\xc5\x64\x2c\xb1\xa0\x54\xf0\x8c\xc8\x3f\x2d"
            b"\x94\x3e\x56\xfd\x3e\xbe\x99",
            "sha256": b"\xb5\xbb\x9d\x80\x14\xa0\xf9\xb1\xd6\x1e\x21\xe7\x96"
            b"\xd7\x8d\xcc\xdf\x13\x52\xf2\x3c\xd3\x28\x12\xf4\x85"
            b"\x0b\x87\x8a\xe4\x94\x4c",
        }

        self.valid_str_hashes = {
            "sha1": "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15",
            "sha1_git": "257cc5642cb1a054f08cc83f2d943e56fd3ebe99",
            "sha256": "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f485"
            "0b878ae4944c",
        }

        self.bad_hash = object()

    def test_valid_bytes_hash(self):
        for hash_type, value in self.valid_byte_hashes.items():
            self.assertTrue(hashes.validate_hash(value, hash_type))

    def test_valid_str_hash(self):
        for hash_type, value in self.valid_str_hashes.items():
            self.assertTrue(hashes.validate_hash(value, hash_type))

    def test_invalid_hash_type(self):
        hash_type = "unknown_hash_type"
        with self.assertRaises(ValidationError) as cm:
            hashes.validate_hash(self.valid_str_hashes["sha1"], hash_type)

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(exc.code, "unexpected-hash-type")
        self.assertEqual(exc.params["hash_type"], hash_type)

        self.assertIn("Unexpected hash type", str(exc))
        self.assertIn(hash_type, str(exc))

    def test_invalid_bytes_len(self):
        for hash_type, value in self.valid_byte_hashes.items():
            value = value + b"\x00\x01"
            with self.assertRaises(ValidationError) as cm:
                hashes.validate_hash(value, hash_type)

            exc = cm.exception
            self.assertIsInstance(str(exc), str)
            self.assertEqual(exc.code, "unexpected-hash-length")
            self.assertEqual(exc.params["hash_type"], hash_type)
            self.assertEqual(exc.params["length"], len(value))

            self.assertIn("Unexpected length", str(exc))
            self.assertIn(str(len(value)), str(exc))

    def test_invalid_str_len(self):
        for hash_type, value in self.valid_str_hashes.items():
            value = value + "0001"
            with self.assertRaises(ValidationError) as cm:
                hashes.validate_hash(value, hash_type)

            exc = cm.exception
            self.assertIsInstance(str(exc), str)
            self.assertEqual(exc.code, "unexpected-hash-length")
            self.assertEqual(exc.params["hash_type"], hash_type)
            self.assertEqual(exc.params["length"], len(value))

            self.assertIn("Unexpected length", str(exc))
            self.assertIn(str(len(value)), str(exc))

    def test_invalid_str_contents(self):
        for hash_type, value in self.valid_str_hashes.items():
            value = "\xa2" + value[1:-1] + "\xc3"
            with self.assertRaises(ValidationError) as cm:
                hashes.validate_hash(value, hash_type)

            exc = cm.exception
            self.assertIsInstance(str(exc), str)
            self.assertEqual(exc.code, "unexpected-hash-contents")
            self.assertEqual(exc.params["hash_type"], hash_type)
            self.assertEqual(exc.params["unexpected_chars"], "\xa2, \xc3")

            self.assertIn("Unexpected characters", str(exc))
            self.assertIn("\xc3", str(exc))
            self.assertIn("\xa2", str(exc))

    def test_invalid_value_type(self):
        with self.assertRaises(ValidationError) as cm:
            hashes.validate_hash(self.bad_hash, "sha1")

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(exc.code, "unexpected-hash-value-type")
        self.assertEqual(exc.params["type"], self.bad_hash.__class__.__name__)

        self.assertIn("Unexpected type", str(exc))
        self.assertIn(self.bad_hash.__class__.__name__, str(exc))

    def test_validate_sha1(self):
        self.assertTrue(hashes.validate_sha1(self.valid_byte_hashes["sha1"]))
        self.assertTrue(hashes.validate_sha1(self.valid_str_hashes["sha1"]))

        with self.assertRaises(ValidationError) as cm:
            hashes.validate_sha1(self.bad_hash)

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(exc.code, "unexpected-hash-value-type")
        self.assertEqual(exc.params["type"], self.bad_hash.__class__.__name__)

    def test_validate_sha1_git(self):
        self.assertTrue(hashes.validate_sha1_git(self.valid_byte_hashes["sha1_git"]))
        self.assertTrue(hashes.validate_sha1_git(self.valid_str_hashes["sha1_git"]))

        with self.assertRaises(ValidationError) as cm:
            hashes.validate_sha1_git(self.bad_hash)

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(exc.code, "unexpected-hash-value-type")
        self.assertEqual(exc.params["type"], self.bad_hash.__class__.__name__)

    def test_validate_sha256(self):
        self.assertTrue(hashes.validate_sha256(self.valid_byte_hashes["sha256"]))
        self.assertTrue(hashes.validate_sha256(self.valid_str_hashes["sha256"]))

        with self.assertRaises(ValidationError) as cm:
            hashes.validate_sha256(self.bad_hash)

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(exc.code, "unexpected-hash-value-type")
        self.assertEqual(exc.params["type"], self.bad_hash.__class__.__name__)
