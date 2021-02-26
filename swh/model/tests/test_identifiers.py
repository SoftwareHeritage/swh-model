# Copyright (C) 2015-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import binascii
import datetime
import itertools
from typing import Dict
import unittest

import attr
import pytest

from swh.model import hashutil, identifiers
from swh.model.exceptions import ValidationError
from swh.model.hashutil import hash_to_bytes as _x
from swh.model.identifiers import (
    CONTENT,
    DIRECTORY,
    RELEASE,
    REVISION,
    SNAPSHOT,
    SWHID,
    SWHID_QUALIFIERS,
    CoreSWHID,
    ExtendedObjectType,
    ExtendedSWHID,
    ObjectType,
    QualifiedSWHID,
    normalize_timestamp,
)


def remove_id(d: Dict) -> Dict:
    """Returns a (shallow) copy of a dict with the 'id' key removed."""
    d = d.copy()
    if "id" in d:
        del d["id"]
    return d


class UtilityFunctionsIdentifier(unittest.TestCase):
    def setUp(self):
        self.str_id = "c2e41aae41ac17bd4a650770d6ee77f62e52235b"
        self.bytes_id = binascii.unhexlify(self.str_id)
        self.bad_type_id = object()

    def test_identifier_to_bytes(self):
        for id in [self.str_id, self.bytes_id]:
            self.assertEqual(identifiers.identifier_to_bytes(id), self.bytes_id)

            # wrong length
            with self.assertRaises(ValueError) as cm:
                identifiers.identifier_to_bytes(id[:-2])

            self.assertIn("length", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            identifiers.identifier_to_bytes(self.bad_type_id)

        self.assertIn("type", str(cm.exception))

    def test_identifier_to_str(self):
        for id in [self.str_id, self.bytes_id]:
            self.assertEqual(identifiers.identifier_to_str(id), self.str_id)

            # wrong length
            with self.assertRaises(ValueError) as cm:
                identifiers.identifier_to_str(id[:-2])

            self.assertIn("length", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            identifiers.identifier_to_str(self.bad_type_id)

        self.assertIn("type", str(cm.exception))


class UtilityFunctionsDateOffset(unittest.TestCase):
    def setUp(self):
        self.dates = {
            b"1448210036": {"seconds": 1448210036, "microseconds": 0,},
            b"1448210036.002342": {"seconds": 1448210036, "microseconds": 2342,},
            b"1448210036.12": {"seconds": 1448210036, "microseconds": 120000,},
        }
        self.broken_dates = [
            1448210036.12,
        ]

        self.offsets = {
            0: b"+0000",
            -630: b"-1030",
            800: b"+1320",
        }

    def test_format_date(self):
        for date_repr, date in self.dates.items():
            self.assertEqual(identifiers.format_date(date), date_repr)

    def test_format_date_fail(self):
        for date in self.broken_dates:
            with self.assertRaises(ValueError):
                identifiers.format_date(date)

    def test_format_offset(self):
        for offset, res in self.offsets.items():
            self.assertEqual(identifiers.format_offset(offset), res)


content_example = {
    "status": "visible",
    "length": 5,
    "data": b"1984\n",
    "ctime": datetime.datetime(2015, 11, 22, 16, 33, 56, tzinfo=datetime.timezone.utc),
}


class ContentIdentifier(unittest.TestCase):
    def setUp(self):
        self.content_id = hashutil.MultiHash.from_data(content_example["data"]).digest()

    def test_content_identifier(self):
        self.assertEqual(
            identifiers.content_identifier(content_example), self.content_id
        )


directory_example = {
    "id": "d7ed3d2c31d608823be58b1cbe57605310615231",
    "entries": [
        {
            "type": "file",
            "perms": 33188,
            "name": b"README",
            "target": _x("37ec8ea2110c0b7a32fbb0e872f6e7debbf95e21"),
        },
        {
            "type": "file",
            "perms": 33188,
            "name": b"Rakefile",
            "target": _x("3bb0e8592a41ae3185ee32266c860714980dbed7"),
        },
        {
            "type": "dir",
            "perms": 16384,
            "name": b"app",
            "target": _x("61e6e867f5d7ba3b40540869bc050b0c4fed9e95"),
        },
        {
            "type": "file",
            "perms": 33188,
            "name": b"1.megabyte",
            "target": _x("7c2b2fbdd57d6765cdc9d84c2d7d333f11be7fb3"),
        },
        {
            "type": "dir",
            "perms": 16384,
            "name": b"config",
            "target": _x("591dfe784a2e9ccc63aaba1cb68a765734310d98"),
        },
        {
            "type": "dir",
            "perms": 16384,
            "name": b"public",
            "target": _x("9588bf4522c2b4648bfd1c61d175d1f88c1ad4a5"),
        },
        {
            "type": "file",
            "perms": 33188,
            "name": b"development.sqlite3",
            "target": _x("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
        },
        {
            "type": "dir",
            "perms": 16384,
            "name": b"doc",
            "target": _x("154705c6aa1c8ead8c99c7915373e3c44012057f"),
        },
        {
            "type": "dir",
            "perms": 16384,
            "name": b"db",
            "target": _x("85f157bdc39356b7bc7de9d0099b4ced8b3b382c"),
        },
        {
            "type": "dir",
            "perms": 16384,
            "name": b"log",
            "target": _x("5e3d3941c51cce73352dff89c805a304ba96fffe"),
        },
        {
            "type": "dir",
            "perms": 16384,
            "name": b"script",
            "target": _x("1b278423caf176da3f3533592012502aa10f566c"),
        },
        {
            "type": "dir",
            "perms": 16384,
            "name": b"test",
            "target": _x("035f0437c080bfd8711670b3e8677e686c69c763"),
        },
        {
            "type": "dir",
            "perms": 16384,
            "name": b"vendor",
            "target": _x("7c0dc9ad978c1af3f9a4ce061e50f5918bd27138"),
        },
        {
            "type": "rev",
            "perms": 57344,
            "name": b"will_paginate",
            "target": _x("3d531e169db92a16a9a8974f0ae6edf52e52659e"),
        },
        # in git order, the dir named "order" should be between the files
        # named "order." and "order0"
        {
            "type": "dir",
            "perms": 16384,
            "name": b"order",
            "target": _x("62cdb7020ff920e5aa642c3d4066950dd1f01f4d"),
        },
        {
            "type": "file",
            "perms": 16384,
            "name": b"order.",
            "target": _x("0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"),
        },
        {
            "type": "file",
            "perms": 16384,
            "name": b"order0",
            "target": _x("bbe960a25ea311d21d40669e93df2003ba9b90a2"),
        },
    ],
}

dummy_qualifiers = {"origin": "https://example.com", "lines": "42"}


class DirectoryIdentifier(unittest.TestCase):
    def setUp(self):
        self.directory = directory_example

        self.empty_directory = {
            "id": "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            "entries": [],
        }

    def test_dir_identifier(self):
        self.assertEqual(
            identifiers.directory_identifier(self.directory), self.directory["id"]
        )
        self.assertEqual(
            identifiers.directory_identifier(remove_id(self.directory)),
            self.directory["id"],
        )

    def test_dir_identifier_entry_order(self):
        # Reverse order of entries, check the id is still the same.
        directory = {"entries": reversed(self.directory["entries"])}
        self.assertEqual(
            identifiers.directory_identifier(remove_id(directory)), self.directory["id"]
        )

    def test_dir_identifier_empty_directory(self):
        self.assertEqual(
            identifiers.directory_identifier(remove_id(self.empty_directory)),
            self.empty_directory["id"],
        )


linus_tz = datetime.timezone(datetime.timedelta(minutes=-420))

revision_example = {
    "id": "bc0195aad0daa2ad5b0d76cce22b167bc3435590",
    "directory": _x("85a74718d377195e1efd0843ba4f3260bad4fe07"),
    "parents": [_x("01e2d0627a9a6edb24c37db45db5ecb31e9de808")],
    "author": {
        "name": b"Linus Torvalds",
        "email": b"torvalds@linux-foundation.org",
        "fullname": b"Linus Torvalds <torvalds@linux-foundation.org>",
    },
    "date": datetime.datetime(2015, 7, 12, 15, 10, 30, tzinfo=linus_tz),
    "committer": {
        "name": b"Linus Torvalds",
        "email": b"torvalds@linux-foundation.org",
        "fullname": b"Linus Torvalds <torvalds@linux-foundation.org>",
    },
    "committer_date": datetime.datetime(2015, 7, 12, 15, 10, 30, tzinfo=linus_tz),
    "message": b"Linux 4.2-rc2\n",
    "type": "git",
    "synthetic": False,
}


class RevisionIdentifier(unittest.TestCase):
    def setUp(self):
        gpgsig = b"""\
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.13 (Darwin)

iQIcBAABAgAGBQJVJcYsAAoJEBiY3kIkQRNJVAUQAJ8/XQIfMqqC5oYeEFfHOPYZ
L7qy46bXHVBa9Qd8zAJ2Dou3IbI2ZoF6/Et89K/UggOycMlt5FKV/9toWyuZv4Po
L682wonoxX99qvVTHo6+wtnmYO7+G0f82h+qHMErxjP+I6gzRNBvRr+SfY7VlGdK
wikMKOMWC5smrScSHITnOq1Ews5pe3N7qDYMzK0XVZmgDoaem4RSWMJs4My/qVLN
e0CqYWq2A22GX7sXl6pjneJYQvcAXUX+CAzp24QnPSb+Q22Guj91TcxLFcHCTDdn
qgqMsEyMiisoglwrCbO+D+1xq9mjN9tNFWP66SQ48mrrHYTBV5sz9eJyDfroJaLP
CWgbDTgq6GzRMehHT3hXfYS5NNatjnhkNISXR7pnVP/obIi/vpWh5ll6Gd8q26z+
a/O41UzOaLTeNI365MWT4/cnXohVLRG7iVJbAbCxoQmEgsYMRc/pBAzWJtLfcB2G
jdTswYL6+MUdL8sB9pZ82D+BP/YAdHe69CyTu1lk9RT2pYtI/kkfjHubXBCYEJSG
+VGllBbYG6idQJpyrOYNRJyrDi9yvDJ2W+S0iQrlZrxzGBVGTB/y65S8C+2WTBcE
lf1Qb5GDsQrZWgD+jtWTywOYHtCBwyCKSAXxSARMbNPeak9WPlcW/Jmu+fUcMe2x
dg1KdHOa34shrKDaOVzW
=od6m
-----END PGP SIGNATURE-----"""

        self.revision = revision_example

        self.revision_none_metadata = {
            "id": "bc0195aad0daa2ad5b0d76cce22b167bc3435590",
            "directory": _x("85a74718d377195e1efd0843ba4f3260bad4fe07"),
            "parents": [_x("01e2d0627a9a6edb24c37db45db5ecb31e9de808")],
            "author": {
                "name": b"Linus Torvalds",
                "email": b"torvalds@linux-foundation.org",
            },
            "date": datetime.datetime(2015, 7, 12, 15, 10, 30, tzinfo=linus_tz),
            "committer": {
                "name": b"Linus Torvalds",
                "email": b"torvalds@linux-foundation.org",
            },
            "committer_date": datetime.datetime(
                2015, 7, 12, 15, 10, 30, tzinfo=linus_tz
            ),
            "message": b"Linux 4.2-rc2\n",
            "metadata": None,
        }

        self.synthetic_revision = {
            "id": b"\xb2\xa7\xe1&\x04\x92\xe3D\xfa\xb3\xcb\xf9\x1b\xc1<\x91"
            b"\xe0T&\xfd",
            "author": {
                "name": b"Software Heritage",
                "email": b"robot@softwareheritage.org",
            },
            "date": {
                "timestamp": {"seconds": 1437047495},
                "offset": 0,
                "negative_utc": False,
            },
            "type": "tar",
            "committer": {
                "name": b"Software Heritage",
                "email": b"robot@softwareheritage.org",
            },
            "committer_date": 1437047495,
            "synthetic": True,
            "parents": [None],
            "message": b"synthetic revision message\n",
            "directory": b"\xd1\x1f\x00\xa6\xa0\xfe\xa6\x05SA\xd2U\x84\xb5\xa9"
            b"e\x16\xc0\xd2\xb8",
            "metadata": {
                "original_artifact": [
                    {
                        "archive_type": "tar",
                        "name": "gcc-5.2.0.tar.bz2",
                        "sha1_git": "39d281aff934d44b439730057e55b055e206a586",
                        "sha1": "fe3f5390949d47054b613edc36c557eb1d51c18e",
                        "sha256": "5f835b04b5f7dd4f4d2dc96190ec1621b8d89f"
                        "2dc6f638f9f8bc1b1014ba8cad",
                    }
                ]
            },
        }

        # cat commit.txt | git hash-object -t commit --stdin
        self.revision_with_extra_headers = {
            "id": "010d34f384fa99d047cdd5e2f41e56e5c2feee45",
            "directory": _x("85a74718d377195e1efd0843ba4f3260bad4fe07"),
            "parents": [_x("01e2d0627a9a6edb24c37db45db5ecb31e9de808")],
            "author": {
                "name": b"Linus Torvalds",
                "email": b"torvalds@linux-foundation.org",
                "fullname": b"Linus Torvalds <torvalds@linux-foundation.org>",
            },
            "date": datetime.datetime(2015, 7, 12, 15, 10, 30, tzinfo=linus_tz),
            "committer": {
                "name": b"Linus Torvalds",
                "email": b"torvalds@linux-foundation.org",
                "fullname": b"Linus Torvalds <torvalds@linux-foundation.org>",
            },
            "committer_date": datetime.datetime(
                2015, 7, 12, 15, 10, 30, tzinfo=linus_tz
            ),
            "message": b"Linux 4.2-rc2\n",
            "extra_headers": (
                (b"svn-repo-uuid", b"046f1af7-66c2-d61b-5410-ce57b7db7bff"),
                (b"svn-revision", b"10"),
            ),
        }

        self.revision_with_gpgsig = {
            "id": "44cc742a8ca17b9c279be4cc195a93a6ef7a320e",
            "directory": _x("b134f9b7dc434f593c0bab696345548b37de0558"),
            "parents": [
                _x("689664ae944b4692724f13b709a4e4de28b54e57"),
                _x("c888305e1efbaa252d01b4e5e6b778f865a97514"),
            ],
            "author": {
                "name": b"Jiang Xin",
                "email": b"worldhello.net@gmail.com",
                "fullname": b"Jiang Xin <worldhello.net@gmail.com>",
            },
            "date": {"timestamp": 1428538899, "offset": 480,},
            "committer": {"name": b"Jiang Xin", "email": b"worldhello.net@gmail.com",},
            "committer_date": {"timestamp": 1428538899, "offset": 480,},
            "extra_headers": ((b"gpgsig", gpgsig),),
            "message": b"""Merge branch 'master' of git://github.com/alexhenrie/git-po

* 'master' of git://github.com/alexhenrie/git-po:
  l10n: ca.po: update translation
""",
        }

        self.revision_no_message = {
            "id": "4cfc623c9238fa92c832beed000ce2d003fd8333",
            "directory": _x("b134f9b7dc434f593c0bab696345548b37de0558"),
            "parents": [
                _x("689664ae944b4692724f13b709a4e4de28b54e57"),
                _x("c888305e1efbaa252d01b4e5e6b778f865a97514"),
            ],
            "author": {
                "name": b"Jiang Xin",
                "email": b"worldhello.net@gmail.com",
                "fullname": b"Jiang Xin <worldhello.net@gmail.com>",
            },
            "date": {"timestamp": 1428538899, "offset": 480,},
            "committer": {"name": b"Jiang Xin", "email": b"worldhello.net@gmail.com",},
            "committer_date": {"timestamp": 1428538899, "offset": 480,},
            "message": None,
        }

        self.revision_empty_message = {
            "id": "7442cd78bd3b4966921d6a7f7447417b7acb15eb",
            "directory": _x("b134f9b7dc434f593c0bab696345548b37de0558"),
            "parents": [
                _x("689664ae944b4692724f13b709a4e4de28b54e57"),
                _x("c888305e1efbaa252d01b4e5e6b778f865a97514"),
            ],
            "author": {
                "name": b"Jiang Xin",
                "email": b"worldhello.net@gmail.com",
                "fullname": b"Jiang Xin <worldhello.net@gmail.com>",
            },
            "date": {"timestamp": 1428538899, "offset": 480,},
            "committer": {"name": b"Jiang Xin", "email": b"worldhello.net@gmail.com",},
            "committer_date": {"timestamp": 1428538899, "offset": 480,},
            "message": b"",
        }

        self.revision_only_fullname = {
            "id": "010d34f384fa99d047cdd5e2f41e56e5c2feee45",
            "directory": _x("85a74718d377195e1efd0843ba4f3260bad4fe07"),
            "parents": [_x("01e2d0627a9a6edb24c37db45db5ecb31e9de808")],
            "author": {"fullname": b"Linus Torvalds <torvalds@linux-foundation.org>",},
            "date": datetime.datetime(2015, 7, 12, 15, 10, 30, tzinfo=linus_tz),
            "committer": {
                "fullname": b"Linus Torvalds <torvalds@linux-foundation.org>",
            },
            "committer_date": datetime.datetime(
                2015, 7, 12, 15, 10, 30, tzinfo=linus_tz
            ),
            "message": b"Linux 4.2-rc2\n",
            "extra_headers": (
                (b"svn-repo-uuid", b"046f1af7-66c2-d61b-5410-ce57b7db7bff"),
                (b"svn-revision", b"10"),
            ),
        }

    def test_revision_identifier(self):
        self.assertEqual(
            identifiers.revision_identifier(self.revision),
            identifiers.identifier_to_str(self.revision["id"]),
        )
        self.assertEqual(
            identifiers.revision_identifier(remove_id(self.revision)),
            identifiers.identifier_to_str(self.revision["id"]),
        )

    def test_revision_identifier_none_metadata(self):
        self.assertEqual(
            identifiers.revision_identifier(remove_id(self.revision_none_metadata)),
            identifiers.identifier_to_str(self.revision_none_metadata["id"]),
        )

    def test_revision_identifier_synthetic(self):
        self.assertEqual(
            identifiers.revision_identifier(remove_id(self.synthetic_revision)),
            identifiers.identifier_to_str(self.synthetic_revision["id"]),
        )

    def test_revision_identifier_with_extra_headers(self):
        self.assertEqual(
            identifiers.revision_identifier(
                remove_id(self.revision_with_extra_headers)
            ),
            identifiers.identifier_to_str(self.revision_with_extra_headers["id"]),
        )

    def test_revision_identifier_with_gpgsig(self):
        self.assertEqual(
            identifiers.revision_identifier(remove_id(self.revision_with_gpgsig)),
            identifiers.identifier_to_str(self.revision_with_gpgsig["id"]),
        )

    def test_revision_identifier_no_message(self):
        self.assertEqual(
            identifiers.revision_identifier(remove_id(self.revision_no_message)),
            identifiers.identifier_to_str(self.revision_no_message["id"]),
        )

    def test_revision_identifier_empty_message(self):
        self.assertEqual(
            identifiers.revision_identifier(remove_id(self.revision_empty_message)),
            identifiers.identifier_to_str(self.revision_empty_message["id"]),
        )

    def test_revision_identifier_only_fullname(self):
        self.assertEqual(
            identifiers.revision_identifier(remove_id(self.revision_only_fullname)),
            identifiers.identifier_to_str(self.revision_only_fullname["id"]),
        )


release_example = {
    "id": "2b10839e32c4c476e9d94492756bb1a3e1ec4aa8",
    "target": b't\x1b"R\xa5\xe1Ml`\xa9\x13\xc7z`\x99\xab\xe7:\x85J',
    "target_type": "revision",
    "name": b"v2.6.14",
    "author": {
        "name": b"Linus Torvalds",
        "email": b"torvalds@g5.osdl.org",
        "fullname": b"Linus Torvalds <torvalds@g5.osdl.org>",
    },
    "date": datetime.datetime(2005, 10, 27, 17, 2, 33, tzinfo=linus_tz),
    "message": b"""\
Linux 2.6.14 release
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.1 (GNU/Linux)

iD8DBQBDYWq6F3YsRnbiHLsRAmaeAJ9RCez0y8rOBbhSv344h86l/VVcugCeIhO1
wdLOnvj91G4wxYqrvThthbE=
=7VeT
-----END PGP SIGNATURE-----
""",
    "synthetic": False,
}


class ReleaseIdentifier(unittest.TestCase):
    def setUp(self):
        linus_tz = datetime.timezone(datetime.timedelta(minutes=-420))

        self.release = release_example

        self.release_no_author = {
            "id": b"&y\x1a\x8b\xcf\x0em3\xf4:\xefv\x82\xbd\xb5U#mV\xde",
            "target": "9ee1c939d1cb936b1f98e8d81aeffab57bae46ab",
            "target_type": "revision",
            "name": b"v2.6.12",
            "message": b"""\
This is the final 2.6.12 release
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.2.4 (GNU/Linux)

iD8DBQBCsykyF3YsRnbiHLsRAvPNAJ482tCZwuxp/bJRz7Q98MHlN83TpACdHr37
o6X/3T+vm8K3bf3driRr34c=
=sBHn
-----END PGP SIGNATURE-----
""",
            "synthetic": False,
        }

        self.release_no_message = {
            "id": "b6f4f446715f7d9543ef54e41b62982f0db40045",
            "target": "9ee1c939d1cb936b1f98e8d81aeffab57bae46ab",
            "target_type": "revision",
            "name": b"v2.6.12",
            "author": {"name": b"Linus Torvalds", "email": b"torvalds@g5.osdl.org",},
            "date": datetime.datetime(2005, 10, 27, 17, 2, 33, tzinfo=linus_tz),
            "message": None,
        }

        self.release_empty_message = {
            "id": "71a0aea72444d396575dc25ac37fec87ee3c6492",
            "target": "9ee1c939d1cb936b1f98e8d81aeffab57bae46ab",
            "target_type": "revision",
            "name": b"v2.6.12",
            "author": {"name": b"Linus Torvalds", "email": b"torvalds@g5.osdl.org",},
            "date": datetime.datetime(2005, 10, 27, 17, 2, 33, tzinfo=linus_tz),
            "message": b"",
        }

        self.release_negative_utc = {
            "id": "97c8d2573a001f88e72d75f596cf86b12b82fd01",
            "name": b"20081029",
            "target": "54e9abca4c77421e2921f5f156c9fe4a9f7441c7",
            "target_type": "revision",
            "date": {
                "timestamp": {"seconds": 1225281976},
                "offset": 0,
                "negative_utc": True,
            },
            "author": {
                "name": b"Otavio Salvador",
                "email": b"otavio@debian.org",
                "id": 17640,
            },
            "synthetic": False,
            "message": b"tagging version 20081029\n\nr56558\n",
        }

        self.release_newline_in_author = {
            "author": {
                "email": b"esycat@gmail.com",
                "fullname": b"Eugene Janusov\n<esycat@gmail.com>",
                "name": b"Eugene Janusov\n",
            },
            "date": {
                "negative_utc": None,
                "offset": 600,
                "timestamp": {"microseconds": 0, "seconds": 1377480558,},
            },
            "id": b"\\\x98\xf5Y\xd04\x16-\xe2->\xbe\xb9T3\xe6\xf8\x88R1",
            "message": b"Release of v0.3.2.",
            "name": b"0.3.2",
            "synthetic": False,
            "target": (b"\xc0j\xa3\xd9;x\xa2\x86\\I5\x17" b"\x000\xf8\xc2\xd79o\xd3"),
            "target_type": "revision",
        }

        self.release_snapshot_target = dict(self.release)
        self.release_snapshot_target["target_type"] = "snapshot"
        self.release_snapshot_target["id"] = "c29c3ddcc6769a04e54dd69d63a6fdcbc566f850"

    def test_release_identifier(self):
        self.assertEqual(
            identifiers.release_identifier(self.release),
            identifiers.identifier_to_str(self.release["id"]),
        )
        self.assertEqual(
            identifiers.release_identifier(remove_id(self.release)),
            identifiers.identifier_to_str(self.release["id"]),
        )

    def test_release_identifier_no_author(self):
        self.assertEqual(
            identifiers.release_identifier(remove_id(self.release_no_author)),
            identifiers.identifier_to_str(self.release_no_author["id"]),
        )

    def test_release_identifier_no_message(self):
        self.assertEqual(
            identifiers.release_identifier(remove_id(self.release_no_message)),
            identifiers.identifier_to_str(self.release_no_message["id"]),
        )

    def test_release_identifier_empty_message(self):
        self.assertEqual(
            identifiers.release_identifier(remove_id(self.release_empty_message)),
            identifiers.identifier_to_str(self.release_empty_message["id"]),
        )

    def test_release_identifier_negative_utc(self):
        self.assertEqual(
            identifiers.release_identifier(remove_id(self.release_negative_utc)),
            identifiers.identifier_to_str(self.release_negative_utc["id"]),
        )

    def test_release_identifier_newline_in_author(self):
        self.assertEqual(
            identifiers.release_identifier(remove_id(self.release_newline_in_author)),
            identifiers.identifier_to_str(self.release_newline_in_author["id"]),
        )

    def test_release_identifier_snapshot_target(self):
        self.assertEqual(
            identifiers.release_identifier(self.release_snapshot_target),
            identifiers.identifier_to_str(self.release_snapshot_target["id"]),
        )


snapshot_example = {
    "id": _x("6e65b86363953b780d92b0a928f3e8fcdd10db36"),
    "branches": {
        b"directory": {
            "target": _x("1bd0e65f7d2ff14ae994de17a1e7fe65111dcad8"),
            "target_type": "directory",
        },
        b"content": {
            "target": _x("fe95a46679d128ff167b7c55df5d02356c5a1ae1"),
            "target_type": "content",
        },
        b"alias": {"target": b"revision", "target_type": "alias",},
        b"revision": {
            "target": _x("aafb16d69fd30ff58afdd69036a26047f3aebdc6"),
            "target_type": "revision",
        },
        b"release": {
            "target": _x("7045404f3d1c54e6473c71bbb716529fbad4be24"),
            "target_type": "release",
        },
        b"snapshot": {
            "target": _x("1a8893e6a86f444e8be8e7bda6cb34fb1735a00e"),
            "target_type": "snapshot",
        },
        b"dangling": None,
    },
}


class SnapshotIdentifier(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.empty = {
            "id": "1a8893e6a86f444e8be8e7bda6cb34fb1735a00e",
            "branches": {},
        }

        self.dangling_branch = {
            "id": "c84502e821eb21ed84e9fd3ec40973abc8b32353",
            "branches": {b"HEAD": None,},
        }

        self.unresolved = {
            "id": "84b4548ea486e4b0a7933fa541ff1503a0afe1e0",
            "branches": {b"foo": {"target": b"bar", "target_type": "alias",},},
        }

        self.all_types = snapshot_example

    def test_empty_snapshot(self):
        self.assertEqual(
            identifiers.snapshot_identifier(remove_id(self.empty)),
            identifiers.identifier_to_str(self.empty["id"]),
        )

    def test_dangling_branch(self):
        self.assertEqual(
            identifiers.snapshot_identifier(remove_id(self.dangling_branch)),
            identifiers.identifier_to_str(self.dangling_branch["id"]),
        )

    def test_unresolved(self):
        with self.assertRaisesRegex(ValueError, "b'foo' -> b'bar'"):
            identifiers.snapshot_identifier(remove_id(self.unresolved))

    def test_unresolved_force(self):
        self.assertEqual(
            identifiers.snapshot_identifier(
                remove_id(self.unresolved), ignore_unresolved=True,
            ),
            identifiers.identifier_to_str(self.unresolved["id"]),
        )

    def test_all_types(self):
        self.assertEqual(
            identifiers.snapshot_identifier(remove_id(self.all_types)),
            identifiers.identifier_to_str(self.all_types["id"]),
        )


origin_example = {
    "url": "https://github.com/torvalds/linux",
}


class OriginIdentifier(unittest.TestCase):
    def test_content_identifier(self):
        self.assertEqual(
            identifiers.origin_identifier(origin_example),
            "b63a575fe3faab7692c9f38fb09d4bb45651bb0f",
        )


TS_DICTS = [
    (
        {"timestamp": 12345, "offset": 0},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset": 0,
            "negative_utc": False,
        },
    ),
    (
        {"timestamp": 12345, "offset": 0, "negative_utc": False},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset": 0,
            "negative_utc": False,
        },
    ),
    (
        {"timestamp": 12345, "offset": 0, "negative_utc": False},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset": 0,
            "negative_utc": False,
        },
    ),
    (
        {"timestamp": 12345, "offset": 0, "negative_utc": None},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset": 0,
            "negative_utc": False,
        },
    ),
    (
        {"timestamp": {"seconds": 12345}, "offset": 0, "negative_utc": None},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset": 0,
            "negative_utc": False,
        },
    ),
    (
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset": 0,
            "negative_utc": None,
        },
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset": 0,
            "negative_utc": False,
        },
    ),
    (
        {
            "timestamp": {"seconds": 12345, "microseconds": 100},
            "offset": 0,
            "negative_utc": None,
        },
        {
            "timestamp": {"seconds": 12345, "microseconds": 100},
            "offset": 0,
            "negative_utc": False,
        },
    ),
    (
        {"timestamp": 12345, "offset": 0, "negative_utc": True},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset": 0,
            "negative_utc": True,
        },
    ),
    (
        {"timestamp": 12345, "offset": 0, "negative_utc": None},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset": 0,
            "negative_utc": False,
        },
    ),
]


@pytest.mark.parametrize("dict_input,expected", TS_DICTS)
def test_normalize_timestamp_dict(dict_input, expected):
    assert normalize_timestamp(dict_input) == expected


TS_DICTS_INVALID_TIMESTAMP = [
    {"timestamp": 1.2, "offset": 0},
    {"timestamp": "1", "offset": 0},
    # these below should really also trigger a ValueError...
    # {"timestamp": {"seconds": "1"}, "offset": 0},
    # {"timestamp": {"seconds": 1.2}, "offset": 0},
    # {"timestamp": {"seconds": 1.2}, "offset": 0},
]


@pytest.mark.parametrize("dict_input", TS_DICTS_INVALID_TIMESTAMP)
def test_normalize_timestamp_dict_invalid_timestamp(dict_input):
    with pytest.raises(ValueError, match="non-integer timestamp"):
        normalize_timestamp(dict_input)


class TestSwhid(unittest.TestCase):
    @pytest.mark.filterwarnings("ignore:.*SWHID.*:DeprecationWarning")
    def test_swhid(self):
        _snapshot_id = _x("c7c108084bc0bf3d81436bf980b46e98bd338453")
        _release_id = "22ece559cc7cc2364edc5e5593d63ae8bd229f9f"
        _revision_id = "309cf2674ee7a0749978cf8265ab91a60aea0f7d"
        _directory_id = "d198bc9d7a6bcf6db04f476d29314f157507d505"
        _content_id = "94a9ed024d3859793618152ea559a168bbcbb5e2"
        _snapshot = {"id": _snapshot_id}
        _release = {"id": _release_id}
        _revision = {"id": _revision_id}
        _directory = {"id": _directory_id}
        _content = {"sha1_git": _content_id}

        for full_type, _hash, expected_swhid, version, _meta in [
            (
                SNAPSHOT,
                _snapshot_id,
                "swh:1:snp:c7c108084bc0bf3d81436bf980b46e98bd338453",
                None,
                {},
            ),
            (
                RELEASE,
                _release_id,
                "swh:1:rel:22ece559cc7cc2364edc5e5593d63ae8bd229f9f",
                1,
                {},
            ),
            (
                REVISION,
                _revision_id,
                "swh:1:rev:309cf2674ee7a0749978cf8265ab91a60aea0f7d",
                None,
                {},
            ),
            (
                DIRECTORY,
                _directory_id,
                "swh:1:dir:d198bc9d7a6bcf6db04f476d29314f157507d505",
                None,
                {},
            ),
            (
                CONTENT,
                _content_id,
                "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2",
                1,
                {},
            ),
            (
                SNAPSHOT,
                _snapshot,
                "swh:1:snp:c7c108084bc0bf3d81436bf980b46e98bd338453",
                None,
                {},
            ),
            (
                RELEASE,
                _release,
                "swh:1:rel:22ece559cc7cc2364edc5e5593d63ae8bd229f9f",
                1,
                {},
            ),
            (
                REVISION,
                _revision,
                "swh:1:rev:309cf2674ee7a0749978cf8265ab91a60aea0f7d",
                None,
                {},
            ),
            (
                DIRECTORY,
                _directory,
                "swh:1:dir:d198bc9d7a6bcf6db04f476d29314f157507d505",
                None,
                {},
            ),
            (
                CONTENT,
                _content,
                "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2",
                1,
                {},
            ),
            (
                CONTENT,
                _content,
                "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2;origin=1",
                1,
                {"origin": "1"},
            ),
        ]:
            if version:
                actual_value = identifiers.swhid(
                    full_type, _hash, version, metadata=_meta
                )
            else:
                actual_value = identifiers.swhid(full_type, _hash, metadata=_meta)

            self.assertEqual(actual_value, expected_swhid)

    def test_swhid_wrong_input(self):
        _snapshot_id = "notahash4bc0bf3d81436bf980b46e98bd338453"
        _snapshot = {"id": _snapshot_id}

        for _type, _hash in [
            (SNAPSHOT, _snapshot_id),
            (SNAPSHOT, _snapshot),
            ("lines", "42"),
        ]:
            with self.assertRaises(ValidationError):
                identifiers.swhid(_type, _hash)

    @pytest.mark.filterwarnings("ignore:.*SWHID.*:DeprecationWarning")
    def test_parse_swhid(self):
        for swhid, _type, _version, _hash in [
            (
                "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2",
                CONTENT,
                1,
                "94a9ed024d3859793618152ea559a168bbcbb5e2",
            ),
            (
                "swh:1:dir:d198bc9d7a6bcf6db04f476d29314f157507d505",
                DIRECTORY,
                1,
                "d198bc9d7a6bcf6db04f476d29314f157507d505",
            ),
            (
                "swh:1:rev:309cf2674ee7a0749978cf8265ab91a60aea0f7d",
                REVISION,
                1,
                "309cf2674ee7a0749978cf8265ab91a60aea0f7d",
            ),
            (
                "swh:1:rel:22ece559cc7cc2364edc5e5593d63ae8bd229f9f",
                RELEASE,
                1,
                "22ece559cc7cc2364edc5e5593d63ae8bd229f9f",
            ),
            (
                "swh:1:snp:c7c108084bc0bf3d81436bf980b46e98bd338453",
                SNAPSHOT,
                1,
                "c7c108084bc0bf3d81436bf980b46e98bd338453",
            ),
        ]:
            with pytest.warns(DeprecationWarning):
                expected_result = SWHID(
                    namespace="swh",
                    scheme_version=_version,
                    object_type=_type,
                    object_id=_hash,
                    metadata={},
                )
                actual_result = identifiers.parse_swhid(swhid)
            self.assertEqual(actual_result, expected_result)
            self.assertEqual(str(expected_result), swhid)

        for swhid, _type, _version, _hash, _metadata in [
            (
                "swh:1:cnt:9c95815d9e9d91b8dae8e05d8bbc696fe19f796b;lines=1-18;origin=https://github.com/python/cpython",  # noqa
                CONTENT,
                1,
                "9c95815d9e9d91b8dae8e05d8bbc696fe19f796b",
                {"lines": "1-18", "origin": "https://github.com/python/cpython"},
            ),
            (
                "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=deb://Debian/packages/linuxdoc-tools",  # noqa
                DIRECTORY,
                1,
                "0b6959356d30f1a4e9b7f6bca59b9a336464c03d",
                {"origin": "deb://Debian/packages/linuxdoc-tools"},
            ),
        ]:
            with pytest.warns(DeprecationWarning):
                expected_result = SWHID(
                    namespace="swh",
                    scheme_version=_version,
                    object_type=_type,
                    object_id=_hash,
                    metadata=_metadata,
                )
                actual_result = identifiers.parse_swhid(swhid)
            self.assertEqual(actual_result, expected_result)
            self.assertEqual(
                expected_result.to_dict(),
                {
                    "namespace": "swh",
                    "scheme_version": _version,
                    "object_type": _type,
                    "object_id": _hash,
                    "metadata": _metadata,
                },
            )
            self.assertEqual(str(expected_result), swhid)


@pytest.mark.parametrize(
    "invalid_swhid",
    [
        "swh:1:cnt",
        "swh:1:",
        "swh:",
        "swh:1:cnt:",
        "foo:1:cnt:abc8bc9d7a6bcf6db04f476d29314f157507d505",
        "swh:2:dir:def8bc9d7a6bcf6db04f476d29314f157507d505",
        "swh:1:foo:fed8bc9d7a6bcf6db04f476d29314f157507d505",
        "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;invalid;malformed",
        "swh:1:snp:gh6959356d30f1a4e9b7f6bca59b9a336464c03d",
        "swh:1:snp:foo",
        # wrong qualifier: ori should be origin
        "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;ori=something;anchor=1;visit=1;path=/",  # noqa
        # wrong qualifier: anc should be anchor
        "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=something;anc=1;visit=1;path=/",  # noqa
        # wrong qualifier: vis should be visit
        "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=something;anchor=1;vis=1;path=/",  # noqa
        # wrong qualifier: pa should be path
        "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=something;anchor=1;visit=1;pa=/",  # noqa
        # wrong qualifier: line should be lines
        "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;line=10;origin=something;anchor=1;visit=1;path=/",  # noqa
        # wrong qualifier value: it contains space before of after
        "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=  https://some-url",  # noqa
        "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=something;anchor=some-anchor    ",  # noqa
        "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=something;anchor=some-anchor    ;visit=1",  # noqa
        # invalid swhid: whitespaces
        "swh :1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;ori=something;anchor=1;visit=1;path=/",  # noqa
        "swh: 1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;ori=something;anchor=1;visit=1;path=/",  # noqa
        "swh: 1: dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;ori=something;anchor=1;visit=1;path=/",  # noqa
        "swh:1: dir: 0b6959356d30f1a4e9b7f6bca59b9a336464c03d",
        "swh:1: dir: 0b6959356d30f1a4e9b7f6bca59b9a336464c03d; origin=blah",
        "swh:1: dir: 0b6959356d30f1a4e9b7f6bca59b9a336464c03d;lines=12",
        # other whitespaces
        "swh\t:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;lines=12",
        "swh:1\n:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;lines=12",
        "swh:1:\rdir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;lines=12",
        "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d\f;lines=12",
        "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;lines=12\v",
    ],
)
def test_parse_swhid_parsing_error(invalid_swhid):
    with pytest.raises(ValidationError):
        identifiers.parse_swhid(invalid_swhid)


@pytest.mark.filterwarnings("ignore:.*SWHID.*:DeprecationWarning")
@pytest.mark.parametrize(
    "ns,version,type,id",
    [
        ("foo", 1, CONTENT, "abc8bc9d7a6bcf6db04f476d29314f157507d505",),
        ("swh", 2, DIRECTORY, "def8bc9d7a6bcf6db04f476d29314f157507d505",),
        ("swh", 1, "foo", "fed8bc9d7a6bcf6db04f476d29314f157507d505",),
        ("swh", 1, SNAPSHOT, "gh6959356d30f1a4e9b7f6bca59b9a336464c03d",),
    ],
)
def test_SWHID_class_validation_error(ns, version, type, id):
    with pytest.raises(ValidationError):
        SWHID(
            namespace=ns, scheme_version=version, object_type=type, object_id=id,
        )


@pytest.mark.filterwarnings("ignore:.*SWHID.*:DeprecationWarning")
def test_SWHID_hash():
    object_id = "94a9ed024d3859793618152ea559a168bbcbb5e2"

    assert hash(SWHID(object_type="directory", object_id=object_id)) == hash(
        SWHID(object_type="directory", object_id=object_id)
    )

    assert hash(
        SWHID(object_type="directory", object_id=object_id, metadata=dummy_qualifiers,)
    ) == hash(
        SWHID(object_type="directory", object_id=object_id, metadata=dummy_qualifiers,)
    )

    # Different order of the dictionary, so the underlying order of the tuple in
    # ImmutableDict is different.
    assert hash(
        SWHID(
            object_type="directory",
            object_id=object_id,
            metadata={"origin": "https://example.com", "lines": "42"},
        )
    ) == hash(
        SWHID(
            object_type="directory",
            object_id=object_id,
            metadata={"lines": "42", "origin": "https://example.com"},
        )
    )


@pytest.mark.filterwarnings("ignore:.*SWHID.*:DeprecationWarning")
def test_SWHID_eq():
    object_id = "94a9ed024d3859793618152ea559a168bbcbb5e2"

    assert SWHID(object_type="directory", object_id=object_id) == SWHID(
        object_type="directory", object_id=object_id
    )

    assert SWHID(
        object_type="directory", object_id=object_id, metadata=dummy_qualifiers,
    ) == SWHID(object_type="directory", object_id=object_id, metadata=dummy_qualifiers,)

    assert SWHID(
        object_type="directory", object_id=object_id, metadata=dummy_qualifiers,
    ) == SWHID(object_type="directory", object_id=object_id, metadata=dummy_qualifiers,)


# SWHIDs that are outright invalid, no matter the context
INVALID_SWHIDS = [
    "swh:1:cnt",
    "swh:1:",
    "swh:",
    "swh:1:cnt:",
    "foo:1:cnt:abc8bc9d7a6bcf6db04f476d29314f157507d505",
    "swh:2:dir:def8bc9d7a6bcf6db04f476d29314f157507d505",
    "swh:1:foo:fed8bc9d7a6bcf6db04f476d29314f157507d505",
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;invalid;malformed",
    "swh:1:snp:gh6959356d30f1a4e9b7f6bca59b9a336464c03d",
    "swh:1:snp:foo",
    # wrong qualifier: ori should be origin
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;ori=something;anchor=1;visit=1;path=/",  # noqa
    # wrong qualifier: anc should be anchor
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=something;anc=1;visit=1;path=/",  # noqa
    # wrong qualifier: vis should be visit
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=something;anchor=1;vis=1;path=/",  # noqa
    # wrong qualifier: pa should be path
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=something;anchor=1;visit=1;pa=/",  # noqa
    # wrong qualifier: line should be lines
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;line=10;origin=something;anchor=1;visit=1;path=/",  # noqa
    # wrong qualifier value: it contains space before of after
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=  https://some-url",  # noqa
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=something;anchor=some-anchor    ",  # noqa
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=something;anchor=some-anchor    ;visit=1",  # noqa
    # invalid swhid: whitespaces
    "swh :1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;ori=something;anchor=1;visit=1;path=/",  # noqa
    "swh: 1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;ori=something;anchor=1;visit=1;path=/",  # noqa
    "swh: 1: dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;ori=something;anchor=1;visit=1;path=/",  # noqa
    "swh:1: dir: 0b6959356d30f1a4e9b7f6bca59b9a336464c03d",
    "swh:1: dir: 0b6959356d30f1a4e9b7f6bca59b9a336464c03d; origin=blah",
    "swh:1: dir: 0b6959356d30f1a4e9b7f6bca59b9a336464c03d;lines=12",
    # other whitespaces
    "swh\t:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;lines=12",
    "swh:1\n:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;lines=12",
    "swh:1:\rdir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;lines=12",
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d\f;lines=12",
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;lines=12\v",
]

SWHID_CLASSES = [CoreSWHID, QualifiedSWHID, ExtendedSWHID]


@pytest.mark.parametrize(
    "invalid_swhid,swhid_class", itertools.product(INVALID_SWHIDS, SWHID_CLASSES)
)
def test_swhid_parsing_error(invalid_swhid, swhid_class):
    """Tests SWHID strings that are invalid for all SWHID classes do raise
    a ValidationError"""
    with pytest.raises(ValidationError):
        swhid_class.from_string(invalid_swhid)


# string SWHIDs, and how they should be parsed by each of the classes,
# or None if the class does not support it
HASH = "94a9ed024d3859793618152ea559a168bbcbb5e2"
VALID_SWHIDS = [
    (
        f"swh:1:cnt:{HASH}",
        CoreSWHID(object_type=ObjectType.CONTENT, object_id=_x(HASH),),
        QualifiedSWHID(object_type=ObjectType.CONTENT, object_id=_x(HASH),),
        ExtendedSWHID(object_type=ExtendedObjectType.CONTENT, object_id=_x(HASH),),
    ),
    (
        f"swh:1:dir:{HASH}",
        CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=_x(HASH),),
        QualifiedSWHID(object_type=ObjectType.DIRECTORY, object_id=_x(HASH),),
        ExtendedSWHID(object_type=ExtendedObjectType.DIRECTORY, object_id=_x(HASH),),
    ),
    (
        f"swh:1:rev:{HASH}",
        CoreSWHID(object_type=ObjectType.REVISION, object_id=_x(HASH),),
        QualifiedSWHID(object_type=ObjectType.REVISION, object_id=_x(HASH),),
        ExtendedSWHID(object_type=ExtendedObjectType.REVISION, object_id=_x(HASH),),
    ),
    (
        f"swh:1:rel:{HASH}",
        CoreSWHID(object_type=ObjectType.RELEASE, object_id=_x(HASH),),
        QualifiedSWHID(object_type=ObjectType.RELEASE, object_id=_x(HASH),),
        ExtendedSWHID(object_type=ExtendedObjectType.RELEASE, object_id=_x(HASH),),
    ),
    (
        f"swh:1:snp:{HASH}",
        CoreSWHID(object_type=ObjectType.SNAPSHOT, object_id=_x(HASH),),
        QualifiedSWHID(object_type=ObjectType.SNAPSHOT, object_id=_x(HASH),),
        ExtendedSWHID(object_type=ExtendedObjectType.SNAPSHOT, object_id=_x(HASH),),
    ),
    (
        f"swh:1:cnt:{HASH};origin=https://github.com/python/cpython;lines=1-18",
        None,  # CoreSWHID does not allow qualifiers
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
            origin="https://github.com/python/cpython",
            lines=(1, 18),
        ),
        None,  # Neither does ExtendedSWHID
    ),
    (
        f"swh:1:cnt:{HASH};origin=https://github.com/python/cpython;lines=18",
        None,  # likewise
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
            origin="https://github.com/python/cpython",
            lines=(18, None),
        ),
        None,  # likewise
    ),
    (
        f"swh:1:dir:{HASH};origin=deb://Debian/packages/linuxdoc-tools",
        None,  # likewise
        QualifiedSWHID(
            object_type=ObjectType.DIRECTORY,
            object_id=_x(HASH),
            origin="deb://Debian/packages/linuxdoc-tools",
        ),
        None,  # likewise
    ),
    (
        f"swh:1:ori:{HASH}",
        None,  # CoreSWHID does not allow origin pseudo-SWHIDs
        None,  # Neither does QualifiedSWHID
        ExtendedSWHID(object_type=ExtendedObjectType.ORIGIN, object_id=_x(HASH),),
    ),
    (
        f"swh:1:emd:{HASH}",
        None,  # likewise for metadata pseudo-SWHIDs
        None,  # Neither does QualifiedSWHID
        ExtendedSWHID(
            object_type=ExtendedObjectType.RAW_EXTRINSIC_METADATA, object_id=_x(HASH),
        ),
    ),
    (
        f"swh:1:emd:{HASH};origin=https://github.com/python/cpython",
        None,  # CoreSWHID does not allow metadata pseudo-SWHIDs or qualifiers
        None,  # QualifiedSWHID does not allow metadata pseudo-SWHIDs
        None,  # ExtendedSWHID does not allow qualifiers
    ),
]


@pytest.mark.parametrize(
    "string,core,qualified,extended",
    [
        pytest.param(string, core, qualified, extended, id=string)
        for (string, core, qualified, extended) in VALID_SWHIDS
    ],
)
def test_parse_unparse_swhids(string, core, qualified, extended):
    """Tests parsing and serializing valid SWHIDs with the various SWHID classes."""
    classes = [CoreSWHID, QualifiedSWHID, ExtendedSWHID]
    for (cls, parsed_swhid) in zip(classes, [core, qualified, extended]):
        if parsed_swhid is None:
            # This class should not accept this SWHID
            with pytest.raises(ValidationError):
                cls.from_string(string)
        else:
            # This class should
            assert cls.from_string(string) == parsed_swhid

            # Also check serialization
            assert string == str(parsed_swhid)


@pytest.mark.parametrize(
    "core,extended",
    [
        pytest.param(core, extended, id=string)
        for (string, core, qualified, extended) in VALID_SWHIDS
        if core is not None
    ],
)
def test_core_to_extended(core, extended):
    assert core.to_extended() == extended


@pytest.mark.parametrize(
    "ns,version,type,id,qualifiers",
    [
        ("foo", 1, ObjectType.CONTENT, "abc8bc9d7a6bcf6db04f476d29314f157507d505", {}),
        ("swh", 2, ObjectType.CONTENT, "def8bc9d7a6bcf6db04f476d29314f157507d505", {}),
        ("swh", 1, ObjectType.DIRECTORY, "aaaa", {}),
    ],
)
def test_QualifiedSWHID_validation_error(ns, version, type, id, qualifiers):
    with pytest.raises(ValidationError):
        QualifiedSWHID(
            namespace=ns,
            scheme_version=version,
            object_type=type,
            object_id=_x(id),
            **qualifiers,
        )


@pytest.mark.parametrize(
    "object_type,qualifiers,expected",
    [
        # No qualifier:
        (ObjectType.CONTENT, {}, f"swh:1:cnt:{HASH}"),
        # origin:
        (ObjectType.CONTENT, {"origin": None}, f"swh:1:cnt:{HASH}"),
        (ObjectType.CONTENT, {"origin": 42}, ValueError),
        # visit:
        (
            ObjectType.CONTENT,
            {"visit": f"swh:1:snp:{HASH}"},
            f"swh:1:cnt:{HASH};visit=swh:1:snp:{HASH}",
        ),
        (
            ObjectType.CONTENT,
            {"visit": CoreSWHID(object_type=ObjectType.SNAPSHOT, object_id=_x(HASH))},
            f"swh:1:cnt:{HASH};visit=swh:1:snp:{HASH}",
        ),
        (ObjectType.CONTENT, {"visit": 42}, TypeError),
        (ObjectType.CONTENT, {"visit": f"swh:1:rel:{HASH}"}, ValidationError,),
        (
            ObjectType.CONTENT,
            {"visit": CoreSWHID(object_type=ObjectType.RELEASE, object_id=_x(HASH))},
            ValidationError,
        ),
        # anchor:
        (
            ObjectType.CONTENT,
            {"anchor": f"swh:1:snp:{HASH}"},
            f"swh:1:cnt:{HASH};anchor=swh:1:snp:{HASH}",
        ),
        (
            ObjectType.CONTENT,
            {"anchor": CoreSWHID(object_type=ObjectType.SNAPSHOT, object_id=_x(HASH))},
            f"swh:1:cnt:{HASH};anchor=swh:1:snp:{HASH}",
        ),
        (
            ObjectType.CONTENT,
            {"anchor": f"swh:1:dir:{HASH}"},
            f"swh:1:cnt:{HASH};anchor=swh:1:dir:{HASH}",
        ),
        (
            ObjectType.CONTENT,
            {"anchor": CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=_x(HASH))},
            f"swh:1:cnt:{HASH};anchor=swh:1:dir:{HASH}",
        ),
        (ObjectType.CONTENT, {"anchor": 42}, TypeError),
        (ObjectType.CONTENT, {"anchor": f"swh:1:cnt:{HASH}"}, ValidationError,),
        (
            ObjectType.CONTENT,
            {"anchor": CoreSWHID(object_type=ObjectType.CONTENT, object_id=_x(HASH))},
            ValidationError,
        ),
        # path:
        (ObjectType.CONTENT, {"path": b"/foo"}, f"swh:1:cnt:{HASH};path=/foo",),
        (
            ObjectType.CONTENT,
            {"path": b"/foo;bar"},
            f"swh:1:cnt:{HASH};path=/foo%3Bbar",
        ),
        (ObjectType.CONTENT, {"path": "/foo"}, f"swh:1:cnt:{HASH};path=/foo",),
        (
            ObjectType.CONTENT,
            {"path": "/foo;bar"},
            f"swh:1:cnt:{HASH};path=/foo%3Bbar",
        ),
        (ObjectType.CONTENT, {"path": 42}, Exception),
        # lines:
        (ObjectType.CONTENT, {"lines": (42, None)}, f"swh:1:cnt:{HASH};lines=42",),
        (ObjectType.CONTENT, {"lines": (21, 42)}, f"swh:1:cnt:{HASH};lines=21-42",),
        (ObjectType.CONTENT, {"lines": 42}, TypeError,),
        (ObjectType.CONTENT, {"lines": (None, 42)}, ValueError,),
        (ObjectType.CONTENT, {"lines": ("42", None)}, ValueError,),
    ],
)
def test_QualifiedSWHID_init(object_type, qualifiers, expected):
    """Tests validation and converters of qualifiers"""
    if isinstance(expected, type):
        assert issubclass(expected, Exception)
        with pytest.raises(expected):
            QualifiedSWHID(object_type=object_type, object_id=_x(HASH), **qualifiers)
    else:
        assert isinstance(expected, str)
        swhid = QualifiedSWHID(
            object_type=object_type, object_id=_x(HASH), **qualifiers
        )

        # Check the build object has the right serialization
        assert expected == str(swhid)

        # Check the internal state of the object is the same as if parsed from a string
        assert QualifiedSWHID.from_string(expected) == swhid


def test_QualifiedSWHID_hash():
    object_id = _x("94a9ed024d3859793618152ea559a168bbcbb5e2")

    assert hash(
        QualifiedSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id)
    ) == hash(QualifiedSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id))

    assert hash(
        QualifiedSWHID(
            object_type=ObjectType.DIRECTORY, object_id=object_id, **dummy_qualifiers,
        )
    ) == hash(
        QualifiedSWHID(
            object_type=ObjectType.DIRECTORY, object_id=object_id, **dummy_qualifiers,
        )
    )

    # Different order of the dictionary, so the underlying order of the tuple in
    # ImmutableDict is different.
    assert hash(
        QualifiedSWHID(
            object_type=ObjectType.DIRECTORY,
            object_id=object_id,
            origin="https://example.com",
            lines=(42, None),
        )
    ) == hash(
        QualifiedSWHID(
            object_type=ObjectType.DIRECTORY,
            object_id=object_id,
            lines=(42, None),
            origin="https://example.com",
        )
    )


def test_QualifiedSWHID_eq():
    object_id = _x("94a9ed024d3859793618152ea559a168bbcbb5e2")

    assert QualifiedSWHID(
        object_type=ObjectType.DIRECTORY, object_id=object_id
    ) == QualifiedSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id)

    assert QualifiedSWHID(
        object_type=ObjectType.DIRECTORY, object_id=object_id, **dummy_qualifiers,
    ) == QualifiedSWHID(
        object_type=ObjectType.DIRECTORY, object_id=object_id, **dummy_qualifiers,
    )

    assert QualifiedSWHID(
        object_type=ObjectType.DIRECTORY, object_id=object_id, **dummy_qualifiers,
    ) == QualifiedSWHID(
        object_type=ObjectType.DIRECTORY, object_id=object_id, **dummy_qualifiers,
    )


QUALIFIED_SWHIDS = [
    # origin:
    (
        f"swh:1:cnt:{HASH};origin=https://github.com/python/cpython",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
            origin="https://github.com/python/cpython",
        ),
    ),
    (
        f"swh:1:cnt:{HASH};origin=https://example.org/foo%3Bbar%25baz",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
            origin="https://example.org/foo%3Bbar%25baz",
        ),
    ),
    # visit:
    (
        f"swh:1:cnt:{HASH};visit=swh:1:snp:{HASH}",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
            visit=CoreSWHID(object_type=ObjectType.SNAPSHOT, object_id=_x(HASH)),
        ),
    ),
    (f"swh:1:cnt:{HASH};visit=swh:1:rel:{HASH}", None,),
    # anchor:
    (
        f"swh:1:cnt:{HASH};anchor=swh:1:dir:{HASH}",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
            anchor=CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=_x(HASH)),
        ),
    ),
    (
        f"swh:1:cnt:{HASH};anchor=swh:1:rev:{HASH}",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
            anchor=CoreSWHID(object_type=ObjectType.REVISION, object_id=_x(HASH)),
        ),
    ),
    (
        f"swh:1:cnt:{HASH};anchor=swh:1:cnt:{HASH}",
        None,  # 'cnt' is not valid in anchor
    ),
    (
        f"swh:1:cnt:{HASH};anchor=swh:1:ori:{HASH}",
        None,  # 'ori' is not valid in a CoreSWHID
    ),
    # path:
    (
        f"swh:1:cnt:{HASH};path=/foo",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT, object_id=_x(HASH), path=b"/foo"
        ),
    ),
    (
        f"swh:1:cnt:{HASH};path=/foo%3Bbar",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT, object_id=_x(HASH), path=b"/foo;bar"
        ),
    ),
    (
        f"swh:1:cnt:{HASH};path=/foo%25bar",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT, object_id=_x(HASH), path=b"/foo%bar"
        ),
    ),
    # lines
    (
        f"swh:1:cnt:{HASH};lines=1-18",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT, object_id=_x(HASH), lines=(1, 18),
        ),
    ),
    (
        f"swh:1:cnt:{HASH};lines=18",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT, object_id=_x(HASH), lines=(18, None),
        ),
    ),
    (f"swh:1:cnt:{HASH};lines=", None,),
    (f"swh:1:cnt:{HASH};lines=aa", None,),
    (f"swh:1:cnt:{HASH};lines=18-aa", None,),
]


@pytest.mark.parametrize("string,parsed", QUALIFIED_SWHIDS)
def test_QualifiedSWHID_parse_serialize_qualifiers(string, parsed):
    """Tests parsing and serializing valid SWHIDs with the various SWHID classes."""
    if parsed is None:
        with pytest.raises(ValidationError):
            print(repr(QualifiedSWHID.from_string(string)))
    else:
        assert QualifiedSWHID.from_string(string) == parsed
        assert str(parsed) == string


def test_QualifiedSWHID_serialize_origin():
    """Checks that semicolon in origins are escaped."""
    string = f"swh:1:cnt:{HASH};origin=https://example.org/foo%3Bbar%25baz"
    swhid = QualifiedSWHID(
        object_type=ObjectType.CONTENT,
        object_id=_x(HASH),
        origin="https://example.org/foo;bar%25baz",
    )
    assert str(swhid) == string


def test_QualifiedSWHID_attributes():
    """Checks the set of QualifiedSWHID attributes match the SWHID_QUALIFIERS
    constant."""

    assert set(attr.fields_dict(QualifiedSWHID)) == {
        "namespace",
        "scheme_version",
        "object_type",
        "object_id",
        *SWHID_QUALIFIERS,
    }


@pytest.mark.parametrize(
    "ns,version,type,id",
    [
        ("foo", 1, ObjectType.CONTENT, "abc8bc9d7a6bcf6db04f476d29314f157507d505"),
        ("swh", 2, ObjectType.CONTENT, "def8bc9d7a6bcf6db04f476d29314f157507d505"),
        ("swh", 1, ObjectType.DIRECTORY, "aaaa"),
    ],
)
def test_CoreSWHID_validation_error(ns, version, type, id):
    with pytest.raises(ValidationError):
        CoreSWHID(
            namespace=ns, scheme_version=version, object_type=type, object_id=_x(id),
        )


def test_CoreSWHID_hash():
    object_id = _x("94a9ed024d3859793618152ea559a168bbcbb5e2")

    assert hash(
        CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id)
    ) == hash(CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id))

    assert hash(
        CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id,)
    ) == hash(CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id,))

    # Different order of the dictionary, so the underlying order of the tuple in
    # ImmutableDict is different.
    assert hash(
        CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id,)
    ) == hash(CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id,))


def test_CoreSWHID_eq():
    object_id = _x("94a9ed024d3859793618152ea559a168bbcbb5e2")

    assert CoreSWHID(
        object_type=ObjectType.DIRECTORY, object_id=object_id
    ) == CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id)

    assert CoreSWHID(
        object_type=ObjectType.DIRECTORY, object_id=object_id,
    ) == CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id,)

    assert CoreSWHID(
        object_type=ObjectType.DIRECTORY, object_id=object_id,
    ) == CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id,)


@pytest.mark.parametrize(
    "ns,version,type,id",
    [
        (
            "foo",
            1,
            ExtendedObjectType.CONTENT,
            "abc8bc9d7a6bcf6db04f476d29314f157507d505",
        ),
        (
            "swh",
            2,
            ExtendedObjectType.CONTENT,
            "def8bc9d7a6bcf6db04f476d29314f157507d505",
        ),
        ("swh", 1, ExtendedObjectType.DIRECTORY, "aaaa"),
    ],
)
def test_ExtendedSWHID_validation_error(ns, version, type, id):
    with pytest.raises(ValidationError):
        ExtendedSWHID(
            namespace=ns, scheme_version=version, object_type=type, object_id=_x(id),
        )


def test_ExtendedSWHID_hash():
    object_id = _x("94a9ed024d3859793618152ea559a168bbcbb5e2")

    assert hash(
        ExtendedSWHID(object_type=ExtendedObjectType.DIRECTORY, object_id=object_id)
    ) == hash(
        ExtendedSWHID(object_type=ExtendedObjectType.DIRECTORY, object_id=object_id)
    )

    assert hash(
        ExtendedSWHID(object_type=ExtendedObjectType.DIRECTORY, object_id=object_id,)
    ) == hash(
        ExtendedSWHID(object_type=ExtendedObjectType.DIRECTORY, object_id=object_id,)
    )

    # Different order of the dictionary, so the underlying order of the tuple in
    # ImmutableDict is different.
    assert hash(
        ExtendedSWHID(object_type=ExtendedObjectType.DIRECTORY, object_id=object_id,)
    ) == hash(
        ExtendedSWHID(object_type=ExtendedObjectType.DIRECTORY, object_id=object_id,)
    )


def test_ExtendedSWHID_eq():
    object_id = _x("94a9ed024d3859793618152ea559a168bbcbb5e2")

    assert ExtendedSWHID(
        object_type=ExtendedObjectType.DIRECTORY, object_id=object_id
    ) == ExtendedSWHID(object_type=ExtendedObjectType.DIRECTORY, object_id=object_id)

    assert ExtendedSWHID(
        object_type=ExtendedObjectType.DIRECTORY, object_id=object_id,
    ) == ExtendedSWHID(object_type=ExtendedObjectType.DIRECTORY, object_id=object_id,)

    assert ExtendedSWHID(
        object_type=ExtendedObjectType.DIRECTORY, object_id=object_id,
    ) == ExtendedSWHID(object_type=ExtendedObjectType.DIRECTORY, object_id=object_id,)


def test_object_types():
    """Checks ExtendedObjectType is a superset of ObjectType"""
    for member in ObjectType:
        assert getattr(ExtendedObjectType, member.name).value == member.value
