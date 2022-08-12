# Copyright (C) 2015-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime
import hashlib
from typing import Dict
import unittest

import pytest

from swh.model import git_objects, hashutil
from swh.model.hashutil import hash_to_bytes as _x
from swh.model.model import (
    Content,
    Directory,
    ExtID,
    Origin,
    RawExtrinsicMetadata,
    Release,
    Revision,
    Snapshot,
    TimestampWithTimezone,
)


def remove_id(d: Dict) -> Dict:
    """Returns a (shallow) copy of a dict with the 'id' key removed."""
    d = d.copy()
    if "id" in d:
        del d["id"]
    return d


class UtilityFunctionsDateOffset(unittest.TestCase):
    def setUp(self):
        self.dates = {
            b"1448210036": {
                "seconds": 1448210036,
                "microseconds": 0,
            },
            b"1448210036.002342": {
                "seconds": 1448210036,
                "microseconds": 2342,
            },
            b"1448210036.12": {
                "seconds": 1448210036,
                "microseconds": 120000,
            },
        }

    def test_format_date(self):
        for date_repr, date in self.dates.items():
            self.assertEqual(git_objects.format_date(date), date_repr)


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
            Content.from_data(content_example["data"]).hashes(), self.content_id
        )


directory_example = {
    "id": _x("d7ed3d2c31d608823be58b1cbe57605310615231"),
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


class DirectoryIdentifier(unittest.TestCase):
    def setUp(self):
        self.directory = directory_example

        self.empty_directory = {
            "id": "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            "entries": [],
        }

    def test_dir_identifier(self):
        self.assertEqual(Directory.from_dict(self.directory).id, self.directory["id"])
        self.assertEqual(
            Directory.from_dict(remove_id(self.directory)).id,
            self.directory["id"],
        )

    def test_dir_identifier_entry_order(self):
        # Reverse order of entries, check the id is still the same.
        directory = {"entries": reversed(self.directory["entries"])}
        self.assertEqual(
            Directory.from_dict(remove_id(directory)).id,
            self.directory["id"],
        )

    def test_dir_identifier_empty_directory(self):
        self.assertEqual(
            Directory.from_dict(remove_id(self.empty_directory)).id,
            _x(self.empty_directory["id"]),
        )


linus_tz = datetime.timezone(datetime.timedelta(minutes=-420))

revision_example = {
    "id": _x("bc0195aad0daa2ad5b0d76cce22b167bc3435590"),
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
            "id": _x("bc0195aad0daa2ad5b0d76cce22b167bc3435590"),
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
            "type": "git",
            "synthetic": False,
            "metadata": None,
        }

        self.synthetic_revision = {
            "id": _x("b2a7e1260492e344fab3cbf91bc13c91e05426fd"),
            "author": {
                "name": b"Software Heritage",
                "email": b"robot@softwareheritage.org",
            },
            "date": {
                "timestamp": {"seconds": 1437047495},
                "offset_bytes": b"+0000",
            },
            "type": "tar",
            "committer": {
                "name": b"Software Heritage",
                "email": b"robot@softwareheritage.org",
            },
            "committer_date": 1437047495,
            "synthetic": True,
            "parents": [],
            "message": b"synthetic revision message\n",
            "directory": _x("d11f00a6a0fea6055341d25584b5a96516c0d2b8"),
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
            "id": _x("010d34f384fa99d047cdd5e2f41e56e5c2feee45"),
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
            "type": "git",
            "synthetic": False,
            "extra_headers": (
                (b"svn-repo-uuid", b"046f1af7-66c2-d61b-5410-ce57b7db7bff"),
                (b"svn-revision", b"10"),
            ),
        }

        self.revision_with_gpgsig = {
            "id": _x("44cc742a8ca17b9c279be4cc195a93a6ef7a320e"),
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
            "date": {
                "timestamp": 1428538899,
                "offset": 480,
            },
            "committer": {
                "name": b"Jiang Xin",
                "email": b"worldhello.net@gmail.com",
            },
            "committer_date": {
                "timestamp": 1428538899,
                "offset": 480,
            },
            "extra_headers": ((b"gpgsig", gpgsig),),
            "message": b"""Merge branch 'master' of git://github.com/alexhenrie/git-po

* 'master' of git://github.com/alexhenrie/git-po:
  l10n: ca.po: update translation
""",
            "type": "git",
            "synthetic": False,
        }

        self.revision_no_message = {
            "id": _x("4cfc623c9238fa92c832beed000ce2d003fd8333"),
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
            "date": {
                "timestamp": 1428538899,
                "offset": 480,
            },
            "committer": {
                "name": b"Jiang Xin",
                "email": b"worldhello.net@gmail.com",
            },
            "committer_date": {
                "timestamp": 1428538899,
                "offset": 480,
            },
            "message": None,
            "type": "git",
            "synthetic": False,
        }

        self.revision_empty_message = {
            "id": _x("7442cd78bd3b4966921d6a7f7447417b7acb15eb"),
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
            "date": {
                "timestamp": 1428538899,
                "offset": 480,
            },
            "committer": {
                "name": b"Jiang Xin",
                "email": b"worldhello.net@gmail.com",
            },
            "committer_date": {
                "timestamp": 1428538899,
                "offset": 480,
            },
            "message": b"",
            "type": "git",
            "synthetic": False,
        }

        self.revision_only_fullname = {
            "id": _x("010d34f384fa99d047cdd5e2f41e56e5c2feee45"),
            "directory": _x("85a74718d377195e1efd0843ba4f3260bad4fe07"),
            "parents": [_x("01e2d0627a9a6edb24c37db45db5ecb31e9de808")],
            "author": {
                "fullname": b"Linus Torvalds <torvalds@linux-foundation.org>",
            },
            "date": datetime.datetime(2015, 7, 12, 15, 10, 30, tzinfo=linus_tz),
            "committer": {
                "fullname": b"Linus Torvalds <torvalds@linux-foundation.org>",
            },
            "committer_date": datetime.datetime(
                2015, 7, 12, 15, 10, 30, tzinfo=linus_tz
            ),
            "message": b"Linux 4.2-rc2\n",
            "type": "git",
            "synthetic": False,
            "extra_headers": (
                (b"svn-repo-uuid", b"046f1af7-66c2-d61b-5410-ce57b7db7bff"),
                (b"svn-revision", b"10"),
            ),
        }

    def test_revision_identifier(self):
        self.assertEqual(
            Revision.from_dict(self.revision).id,
            self.revision["id"],
        )
        self.assertEqual(
            Revision.from_dict(remove_id(self.revision)).id,
            self.revision["id"],
        )

    def test_revision_identifier_none_metadata(self):
        self.assertEqual(
            Revision.from_dict(remove_id(self.revision_none_metadata)).id,
            self.revision_none_metadata["id"],
        )

    def test_revision_identifier_synthetic(self):
        self.assertEqual(
            Revision.from_dict(remove_id(self.synthetic_revision)).id,
            self.synthetic_revision["id"],
        )

    def test_revision_identifier_with_extra_headers(self):
        self.assertEqual(
            Revision.from_dict(remove_id(self.revision_with_extra_headers)).id,
            self.revision_with_extra_headers["id"],
        )

    def test_revision_identifier_with_gpgsig(self):
        self.assertEqual(
            Revision.from_dict(remove_id(self.revision_with_gpgsig)).id,
            self.revision_with_gpgsig["id"],
        )

    def test_revision_identifier_no_message(self):
        self.assertEqual(
            Revision.from_dict(remove_id(self.revision_no_message)).id,
            self.revision_no_message["id"],
        )

    def test_revision_identifier_empty_message(self):
        self.assertEqual(
            Revision.from_dict(remove_id(self.revision_empty_message)).id,
            self.revision_empty_message["id"],
        )

    def test_revision_identifier_only_fullname(self):
        self.assertEqual(
            Revision.from_dict(remove_id(self.revision_only_fullname)).id,
            self.revision_only_fullname["id"],
        )


release_example = {
    "id": _x("2b10839e32c4c476e9d94492756bb1a3e1ec4aa8"),
    "target": _x("741b2252a5e14d6c60a913c77a6099abe73a854a"),
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
            "id": _x("26791a8bcf0e6d33f43aef7682bdb555236d56de"),
            "target": _x("9ee1c939d1cb936b1f98e8d81aeffab57bae46ab"),
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
            "id": _x("b6f4f446715f7d9543ef54e41b62982f0db40045"),
            "target": _x("9ee1c939d1cb936b1f98e8d81aeffab57bae46ab"),
            "target_type": "revision",
            "name": b"v2.6.12",
            "author": {
                "name": b"Linus Torvalds",
                "email": b"torvalds@g5.osdl.org",
            },
            "date": datetime.datetime(2005, 10, 27, 17, 2, 33, tzinfo=linus_tz),
            "message": None,
            "synthetic": False,
        }

        self.release_empty_message = {
            "id": _x("71a0aea72444d396575dc25ac37fec87ee3c6492"),
            "target": _x("9ee1c939d1cb936b1f98e8d81aeffab57bae46ab"),
            "target_type": "revision",
            "name": b"v2.6.12",
            "author": {
                "name": b"Linus Torvalds",
                "email": b"torvalds@g5.osdl.org",
            },
            "date": datetime.datetime(2005, 10, 27, 17, 2, 33, tzinfo=linus_tz),
            "message": b"",
            "synthetic": False,
        }

        self.release_negative_utc = {
            "id": _x("97c8d2573a001f88e72d75f596cf86b12b82fd01"),
            "name": b"20081029",
            "target": _x("54e9abca4c77421e2921f5f156c9fe4a9f7441c7"),
            "target_type": "revision",
            "date": {
                "timestamp": {"seconds": 1225281976},
                "offset_bytes": b"-0000",
            },
            "author": {
                "name": b"Otavio Salvador",
                "email": b"otavio@debian.org",
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
                "offset_bytes": b"+1000",
                "timestamp": {
                    "microseconds": 0,
                    "seconds": 1377480558,
                },
            },
            "id": _x("5c98f559d034162de22d3ebeb95433e6f8885231"),
            "message": b"Release of v0.3.2.",
            "name": b"0.3.2",
            "synthetic": False,
            "target": _x("c06aa3d93b78a2865c4935170030f8c2d7396fd3"),
            "target_type": "revision",
        }

        self.release_snapshot_target = dict(self.release)
        self.release_snapshot_target["target_type"] = "snapshot"
        self.release_snapshot_target["id"] = _x(
            "c29c3ddcc6769a04e54dd69d63a6fdcbc566f850"
        )

    def test_release_identifier(self):
        self.assertEqual(
            Release.from_dict(self.release).id,
            self.release["id"],
        )
        self.assertEqual(
            Release.from_dict(remove_id(self.release)).id,
            self.release["id"],
        )

    def test_release_identifier_no_author(self):
        self.assertEqual(
            Release.from_dict(remove_id(self.release_no_author)).id,
            self.release_no_author["id"],
        )

    def test_release_identifier_no_message(self):
        self.assertEqual(
            Release.from_dict(remove_id(self.release_no_message)).id,
            self.release_no_message["id"],
        )

    def test_release_identifier_empty_message(self):
        self.assertEqual(
            Release.from_dict(remove_id(self.release_empty_message)).id,
            self.release_empty_message["id"],
        )

    def test_release_identifier_negative_utc(self):
        self.assertEqual(
            Release.from_dict(remove_id(self.release_negative_utc)).id,
            self.release_negative_utc["id"],
        )

    def test_release_identifier_newline_in_author(self):
        self.assertEqual(
            Release.from_dict(remove_id(self.release_newline_in_author)).id,
            self.release_newline_in_author["id"],
        )

    def test_release_identifier_snapshot_target(self):
        self.assertEqual(
            Release.from_dict(self.release_snapshot_target).id,
            self.release_snapshot_target["id"],
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
        b"alias": {
            "target": b"revision",
            "target_type": "alias",
        },
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
            "id": _x("1a8893e6a86f444e8be8e7bda6cb34fb1735a00e"),
            "branches": {},
        }

        self.dangling_branch = {
            "id": _x("c84502e821eb21ed84e9fd3ec40973abc8b32353"),
            "branches": {
                b"HEAD": None,
            },
        }

        self.unresolved = {
            "id": _x("84b4548ea486e4b0a7933fa541ff1503a0afe1e0"),
            "branches": {
                b"foo": {
                    "target": b"bar",
                    "target_type": "alias",
                },
            },
        }

        self.all_types = snapshot_example

    def test_empty_snapshot(self):
        self.assertEqual(
            Snapshot.from_dict(remove_id(self.empty)).id,
            self.empty["id"],
        )

    def test_dangling_branch(self):
        self.assertEqual(
            Snapshot.from_dict(remove_id(self.dangling_branch)).id,
            self.dangling_branch["id"],
        )

    def test_unresolved(self):
        self.assertEqual(
            Snapshot.from_dict(remove_id(self.unresolved)).id, self.unresolved["id"]
        )

    def test_git_object_unresolved(self):
        with self.assertRaisesRegex(ValueError, "b'foo' -> b'bar'"):
            git_objects.snapshot_git_object(self.unresolved)
        git_objects.snapshot_git_object(self.unresolved, ignore_unresolved=True)

    def test_all_types(self):
        self.assertEqual(
            Snapshot.from_dict(remove_id(self.all_types)).id,
            self.all_types["id"],
        )


authority_example = {
    "type": "forge",
    "url": "https://forge.softwareheritage.org/",
}
fetcher_example = {
    "name": "swh-phabricator-metadata-fetcher",
    "version": "0.0.1",
}
metadata_example = {
    "target": "swh:1:cnt:568aaf43d83b2c3df8067f3bedbb97d83260be6d",
    "discovery_date": datetime.datetime(
        2021, 1, 25, 11, 27, 51, tzinfo=datetime.timezone.utc
    ),
    "authority": authority_example,
    "fetcher": fetcher_example,
    "format": "json",
    "metadata": b'{"foo": "bar"}',
}


class RawExtrinsicMetadataIdentifier(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.minimal = metadata_example
        self.maximal = {
            **self.minimal,
            "origin": "https://forge.softwareheritage.org/source/swh-model/",
            "visit": 42,
            "snapshot": "swh:1:snp:" + "00" * 20,
            "release": "swh:1:rel:" + "01" * 20,
            "revision": "swh:1:rev:" + "02" * 20,
            "path": b"/abc/def",
            "directory": "swh:1:dir:" + "03" * 20,
        }

    def test_minimal(self):
        git_object = (
            b"raw_extrinsic_metadata 210\0"
            b"target swh:1:cnt:568aaf43d83b2c3df8067f3bedbb97d83260be6d\n"
            b"discovery_date 1611574071\n"
            b"authority forge https://forge.softwareheritage.org/\n"
            b"fetcher swh-phabricator-metadata-fetcher 0.0.1\n"
            b"format json\n"
            b"\n"
            b'{"foo": "bar"}'
        )

        self.assertEqual(
            git_objects.raw_extrinsic_metadata_git_object(
                RawExtrinsicMetadata.from_dict(self.minimal)
            ),
            git_object,
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(self.minimal).id,
            hashlib.sha1(git_object).digest(),
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(self.minimal).id,
            _x("5c13f20ba336e44549baf3d7b9305b027ec9f43d"),
        )

    def test_maximal(self):
        git_object = (
            b"raw_extrinsic_metadata 533\0"
            b"target swh:1:cnt:568aaf43d83b2c3df8067f3bedbb97d83260be6d\n"
            b"discovery_date 1611574071\n"
            b"authority forge https://forge.softwareheritage.org/\n"
            b"fetcher swh-phabricator-metadata-fetcher 0.0.1\n"
            b"format json\n"
            b"origin https://forge.softwareheritage.org/source/swh-model/\n"
            b"visit 42\n"
            b"snapshot swh:1:snp:0000000000000000000000000000000000000000\n"
            b"release swh:1:rel:0101010101010101010101010101010101010101\n"
            b"revision swh:1:rev:0202020202020202020202020202020202020202\n"
            b"path /abc/def\n"
            b"directory swh:1:dir:0303030303030303030303030303030303030303\n"
            b"\n"
            b'{"foo": "bar"}'
        )

        self.assertEqual(
            git_objects.raw_extrinsic_metadata_git_object(
                RawExtrinsicMetadata.from_dict(self.maximal)
            ),
            git_object,
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(self.maximal).id,
            hashlib.sha1(git_object).digest(),
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(self.maximal).id,
            _x("f96966e1093d15236a31fde07e47d5b1c9428049"),
        )

    def test_nonascii_path(self):
        metadata = {
            **self.minimal,
            "path": b"/ab\nc/d\xf0\x9f\xa4\xb7e\x00f",
        }
        git_object = (
            b"raw_extrinsic_metadata 231\0"
            b"target swh:1:cnt:568aaf43d83b2c3df8067f3bedbb97d83260be6d\n"
            b"discovery_date 1611574071\n"
            b"authority forge https://forge.softwareheritage.org/\n"
            b"fetcher swh-phabricator-metadata-fetcher 0.0.1\n"
            b"format json\n"
            b"path /ab\n"
            b" c/d\xf0\x9f\xa4\xb7e\x00f\n"
            b"\n"
            b'{"foo": "bar"}'
        )

        self.assertEqual(
            git_objects.raw_extrinsic_metadata_git_object(
                RawExtrinsicMetadata.from_dict(metadata)
            ),
            git_object,
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(metadata).id,
            hashlib.sha1(git_object).digest(),
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(metadata).id,
            _x("7cc83fd1912176510c083f5df43f01b09af4b333"),
        )

    def test_timezone_insensitive(self):
        """Checks the timezone of the datetime.datetime does not affect the
        hashed git_object."""
        utc_plus_one = datetime.timezone(datetime.timedelta(hours=1))
        metadata = {
            **self.minimal,
            "discovery_date": datetime.datetime(
                2021,
                1,
                25,
                12,
                27,
                51,
                tzinfo=utc_plus_one,
            ),
        }

        self.assertEqual(
            git_objects.raw_extrinsic_metadata_git_object(
                RawExtrinsicMetadata.from_dict(self.minimal)
            ),
            git_objects.raw_extrinsic_metadata_git_object(
                RawExtrinsicMetadata.from_dict(metadata)
            ),
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(self.minimal).id,
            RawExtrinsicMetadata.from_dict(metadata).id,
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(metadata).id,
            _x("5c13f20ba336e44549baf3d7b9305b027ec9f43d"),
        )

    def test_microsecond_insensitive(self):
        """Checks the microseconds of the datetime.datetime does not affect the
        hashed manifest."""
        metadata = {
            **self.minimal,
            "discovery_date": datetime.datetime(
                2021,
                1,
                25,
                11,
                27,
                51,
                123456,
                tzinfo=datetime.timezone.utc,
            ),
        }

        self.assertEqual(
            git_objects.raw_extrinsic_metadata_git_object(
                RawExtrinsicMetadata.from_dict(self.minimal)
            ),
            git_objects.raw_extrinsic_metadata_git_object(
                RawExtrinsicMetadata.from_dict(metadata)
            ),
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(self.minimal).id,
            RawExtrinsicMetadata.from_dict(metadata).id,
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(metadata).id,
            _x("5c13f20ba336e44549baf3d7b9305b027ec9f43d"),
        )

    def test_noninteger_timezone(self):
        """Checks the discovery_date is translated to UTC before truncating
        microseconds"""
        tz = datetime.timezone(datetime.timedelta(microseconds=-42))
        metadata = {
            **self.minimal,
            "discovery_date": datetime.datetime(
                2021,
                1,
                25,
                11,
                27,
                50,
                1_000_000 - 42,
                tzinfo=tz,
            ),
        }

        self.assertEqual(
            git_objects.raw_extrinsic_metadata_git_object(
                RawExtrinsicMetadata.from_dict(self.minimal)
            ),
            git_objects.raw_extrinsic_metadata_git_object(
                RawExtrinsicMetadata.from_dict(metadata)
            ),
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(self.minimal).id,
            RawExtrinsicMetadata.from_dict(metadata).id,
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(metadata).id,
            _x("5c13f20ba336e44549baf3d7b9305b027ec9f43d"),
        )

    def test_negative_timestamp(self):
        metadata = {
            **self.minimal,
            "discovery_date": datetime.datetime(
                1960,
                1,
                25,
                11,
                27,
                51,
                tzinfo=datetime.timezone.utc,
            ),
        }

        git_object = (
            b"raw_extrinsic_metadata 210\0"
            b"target swh:1:cnt:568aaf43d83b2c3df8067f3bedbb97d83260be6d\n"
            b"discovery_date -313504329\n"
            b"authority forge https://forge.softwareheritage.org/\n"
            b"fetcher swh-phabricator-metadata-fetcher 0.0.1\n"
            b"format json\n"
            b"\n"
            b'{"foo": "bar"}'
        )

        self.assertEqual(
            git_objects.raw_extrinsic_metadata_git_object(
                RawExtrinsicMetadata.from_dict(metadata)
            ),
            git_object,
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(metadata).id,
            hashlib.sha1(git_object).digest(),
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(metadata).id,
            _x("895d0821a2991dd376ddc303424aceb7c68280f9"),
        )

    def test_epoch(self):
        metadata = {
            **self.minimal,
            "discovery_date": datetime.datetime(
                1970,
                1,
                1,
                0,
                0,
                0,
                tzinfo=datetime.timezone.utc,
            ),
        }

        git_object = (
            b"raw_extrinsic_metadata 201\0"
            b"target swh:1:cnt:568aaf43d83b2c3df8067f3bedbb97d83260be6d\n"
            b"discovery_date 0\n"
            b"authority forge https://forge.softwareheritage.org/\n"
            b"fetcher swh-phabricator-metadata-fetcher 0.0.1\n"
            b"format json\n"
            b"\n"
            b'{"foo": "bar"}'
        )

        self.assertEqual(
            git_objects.raw_extrinsic_metadata_git_object(
                RawExtrinsicMetadata.from_dict(metadata)
            ),
            git_object,
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(metadata).id,
            hashlib.sha1(git_object).digest(),
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(metadata).id,
            _x("27a53df54ace35ebd910493cdc70b334d6b7cb88"),
        )

    def test_negative_epoch(self):
        metadata = {
            **self.minimal,
            "discovery_date": datetime.datetime(
                1969,
                12,
                31,
                23,
                59,
                59,
                1,
                tzinfo=datetime.timezone.utc,
            ),
        }

        git_object = (
            b"raw_extrinsic_metadata 202\0"
            b"target swh:1:cnt:568aaf43d83b2c3df8067f3bedbb97d83260be6d\n"
            b"discovery_date -1\n"
            b"authority forge https://forge.softwareheritage.org/\n"
            b"fetcher swh-phabricator-metadata-fetcher 0.0.1\n"
            b"format json\n"
            b"\n"
            b'{"foo": "bar"}'
        )

        self.assertEqual(
            git_objects.raw_extrinsic_metadata_git_object(
                RawExtrinsicMetadata.from_dict(metadata)
            ),
            git_object,
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(metadata).id,
            hashlib.sha1(git_object).digest(),
        )
        self.assertEqual(
            RawExtrinsicMetadata.from_dict(metadata).id,
            _x("be7154a8fd49d87f81547ea634d1e2152907d089"),
        )


origin_example = {
    "url": "https://github.com/torvalds/linux",
}


class OriginIdentifier(unittest.TestCase):
    def test_content_identifier(self):
        self.assertEqual(
            Origin.from_dict(origin_example).id,
            _x("b63a575fe3faab7692c9f38fb09d4bb45651bb0f"),
        )


# Format: [
#   (
#       input1,
#       expected_output1,
#   ),
#   (
#       input2,
#       expected_output2,
#   ),
#   ...
# ]
TS_DICTS = [
    # with current input dict format (offset_bytes)
    (
        {"timestamp": 12345, "offset_bytes": b"+0000"},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset_bytes": b"+0000",
        },
    ),
    (
        {"timestamp": 12345, "offset_bytes": b"-0000"},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset_bytes": b"-0000",
        },
    ),
    (
        {"timestamp": 12345, "offset_bytes": b"+0200"},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset_bytes": b"+0200",
        },
    ),
    (
        {"timestamp": 12345, "offset_bytes": b"-0200"},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset_bytes": b"-0200",
        },
    ),
    (
        {"timestamp": 12345, "offset_bytes": b"--700"},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset_bytes": b"--700",
        },
    ),
    (
        {"timestamp": 12345, "offset_bytes": b"1234567"},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset_bytes": b"1234567",
        },
    ),
    # with old-style input dicts (numeric offset + optional negative_utc):
    (
        {"timestamp": 12345, "offset": 0},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset_bytes": b"+0000",
        },
    ),
    (
        {"timestamp": 12345, "offset": 0, "negative_utc": False},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset_bytes": b"+0000",
        },
    ),
    (
        {"timestamp": 12345, "offset": 0, "negative_utc": False},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset_bytes": b"+0000",
        },
    ),
    (
        {"timestamp": 12345, "offset": 0, "negative_utc": None},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset_bytes": b"+0000",
        },
    ),
    (
        {"timestamp": {"seconds": 12345}, "offset": 0, "negative_utc": None},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset_bytes": b"+0000",
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
            "offset_bytes": b"+0000",
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
            "offset_bytes": b"+0000",
        },
    ),
    (
        {"timestamp": 12345, "offset": 0, "negative_utc": True},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset_bytes": b"-0000",
        },
    ),
    (
        {"timestamp": 12345, "offset": 0, "negative_utc": None},
        {
            "timestamp": {"seconds": 12345, "microseconds": 0},
            "offset_bytes": b"+0000",
        },
    ),
]


@pytest.mark.parametrize("dict_input,expected", TS_DICTS)
def test_normalize_timestamp_dict(dict_input, expected):
    assert TimestampWithTimezone.from_dict(dict_input).to_dict() == expected


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
        TimestampWithTimezone.from_dict(dict_input)


UTC = datetime.timezone.utc
TS_TIMEZONES = [
    datetime.timezone.min,
    datetime.timezone(datetime.timedelta(hours=-1)),
    UTC,
    datetime.timezone(datetime.timedelta(minutes=+60)),
    datetime.timezone.max,
]
TS_TZ_EXPECTED = [-1439, -60, 0, 60, 1439]
TS_TZ_BYTES_EXPECTED = [b"-2359", b"-0100", b"+0000", b"+0100", b"+2359"]
TS_DATETIMES = [
    datetime.datetime(2020, 2, 27, 14, 39, 19, tzinfo=UTC),
    datetime.datetime(2120, 12, 31, 23, 59, 59, tzinfo=UTC),
    datetime.datetime(1610, 5, 14, 15, 43, 0, tzinfo=UTC),
]
TS_DT_EXPECTED = [1582814359, 4765132799, -11348929020]


@pytest.mark.parametrize("date, seconds", zip(TS_DATETIMES, TS_DT_EXPECTED))
@pytest.mark.parametrize(
    "tz, offset, offset_bytes", zip(TS_TIMEZONES, TS_TZ_EXPECTED, TS_TZ_BYTES_EXPECTED)
)
@pytest.mark.parametrize("microsecond", [0, 1, 10, 100, 1000, 999999])
def test_normalize_timestamp_datetime(
    date, seconds, tz, offset, offset_bytes, microsecond
):
    date = date.astimezone(tz).replace(microsecond=microsecond)
    assert TimestampWithTimezone.from_dict(date).to_dict() == {
        "timestamp": {"seconds": seconds, "microseconds": microsecond},
        "offset_bytes": offset_bytes,
    }


def test_extid_identifier_bwcompat():
    extid_dict = {
        "extid_type": "test-type",
        "extid": b"extid",
        "target": "swh:1:dir:" + "00" * 20,
    }

    assert ExtID.from_dict(extid_dict).id == _x(
        "b9295e1931c31e40a7e3e1e967decd1c89426455"
    )

    assert (
        ExtID.from_dict({**extid_dict, "extid_version": 0}).id
        == ExtID.from_dict(extid_dict).id
    )

    assert (
        ExtID.from_dict({**extid_dict, "extid_version": 1}).id
        != ExtID.from_dict(extid_dict).id
    )
