# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import string
from ..exceptions import ValidationError


def validate_hash(value, hash_type):
    """Validate that the given value represents a hash of the given hash_type.

    Args:
        value: the value to check
        hash_type: the type of hash the value is representing

    Returns:
        True if the hash validates

    Raises:
        ValueError if the hash does not validate
    """

    hash_lengths = {
        "sha1": 20,
        "sha1_git": 20,
        "sha256": 32,
    }

    hex_digits = set(string.hexdigits)

    if hash_type not in hash_lengths:
        raise ValidationError(
            "Unexpected hash type %(hash_type)s, expected one of" " %(hash_types)s",
            params={
                "hash_type": hash_type,
                "hash_types": ", ".join(sorted(hash_lengths)),
            },
            code="unexpected-hash-type",
        )

    if isinstance(value, str):
        errors = []
        extra_chars = set(value) - hex_digits
        if extra_chars:
            errors.append(
                ValidationError(
                    "Unexpected characters `%(unexpected_chars)s' for hash "
                    "type %(hash_type)s",
                    params={
                        "unexpected_chars": ", ".join(sorted(extra_chars)),
                        "hash_type": hash_type,
                    },
                    code="unexpected-hash-contents",
                )
            )

        length = len(value)
        expected_length = 2 * hash_lengths[hash_type]
        if length != expected_length:
            errors.append(
                ValidationError(
                    "Unexpected length %(length)d for hash type "
                    "%(hash_type)s, expected %(expected_length)d",
                    params={
                        "length": length,
                        "expected_length": expected_length,
                        "hash_type": hash_type,
                    },
                    code="unexpected-hash-length",
                )
            )

        if errors:
            raise ValidationError(errors)

        return True

    if isinstance(value, bytes):
        length = len(value)
        expected_length = hash_lengths[hash_type]
        if length != expected_length:
            raise ValidationError(
                "Unexpected length %(length)d for hash type "
                "%(hash_type)s, expected %(expected_length)d",
                params={
                    "length": length,
                    "expected_length": expected_length,
                    "hash_type": hash_type,
                },
                code="unexpected-hash-length",
            )

        return True

    raise ValidationError(
        "Unexpected type %(type)s for hash, expected str or bytes",
        params={"type": value.__class__.__name__,},
        code="unexpected-hash-value-type",
    )


def validate_sha1(sha1):
    """Validate that sha1 is a valid sha1 hash"""
    return validate_hash(sha1, "sha1")


def validate_sha1_git(sha1_git):
    """Validate that sha1_git is a valid sha1_git hash"""
    return validate_hash(sha1_git, "sha1_git")


def validate_sha256(sha256):
    """Validate that sha256 is a valid sha256 hash"""
    return validate_hash(sha256, "sha256")
