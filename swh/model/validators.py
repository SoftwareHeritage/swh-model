# Copyright (C) 2015-2018  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from . import fields
from .exceptions import NON_FIELD_ERRORS, ValidationError
from .hashutil import MultiHash, hash_to_bytes


def validate_content(content):
    """Validate that a content has the correct schema.

    Args: a content (dictionary) to validate."""

    def validate_content_status(status):
        return fields.validate_enum(status, {"absent", "visible", "hidden"})

    def validate_keys(content):
        hashes = {"sha1", "sha1_git", "sha256"}
        errors = []

        out = True
        if content["status"] == "absent":
            try:
                out = out and fields.validate_all_keys(content, {"reason", "origin"})
            except ValidationError as e:
                errors.append(e)
            try:
                out = out and fields.validate_any_key(content, hashes)
            except ValidationError as e:
                errors.append(e)
        else:
            try:
                out = out and fields.validate_all_keys(content, hashes)
            except ValidationError as e:
                errors.append(e)

        if errors:
            raise ValidationError(errors)

        return out

    def validate_hashes(content):
        errors = []
        if "data" in content:
            hashes = MultiHash.from_data(content["data"]).digest()
            for hash_type, computed_hash in hashes.items():
                if hash_type not in content:
                    continue
                content_hash = hash_to_bytes(content[hash_type])
                if content_hash != computed_hash:
                    errors.append(
                        ValidationError(
                            "hash mismatch in content for hash %(hash)s",
                            params={"hash": hash_type},
                            code="content-hash-mismatch",
                        )
                    )
            if errors:
                raise ValidationError(errors)

        return True

    content_schema = {
        "sha1": (False, fields.validate_sha1),
        "sha1_git": (False, fields.validate_sha1_git),
        "sha256": (False, fields.validate_sha256),
        "status": (True, validate_content_status),
        "length": (True, fields.validate_int),
        "ctime": (True, fields.validate_datetime),
        "reason": (False, fields.validate_str),
        "origin": (False, fields.validate_int),
        "data": (False, fields.validate_bytes),
        NON_FIELD_ERRORS: [validate_keys, validate_hashes],
    }

    return fields.validate_against_schema("content", content_schema, content)
