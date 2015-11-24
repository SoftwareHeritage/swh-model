# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from .exceptions import ValidationError, NON_FIELD_ERRORS
from . import fields


def validate_content(content):
    """Validate that a content has the correct schema.

    Args: a content (dictionary) to validate."""

    def validate_content_status(status):
        return fields.validate_enum(status, {'absent', 'visible', 'hidden'})

    def validate_keys(content):
        hashes = {'sha1', 'sha1_git', 'sha256'}
        errors = []

        if content['status'] == 'absent':
            try:
                out = fields.validate_all_keys(content, {'reason', 'origin'})
            except ValidationError as e:
                errors.append(e)
            try:
                out = out and fields.validate_any_key(content, hashes)
            except ValidationError as e:
                errors.append(e)
        else:
            try:
                out = fields.validate_all_keys(content, hashes)
            except ValidationError as e:
                errors.append(e)

        if errors:
            raise ValidationError(errors)

        return out

    content_schema = {
        'sha1': (False, fields.validate_sha1),
        'sha1_git': (False, fields.validate_sha1_git),
        'sha256': (False, fields.validate_sha256),
        'status': (True, validate_content_status),
        'length': (True, fields.validate_int),
        'ctime': (True, fields.validate_datetime),
        'reason': (False, fields.validate_str),
        'origin': (False, fields.validate_int),
        NON_FIELD_ERRORS: validate_keys,
    }

    return fields.validate_against_schema('content', content_schema, content)
