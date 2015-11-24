# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime
import numbers

from ..exceptions import ValidationError


def validate_type(value, type):
    """Validate that value is an integer"""
    if not isinstance(value, type):
        if isinstance(type, tuple):
            typestr = 'one of %s' % ', '.join(typ.__name__ for typ in type)
        else:
            typestr = type.__name__
        raise ValidationError(
            'Unexpected type %(type)s, expected %(expected_type)s',
            params={
                'type': value.__class__.__name__,
                'expected_type': typestr,
            },
            code='unexpected-type'
        )

    return True


def validate_int(value):
    """Validate that the given value is an int"""
    return validate_type(value, numbers.Integral)


def validate_str(value):
    """Validate that the given value is a string"""
    return validate_type(value, str)


def validate_bytes(value):
    """Validate that the given value is a bytes object"""
    return validate_type(value, bytes)


def validate_datetime(value):
    """Validate that the given value is either a datetime, or a numeric number
    of seconds since the UNIX epoch."""

    errors = []
    try:
        validate_type(value, (datetime.datetime, numbers.Real))
    except ValidationError as e:
        errors.append(e)

    if isinstance(value, datetime.datetime) and value.tzinfo is None:
        errors.append(ValidationError(
            'Datetimes must be timezone-aware in swh',
            code='datetime-without-tzinfo',
        ))

    if errors:
        raise ValidationError(errors)

    return True


def validate_enum(value, expected_values):
    """Validate that value is contained in expected_values"""
    if value not in expected_values:
        raise ValidationError(
            'Unexpected value %(value)s, expected one of %(expected_values)s',
            params={
                'value': value,
                'expected_values': ', '.join(sorted(expected_values)),
            },
            code='unexpected-value',
        )

    return True
