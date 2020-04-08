# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from collections import defaultdict
import itertools

from ..exceptions import ValidationError, NON_FIELD_ERRORS


def validate_against_schema(model, schema, value):
    """Validate a value for the given model against the given schema.

    Args:
        model: the name of the model
        schema: the schema to validate against
        value: the value to validate

    Returns:
        True if the value is correct against the schema

    Raises:
        ValidationError if the value does not validate against the schema
    """

    if not isinstance(value, dict):
        raise ValidationError(
            "Unexpected type %(type)s for %(model)s, expected dict",
            params={"model": model, "type": value.__class__.__name__,},
            code="model-unexpected-type",
        )

    errors = defaultdict(list)

    for key, (mandatory, validators) in itertools.chain(
        ((k, v) for k, v in schema.items() if k != NON_FIELD_ERRORS),
        [(NON_FIELD_ERRORS, (False, schema.get(NON_FIELD_ERRORS, [])))],
    ):
        if not validators:
            continue

        if not isinstance(validators, list):
            validators = [validators]

        validated_value = value
        if key != NON_FIELD_ERRORS:
            try:
                validated_value = value[key]
            except KeyError:
                if mandatory:
                    errors[key].append(
                        ValidationError(
                            "Field %(field)s is mandatory",
                            params={"field": key},
                            code="model-field-mandatory",
                        )
                    )

                continue
        else:
            if errors:
                # Don't validate the whole object if some fields are broken
                continue

        for validator in validators:
            try:
                valid = validator(validated_value)
            except ValidationError as e:
                errors[key].append(e)
            else:
                if not valid:
                    errdata = {
                        "validator": validator.__name__,
                    }

                    if key == NON_FIELD_ERRORS:
                        errmsg = (
                            "Validation of model %(model)s failed in " "%(validator)s"
                        )
                        errdata["model"] = model
                        errcode = "model-validation-failed"
                    else:
                        errmsg = (
                            "Validation of field %(field)s failed in " "%(validator)s"
                        )
                        errdata["field"] = key
                        errcode = "field-validation-failed"

                    errors[key].append(
                        ValidationError(errmsg, params=errdata, code=errcode)
                    )

    if errors:
        raise ValidationError(dict(errors))

    return True


def validate_all_keys(value, keys):
    """Validate that all the given keys are present in value"""
    missing_keys = set(keys) - set(value)
    if missing_keys:
        missing_fields = ", ".join(sorted(missing_keys))
        raise ValidationError(
            "Missing mandatory fields %(missing_fields)s",
            params={"missing_fields": missing_fields},
            code="missing-mandatory-field",
        )

    return True


def validate_any_key(value, keys):
    """Validate that any of the given keys is present in value"""
    present_keys = set(keys) & set(value)
    if not present_keys:
        missing_fields = ", ".join(sorted(keys))
        raise ValidationError(
            "Must contain one of the alternative fields %(missing_fields)s",
            params={"missing_fields": missing_fields},
            code="missing-alternative-field",
        )

    return True
