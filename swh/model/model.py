# Copyright (C) 2018-2020 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

"""
Implementation of Software Heritage's data model

See :ref:`data-model` for an overview of the data model.

The classes defined in this module are immutable
`attrs objects <https://attrs.org/>`__ and enums.

All classes define a ``from_dict`` class method and a ``to_dict``
method to convert between them and msgpack-serializable objects.
"""

from abc import ABCMeta, abstractmethod
import collections
import datetime
from enum import Enum
import hashlib
from typing import Any, Dict, Iterable, List, Optional, Tuple, Type, TypeVar, Union

import attr
from attr._make import _AndValidator
from attr.validators import and_
from attrs_strict import AttributeTypeError
import dateutil.parser
import iso8601
from typing_extensions import Final

from . import git_objects
from .collections import ImmutableDict
from .hashutil import DEFAULT_ALGORITHMS, MultiHash, hash_to_bytehex, hash_to_hex
from .swhids import CoreSWHID
from .swhids import ExtendedObjectType as SwhidExtendedObjectType
from .swhids import ExtendedSWHID
from .swhids import ObjectType as SwhidObjectType


class MissingData(Exception):
    """Raised by `Content.with_data` when it has no way of fetching the
    data (but not when fetching the data fails)."""

    pass


KeyType = Union[Dict[str, str], Dict[str, bytes], bytes]
"""The type returned by BaseModel.unique_key()."""


SHA1_SIZE = 20

_OFFSET_CHARS = frozenset(b"+-0123456789")

# TODO: Limit this to 20 bytes
Sha1Git = bytes
Sha1 = bytes


KT = TypeVar("KT")
VT = TypeVar("VT")


def hash_repr(h: bytes) -> str:
    if h is None:
        return "None"
    else:
        return f"hash_to_bytes('{hash_to_hex(h)}')"


def freeze_optional_dict(
    d: Union[None, Dict[KT, VT], ImmutableDict[KT, VT]]  # type: ignore
) -> Optional[ImmutableDict[KT, VT]]:
    if isinstance(d, dict):
        return ImmutableDict(d)
    else:
        return d


def dictify(value):
    "Helper function used by BaseModel.to_dict()"
    if isinstance(value, BaseModel):
        return value.to_dict()
    elif isinstance(value, (CoreSWHID, ExtendedSWHID)):
        return str(value)
    elif isinstance(value, Enum):
        return value.value
    elif isinstance(value, (dict, ImmutableDict)):
        return {k: dictify(v) for k, v in value.items()}
    elif isinstance(value, tuple):
        return tuple(dictify(v) for v in value)
    else:
        return value


def generic_type_validator(instance, attribute, value):
    """validates the type of an attribute value whatever the attribute type"""
    raise NotImplementedError("generic type check should have been optimized")


def _true_validator(instance, attribute, value, expected_type=None, origin_value=None):
    pass


def _none_validator(instance, attribute, value, expected_type=None, origin_value=None):
    if value is not None:
        if origin_value is None:
            origin_value = value
        raise AttributeTypeError(origin_value, attribute)


def _origin_type_validator(
    instance, attribute, value, expected_type=None, origin_value=None
):
    # This is functionally equivalent to using just this:
    #   return isinstance(value, type)
    # but using type equality before isinstance allows very quick checks
    # when the exact class is used (which is the overwhelming majority of cases)
    # while still allowing subclasses to be used.
    if expected_type is None:
        expected_type = attribute.type
    if not (type(value) == expected_type or isinstance(value, expected_type)):
        if origin_value is None:
            origin_value = value
        raise AttributeTypeError(origin_value, attribute)


def _tuple_infinite_validator(
    instance,
    attribute,
    value,
    expected_type=None,
    origin_value=None,
):
    type_ = type(value)
    if origin_value is None:
        origin_value = value
    if type_ != tuple and not isinstance(value, tuple):
        raise AttributeTypeError(origin_value, attribute)
    if expected_type is None:
        expected_type = attribute.type
    args = expected_type.__args__
    # assert len(args) == 2 and args[1] is Ellipsis
    expected_value_type = args[0]
    validator = optimized_validator(expected_value_type)
    for i in value:
        validator(
            instance,
            attribute,
            i,
            expected_type=expected_value_type,
            origin_value=origin_value,
        )


def _tuple_bytes_bytes_validator(
    instance,
    attribute,
    value,
    expected_type=None,
    origin_value=None,
):
    type_ = type(value)
    if type_ != tuple and not isinstance(value, tuple):
        if origin_value is None:
            origin_value = value
        raise AttributeTypeError(origin_value, attribute)
    if len(value) != 2:
        if origin_value is None:
            origin_value = value
        raise AttributeTypeError(origin_value, attribute)
    if type(value[0]) is not bytes or type(value[1]) is not bytes:
        if origin_value is None:
            origin_value = value
        raise AttributeTypeError(origin_value, attribute)


def _tuple_finite_validator(
    instance,
    attribute,
    value,
    expected_type=None,
    origin_value=None,
):
    # might be useful to optimise the sub-validator tuple, in practice, we only
    # have [bytes, bytes]
    type_ = type(value)
    if origin_value is None:
        origin_value = value
    if type_ != tuple and not isinstance(value, tuple):
        raise AttributeTypeError(origin_value, attribute)
    if expected_type is None:
        expected_type = attribute.type
    args = expected_type.__args__

    # assert len(args) != 2 or args[1] is Ellipsis
    if len(args) != len(value):
        raise AttributeTypeError(origin_value, attribute)
    for item_type, item in zip(args, value):
        validator = optimized_validator(item_type)
        validator(
            instance,
            attribute,
            item,
            expected_type=item_type,
            origin_value=origin_value,
        )


def _immutable_dict_validator(
    instance,
    attribute,
    value,
    expected_type=None,
    origin_value=None,
):
    value_type = type(value)
    if origin_value is None:
        origin_value = value
    if value_type != ImmutableDict and not isinstance(value, ImmutableDict):
        raise AttributeTypeError(origin_value, attribute)

    if expected_type is None:
        expected_type = attribute.type
    (expected_key_type, expected_value_type) = expected_type.__args__

    key_validator = optimized_validator(expected_key_type)
    value_validator = optimized_validator(expected_value_type)

    for (item_key, item_value) in value.items():
        key_validator(
            instance,
            attribute,
            item_key,
            expected_type=expected_key_type,
            origin_value=origin_value,
        )
        value_validator(
            instance,
            attribute,
            item_value,
            expected_type=expected_value_type,
            origin_value=origin_value,
        )


def optimized_validator(type_):
    if type_ is object or type_ is Any:
        return _true_validator

    if type_ is None:
        return _none_validator

    origin = getattr(type_, "__origin__", None)

    # Non-generic type, check it directly
    if origin is None:
        return _origin_type_validator

    # Then, if it's a container, check its items.
    if origin is tuple:
        args = type_.__args__
        if len(args) == 2 and args[1] is Ellipsis:
            # Infinite tuple
            return _tuple_infinite_validator
        elif args == (bytes, bytes):
            return _tuple_bytes_bytes_validator
        else:
            return _tuple_finite_validator
    elif origin is Union:
        args = type_.__args__
        all_validators = tuple((optimized_validator(t), t) for t in args)

        def union_validator(
            instance,
            attribute,
            value,
            expected_type=None,
            origin_value=None,
        ):
            if origin_value is None:
                origin_value = value
            for (validator, type_) in all_validators:
                try:
                    validator(
                        instance,
                        attribute,
                        value,
                        expected_type=type_,
                        origin_value=origin_value,
                    )
                except AttributeTypeError:
                    pass
                else:
                    break
            else:
                raise AttributeTypeError(origin_value, attribute)

        return union_validator
    elif origin is ImmutableDict:
        return _immutable_dict_validator
    # No need to check dict or list. because they are converted to ImmutableDict
    # and tuple respectively.
    raise NotImplementedError(f"Type-checking {type_}")


def optimize_all_validators(cls, old_fields):
    """process validators to turn them into a faster version … eventually"""
    new_fields = []
    for f in old_fields:
        validator = f.validator
        if validator is generic_type_validator:
            validator = optimized_validator(f.type)
        elif isinstance(validator, _AndValidator):
            new_and = []
            for v in validator._validators:
                if v is generic_type_validator:
                    v = optimized_validator(f.type)
                new_and.append(v)
            validator = and_(*new_and)
        else:
            validator = None

        if validator is not None:
            f = f.evolve(validator=validator)
        new_fields.append(f)
    if attr.__version__ < "21.3.0":
        # https://github.com/python-attrs/attrs/issues/821
        from attr._make import _make_attr_tuple_class

        attr_names = [f.name for f in new_fields]
        AttrsClass = _make_attr_tuple_class(cls.__name__, attr_names)
        return AttrsClass(new_fields)
    else:
        return new_fields


ModelType = TypeVar("ModelType", bound="BaseModel")


class BaseModel:
    """Base class for SWH model classes.

    Provides serialization/deserialization to/from Python dictionaries,
    that are suitable for JSON/msgpack-like formats."""

    __slots__ = ()

    def to_dict(self):
        """Wrapper of `attr.asdict` that can be overridden by subclasses
        that have special handling of some of the fields."""
        return dictify(attr.asdict(self, recurse=False))

    @classmethod
    def from_dict(cls, d):
        """Takes a dictionary representing a tree of SWH objects, and
        recursively builds the corresponding objects."""
        return cls(**d)

    def anonymize(self: ModelType) -> Optional[ModelType]:
        """Returns an anonymized version of the object, if needed.

        If the object model does not need/support anonymization, returns None.
        """
        return None

    def unique_key(self) -> KeyType:
        """Returns a unique key for this object, that can be used for
        deduplication."""
        raise NotImplementedError(f"unique_key for {self}")

    def check(self) -> None:
        """Performs internal consistency checks, and raises an error if one fails."""
        # without the type-ignore comment below, attr >= 22.1.0 causes mypy to report:
        #   Argument 1 has incompatible type "BaseModel"; expected "AttrsInstance"
        attr.validate(self)  # type: ignore[arg-type]


def _compute_hash_from_manifest(manifest: bytes) -> Sha1Git:
    return hashlib.new("sha1", manifest).digest()


class HashableObject(metaclass=ABCMeta):
    """Mixin to automatically compute object identifier hash when
    the associated model is instantiated."""

    __slots__ = ()

    id: Sha1Git

    def compute_hash(self) -> bytes:
        """Derived model classes must implement this to compute
        the object hash.

        This method is called by the object initialization if the `id`
        attribute is set to an empty value.
        """
        return self._compute_hash_from_attributes()

    @abstractmethod
    def _compute_hash_from_attributes(self) -> Sha1Git:
        raise NotImplementedError(f"_compute_hash_from_attributes for {self}")

    def __attrs_post_init__(self):
        if not self.id:
            obj_id = self.compute_hash()
            object.__setattr__(self, "id", obj_id)

    def unique_key(self) -> KeyType:
        return self.id

    def check(self) -> None:
        super().check()  # type: ignore

        if self.id != self.compute_hash():
            raise ValueError("'id' does not match recomputed hash.")


class HashableObjectWithManifest(HashableObject):
    """Derived class of HashableObject, for objects that may need to store
    verbatim git objects as ``raw_manifest`` to preserve original hashes."""

    __slots__ = ()

    raw_manifest: Optional[bytes] = None
    """Stores the original content of git objects when they cannot be faithfully
    represented using only the other attributes.

    This should only be used as a last resort, and only set in the Git loader,
    for objects too corrupt to fit the data model."""

    def to_dict(self):
        d = super().to_dict()
        if d["raw_manifest"] is None:
            del d["raw_manifest"]
        return d

    def compute_hash(self) -> bytes:
        """Derived model classes must implement this to compute
        the object hash.

        This method is called by the object initialization if the `id`
        attribute is set to an empty value.
        """
        if self.raw_manifest is None:
            return super().compute_hash()  # calls self._compute_hash_from_attributes()
        else:
            return _compute_hash_from_manifest(self.raw_manifest)

    def check(self) -> None:
        super().check()

        if (
            self.raw_manifest is not None
            and self.id == self._compute_hash_from_attributes()
        ):
            raise ValueError(
                f"{self} has a non-none raw_manifest attribute, but does not need it."
            )


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class Person(BaseModel):
    """Represents the author/committer of a revision or release."""

    object_type: Final = "person"

    fullname = attr.ib(type=bytes, validator=generic_type_validator)
    name = attr.ib(type=Optional[bytes], validator=generic_type_validator, eq=False)
    email = attr.ib(type=Optional[bytes], validator=generic_type_validator, eq=False)

    @classmethod
    def from_fullname(cls, fullname: bytes):
        """Returns a Person object, by guessing the name and email from the
        fullname, in the `name <email>` format.

        The fullname is left unchanged."""
        if fullname is None:
            raise TypeError("fullname is None.")

        name: Optional[bytes]
        email: Optional[bytes]

        try:
            open_bracket = fullname.index(b"<")
        except ValueError:
            name = fullname
            email = None
        else:
            raw_name = fullname[:open_bracket]
            raw_email = fullname[open_bracket + 1 :]

            if not raw_name:
                name = None
            else:
                name = raw_name.strip()

            try:
                close_bracket = raw_email.rindex(b">")
            except ValueError:
                email = raw_email
            else:
                email = raw_email[:close_bracket]

        return Person(
            name=name or None,
            email=email or None,
            fullname=fullname,
        )

    def anonymize(self) -> "Person":
        """Returns an anonymized version of the Person object.

        Anonymization is simply a Person which fullname is the hashed, with unset name
        or email.
        """
        return Person(
            fullname=hashlib.sha256(self.fullname).digest(),
            name=None,
            email=None,
        )

    @classmethod
    def from_dict(cls, d):
        """
        If the fullname is missing, construct a fullname
        using the following heuristics: if the name value is None, we return the
        email in angle brackets, else, we return the name, a space, and the email
        in angle brackets.
        """
        if "fullname" not in d:
            parts = []
            if d["name"] is not None:
                parts.append(d["name"])
            if d["email"] is not None:
                parts.append(b"".join([b"<", d["email"], b">"]))

            fullname = b" ".join(parts)
            d = {**d, "fullname": fullname}
        d = {"name": None, "email": None, **d}
        return super().from_dict(d)


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class Timestamp(BaseModel):
    """Represents a naive timestamp from a VCS."""

    object_type: Final = "timestamp"

    seconds = attr.ib(type=int)
    microseconds = attr.ib(type=int)

    @seconds.validator
    def check_seconds(self, attribute, value):
        """Check that seconds fit in a 64-bits signed integer."""
        if value.__class__ is not int:
            raise AttributeTypeError(value, attribute)
        if not (-(2**63) <= value < 2**63):
            raise ValueError("Seconds must be a signed 64-bits integer.")

    @microseconds.validator
    def check_microseconds(self, attribute, value):
        """Checks that microseconds are positive and < 1000000."""
        if value.__class__ is not int:
            raise AttributeTypeError(value, attribute)
        if not (0 <= value < 10**6):
            raise ValueError("Microseconds must be in [0, 1000000[.")


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class TimestampWithTimezone(BaseModel):
    """Represents a TZ-aware timestamp from a VCS."""

    object_type: Final = "timestamp_with_timezone"

    timestamp = attr.ib(type=Timestamp, validator=generic_type_validator)

    offset_bytes = attr.ib(type=bytes, validator=generic_type_validator)
    """Raw git representation of the timezone, as an offset from UTC.
    It should follow this format: ``+HHMM`` or ``-HHMM`` (including ``+0000`` and
    ``-0000``).

    However, when created from git objects, it must be the exact bytes used in the
    original objects, so it may differ from this format when they do.
    """

    @classmethod
    def from_numeric_offset(
        cls, timestamp: Timestamp, offset: int, negative_utc: bool
    ) -> "TimestampWithTimezone":
        """Returns a :class:`TimestampWithTimezone` instance from the old dictionary
        format (with ``offset`` and ``negative_utc`` instead of ``offset_bytes``).
        """
        negative = offset < 0 or negative_utc
        (hours, minutes) = divmod(abs(offset), 60)
        offset_bytes = f"{'-' if negative else '+'}{hours:02}{minutes:02}".encode()
        tstz = TimestampWithTimezone(timestamp=timestamp, offset_bytes=offset_bytes)
        assert tstz.offset_minutes() == offset, (tstz.offset_minutes(), offset)
        return tstz

    @classmethod
    def from_dict(
        cls, time_representation: Union[Dict, datetime.datetime, int]
    ) -> "TimestampWithTimezone":
        """Builds a TimestampWithTimezone from any of the formats
        accepted by :func:`swh.model.normalize_timestamp`."""
        # TODO: this accept way more types than just dicts; find a better
        # name
        if isinstance(time_representation, dict):
            ts = time_representation["timestamp"]
            if isinstance(ts, dict):
                seconds = ts.get("seconds", 0)
                microseconds = ts.get("microseconds", 0)
            elif isinstance(ts, int):
                seconds = ts
                microseconds = 0
            else:
                raise ValueError(
                    f"TimestampWithTimezone.from_dict received non-integer timestamp "
                    f"member {ts!r}"
                )

            timestamp = Timestamp(seconds=seconds, microseconds=microseconds)

            if "offset_bytes" in time_representation:
                return cls(
                    timestamp=timestamp,
                    offset_bytes=time_representation["offset_bytes"],
                )
            else:
                # old format
                offset = time_representation["offset"]
                negative_utc = time_representation.get("negative_utc") or False
                return cls.from_numeric_offset(timestamp, offset, negative_utc)
        elif isinstance(time_representation, datetime.datetime):
            # TODO: warn when using from_dict() on a datetime
            utcoffset = time_representation.utcoffset()
            time_representation = time_representation.astimezone(datetime.timezone.utc)
            microseconds = time_representation.microsecond
            if microseconds:
                time_representation = time_representation.replace(microsecond=0)
            seconds = int(time_representation.timestamp())
            if utcoffset is None:
                raise ValueError(
                    f"TimestampWithTimezone.from_dict received datetime without "
                    f"timezone: {time_representation}"
                )

            # utcoffset is an integer number of minutes
            seconds_offset = utcoffset.total_seconds()
            offset = int(seconds_offset) // 60
            # TODO: warn if remainder is not zero
            return cls.from_numeric_offset(
                Timestamp(seconds=seconds, microseconds=microseconds), offset, False
            )
        elif isinstance(time_representation, int):
            # TODO: warn when using from_dict() on an int
            seconds = time_representation
            timestamp = Timestamp(seconds=time_representation, microseconds=0)
            return cls(timestamp=timestamp, offset_bytes=b"+0000")
        else:
            raise ValueError(
                f"TimestampWithTimezone.from_dict received non-integer timestamp: "
                f"{time_representation!r}"
            )

    @classmethod
    def from_datetime(cls, dt: datetime.datetime) -> "TimestampWithTimezone":
        return cls.from_dict(dt)

    def to_datetime(self) -> datetime.datetime:
        """Convert to a datetime (with a timezone set to the recorded fixed UTC offset)

        Beware that this conversion can be lossy: ``-0000`` and 'weird' offsets
        cannot be represented. Also note that it may fail due to type overflow.
        """
        timestamp = datetime.datetime.fromtimestamp(
            self.timestamp.seconds,
            datetime.timezone(datetime.timedelta(minutes=self.offset_minutes())),
        )
        timestamp = timestamp.replace(microsecond=self.timestamp.microseconds)
        return timestamp

    @classmethod
    def from_iso8601(cls, s):
        """Builds a TimestampWithTimezone from an ISO8601-formatted string."""
        dt = iso8601.parse_date(s)
        tstz = cls.from_datetime(dt)
        if dt.tzname() == "-00:00":
            assert tstz.offset_bytes == b"+0000"
            tstz = attr.evolve(tstz, offset_bytes=b"-0000")
        return tstz

    @staticmethod
    def _parse_offset_bytes(offset_bytes: bytes) -> int:
        """Parses an ``offset_bytes`` value (in Git's ``[+-]HHMM`` format),
        and returns the corresponding numeric values (in number of minutes).

        Tries to account for some mistakes in the format, to support incorrect
        Git implementations.

        >>> TimestampWithTimezone._parse_offset_bytes(b"+0000")
        0
        >>> TimestampWithTimezone._parse_offset_bytes(b"-0000")
        0
        >>> TimestampWithTimezone._parse_offset_bytes(b"+0200")
        120
        >>> TimestampWithTimezone._parse_offset_bytes(b"-0200")
        -120
        >>> TimestampWithTimezone._parse_offset_bytes(b"+200")
        120
        >>> TimestampWithTimezone._parse_offset_bytes(b"-200")
        -120
        >>> TimestampWithTimezone._parse_offset_bytes(b"+02")
        120
        >>> TimestampWithTimezone._parse_offset_bytes(b"-02")
        -120
        >>> TimestampWithTimezone._parse_offset_bytes(b"+0010")
        10
        >>> TimestampWithTimezone._parse_offset_bytes(b"-0010")
        -10
        >>> TimestampWithTimezone._parse_offset_bytes(b"+200000000000000000")
        0
        >>> TimestampWithTimezone._parse_offset_bytes(b"+0160")  # 60 minutes...
        0
        """
        offset_str = offset_bytes.decode()
        assert offset_str[0] in "+-"
        sign = int(offset_str[0] + "1")
        if len(offset_str) <= 3:
            hours = int(offset_str[1:])
            minutes = 0
        else:
            hours = int(offset_str[1:-2])
            minutes = int(offset_str[-2:])

        offset = sign * (hours * 60 + minutes)
        if (0 <= minutes <= 59) and (-(2**15) <= offset < 2**15):
            return offset
        else:
            # can't parse it to a reasonable value; give up and pretend it's UTC.
            return 0

    def offset_minutes(self):
        """Returns the offset, as a number of minutes since UTC.

        >>> TimestampWithTimezone(
        ...     Timestamp(seconds=1642765364, microseconds=0), offset_bytes=b"+0000"
        ... ).offset_minutes()
        0
        >>> TimestampWithTimezone(
        ...     Timestamp(seconds=1642765364, microseconds=0), offset_bytes=b"+0200"
        ... ).offset_minutes()
        120
        >>> TimestampWithTimezone(
        ...     Timestamp(seconds=1642765364, microseconds=0), offset_bytes=b"-0200"
        ... ).offset_minutes()
        -120
        >>> TimestampWithTimezone(
        ...     Timestamp(seconds=1642765364, microseconds=0), offset_bytes=b"+0530"
        ... ).offset_minutes()
        330
        """
        return self._parse_offset_bytes(self.offset_bytes)


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class Origin(HashableObject, BaseModel):
    """Represents a software source: a VCS and an URL."""

    object_type: Final = "origin"

    url = attr.ib(type=str, validator=generic_type_validator)

    id = attr.ib(type=Sha1Git, validator=generic_type_validator, default=b"")

    def unique_key(self) -> KeyType:
        return {"url": self.url}

    def _compute_hash_from_attributes(self) -> bytes:
        return _compute_hash_from_manifest(self.url.encode("utf-8"))

    def swhid(self) -> ExtendedSWHID:
        """Returns a SWHID representing this origin."""
        return ExtendedSWHID(
            object_type=SwhidExtendedObjectType.ORIGIN,
            object_id=self.id,
        )


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class OriginVisit(BaseModel):
    """Represents an origin visit with a given type at a given point in time, by a
    SWH loader."""

    object_type: Final = "origin_visit"

    origin = attr.ib(type=str, validator=generic_type_validator)
    date = attr.ib(type=datetime.datetime)
    type = attr.ib(type=str, validator=generic_type_validator)
    """Should not be set before calling 'origin_visit_add()'."""
    visit = attr.ib(type=Optional[int], validator=generic_type_validator, default=None)

    @date.validator
    def check_date(self, attribute, value):
        """Checks the date has a timezone."""
        if value.__class__ is not datetime.datetime:
            raise AttributeTypeError(value, attribute)
        if value is not None and value.tzinfo is None:
            raise ValueError("date must be a timezone-aware datetime.")

    def to_dict(self):
        """Serializes the date as a string and omits the visit id if it is
        `None`."""
        ov = super().to_dict()
        if ov["visit"] is None:
            del ov["visit"]
        return ov

    def unique_key(self) -> KeyType:
        return {"origin": self.origin, "date": str(self.date)}


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class OriginVisitStatus(BaseModel):
    """Represents a visit update of an origin at a given point in time."""

    object_type: Final = "origin_visit_status"

    origin = attr.ib(type=str, validator=generic_type_validator)
    visit = attr.ib(type=int, validator=generic_type_validator)

    date = attr.ib(type=datetime.datetime)
    status = attr.ib(
        type=str,
        validator=attr.validators.in_(
            ["created", "ongoing", "full", "partial", "not_found", "failed"]
        ),
    )
    snapshot = attr.ib(
        type=Optional[Sha1Git], validator=generic_type_validator, repr=hash_repr
    )
    # Type is optional be to able to use it before adding it to the database model
    type = attr.ib(type=Optional[str], validator=generic_type_validator, default=None)
    metadata = attr.ib(
        type=Optional[ImmutableDict[str, object]],
        validator=generic_type_validator,
        converter=freeze_optional_dict,
        default=None,
    )

    @date.validator
    def check_date(self, attribute, value):
        """Checks the date has a timezone."""
        if value.__class__ is not datetime.datetime:
            raise AttributeTypeError(value, attribute)
        if value is not None and value.tzinfo is None:
            raise ValueError("date must be a timezone-aware datetime.")

    def unique_key(self) -> KeyType:
        return {"origin": self.origin, "visit": str(self.visit), "date": str(self.date)}


class TargetType(Enum):
    """The type of content pointed to by a snapshot branch. Usually a
    revision or an alias."""

    CONTENT = "content"
    DIRECTORY = "directory"
    REVISION = "revision"
    RELEASE = "release"
    SNAPSHOT = "snapshot"
    ALIAS = "alias"

    def __repr__(self):
        return f"TargetType.{self.name}"


class ObjectType(Enum):
    """The type of content pointed to by a release. Usually a revision"""

    CONTENT = "content"
    DIRECTORY = "directory"
    REVISION = "revision"
    RELEASE = "release"
    SNAPSHOT = "snapshot"

    def __repr__(self):
        return f"ObjectType.{self.name}"


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class SnapshotBranch(BaseModel):
    """Represents one of the branches of a snapshot."""

    object_type: Final = "snapshot_branch"

    target = attr.ib(type=bytes, repr=hash_repr)
    target_type = attr.ib(type=TargetType, validator=generic_type_validator)

    @target.validator
    def check_target(self, attribute, value):
        """Checks the target type is not an alias, checks the target is a
        valid sha1_git."""
        if value.__class__ is not bytes:
            raise AttributeTypeError(value, attribute)
        if self.target_type != TargetType.ALIAS and self.target is not None:
            if len(value) != 20:
                raise ValueError("Wrong length for bytes identifier: %d" % len(value))

    @classmethod
    def from_dict(cls, d):
        return cls(target=d["target"], target_type=TargetType(d["target_type"]))


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class Snapshot(HashableObject, BaseModel):
    """Represents the full state of an origin at a given point in time."""

    object_type: Final = "snapshot"

    branches = attr.ib(
        type=ImmutableDict[bytes, Optional[SnapshotBranch]],
        validator=generic_type_validator,
        converter=freeze_optional_dict,
    )
    id = attr.ib(
        type=Sha1Git, validator=generic_type_validator, default=b"", repr=hash_repr
    )

    def _compute_hash_from_attributes(self) -> bytes:
        return _compute_hash_from_manifest(
            git_objects.snapshot_git_object(self, ignore_unresolved=True)
        )

    @classmethod
    def from_dict(cls, d):
        d = d.copy()
        return cls(
            branches=ImmutableDict(
                (name, SnapshotBranch.from_dict(branch) if branch else None)
                for (name, branch) in d.pop("branches").items()
            ),
            **d,
        )

    def swhid(self) -> CoreSWHID:
        """Returns a SWHID representing this object."""
        return CoreSWHID(object_type=SwhidObjectType.SNAPSHOT, object_id=self.id)


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class Release(HashableObjectWithManifest, BaseModel):
    object_type: Final = "release"

    name = attr.ib(type=bytes, validator=generic_type_validator)
    message = attr.ib(type=Optional[bytes], validator=generic_type_validator)
    target = attr.ib(
        type=Optional[Sha1Git], validator=generic_type_validator, repr=hash_repr
    )
    target_type = attr.ib(type=ObjectType, validator=generic_type_validator)
    synthetic = attr.ib(type=bool, validator=generic_type_validator)
    author = attr.ib(
        type=Optional[Person], validator=generic_type_validator, default=None
    )
    date = attr.ib(
        type=Optional[TimestampWithTimezone],
        validator=generic_type_validator,
        default=None,
    )
    metadata = attr.ib(
        type=Optional[ImmutableDict[str, object]],
        validator=generic_type_validator,
        converter=freeze_optional_dict,
        default=None,
    )
    id = attr.ib(
        type=Sha1Git, validator=generic_type_validator, default=b"", repr=hash_repr
    )
    raw_manifest = attr.ib(type=Optional[bytes], default=None)

    def _compute_hash_from_attributes(self) -> bytes:
        return _compute_hash_from_manifest(git_objects.release_git_object(self))

    @author.validator
    def check_author(self, attribute, value):
        """If the author is `None`, checks the date is `None` too."""
        if self.author is None and self.date is not None:
            raise ValueError("release date must be None if author is None.")

    def to_dict(self):
        rel = super().to_dict()
        if rel["metadata"] is None:
            del rel["metadata"]
        return rel

    @classmethod
    def from_dict(cls, d):
        d = d.copy()
        if d.get("author"):
            d["author"] = Person.from_dict(d["author"])
        if d.get("date"):
            d["date"] = TimestampWithTimezone.from_dict(d["date"])
        return cls(target_type=ObjectType(d.pop("target_type")), **d)

    def swhid(self) -> CoreSWHID:
        """Returns a SWHID representing this object."""
        return CoreSWHID(object_type=SwhidObjectType.RELEASE, object_id=self.id)

    def anonymize(self) -> "Release":
        """Returns an anonymized version of the Release object.

        Anonymization consists in replacing the author with an anonymized Person object.
        """
        author = self.author and self.author.anonymize()
        return attr.evolve(self, author=author)


class RevisionType(Enum):
    GIT = "git"
    TAR = "tar"
    DSC = "dsc"
    SUBVERSION = "svn"
    MERCURIAL = "hg"
    CVS = "cvs"
    BAZAAR = "bzr"

    def __repr__(self):
        return f"RevisionType.{self.name}"


def tuplify_extra_headers(value: Iterable):
    return tuple((k, v) for k, v in value)


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class Revision(HashableObjectWithManifest, BaseModel):
    object_type: Final = "revision"

    message = attr.ib(type=Optional[bytes], validator=generic_type_validator)
    author = attr.ib(type=Optional[Person], validator=generic_type_validator)
    committer = attr.ib(type=Optional[Person], validator=generic_type_validator)
    date = attr.ib(
        type=Optional[TimestampWithTimezone], validator=generic_type_validator
    )
    committer_date = attr.ib(
        type=Optional[TimestampWithTimezone], validator=generic_type_validator
    )
    type = attr.ib(type=RevisionType, validator=generic_type_validator)
    directory = attr.ib(type=Sha1Git, validator=generic_type_validator, repr=hash_repr)
    synthetic = attr.ib(type=bool, validator=generic_type_validator)
    metadata = attr.ib(
        type=Optional[ImmutableDict[str, object]],
        validator=generic_type_validator,
        converter=freeze_optional_dict,
        default=None,
    )
    parents = attr.ib(
        type=Tuple[Sha1Git, ...], validator=generic_type_validator, default=()
    )
    id = attr.ib(
        type=Sha1Git, validator=generic_type_validator, default=b"", repr=hash_repr
    )
    extra_headers = attr.ib(
        type=Tuple[Tuple[bytes, bytes], ...],
        validator=generic_type_validator,
        converter=tuplify_extra_headers,
        default=(),
    )
    raw_manifest = attr.ib(type=Optional[bytes], default=None)

    def __attrs_post_init__(self):
        super().__attrs_post_init__()
        # ensure metadata is a deep copy of whatever was given, and if needed
        # extract extra_headers from there
        if self.metadata:
            metadata = self.metadata
            if not self.extra_headers and "extra_headers" in metadata:
                (extra_headers, metadata) = metadata.copy_pop("extra_headers")
                object.__setattr__(
                    self,
                    "extra_headers",
                    tuplify_extra_headers(extra_headers),
                )
                attr.validate(self)
            object.__setattr__(self, "metadata", metadata)

    def _compute_hash_from_attributes(self) -> bytes:
        return _compute_hash_from_manifest(git_objects.revision_git_object(self))

    @author.validator
    def check_author(self, attribute, value):
        """If the author is `None`, checks the date is `None` too."""
        if self.author is None and self.date is not None:
            raise ValueError("revision date must be None if author is None.")

    @committer.validator
    def check_committer(self, attribute, value):
        """If the committer is `None`, checks the committer_date is `None` too."""
        if self.committer is None and self.committer_date is not None:
            raise ValueError(
                "revision committer_date must be None if committer is None."
            )

    @classmethod
    def from_dict(cls, d):
        d = d.copy()
        date = d.pop("date")
        if date:
            date = TimestampWithTimezone.from_dict(date)

        committer_date = d.pop("committer_date")
        if committer_date:
            committer_date = TimestampWithTimezone.from_dict(committer_date)

        author = d.pop("author")
        if author:
            author = Person.from_dict(author)

        committer = d.pop("committer")
        if committer:
            committer = Person.from_dict(committer)

        return cls(
            author=author,
            committer=committer,
            date=date,
            committer_date=committer_date,
            type=RevisionType(d.pop("type")),
            parents=tuple(d.pop("parents")),  # for BW compat
            **d,
        )

    def swhid(self) -> CoreSWHID:
        """Returns a SWHID representing this object."""
        return CoreSWHID(object_type=SwhidObjectType.REVISION, object_id=self.id)

    def anonymize(self) -> "Revision":
        """Returns an anonymized version of the Revision object.

        Anonymization consists in replacing the author and committer with an anonymized
        Person object.
        """
        return attr.evolve(
            self,
            author=None if self.author is None else self.author.anonymize(),
            committer=None if self.committer is None else self.committer.anonymize(),
        )


_DIR_ENTRY_TYPES = ["file", "dir", "rev"]


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class DirectoryEntry(BaseModel):
    object_type: Final = "directory_entry"

    name = attr.ib(type=bytes)
    type = attr.ib(type=str, validator=attr.validators.in_(_DIR_ENTRY_TYPES))
    target = attr.ib(type=Sha1Git, validator=generic_type_validator, repr=hash_repr)
    perms = attr.ib(type=int, validator=generic_type_validator, converter=int, repr=oct)
    """Usually one of the values of `swh.model.from_disk.DentryPerms`."""

    @name.validator
    def check_name(self, attribute, value):
        if value.__class__ is not bytes:
            raise AttributeTypeError(value, attribute)
        if b"/" in value:
            raise ValueError(f"{value!r} is not a valid directory entry name.")


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class Directory(HashableObjectWithManifest, BaseModel):
    object_type: Final = "directory"

    entries = attr.ib(type=Tuple[DirectoryEntry, ...], validator=generic_type_validator)
    id = attr.ib(
        type=Sha1Git, validator=generic_type_validator, default=b"", repr=hash_repr
    )
    raw_manifest = attr.ib(type=Optional[bytes], default=None)

    def _compute_hash_from_attributes(self) -> bytes:
        return _compute_hash_from_manifest(git_objects.directory_git_object(self))

    @entries.validator
    def check_entries(self, attribute, value):
        seen = set()
        for entry in value:
            if entry.name in seen:
                # Cannot use self.swhid() here, self.id may be None
                raise ValueError(
                    f"swh:1:dir:{hash_to_hex(self.id)} has duplicated entry name: "
                    f"{entry.name!r}"
                )
            seen.add(entry.name)

    @classmethod
    def from_dict(cls, d):
        d = d.copy()
        return cls(
            entries=tuple(
                DirectoryEntry.from_dict(entry) for entry in d.pop("entries")
            ),
            **d,
        )

    def swhid(self) -> CoreSWHID:
        """Returns a SWHID representing this object."""
        return CoreSWHID(object_type=SwhidObjectType.DIRECTORY, object_id=self.id)

    @classmethod
    def from_possibly_duplicated_entries(
        cls,
        *,
        entries: Tuple[DirectoryEntry, ...],
        id: Sha1Git = b"",
        raw_manifest: Optional[bytes] = None,
    ) -> Tuple[bool, "Directory"]:
        """Constructs a ``Directory`` object from a list of entries that may contain
        duplicated names.

        This is required to represent legacy objects, that were ingested in the
        storage database before this check was added.

        As it is impossible for a ``Directory`` instances to have more than one entry
        with a given names, this function computes a ``raw_manifest`` and renames one of
        the entries before constructing the ``Directory``.

        Returns:
            ``(is_corrupt, directory)`` where ``is_corrupt`` is True iff some
            entry names were indeed duplicated
        """
        # First, try building a Directory object normally without any extra computation,
        # which works the overwhelming majority of the time:
        try:
            return (False, Directory(entries=entries, id=id, raw_manifest=raw_manifest))
        except ValueError:
            pass

        # If it fails:
        # 1. compute a raw_manifest if there isn't already one:
        if raw_manifest is None:
            # invalid_directory behaves like a Directory object, but without the
            # duplicated entry check; which allows computing its raw_manifest
            invalid_directory = type("", (), {})()
            invalid_directory.entries = entries
            raw_manifest = git_objects.directory_git_object(invalid_directory)

        # 2. look for duplicated entries:
        entries_by_name: Dict[
            bytes, Dict[str, List[DirectoryEntry]]
        ] = collections.defaultdict(lambda: collections.defaultdict(list))
        for entry in entries:
            entries_by_name[entry.name][entry.type].append(entry)

        # 3. strip duplicates
        deduplicated_entries = []
        for entry_lists in entries_by_name.values():
            # We could pick one entry at random to keep the original name; but we try to
            # "minimize" the impact, by preserving entries of type "rev" first
            # (because renaming them would likely break git submodules entirely
            # when this directory is written to disk),
            # then entries of type "dir" (because renaming them affects the path
            # of every file in the dir, instead of just one "cnt").
            dir_entry_types = ("rev", "dir", "file")
            assert set(dir_entry_types) == set(_DIR_ENTRY_TYPES)
            picked_winner = False  # when True, all future entries must be renamed
            for type_ in dir_entry_types:
                for entry in entry_lists[type_]:
                    if not picked_winner:
                        # this is the "most important" entry according to this
                        # heuristic; it gets to keep its name.
                        deduplicated_entries.append(entry)
                        picked_winner = True
                    else:
                        # the heuristic already found an entry more important than
                        # this one; so this one must be renamed to something.
                        # we pick the beginning of its hash, it should be good enough
                        # to avoid any conflict.
                        new_name = (
                            entry.name + b"_" + hash_to_bytehex(entry.target)[0:10]
                        )
                        renamed_entry = attr.evolve(entry, name=new_name)
                        deduplicated_entries.append(renamed_entry)

        # Finally, return the "fixed" the directory
        dir_ = Directory(
            entries=tuple(deduplicated_entries), id=id, raw_manifest=raw_manifest
        )
        return (True, dir_)


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class BaseContent(BaseModel):
    status = attr.ib(
        type=str, validator=attr.validators.in_(["visible", "hidden", "absent"])
    )

    @staticmethod
    def _hash_data(data: bytes):
        """Hash some data, returning most of the fields of a content object"""
        d = MultiHash.from_data(data).digest()
        d["data"] = data
        d["length"] = len(data)

        return d

    @classmethod
    def from_dict(cls, d, use_subclass=True):
        if use_subclass:
            # Chooses a subclass to instantiate instead.
            if d["status"] == "absent":
                return SkippedContent.from_dict(d)
            else:
                return Content.from_dict(d)
        else:
            return super().from_dict(d)

    def get_hash(self, hash_name):
        if hash_name not in DEFAULT_ALGORITHMS:
            raise ValueError("{} is not a valid hash name.".format(hash_name))
        return getattr(self, hash_name)

    def hashes(self) -> Dict[str, bytes]:
        """Returns a dictionary {hash_name: hash_value}"""
        return {algo: getattr(self, algo) for algo in DEFAULT_ALGORITHMS}


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class Content(BaseContent):
    object_type: Final = "content"

    sha1 = attr.ib(type=bytes, validator=generic_type_validator, repr=hash_repr)
    sha1_git = attr.ib(type=Sha1Git, validator=generic_type_validator, repr=hash_repr)
    sha256 = attr.ib(type=bytes, validator=generic_type_validator, repr=hash_repr)
    blake2s256 = attr.ib(type=bytes, validator=generic_type_validator, repr=hash_repr)

    length = attr.ib(type=int)

    status = attr.ib(
        type=str,
        validator=attr.validators.in_(["visible", "hidden"]),
        default="visible",
    )

    data = attr.ib(type=Optional[bytes], validator=generic_type_validator, default=None)

    ctime = attr.ib(
        type=Optional[datetime.datetime],
        default=None,
        eq=False,
    )

    @length.validator
    def check_length(self, attribute, value):
        """Checks the length is positive."""
        if value.__class__ is not int:
            raise AttributeTypeError(value, attribute)
        if value < 0:
            raise ValueError("Length must be positive.")

    @ctime.validator
    def check_ctime(self, attribute, value):
        """Checks the ctime has a timezone."""
        if value is not None:
            if value.__class__ is not datetime.datetime:
                raise AttributeTypeError(value, attribute)
            if value.tzinfo is None:
                raise ValueError("ctime must be a timezone-aware datetime.")

    def to_dict(self):
        content = super().to_dict()
        if content["data"] is None:
            del content["data"]
        if content["ctime"] is None:
            del content["ctime"]
        return content

    @classmethod
    def from_data(cls, data, status="visible", ctime=None) -> "Content":
        """Generate a Content from a given `data` byte string.

        This populates the Content with the hashes and length for the data
        passed as argument, as well as the data itself.
        """
        d = cls._hash_data(data)
        d["status"] = status
        d["ctime"] = ctime
        return cls(**d)

    @classmethod
    def from_dict(cls, d):
        if isinstance(d.get("ctime"), str):
            d = d.copy()
            d["ctime"] = dateutil.parser.parse(d["ctime"])
        return super().from_dict(d, use_subclass=False)

    def with_data(self) -> "Content":
        """Loads the `data` attribute; meaning that it is guaranteed not to
        be None after this call.

        This call is almost a no-op, but subclasses may overload this method
        to lazy-load data (eg. from disk or objstorage)."""
        if self.data is None:
            raise MissingData("Content data is None.")
        return self

    def unique_key(self) -> KeyType:
        return self.sha1  # TODO: use a dict of hashes

    def swhid(self) -> CoreSWHID:
        """Returns a SWHID representing this object."""
        return CoreSWHID(object_type=SwhidObjectType.CONTENT, object_id=self.sha1_git)


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class SkippedContent(BaseContent):
    object_type: Final = "skipped_content"

    sha1 = attr.ib(
        type=Optional[bytes], validator=generic_type_validator, repr=hash_repr
    )
    sha1_git = attr.ib(
        type=Optional[Sha1Git], validator=generic_type_validator, repr=hash_repr
    )
    sha256 = attr.ib(
        type=Optional[bytes], validator=generic_type_validator, repr=hash_repr
    )
    blake2s256 = attr.ib(
        type=Optional[bytes], validator=generic_type_validator, repr=hash_repr
    )

    length = attr.ib(type=Optional[int])

    status = attr.ib(type=str, validator=attr.validators.in_(["absent"]))
    reason = attr.ib(type=Optional[str], default=None)

    origin = attr.ib(type=Optional[str], validator=generic_type_validator, default=None)

    ctime = attr.ib(
        type=Optional[datetime.datetime],
        validator=generic_type_validator,
        default=None,
        eq=False,
    )

    @reason.validator
    def check_reason(self, attribute, value):
        """Checks the reason is full if status != absent."""
        assert self.reason == value
        if value is None:
            raise ValueError("Must provide a reason if content is absent.")
        elif value.__class__ is not str:
            raise AttributeTypeError(value, attribute)

    @length.validator
    def check_length(self, attribute, value):
        """Checks the length is positive or -1."""
        if value.__class__ is not int:
            raise AttributeTypeError(value, attribute)
        elif value < -1:
            raise ValueError("Length must be positive or -1.")

    @ctime.validator
    def check_ctime(self, attribute, value):
        """Checks the ctime has a timezone."""
        if value is not None:
            if value.__class__ is not datetime.datetime:
                raise AttributeTypeError(value, attribute)
            elif value.tzinfo is None:
                raise ValueError("ctime must be a timezone-aware datetime.")

    def to_dict(self):
        content = super().to_dict()
        if content["origin"] is None:
            del content["origin"]
        if content["ctime"] is None:
            del content["ctime"]
        return content

    @classmethod
    def from_data(
        cls, data: bytes, reason: str, ctime: Optional[datetime.datetime] = None
    ) -> "SkippedContent":
        """Generate a SkippedContent from a given `data` byte string.

        This populates the SkippedContent with the hashes and length for the
        data passed as argument.

        You can use `attr.evolve` on such a generated content to nullify some
        of its attributes, e.g. for tests.
        """
        d = cls._hash_data(data)
        del d["data"]
        d["status"] = "absent"
        d["reason"] = reason
        d["ctime"] = ctime
        return cls(**d)

    @classmethod
    def from_dict(cls, d):
        d2 = d.copy()
        if d2.pop("data", None) is not None:
            raise ValueError('SkippedContent has no "data" attribute %r' % d)
        return super().from_dict(d2, use_subclass=False)

    def unique_key(self) -> KeyType:
        return self.hashes()


class MetadataAuthorityType(Enum):
    DEPOSIT_CLIENT = "deposit_client"
    FORGE = "forge"
    REGISTRY = "registry"

    def __repr__(self):
        return f"MetadataAuthorityType.{self.name}"


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class MetadataAuthority(BaseModel):
    """Represents an entity that provides metadata about an origin or
    software artifact."""

    object_type: Final = "metadata_authority"

    type = attr.ib(type=MetadataAuthorityType, validator=generic_type_validator)
    url = attr.ib(type=str, validator=generic_type_validator)
    metadata = attr.ib(
        type=Optional[ImmutableDict[str, Any]],
        default=None,
        validator=generic_type_validator,
        converter=freeze_optional_dict,
    )

    def to_dict(self):
        d = super().to_dict()
        if d["metadata"] is None:
            del d["metadata"]
        return d

    @classmethod
    def from_dict(cls, d):
        d = {
            **d,
            "type": MetadataAuthorityType(d["type"]),
        }
        return super().from_dict(d)

    def unique_key(self) -> KeyType:
        return {"type": self.type.value, "url": self.url}


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class MetadataFetcher(BaseModel):
    """Represents a software component used to fetch metadata from a metadata
    authority, and ingest them into the Software Heritage archive."""

    object_type: Final = "metadata_fetcher"

    name = attr.ib(type=str, validator=generic_type_validator)
    version = attr.ib(type=str, validator=generic_type_validator)
    metadata = attr.ib(
        type=Optional[ImmutableDict[str, Any]],
        default=None,
        validator=generic_type_validator,
        converter=freeze_optional_dict,
    )

    def to_dict(self):
        d = super().to_dict()
        if d["metadata"] is None:
            del d["metadata"]
        return d

    def unique_key(self) -> KeyType:
        return {"name": self.name, "version": self.version}


def normalize_discovery_date(value: Any) -> datetime.datetime:
    if not isinstance(value, datetime.datetime):
        raise TypeError("discovery_date must be a timezone-aware datetime.")

    if value.tzinfo is None:
        raise ValueError("discovery_date must be a timezone-aware datetime.")

    # Normalize timezone to utc, and truncate microseconds to 0
    return value.astimezone(datetime.timezone.utc).replace(microsecond=0)


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class RawExtrinsicMetadata(HashableObject, BaseModel):
    object_type: Final = "raw_extrinsic_metadata"

    # target object
    target = attr.ib(type=ExtendedSWHID, validator=generic_type_validator)

    # source
    discovery_date = attr.ib(type=datetime.datetime, converter=normalize_discovery_date)
    authority = attr.ib(type=MetadataAuthority, validator=generic_type_validator)
    fetcher = attr.ib(type=MetadataFetcher, validator=generic_type_validator)

    # the metadata itself
    format = attr.ib(type=str, validator=generic_type_validator)
    metadata = attr.ib(type=bytes, validator=generic_type_validator)

    # context
    origin = attr.ib(type=Optional[str], default=None, validator=generic_type_validator)
    visit = attr.ib(type=Optional[int], default=None)
    snapshot = attr.ib(type=Optional[CoreSWHID], default=None)
    release = attr.ib(type=Optional[CoreSWHID], default=None)
    revision = attr.ib(type=Optional[CoreSWHID], default=None)
    path = attr.ib(type=Optional[bytes], default=None)
    directory = attr.ib(type=Optional[CoreSWHID], default=None)

    id = attr.ib(
        type=Sha1Git, validator=generic_type_validator, default=b"", repr=hash_repr
    )

    def _compute_hash_from_attributes(self) -> bytes:
        return _compute_hash_from_manifest(
            git_objects.raw_extrinsic_metadata_git_object(self)
        )

    @origin.validator
    def check_origin(self, attribute, value):
        if value is None:
            return

        if value.__class__ is not str:
            raise AttributeTypeError(value, attribute)
        obj_type = self.target.object_type
        if not (
            obj_type is SwhidExtendedObjectType.SNAPSHOT
            or obj_type is SwhidExtendedObjectType.RELEASE
            or obj_type is SwhidExtendedObjectType.REVISION
            or obj_type is SwhidExtendedObjectType.DIRECTORY
            or obj_type is SwhidExtendedObjectType.CONTENT
        ):
            raise ValueError(
                f"Unexpected 'origin' context for "
                f"{self.target.object_type.name.lower()} object: {value}"
            )

        if value.startswith("swh:"):
            # Technically this is valid; but:
            # 1. SWHIDs are URIs, not URLs
            # 2. if a SWHID gets here, it's very likely to be a mistake
            #    (and we can remove this check if it turns out there is a
            #    legitimate use for it).
            raise ValueError(f"SWHID used as context origin URL: {value}")

    @visit.validator
    def check_visit(self, attribute, value):
        if value is None:
            return
        if value.__class__ is not int:
            raise AttributeTypeError(value, attribute)

        obj_type = self.target.object_type
        if not (
            obj_type is SwhidExtendedObjectType.SNAPSHOT
            or obj_type is SwhidExtendedObjectType.RELEASE
            or obj_type is SwhidExtendedObjectType.REVISION
            or obj_type is SwhidExtendedObjectType.DIRECTORY
            or obj_type is SwhidExtendedObjectType.CONTENT
        ):
            raise ValueError(
                f"Unexpected 'visit' context for "
                f"{self.target.object_type.name.lower()} object: {value}"
            )

        if self.origin is None:
            raise ValueError("'origin' context must be set if 'visit' is.")

        if value <= 0:
            raise ValueError("Nonpositive visit id")

    @snapshot.validator
    def check_snapshot(self, attribute, value):
        if value is None:
            return
        if value.__class__ is not CoreSWHID:
            raise AttributeTypeError(value, attribute)

        obj_type = self.target.object_type
        if not (
            obj_type is SwhidExtendedObjectType.RELEASE
            or obj_type is SwhidExtendedObjectType.REVISION
            or obj_type is SwhidExtendedObjectType.DIRECTORY
            or obj_type is SwhidExtendedObjectType.CONTENT
        ):
            raise ValueError(
                f"Unexpected 'snapshot' context for "
                f"{self.target.object_type.name.lower()} object: {value}"
            )

        if value.object_type != SwhidObjectType.SNAPSHOT:
            raise ValueError(
                f"Expected SWHID type 'snapshot', "
                f"got '{value.object_type.name.lower()}' in {value}"
            )

    @release.validator
    def check_release(self, attribute, value):
        if value is None:
            return
        if value.__class__ is not CoreSWHID:
            raise AttributeTypeError(value, attribute)

        obj_type = self.target.object_type
        if not (
            obj_type is SwhidExtendedObjectType.REVISION
            or obj_type is SwhidExtendedObjectType.DIRECTORY
            or obj_type is SwhidExtendedObjectType.CONTENT
        ):
            raise ValueError(
                f"Unexpected 'release' context for "
                f"{self.target.object_type.name.lower()} object: {value}"
            )

        if value.object_type != SwhidObjectType.RELEASE:
            raise ValueError(
                f"Expected SWHID type 'release', "
                f"got '{value.object_type.name.lower()}' in {value}"
            )

    @revision.validator
    def check_revision(self, attribute, value):
        if value is None:
            return

        if value.__class__ is not CoreSWHID:
            raise AttributeTypeError(value, attribute)

        obj_type = self.target.object_type
        if not (
            obj_type is SwhidExtendedObjectType.DIRECTORY
            or obj_type is SwhidExtendedObjectType.CONTENT
        ):
            raise ValueError(
                f"Unexpected 'revision' context for "
                f"{self.target.object_type.name.lower()} object: {value}"
            )

        if value.object_type != SwhidObjectType.REVISION:
            raise ValueError(
                f"Expected SWHID type 'revision', "
                f"got '{value.object_type.name.lower()}' in {value}"
            )

    @path.validator
    def check_path(self, attribute, value):
        if value is None:
            return

        if value.__class__ is not bytes:
            raise AttributeTypeError(value, attribute)

        obj_type = self.target.object_type
        if not (
            obj_type is SwhidExtendedObjectType.DIRECTORY
            or obj_type is SwhidExtendedObjectType.CONTENT
        ):
            raise ValueError(
                f"Unexpected 'path' context for "
                f"{self.target.object_type.name.lower()} object: {value}"
            )

    @directory.validator
    def check_directory(self, attribute, value):
        if value is None:
            return

        if value.__class__ is not CoreSWHID:
            raise AttributeTypeError(value, attribute)

        if self.target.object_type is not SwhidExtendedObjectType.CONTENT:
            raise ValueError(
                f"Unexpected 'directory' context for "
                f"{self.target.object_type.name.lower()} object: {value}"
            )

        if value.object_type != SwhidObjectType.DIRECTORY:
            raise ValueError(
                f"Expected SWHID type 'directory', "
                f"got '{value.object_type.name.lower()}' in {value}"
            )

    def to_dict(self):
        d = super().to_dict()

        context_keys = (
            "origin",
            "visit",
            "snapshot",
            "release",
            "revision",
            "directory",
            "path",
        )
        for context_key in context_keys:
            if d[context_key] is None:
                del d[context_key]
        return d

    @classmethod
    def from_dict(cls, d):
        if "type" in d:
            # Convert from old schema
            type_ = d.pop("type")
            if type_ == "origin":
                d["target"] = str(Origin(d["target"]).swhid())

        d = {
            **d,
            "target": ExtendedSWHID.from_string(d["target"]),
            "authority": MetadataAuthority.from_dict(d["authority"]),
            "fetcher": MetadataFetcher.from_dict(d["fetcher"]),
        }

        swhid_keys = ("snapshot", "release", "revision", "directory")
        for swhid_key in swhid_keys:
            if d.get(swhid_key):
                d[swhid_key] = CoreSWHID.from_string(d[swhid_key])

        return super().from_dict(d)

    def swhid(self) -> ExtendedSWHID:
        """Returns a SWHID representing this RawExtrinsicMetadata object."""
        return ExtendedSWHID(
            object_type=SwhidExtendedObjectType.RAW_EXTRINSIC_METADATA,
            object_id=self.id,
        )


@attr.s(frozen=True, slots=True, field_transformer=optimize_all_validators)
class ExtID(HashableObject, BaseModel):
    object_type: Final = "extid"

    extid_type = attr.ib(type=str, validator=generic_type_validator)
    extid = attr.ib(type=bytes, validator=generic_type_validator)
    target = attr.ib(type=CoreSWHID, validator=generic_type_validator)
    extid_version = attr.ib(type=int, validator=generic_type_validator, default=0)

    id = attr.ib(
        type=Sha1Git, validator=generic_type_validator, default=b"", repr=hash_repr
    )

    @classmethod
    def from_dict(cls, d):
        return cls(
            extid=d["extid"],
            extid_type=d["extid_type"],
            target=CoreSWHID.from_string(d["target"]),
            extid_version=d.get("extid_version", 0),
        )

    def _compute_hash_from_attributes(self) -> bytes:
        return _compute_hash_from_manifest(git_objects.extid_git_object(self))


# Note: we need the type ignore stanza here because mypy cannot figure that all
# subclasses of BaseModel do have an object_type attribute, even if BaseModel
# itself does not (because these are Final)
SWH_MODEL_OBJECT_TYPES: Dict[str, Type[BaseModel]] = {
    cls.object_type: cls  # type: ignore
    for cls in (
        Person,
        Timestamp,
        TimestampWithTimezone,
        Origin,
        OriginVisit,
        OriginVisitStatus,
        Snapshot,
        SnapshotBranch,
        Release,
        Revision,
        Directory,
        DirectoryEntry,
        Content,
        SkippedContent,
        MetadataAuthority,
        MetadataFetcher,
        RawExtrinsicMetadata,
        ExtID,
    )
}
