# Copyright (C) 2019-2020 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import collections
import copy
import datetime
import hashlib
from typing import Any, List, Optional, Tuple, Union

import attr
from attrs_strict import AttributeTypeError
import dateutil
from hypothesis import given
from hypothesis.strategies import binary, none
import pytest

from swh.model.collections import ImmutableDict
from swh.model.from_disk import DentryPerms
import swh.model.git_objects
from swh.model.hashutil import MultiHash, hash_to_bytes
import swh.model.hypothesis_strategies as strategies
import swh.model.model
from swh.model.model import (
    BaseModel,
    Content,
    Directory,
    DirectoryEntry,
    MetadataAuthority,
    MetadataAuthorityType,
    MetadataFetcher,
    MissingData,
    Origin,
    OriginVisit,
    OriginVisitStatus,
    Person,
    RawExtrinsicMetadata,
    Release,
    Revision,
    SkippedContent,
    Snapshot,
    TargetType,
    Timestamp,
    TimestampWithTimezone,
    optimized_validator,
)
import swh.model.swhids
from swh.model.swhids import CoreSWHID, ExtendedSWHID, ObjectType
from swh.model.tests.swh_model_data import TEST_OBJECTS
from swh.model.tests.test_identifiers import (
    TS_DATETIMES,
    TS_TIMEZONES,
    directory_example,
    metadata_example,
    release_example,
    revision_example,
    snapshot_example,
)

EXAMPLE_HASH = hash_to_bytes("94a9ed024d3859793618152ea559a168bbcbb5e2")


@given(strategies.objects())
def test_todict_inverse_fromdict(objtype_and_obj):
    (obj_type, obj) = objtype_and_obj

    if obj_type in ("origin", "origin_visit"):
        return

    obj_as_dict = obj.to_dict()
    obj_as_dict_copy = copy.deepcopy(obj_as_dict)

    # Check the composition of to_dict and from_dict is the identity
    assert obj == type(obj).from_dict(obj_as_dict)

    # Check from_dict() does not change the input dict
    assert obj_as_dict == obj_as_dict_copy

    # Check the composition of from_dict and to_dict is the identity
    assert obj_as_dict == type(obj).from_dict(obj_as_dict).to_dict()


@given(strategies.objects())
def test_repr(objtype_and_obj):
    """Checks every model object has a working repr(), and that it can be eval()uated
    (so that printed objects can be copy-pasted to write test cases.)"""
    (obj_type, obj) = objtype_and_obj

    r = repr(obj)
    env = {
        "tzutc": lambda: datetime.timezone.utc,
        "tzfile": dateutil.tz.tzfile,
        "hash_to_bytes": hash_to_bytes,
        **swh.model.swhids.__dict__,
        **swh.model.model.__dict__,
    }
    assert eval(r, env) == obj


@attr.s
class Cls1:
    pass


@attr.s
class Cls2(Cls1):
    pass


_custom_namedtuple = collections.namedtuple("_custom_namedtuple", "a b")


class _custom_tuple(tuple):
    pass


# List of (type, valid_values, invalid_values)
_TYPE_VALIDATOR_PARAMETERS: List[Tuple[Any, List[Any], List[Any]]] = [
    # base types:
    (
        bool,
        [True, False],
        [-1, 0, 1, 42, 1000, None, "123", 0.0, (), ("foo",), ImmutableDict()],
    ),
    (
        int,
        [-1, 0, 1, 42, 1000, DentryPerms.directory, True, False],
        [None, "123", 0.0, (), ImmutableDict()],
    ),
    (
        float,
        [-1.0, 0.0, 1.0, float("infinity"), float("NaN")],
        [True, False, None, 1, "1.2", (), ImmutableDict()],
    ),
    (
        bytes,
        [b"", b"123"],
        [None, bytearray(b"\x12\x34"), "123", 0, 123, (), (1, 2, 3), ImmutableDict()],
    ),
    (str, ["", "123"], [None, b"123", b"", 0, (), (1, 2, 3), ImmutableDict()]),
    (None, [None], [b"", b"123", "", "foo", 0, 123, ImmutableDict(), float("NaN")]),
    # unions:
    (
        Optional[int],
        [None, -1, 0, 1, 42, 1000, DentryPerms.directory],
        ["123", 0.0, (), ImmutableDict()],
    ),
    (
        Optional[bytes],
        [None, b"", b"123"],
        ["123", "", 0, (), (1, 2, 3), ImmutableDict()],
    ),
    (
        Union[str, bytes],
        ["", "123", b"123", b""],
        [None, 0, (), (1, 2, 3), ImmutableDict()],
    ),
    (
        Union[str, bytes, None],
        ["", "123", b"123", b"", None],
        [0, (), (1, 2, 3), ImmutableDict()],
    ),
    # tuples
    (
        Tuple[str, str],
        [("foo", "bar"), ("", ""), _custom_namedtuple("", ""), _custom_tuple(("", ""))],
        [("foo",), ("foo", "bar", "baz"), ("foo", 42), (42, "foo")],
    ),
    (
        Tuple[bytes, bytes],
        [
            (b"foo", b"bar"),
            (b"", b""),
            _custom_namedtuple(b"", b""),
            _custom_tuple((b"", b"")),
        ],
        [(b"foo",), (b"foo", b"bar", b"baz"), (b"foo", 42), (42, b"foo")],
    ),
    (
        Tuple[str, ...],
        [
            ("foo",),
            ("foo", "bar"),
            ("", ""),
            ("foo", "bar", "baz"),
            _custom_namedtuple("", ""),
            _custom_tuple(("", "")),
        ],
        [("foo", 42), (42, "foo")],
    ),
    # composite generic:
    (
        Tuple[Union[str, int], Union[str, int]],
        [("foo", "foo"), ("foo", 42), (42, "foo"), (42, 42)],
        [("foo", b"bar"), (b"bar", "foo")],
    ),
    (
        Union[Tuple[str, str], Tuple[int, int]],
        [("foo", "foo"), (42, 42)],
        [("foo", b"bar"), (b"bar", "foo"), ("foo", 42), (42, "foo")],
    ),
    (
        Tuple[Tuple[bytes, bytes], ...],
        [(), ((b"foo", b"bar"),), ((b"foo", b"bar"), (b"baz", b"qux"))],
        [((b"foo", "bar"),), ((b"foo", b"bar"), ("baz", b"qux"))],
    ),
    # standard types:
    (
        datetime.datetime,
        [
            datetime.datetime(2021, 12, 15, 12, 59, 27),
            datetime.datetime(2021, 12, 15, 12, 59, 27, tzinfo=datetime.timezone.utc),
        ],
        [None, 123],
    ),
    # ImmutableDict
    (
        ImmutableDict[str, int],
        [
            ImmutableDict(),
            ImmutableDict({"foo": 42}),
            ImmutableDict({"foo": 42, "bar": 123}),
        ],
        [ImmutableDict({"foo": "bar"}), ImmutableDict({42: 123})],
    ),
    # Any:
    (
        object,
        [-1, 0, 1, 42, 1000, None, "123", 0.0, (), ImmutableDict()],
        [],
    ),
    (
        Any,
        [-1, 0, 1, 42, 1000, None, "123", 0.0, (), ImmutableDict()],
        [],
    ),
    (
        ImmutableDict[Any, int],
        [
            ImmutableDict(),
            ImmutableDict({"foo": 42}),
            ImmutableDict({"foo": 42, "bar": 123}),
            ImmutableDict({42: 123}),
        ],
        [ImmutableDict({"foo": "bar"})],
    ),
    (
        ImmutableDict[str, Any],
        [
            ImmutableDict(),
            ImmutableDict({"foo": 42}),
            ImmutableDict({"foo": "bar"}),
            ImmutableDict({"foo": 42, "bar": 123}),
        ],
        [ImmutableDict({42: 123})],
    ),
    # attr objects:
    (
        Timestamp,
        [
            Timestamp(seconds=123, microseconds=0),
        ],
        [None, "2021-09-28T11:27:59", 123],
    ),
    (
        Cls1,
        [Cls1(), Cls2()],
        [None, b"abcd"],
    ),
    # enums:
    (
        TargetType,
        [TargetType.CONTENT, TargetType.ALIAS],
        ["content", "alias", 123, None],
    ),
]


@pytest.mark.parametrize(
    "type_,value",
    [
        pytest.param(type_, value, id=f"type={type_}, value={value}")
        for (type_, values, _) in _TYPE_VALIDATOR_PARAMETERS
        for value in values
    ],
)
def test_optimized_type_validator_valid(type_, value):
    validator = optimized_validator(type_)
    validator(None, attr.ib(type=type_), value)


@pytest.mark.parametrize(
    "type_,value",
    [
        pytest.param(type_, value, id=f"type={type_}, value={value}")
        for (type_, _, values) in _TYPE_VALIDATOR_PARAMETERS
        for value in values
    ],
)
def test_optimized_type_validator_invalid(type_, value):
    validator = optimized_validator(type_)
    with pytest.raises(AttributeTypeError):
        validator(None, attr.ib(type=type_), value)


@pytest.mark.parametrize("object_type, objects", TEST_OBJECTS.items())
def test_swh_model_todict_fromdict(object_type, objects):
    """checks model objects in swh_model_data are in correct shape"""
    assert objects
    for obj in objects:
        # Check the composition of from_dict and to_dict is the identity
        obj_as_dict = obj.to_dict()
        assert obj == type(obj).from_dict(obj_as_dict)
        assert obj_as_dict == type(obj).from_dict(obj_as_dict).to_dict()


def test_unique_key():
    url = "http://example.org/"
    date = datetime.datetime.now(tz=datetime.timezone.utc)
    id_ = b"42" * 10
    assert Origin(url=url).unique_key() == {"url": url}
    assert OriginVisit(origin=url, date=date, type="git").unique_key() == {
        "origin": url,
        "date": str(date),
    }
    assert OriginVisitStatus(
        origin=url, visit=42, date=date, status="created", snapshot=None
    ).unique_key() == {
        "origin": url,
        "visit": "42",
        "date": str(date),
    }

    assert Snapshot.from_dict({**snapshot_example, "id": id_}).unique_key() == id_
    assert Release.from_dict({**release_example, "id": id_}).unique_key() == id_
    assert Revision.from_dict({**revision_example, "id": id_}).unique_key() == id_
    assert Directory.from_dict({**directory_example, "id": id_}).unique_key() == id_
    assert (
        RawExtrinsicMetadata.from_dict({**metadata_example, "id": id_}).unique_key()
        == id_
    )

    cont = Content.from_data(b"foo")
    assert cont.unique_key().hex() == "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"

    kwargs = {
        **cont.to_dict(),
        "reason": "foo",
        "status": "absent",
    }
    del kwargs["data"]
    assert SkippedContent(**kwargs).unique_key() == cont.hashes()


# Anonymization


@given(strategies.objects())
def test_anonymization(objtype_and_obj):
    (obj_type, obj) = objtype_and_obj

    def check_person(p):
        if p is not None:
            assert p.name is None
            assert p.email is None
            assert len(p.fullname) == 32

    anon_obj = obj.anonymize()
    if obj_type == "person":
        assert anon_obj is not None
        check_person(anon_obj)
    elif obj_type == "release":
        assert anon_obj is not None
        check_person(anon_obj.author)
    elif obj_type == "revision":
        assert anon_obj is not None
        check_person(anon_obj.author)
        check_person(anon_obj.committer)
    else:
        assert anon_obj is None


# Origin, OriginVisit, OriginVisitStatus


@given(strategies.origins())
def test_todict_origins(origin):
    obj = origin.to_dict()

    assert "type" not in obj
    assert type(origin)(url=origin.url) == type(origin).from_dict(obj)


@given(strategies.origin_visits())
def test_todict_origin_visits(origin_visit):
    obj = origin_visit.to_dict()

    assert origin_visit == type(origin_visit).from_dict(obj)


def test_origin_visit_naive_datetime():
    with pytest.raises(ValueError, match="must be a timezone-aware datetime"):
        OriginVisit(
            origin="http://foo/",
            date=datetime.datetime.now(),
            type="git",
        )


@given(strategies.origin_visit_statuses())
def test_todict_origin_visit_statuses(origin_visit_status):
    obj = origin_visit_status.to_dict()

    assert origin_visit_status == type(origin_visit_status).from_dict(obj)


def test_origin_visit_status_naive_datetime():
    with pytest.raises(ValueError, match="must be a timezone-aware datetime"):
        OriginVisitStatus(
            origin="http://foo/",
            visit=42,
            date=datetime.datetime.now(),
            status="ongoing",
            snapshot=None,
        )


# Timestamp


@given(strategies.timestamps())
def test_timestamps_strategy(timestamp):
    attr.validate(timestamp)


def test_timestamp_seconds():
    attr.validate(Timestamp(seconds=0, microseconds=0))
    with pytest.raises(AttributeTypeError):
        Timestamp(seconds="0", microseconds=0)

    attr.validate(Timestamp(seconds=2**63 - 1, microseconds=0))
    with pytest.raises(ValueError):
        Timestamp(seconds=2**63, microseconds=0)

    attr.validate(Timestamp(seconds=-(2**63), microseconds=0))
    with pytest.raises(ValueError):
        Timestamp(seconds=-(2**63) - 1, microseconds=0)


def test_timestamp_microseconds():
    attr.validate(Timestamp(seconds=0, microseconds=0))
    with pytest.raises(AttributeTypeError):
        Timestamp(seconds=0, microseconds="0")

    attr.validate(Timestamp(seconds=0, microseconds=10**6 - 1))
    with pytest.raises(ValueError):
        Timestamp(seconds=0, microseconds=10**6)

    with pytest.raises(ValueError):
        Timestamp(seconds=0, microseconds=-1)


def test_timestamp_from_dict():
    assert Timestamp.from_dict({"seconds": 10, "microseconds": 5})

    with pytest.raises(AttributeTypeError):
        Timestamp.from_dict({"seconds": "10", "microseconds": 5})

    with pytest.raises(AttributeTypeError):
        Timestamp.from_dict({"seconds": 10, "microseconds": "5"})
    with pytest.raises(ValueError):
        Timestamp.from_dict({"seconds": 0, "microseconds": -1})

    Timestamp.from_dict({"seconds": 0, "microseconds": 10**6 - 1})
    with pytest.raises(ValueError):
        Timestamp.from_dict({"seconds": 0, "microseconds": 10**6})


# TimestampWithTimezone


def test_timestampwithtimezone():
    ts = Timestamp(seconds=0, microseconds=0)
    tstz = TimestampWithTimezone(timestamp=ts, offset_bytes=b"+0000")
    attr.validate(tstz)
    assert tstz.offset_minutes() == 0
    assert tstz.offset_bytes == b"+0000"

    tstz = TimestampWithTimezone(timestamp=ts, offset_bytes=b"+0010")
    attr.validate(tstz)
    assert tstz.offset_minutes() == 10
    assert tstz.offset_bytes == b"+0010"

    tstz = TimestampWithTimezone(timestamp=ts, offset_bytes=b"-0010")
    attr.validate(tstz)
    assert tstz.offset_minutes() == -10
    assert tstz.offset_bytes == b"-0010"

    tstz = TimestampWithTimezone(timestamp=ts, offset_bytes=b"-0000")
    attr.validate(tstz)
    assert tstz.offset_minutes() == 0
    assert tstz.offset_bytes == b"-0000"

    tstz = TimestampWithTimezone(timestamp=ts, offset_bytes=b"-1030")
    attr.validate(tstz)
    assert tstz.offset_minutes() == -630
    assert tstz.offset_bytes == b"-1030"

    tstz = TimestampWithTimezone(timestamp=ts, offset_bytes=b"+1320")
    attr.validate(tstz)
    assert tstz.offset_minutes() == 800
    assert tstz.offset_bytes == b"+1320"

    tstz = TimestampWithTimezone(timestamp=ts, offset_bytes=b"+200")
    attr.validate(tstz)
    assert tstz.offset_minutes() == 120
    assert tstz.offset_bytes == b"+200"

    tstz = TimestampWithTimezone(timestamp=ts, offset_bytes=b"+02")
    attr.validate(tstz)
    assert tstz.offset_minutes() == 120
    assert tstz.offset_bytes == b"+02"

    tstz = TimestampWithTimezone(timestamp=ts, offset_bytes=b"+2000000000")
    attr.validate(tstz)
    assert tstz.offset_minutes() == 0
    assert tstz.offset_bytes == b"+2000000000"

    with pytest.raises(AttributeTypeError):
        TimestampWithTimezone(timestamp=datetime.datetime.now(), offset_bytes=b"+0000")

    with pytest.raises((AttributeTypeError, TypeError)):
        TimestampWithTimezone(timestamp=ts, offset_bytes=0)


def test_timestampwithtimezone_from_datetime():
    # Typical case
    tz = datetime.timezone(datetime.timedelta(minutes=+60))
    date = datetime.datetime(2020, 2, 27, 14, 39, 19, tzinfo=tz)
    tstz = TimestampWithTimezone.from_datetime(date)
    assert tstz == TimestampWithTimezone(
        timestamp=Timestamp(
            seconds=1582810759,
            microseconds=0,
        ),
        offset_bytes=b"+0100",
    )

    # Typical case (close to epoch)
    tz = datetime.timezone(datetime.timedelta(minutes=+60))
    date = datetime.datetime(1970, 1, 1, 1, 0, 5, tzinfo=tz)
    tstz = TimestampWithTimezone.from_datetime(date)
    assert tstz == TimestampWithTimezone(
        timestamp=Timestamp(
            seconds=5,
            microseconds=0,
        ),
        offset_bytes=b"+0100",
    )

    # non-integer number of seconds before UNIX epoch
    date = datetime.datetime(
        1969, 12, 31, 23, 59, 59, 100000, tzinfo=datetime.timezone.utc
    )
    tstz = TimestampWithTimezone.from_datetime(date)
    assert tstz == TimestampWithTimezone(
        timestamp=Timestamp(
            seconds=-1,
            microseconds=100000,
        ),
        offset_bytes=b"+0000",
    )

    # non-integer number of seconds in both the timestamp and the offset
    tz = datetime.timezone(datetime.timedelta(microseconds=-600000))
    date = datetime.datetime(1969, 12, 31, 23, 59, 59, 600000, tzinfo=tz)
    tstz = TimestampWithTimezone.from_datetime(date)
    assert tstz == TimestampWithTimezone(
        timestamp=Timestamp(
            seconds=0,
            microseconds=200000,
        ),
        offset_bytes=b"+0000",
    )

    # timezone offset with non-integer number of seconds, for dates before epoch
    # we round down to the previous second, so it should be the same as
    # 1969-01-01T23:59:59Z
    tz = datetime.timezone(datetime.timedelta(microseconds=900000))
    date = datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=tz)
    tstz = TimestampWithTimezone.from_datetime(date)
    assert tstz == TimestampWithTimezone(
        timestamp=Timestamp(
            seconds=-1,
            microseconds=100000,
        ),
        offset_bytes=b"+0000",
    )


def test_timestampwithtimezone_from_naive_datetime():
    date = datetime.datetime(2020, 2, 27, 14, 39, 19)

    with pytest.raises(ValueError, match="datetime without timezone"):
        TimestampWithTimezone.from_datetime(date)


def test_timestampwithtimezone_from_iso8601():
    date = "2020-02-27 14:39:19.123456+0100"

    tstz = TimestampWithTimezone.from_iso8601(date)

    assert tstz == TimestampWithTimezone(
        timestamp=Timestamp(
            seconds=1582810759,
            microseconds=123456,
        ),
        offset_bytes=b"+0100",
    )


def test_timestampwithtimezone_from_iso8601_negative_utc():
    date = "2020-02-27 13:39:19-0000"

    tstz = TimestampWithTimezone.from_iso8601(date)

    assert tstz == TimestampWithTimezone(
        timestamp=Timestamp(
            seconds=1582810759,
            microseconds=0,
        ),
        offset_bytes=b"-0000",
    )


@pytest.mark.parametrize("date", TS_DATETIMES)
@pytest.mark.parametrize("tz", TS_TIMEZONES)
@pytest.mark.parametrize("microsecond", [0, 1, 10, 100, 1000, 999999])
def test_timestampwithtimezone_to_datetime(date, tz, microsecond):
    date = date.replace(tzinfo=tz, microsecond=microsecond)
    tstz = TimestampWithTimezone.from_datetime(date)

    assert tstz.to_datetime() == date
    assert tstz.to_datetime().utcoffset() == date.utcoffset()


def test_person_from_fullname():
    """The author should have name, email and fullname filled."""
    actual_person = Person.from_fullname(b"tony <ynot@dagobah>")
    assert actual_person == Person(
        fullname=b"tony <ynot@dagobah>",
        name=b"tony",
        email=b"ynot@dagobah",
    )


def test_person_from_fullname_no_email():
    """The author and fullname should be the same as the input (author)."""
    actual_person = Person.from_fullname(b"tony")
    assert actual_person == Person(
        fullname=b"tony",
        name=b"tony",
        email=None,
    )


def test_person_from_fullname_empty_person():
    """Empty person has only its fullname filled with the empty
    byte-string.

    """
    actual_person = Person.from_fullname(b"")
    assert actual_person == Person(
        fullname=b"",
        name=None,
        email=None,
    )


def test_git_author_line_to_author():
    # edge case out of the way
    with pytest.raises(TypeError):
        Person.from_fullname(None)

    tests = {
        b"a <b@c.com>": Person(
            name=b"a",
            email=b"b@c.com",
            fullname=b"a <b@c.com>",
        ),
        b"<foo@bar.com>": Person(
            name=None,
            email=b"foo@bar.com",
            fullname=b"<foo@bar.com>",
        ),
        b"malformed <email": Person(
            name=b"malformed", email=b"email", fullname=b"malformed <email"
        ),
        b'malformed <"<br"@ckets>': Person(
            name=b"malformed",
            email=b'"<br"@ckets',
            fullname=b'malformed <"<br"@ckets>',
        ),
        b"trailing <sp@c.e> ": Person(
            name=b"trailing",
            email=b"sp@c.e",
            fullname=b"trailing <sp@c.e> ",
        ),
        b"no<sp@c.e>": Person(
            name=b"no",
            email=b"sp@c.e",
            fullname=b"no<sp@c.e>",
        ),
        b" more   <sp@c.es>": Person(
            name=b"more",
            email=b"sp@c.es",
            fullname=b" more   <sp@c.es>",
        ),
        b" <>": Person(
            name=None,
            email=None,
            fullname=b" <>",
        ),
    }

    for person in sorted(tests):
        expected_person = tests[person]
        assert expected_person == Person.from_fullname(person)


def test_person_comparison():
    """Check only the fullname attribute is used to compare Person objects"""
    person = Person(fullname=b"p1", name=None, email=None)
    assert attr.evolve(person, name=b"toto") == person
    assert attr.evolve(person, email=b"toto@example.com") == person

    person = Person(fullname=b"", name=b"toto", email=b"toto@example.com")
    assert attr.evolve(person, fullname=b"dude") != person


# Content


def test_content_get_hash():
    hashes = dict(sha1=b"foo", sha1_git=b"bar", sha256=b"baz", blake2s256=b"qux")
    c = Content(length=42, status="visible", **hashes)
    for (hash_name, hash_) in hashes.items():
        assert c.get_hash(hash_name) == hash_


def test_content_hashes():
    hashes = dict(sha1=b"foo", sha1_git=b"bar", sha256=b"baz", blake2s256=b"qux")
    c = Content(length=42, status="visible", **hashes)
    assert c.hashes() == hashes


def test_content_data():
    c = Content(
        length=42,
        status="visible",
        data=b"foo",
        sha1=b"foo",
        sha1_git=b"bar",
        sha256=b"baz",
        blake2s256=b"qux",
    )
    assert c.with_data() == c


def test_content_data_missing():
    c = Content(
        length=42,
        status="visible",
        sha1=b"foo",
        sha1_git=b"bar",
        sha256=b"baz",
        blake2s256=b"qux",
    )
    with pytest.raises(MissingData):
        c.with_data()


@given(strategies.present_contents_d())
def test_content_from_dict(content_d):
    c = Content.from_data(**content_d)
    assert c
    assert c.ctime == content_d["ctime"]

    content_d2 = c.to_dict()
    c2 = Content.from_dict(content_d2)
    assert c2.ctime == c.ctime


def test_content_from_dict_str_ctime():
    # test with ctime as a string
    n = datetime.datetime(2020, 5, 6, 12, 34, tzinfo=datetime.timezone.utc)
    content_d = {
        "ctime": n.isoformat(),
        "data": b"",
        "length": 0,
        "sha1": b"\x00",
        "sha256": b"\x00",
        "sha1_git": b"\x00",
        "blake2s256": b"\x00",
    }
    c = Content.from_dict(content_d)
    assert c.ctime == n


def test_content_from_dict_str_naive_ctime():
    # test with ctime as a string
    n = datetime.datetime(2020, 5, 6, 12, 34)
    content_d = {
        "ctime": n.isoformat(),
        "data": b"",
        "length": 0,
        "sha1": b"\x00",
        "sha256": b"\x00",
        "sha1_git": b"\x00",
        "blake2s256": b"\x00",
    }
    with pytest.raises(ValueError, match="must be a timezone-aware datetime."):
        Content.from_dict(content_d)


@given(binary(max_size=4096))
def test_content_from_data(data):
    c = Content.from_data(data)
    assert c.data == data
    assert c.length == len(data)
    assert c.status == "visible"
    for key, value in MultiHash.from_data(data).digest().items():
        assert getattr(c, key) == value


@given(binary(max_size=4096))
def test_hidden_content_from_data(data):
    c = Content.from_data(data, status="hidden")
    assert c.data == data
    assert c.length == len(data)
    assert c.status == "hidden"
    for key, value in MultiHash.from_data(data).digest().items():
        assert getattr(c, key) == value


def test_content_naive_datetime():
    c = Content.from_data(b"foo")
    with pytest.raises(ValueError, match="must be a timezone-aware datetime"):
        Content(
            **c.to_dict(),
            ctime=datetime.datetime.now(),
        )


@given(strategies.present_contents())
def test_content_git_roundtrip(content):
    assert content.data is not None
    raw = swh.model.git_objects.content_git_object(content)
    sha1_git = hashlib.new("sha1", raw).digest()
    assert content.sha1_git == sha1_git


# SkippedContent


@given(binary(max_size=4096))
def test_skipped_content_from_data(data):
    c = SkippedContent.from_data(data, reason="reason")
    assert c.reason == "reason"
    assert c.length == len(data)
    assert c.status == "absent"
    for key, value in MultiHash.from_data(data).digest().items():
        assert getattr(c, key) == value


@given(strategies.skipped_contents_d())
def test_skipped_content_origin_is_str(skipped_content_d):
    assert SkippedContent.from_dict(skipped_content_d)

    skipped_content_d["origin"] = "http://path/to/origin"
    assert SkippedContent.from_dict(skipped_content_d)

    skipped_content_d["origin"] = Origin(url="http://path/to/origin")
    with pytest.raises(ValueError, match="origin"):
        SkippedContent.from_dict(skipped_content_d)


def test_skipped_content_naive_datetime():
    c = SkippedContent.from_data(b"foo", reason="reason")
    with pytest.raises(ValueError, match="must be a timezone-aware datetime"):
        SkippedContent(
            **c.to_dict(),
            ctime=datetime.datetime.now(),
        )


# Directory


@given(strategies.directories(raw_manifest=none()))
def test_directory_check(directory):
    directory.check()

    directory2 = attr.evolve(directory, id=b"\x00" * 20)
    with pytest.raises(ValueError, match="does not match recomputed hash"):
        directory2.check()

    directory2 = attr.evolve(
        directory, raw_manifest=swh.model.git_objects.directory_git_object(directory)
    )
    with pytest.raises(
        ValueError, match="non-none raw_manifest attribute, but does not need it."
    ):
        directory2.check()


@given(strategies.directories(raw_manifest=none()))
def test_directory_raw_manifest(directory):
    assert "raw_manifest" not in directory.to_dict()

    raw_manifest = b"foo"
    id_ = hashlib.new("sha1", raw_manifest).digest()

    directory2 = attr.evolve(directory, raw_manifest=raw_manifest)
    assert directory2.to_dict()["raw_manifest"] == raw_manifest
    with pytest.raises(ValueError, match="does not match recomputed hash"):
        directory2.check()

    directory2 = attr.evolve(directory, raw_manifest=raw_manifest, id=id_)
    assert directory2.id is not None
    assert directory2.id == id_ != directory.id
    assert directory2.to_dict()["raw_manifest"] == raw_manifest
    directory2.check()


def test_directory_entry_name_validation():
    with pytest.raises(ValueError, match="valid directory entry name."):
        DirectoryEntry(name=b"foo/", type="dir", target=b"\x00" * 20, perms=0),


def test_directory_duplicate_entry_name():
    entries = (
        DirectoryEntry(name=b"foo", type="file", target=b"\x00" * 20, perms=0),
        DirectoryEntry(name=b"foo", type="dir", target=b"\x01" * 20, perms=1),
    )
    with pytest.raises(ValueError, match="duplicated entry name"):
        Directory(entries=entries)

    entries = (
        DirectoryEntry(name=b"foo", type="file", target=b"\x00" * 20, perms=0),
        DirectoryEntry(name=b"foo", type="file", target=b"\x00" * 20, perms=0),
    )
    with pytest.raises(ValueError, match="duplicated entry name"):
        Directory(entries=entries)


@given(strategies.directories())
def test_directory_from_possibly_duplicated_entries__no_duplicates(directory):
    """
    Directory.from_possibly_duplicated_entries should return the directory
    unchanged if it has no duplicated entry name.
    """
    assert (False, directory) == Directory.from_possibly_duplicated_entries(
        id=directory.id, entries=directory.entries, raw_manifest=directory.raw_manifest
    )
    assert (False, directory) == Directory.from_possibly_duplicated_entries(
        entries=directory.entries, raw_manifest=directory.raw_manifest
    )


@pytest.mark.parametrize("rev_first", [True, False])
def test_directory_from_possibly_duplicated_entries__rev_and_dir(rev_first):
    entries = (
        DirectoryEntry(name=b"foo", type="dir", target=b"\x01" * 20, perms=1),
        DirectoryEntry(name=b"foo", type="rev", target=b"\x00" * 20, perms=0),
    )
    if rev_first:
        entries = tuple(reversed(entries))
    (is_corrupt, dir_) = Directory.from_possibly_duplicated_entries(entries=entries)
    assert is_corrupt
    assert dir_.entries == (
        DirectoryEntry(name=b"foo", type="rev", target=b"\x00" * 20, perms=0),
        DirectoryEntry(
            name=b"foo_0101010101", type="dir", target=b"\x01" * 20, perms=1
        ),
    )

    # order is independent of 'rev_first' because it is always sorted in git order
    assert dir_.raw_manifest == (
        # fmt: off
        b"tree 52\x00"
        + b"0 foo\x00" + b"\x00" * 20
        + b"1 foo\x00" + b"\x01" * 20
        # fmt: on
    )


@pytest.mark.parametrize("file_first", [True, False])
def test_directory_from_possibly_duplicated_entries__file_and_dir(file_first):
    entries = (
        DirectoryEntry(name=b"foo", type="dir", target=b"\x01" * 20, perms=1),
        DirectoryEntry(name=b"foo", type="file", target=b"\x00" * 20, perms=0),
    )
    if file_first:
        entries = tuple(reversed(entries))
    (is_corrupt, dir_) = Directory.from_possibly_duplicated_entries(entries=entries)
    assert is_corrupt
    assert dir_.entries == (
        DirectoryEntry(name=b"foo", type="dir", target=b"\x01" * 20, perms=1),
        DirectoryEntry(
            name=b"foo_0000000000", type="file", target=b"\x00" * 20, perms=0
        ),
    )

    # order is independent of 'file_first' because it is always sorted in git order
    assert dir_.raw_manifest == (
        # fmt: off
        b"tree 52\x00"
        + b"0 foo\x00" + b"\x00" * 20
        + b"1 foo\x00" + b"\x01" * 20
        # fmt: on
    )


def test_directory_from_possibly_duplicated_entries__two_files1():
    entries = (
        DirectoryEntry(name=b"foo", type="file", target=b"\x01" * 20, perms=1),
        DirectoryEntry(name=b"foo", type="file", target=b"\x00" * 20, perms=0),
    )
    (is_corrupt, dir_) = Directory.from_possibly_duplicated_entries(entries=entries)
    assert is_corrupt

    assert dir_.entries == (
        DirectoryEntry(name=b"foo", type="file", target=b"\x01" * 20, perms=1),
        DirectoryEntry(
            name=b"foo_0000000000", type="file", target=b"\x00" * 20, perms=0
        ),
    )
    assert dir_.raw_manifest == (
        # fmt: off
        b"tree 52\x00"
        + b"1 foo\x00" + b"\x01" * 20
        + b"0 foo\x00" + b"\x00" * 20
        # fmt: on
    )


def test_directory_from_possibly_duplicated_entries__two_files2():
    """
    Same as above, but entries are in a different order (and order matters
    to break the tie)
    """
    entries = (
        DirectoryEntry(name=b"foo", type="file", target=b"\x00" * 20, perms=0),
        DirectoryEntry(name=b"foo", type="file", target=b"\x01" * 20, perms=1),
    )
    (is_corrupt, dir_) = Directory.from_possibly_duplicated_entries(entries=entries)
    assert is_corrupt

    assert dir_.entries == (
        DirectoryEntry(name=b"foo", type="file", target=b"\x00" * 20, perms=0),
        DirectoryEntry(
            name=b"foo_0101010101", type="file", target=b"\x01" * 20, perms=1
        ),
    )
    assert dir_.raw_manifest == (
        # fmt: off
        b"tree 52\x00"
        + b"0 foo\x00" + b"\x00" * 20
        + b"1 foo\x00" + b"\x01" * 20
        # fmt: on
    )


def test_directory_from_possibly_duplicated_entries__preserve_manifest():
    entries = (
        DirectoryEntry(name=b"foo", type="dir", target=b"\x01" * 20, perms=1),
        DirectoryEntry(name=b"foo", type="rev", target=b"\x00" * 20, perms=0),
    )
    (is_corrupt, dir_) = Directory.from_possibly_duplicated_entries(
        entries=entries, raw_manifest=b"blah"
    )
    assert is_corrupt
    assert dir_.entries == (
        DirectoryEntry(name=b"foo", type="rev", target=b"\x00" * 20, perms=0),
        DirectoryEntry(
            name=b"foo_0101010101", type="dir", target=b"\x01" * 20, perms=1
        ),
    )

    assert dir_.raw_manifest == b"blah"


# Release


@given(strategies.releases(raw_manifest=none()))
def test_release_check(release):
    release.check()

    release2 = attr.evolve(release, id=b"\x00" * 20)
    with pytest.raises(ValueError, match="does not match recomputed hash"):
        release2.check()

    release2 = attr.evolve(
        release, raw_manifest=swh.model.git_objects.release_git_object(release)
    )
    with pytest.raises(
        ValueError, match="non-none raw_manifest attribute, but does not need it."
    ):
        release2.check()


@given(strategies.releases(raw_manifest=none()))
def test_release_raw_manifest(release):
    raw_manifest = b"foo"
    id_ = hashlib.new("sha1", raw_manifest).digest()

    release2 = attr.evolve(release, raw_manifest=raw_manifest)
    assert release2.to_dict()["raw_manifest"] == raw_manifest
    with pytest.raises(ValueError, match="does not match recomputed hash"):
        release2.check()

    release2 = attr.evolve(release, raw_manifest=raw_manifest, id=id_)
    assert release2.id is not None
    assert release2.id == id_ != release.id
    assert release2.to_dict()["raw_manifest"] == raw_manifest
    release2.check()


# Revision


@given(strategies.revisions(raw_manifest=none()))
def test_revision_check(revision):
    revision.check()

    revision2 = attr.evolve(revision, id=b"\x00" * 20)
    with pytest.raises(ValueError, match="does not match recomputed hash"):
        revision2.check()

    revision2 = attr.evolve(
        revision, raw_manifest=swh.model.git_objects.revision_git_object(revision)
    )
    with pytest.raises(
        ValueError, match="non-none raw_manifest attribute, but does not need it."
    ):
        revision2.check()


@given(strategies.revisions(raw_manifest=none()))
def test_revision_raw_manifest(revision):

    raw_manifest = b"foo"
    id_ = hashlib.new("sha1", raw_manifest).digest()

    revision2 = attr.evolve(revision, raw_manifest=raw_manifest)
    assert revision2.to_dict()["raw_manifest"] == raw_manifest
    with pytest.raises(ValueError, match="does not match recomputed hash"):
        revision2.check()

    revision2 = attr.evolve(revision, raw_manifest=raw_manifest, id=id_)
    assert revision2.id is not None
    assert revision2.id == id_ != revision.id
    assert revision2.to_dict()["raw_manifest"] == raw_manifest
    revision2.check()


def test_revision_extra_headers_no_headers():
    rev_dict = revision_example.copy()
    rev_dict.pop("id")
    rev = Revision.from_dict(rev_dict)
    rev_dict = attr.asdict(rev, recurse=False)

    rev_model = Revision(**rev_dict)
    assert rev_model.metadata is None
    assert rev_model.extra_headers == ()

    rev_dict["metadata"] = {
        "something": "somewhere",
        "some other thing": "stranger",
    }
    rev_model = Revision(**rev_dict)
    assert rev_model.metadata == rev_dict["metadata"]
    assert rev_model.extra_headers == ()


def test_revision_extra_headers_with_headers():
    rev_dict = revision_example.copy()
    rev_dict.pop("id")
    rev = Revision.from_dict(rev_dict)
    rev_dict = attr.asdict(rev, recurse=False)
    rev_dict["metadata"] = {
        "something": "somewhere",
        "some other thing": "stranger",
    }
    extra_headers = (
        (b"header1", b"value1"),
        (b"header2", b"42"),
        (b"header3", b"should I?\x00"),
        (b"header1", b"again"),
    )

    rev_dict["extra_headers"] = extra_headers
    rev_model = Revision(**rev_dict)
    assert "extra_headers" not in rev_model.metadata
    assert rev_model.extra_headers == extra_headers


def test_revision_extra_headers_in_metadata():
    rev_dict = revision_example.copy()
    rev_dict.pop("id")
    rev = Revision.from_dict(rev_dict)
    rev_dict = attr.asdict(rev, recurse=False)
    rev_dict["metadata"] = {
        "something": "somewhere",
        "some other thing": "stranger",
    }

    extra_headers = (
        (b"header1", b"value1"),
        (b"header2", b"42"),
        (b"header3", b"should I?\x00"),
        (b"header1", b"again"),
    )

    # check the bw-compat init hook does the job
    # ie. extra_headers are given in the metadata field
    rev_dict["metadata"]["extra_headers"] = extra_headers
    rev_model = Revision(**rev_dict)
    assert "extra_headers" not in rev_model.metadata
    assert rev_model.extra_headers == extra_headers


def test_revision_extra_headers_as_lists():
    rev_dict = revision_example.copy()
    rev_dict.pop("id")
    rev = Revision.from_dict(rev_dict)
    rev_dict = attr.asdict(rev, recurse=False)
    rev_dict["metadata"] = {}

    extra_headers = (
        (b"header1", b"value1"),
        (b"header2", b"42"),
        (b"header3", b"should I?\x00"),
        (b"header1", b"again"),
    )

    # check Revision.extra_headers tuplify does the job
    rev_dict["extra_headers"] = [list(x) for x in extra_headers]
    rev_model = Revision(**rev_dict)
    assert "extra_headers" not in rev_model.metadata
    assert rev_model.extra_headers == extra_headers


def test_revision_extra_headers_type_error():
    rev_dict = revision_example.copy()
    rev_dict.pop("id")
    rev = Revision.from_dict(rev_dict)
    orig_rev_dict = attr.asdict(rev, recurse=False)
    orig_rev_dict["metadata"] = {
        "something": "somewhere",
        "some other thing": "stranger",
    }
    extra_headers = (
        ("header1", b"value1"),
        (b"header2", 42),
        ("header1", "again"),
    )
    # check headers one at a time
    #   if given as extra_header
    for extra_header in extra_headers:
        rev_dict = copy.deepcopy(orig_rev_dict)
        rev_dict["extra_headers"] = (extra_header,)
        with pytest.raises(AttributeTypeError):
            Revision(**rev_dict)
    #   if given as metadata
    for extra_header in extra_headers:
        rev_dict = copy.deepcopy(orig_rev_dict)
        rev_dict["metadata"]["extra_headers"] = (extra_header,)
        with pytest.raises(AttributeTypeError):
            Revision(**rev_dict)


def test_revision_extra_headers_from_dict():
    rev_dict = revision_example.copy()
    rev_dict.pop("id")
    rev_model = Revision.from_dict(rev_dict)
    assert rev_model.metadata is None
    assert rev_model.extra_headers == ()

    rev_dict["metadata"] = {
        "something": "somewhere",
        "some other thing": "stranger",
    }
    rev_model = Revision.from_dict(rev_dict)
    assert rev_model.metadata == rev_dict["metadata"]
    assert rev_model.extra_headers == ()

    extra_headers = (
        (b"header1", b"value1"),
        (b"header2", b"42"),
        (b"header3", b"should I?\nmaybe\x00\xff"),
        (b"header1", b"again"),
    )
    rev_dict["extra_headers"] = extra_headers
    rev_model = Revision.from_dict(rev_dict)
    assert "extra_headers" not in rev_model.metadata
    assert rev_model.extra_headers == extra_headers


def test_revision_extra_headers_in_metadata_from_dict():
    rev_dict = revision_example.copy()
    rev_dict.pop("id")

    rev_dict["metadata"] = {
        "something": "somewhere",
        "some other thing": "stranger",
    }
    extra_headers = (
        (b"header1", b"value1"),
        (b"header2", b"42"),
        (b"header3", b"should I?\nmaybe\x00\xff"),
        (b"header1", b"again"),
    )
    # check the bw-compat init hook does the job
    rev_dict["metadata"]["extra_headers"] = extra_headers
    rev_model = Revision.from_dict(rev_dict)
    assert "extra_headers" not in rev_model.metadata
    assert rev_model.extra_headers == extra_headers


def test_revision_extra_headers_as_lists_from_dict():
    rev_dict = revision_example.copy()
    rev_dict.pop("id")
    rev_model = Revision.from_dict(rev_dict)
    rev_dict["metadata"] = {
        "something": "somewhere",
        "some other thing": "stranger",
    }
    extra_headers = (
        (b"header1", b"value1"),
        (b"header2", b"42"),
        (b"header3", b"should I?\nmaybe\x00\xff"),
        (b"header1", b"again"),
    )
    # check Revision.extra_headers converter does the job
    rev_dict["extra_headers"] = [list(x) for x in extra_headers]
    rev_model = Revision.from_dict(rev_dict)
    assert "extra_headers" not in rev_model.metadata
    assert rev_model.extra_headers == extra_headers


def test_revision_no_author_or_committer_from_dict():
    rev_dict = revision_example.copy()
    rev_dict["author"] = rev_dict["date"] = None
    rev_dict["committer"] = rev_dict["committer_date"] = None
    rev_model = Revision.from_dict(rev_dict)
    assert rev_model.to_dict() == {
        **rev_dict,
        "parents": tuple(rev_dict["parents"]),
        "extra_headers": (),
        "metadata": None,
    }


def test_revision_none_author_or_committer():
    rev_dict = revision_example.copy()
    rev_dict["author"] = None
    with pytest.raises(ValueError, match=".*date must be None if author is None.*"):
        Revision.from_dict(rev_dict)

    rev_dict = revision_example.copy()
    rev_dict["committer"] = None
    with pytest.raises(
        ValueError, match=".*committer_date must be None if committer is None.*"
    ):
        Revision.from_dict(rev_dict)


@given(strategies.objects(split_content=True))
def test_object_type(objtype_and_obj):
    obj_type, obj = objtype_and_obj
    assert obj_type == obj.object_type


def test_object_type_is_final():
    object_types = set()

    def check_final(cls):
        if hasattr(cls, "object_type"):
            assert cls.object_type not in object_types
            object_types.add(cls.object_type)
        if cls.__subclasses__():
            assert not hasattr(cls, "object_type")
        for subcls in cls.__subclasses__():
            check_final(subcls)

    check_final(BaseModel)


_metadata_authority = MetadataAuthority(
    type=MetadataAuthorityType.FORGE,
    url="https://forge.softwareheritage.org",
)
_metadata_fetcher = MetadataFetcher(
    name="test-fetcher",
    version="0.0.1",
)
_content_swhid = ExtendedSWHID.from_string(
    "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"
)
_origin_url = "https://forge.softwareheritage.org/source/swh-model.git"
_origin_swhid = ExtendedSWHID.from_string(
    "swh:1:ori:433b4f5612f0720ed51fa7aeaf43a3625870057b"
)
_dummy_qualifiers = {"origin": "https://example.com", "lines": "42"}
_common_metadata_fields = dict(
    discovery_date=datetime.datetime(
        2021, 1, 29, 13, 57, 9, tzinfo=datetime.timezone.utc
    ),
    authority=_metadata_authority,
    fetcher=_metadata_fetcher,
    format="json",
    metadata=b'{"origin": "https://example.com", "lines": "42"}',
)


def test_metadata_valid():
    """Checks valid RawExtrinsicMetadata objects don't raise an error."""

    # Simplest case
    RawExtrinsicMetadata(target=_origin_swhid, **_common_metadata_fields)

    # Object with an SWHID
    RawExtrinsicMetadata(
        target=_content_swhid,
        **_common_metadata_fields,
    )


def test_metadata_from_old_dict():
    common_fields = {
        "authority": {"type": "forge", "url": "https://forge.softwareheritage.org"},
        "fetcher": {
            "name": "test-fetcher",
            "version": "0.0.1",
        },
        "discovery_date": _common_metadata_fields["discovery_date"],
        "format": "json",
        "metadata": b'{"origin": "https://example.com", "lines": "42"}',
    }

    m = RawExtrinsicMetadata(
        target=_origin_swhid,
        **_common_metadata_fields,
    )
    assert (
        RawExtrinsicMetadata.from_dict(
            {"id": m.id, "target": _origin_url, "type": "origin", **common_fields}
        )
        == m
    )

    m = RawExtrinsicMetadata(
        target=_content_swhid,
        **_common_metadata_fields,
    )
    assert (
        RawExtrinsicMetadata.from_dict(
            {"target": str(_content_swhid), "type": "content", **common_fields}
        )
        == m
    )


def test_metadata_to_dict():
    """Checks valid RawExtrinsicMetadata objects don't raise an error."""

    common_fields = {
        "authority": {"type": "forge", "url": "https://forge.softwareheritage.org"},
        "fetcher": {
            "name": "test-fetcher",
            "version": "0.0.1",
        },
        "discovery_date": _common_metadata_fields["discovery_date"],
        "format": "json",
        "metadata": b'{"origin": "https://example.com", "lines": "42"}',
    }

    m = RawExtrinsicMetadata(
        target=_origin_swhid,
        **_common_metadata_fields,
    )
    assert m.to_dict() == {
        "target": str(_origin_swhid),
        "id": b"\xa3)q\x0f\xf7p\xc7\xb0\\O\xe8\x84\x83Z\xb0]\x81\xe9\x95\x13",
        **common_fields,
    }
    assert RawExtrinsicMetadata.from_dict(m.to_dict()) == m

    m = RawExtrinsicMetadata(
        target=_content_swhid,
        **_common_metadata_fields,
    )
    assert m.to_dict() == {
        "target": "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2",
        "id": b"\xbc\xa3U\xddf\x19U\xc5\xd2\xd7\xdfK\xd7c\x1f\xa8\xfeh\x992",
        **common_fields,
    }
    assert RawExtrinsicMetadata.from_dict(m.to_dict()) == m

    hash_hex = "6162" * 10
    hash_bin = b"ab" * 10
    m = RawExtrinsicMetadata(
        target=_content_swhid,
        **_common_metadata_fields,
        origin="https://example.org/",
        snapshot=CoreSWHID(object_type=ObjectType.SNAPSHOT, object_id=hash_bin),
        release=CoreSWHID(object_type=ObjectType.RELEASE, object_id=hash_bin),
        revision=CoreSWHID(object_type=ObjectType.REVISION, object_id=hash_bin),
        path=b"/foo/bar",
        directory=CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=hash_bin),
    )
    assert m.to_dict() == {
        "target": "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2",
        "id": b"\x14l\xb0\x1f\xb9\xc0{)\xc7\x0f\xbd\xc0*,YZ\xf5C\xab\xfc",
        **common_fields,
        "origin": "https://example.org/",
        "snapshot": f"swh:1:snp:{hash_hex}",
        "release": f"swh:1:rel:{hash_hex}",
        "revision": f"swh:1:rev:{hash_hex}",
        "path": b"/foo/bar",
        "directory": f"swh:1:dir:{hash_hex}",
    }
    assert RawExtrinsicMetadata.from_dict(m.to_dict()) == m


def test_metadata_invalid_target():
    """Checks various invalid values for the 'target' field."""
    # SWHID passed as string instead of SWHID
    with pytest.raises(ValueError, match="target must be.*ExtendedSWHID"):
        RawExtrinsicMetadata(
            target="swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2",
            **_common_metadata_fields,
        )


def test_metadata_naive_datetime():
    with pytest.raises(ValueError, match="must be a timezone-aware datetime"):
        RawExtrinsicMetadata(
            target=_origin_swhid,
            **{**_common_metadata_fields, "discovery_date": datetime.datetime.now()},
        )


def test_metadata_validate_context_origin():
    """Checks validation of RawExtrinsicMetadata.origin."""

    # Origins can't have an 'origin' context
    with pytest.raises(
        ValueError, match="Unexpected 'origin' context for origin object"
    ):
        RawExtrinsicMetadata(
            target=_origin_swhid,
            origin=_origin_url,
            **_common_metadata_fields,
        )

    # but all other types can
    RawExtrinsicMetadata(
        target=_content_swhid,
        origin=_origin_url,
        **_common_metadata_fields,
    )

    # SWHIDs aren't valid origin URLs
    with pytest.raises(ValueError, match="SWHID used as context origin URL"):
        RawExtrinsicMetadata(
            target=_content_swhid,
            origin="swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2",
            **_common_metadata_fields,
        )


def test_metadata_validate_context_visit():
    """Checks validation of RawExtrinsicMetadata.visit."""

    # Origins can't have a 'visit' context
    with pytest.raises(
        ValueError, match="Unexpected 'visit' context for origin object"
    ):
        RawExtrinsicMetadata(
            target=_origin_swhid,
            visit=42,
            **_common_metadata_fields,
        )

    # but all other types can
    RawExtrinsicMetadata(
        target=_content_swhid,
        origin=_origin_url,
        visit=42,
        **_common_metadata_fields,
    )

    # Missing 'origin'
    with pytest.raises(ValueError, match="'origin' context must be set if 'visit' is"):
        RawExtrinsicMetadata(
            target=_content_swhid,
            visit=42,
            **_common_metadata_fields,
        )

    # visit id must be positive
    with pytest.raises(ValueError, match="Nonpositive visit id"):
        RawExtrinsicMetadata(
            target=_content_swhid,
            origin=_origin_url,
            visit=-42,
            **_common_metadata_fields,
        )


def test_metadata_validate_context_snapshot():
    """Checks validation of RawExtrinsicMetadata.snapshot."""

    # Origins can't have a 'snapshot' context
    with pytest.raises(
        ValueError, match="Unexpected 'snapshot' context for origin object"
    ):
        RawExtrinsicMetadata(
            target=_origin_swhid,
            snapshot=CoreSWHID(
                object_type=ObjectType.SNAPSHOT,
                object_id=EXAMPLE_HASH,
            ),
            **_common_metadata_fields,
        )

    # but content can
    RawExtrinsicMetadata(
        target=_content_swhid,
        snapshot=CoreSWHID(object_type=ObjectType.SNAPSHOT, object_id=EXAMPLE_HASH),
        **_common_metadata_fields,
    )

    # SWHID type doesn't match the expected type of this context key
    with pytest.raises(
        ValueError, match="Expected SWHID type 'snapshot', got 'content'"
    ):
        RawExtrinsicMetadata(
            target=_content_swhid,
            snapshot=CoreSWHID(
                object_type=ObjectType.CONTENT,
                object_id=EXAMPLE_HASH,
            ),
            **_common_metadata_fields,
        )


def test_metadata_validate_context_release():
    """Checks validation of RawExtrinsicMetadata.release."""

    # Origins can't have a 'release' context
    with pytest.raises(
        ValueError, match="Unexpected 'release' context for origin object"
    ):
        RawExtrinsicMetadata(
            target=_origin_swhid,
            release=CoreSWHID(
                object_type=ObjectType.RELEASE,
                object_id=EXAMPLE_HASH,
            ),
            **_common_metadata_fields,
        )

    # but content can
    RawExtrinsicMetadata(
        target=_content_swhid,
        release=CoreSWHID(object_type=ObjectType.RELEASE, object_id=EXAMPLE_HASH),
        **_common_metadata_fields,
    )

    # SWHID type doesn't match the expected type of this context key
    with pytest.raises(
        ValueError, match="Expected SWHID type 'release', got 'content'"
    ):
        RawExtrinsicMetadata(
            target=_content_swhid,
            release=CoreSWHID(
                object_type=ObjectType.CONTENT,
                object_id=EXAMPLE_HASH,
            ),
            **_common_metadata_fields,
        )


def test_metadata_validate_context_revision():
    """Checks validation of RawExtrinsicMetadata.revision."""

    # Origins can't have a 'revision' context
    with pytest.raises(
        ValueError, match="Unexpected 'revision' context for origin object"
    ):
        RawExtrinsicMetadata(
            target=_origin_swhid,
            revision=CoreSWHID(
                object_type=ObjectType.REVISION,
                object_id=EXAMPLE_HASH,
            ),
            **_common_metadata_fields,
        )

    # but content can
    RawExtrinsicMetadata(
        target=_content_swhid,
        revision=CoreSWHID(object_type=ObjectType.REVISION, object_id=EXAMPLE_HASH),
        **_common_metadata_fields,
    )

    # SWHID type doesn't match the expected type of this context key
    with pytest.raises(
        ValueError, match="Expected SWHID type 'revision', got 'content'"
    ):
        RawExtrinsicMetadata(
            target=_content_swhid,
            revision=CoreSWHID(
                object_type=ObjectType.CONTENT,
                object_id=EXAMPLE_HASH,
            ),
            **_common_metadata_fields,
        )


def test_metadata_validate_context_path():
    """Checks validation of RawExtrinsicMetadata.path."""

    # Origins can't have a 'path' context
    with pytest.raises(ValueError, match="Unexpected 'path' context for origin object"):
        RawExtrinsicMetadata(
            target=_origin_swhid,
            path=b"/foo/bar",
            **_common_metadata_fields,
        )

    # but content can
    RawExtrinsicMetadata(
        target=_content_swhid,
        path=b"/foo/bar",
        **_common_metadata_fields,
    )


def test_metadata_validate_context_directory():
    """Checks validation of RawExtrinsicMetadata.directory."""

    # Origins can't have a 'directory' context
    with pytest.raises(
        ValueError, match="Unexpected 'directory' context for origin object"
    ):
        RawExtrinsicMetadata(
            target=_origin_swhid,
            directory=CoreSWHID(
                object_type=ObjectType.DIRECTORY,
                object_id=EXAMPLE_HASH,
            ),
            **_common_metadata_fields,
        )

    # but content can
    RawExtrinsicMetadata(
        target=_content_swhid,
        directory=CoreSWHID(
            object_type=ObjectType.DIRECTORY,
            object_id=EXAMPLE_HASH,
        ),
        **_common_metadata_fields,
    )

    # SWHID type doesn't match the expected type of this context key
    with pytest.raises(
        ValueError, match="Expected SWHID type 'directory', got 'content'"
    ):
        RawExtrinsicMetadata(
            target=_content_swhid,
            directory=CoreSWHID(
                object_type=ObjectType.CONTENT,
                object_id=EXAMPLE_HASH,
            ),
            **_common_metadata_fields,
        )


def test_metadata_normalize_discovery_date():
    fields_copy = {**_common_metadata_fields}
    truncated_date = fields_copy.pop("discovery_date")
    assert truncated_date.microsecond == 0

    # Check for TypeError on disabled object type: we removed attrs_strict's
    # type_validator
    with pytest.raises(TypeError):
        RawExtrinsicMetadata(
            target=_content_swhid, discovery_date="not a datetime", **fields_copy
        )

    # Check for truncation to integral second
    date_with_us = truncated_date.replace(microsecond=42)
    md = RawExtrinsicMetadata(
        target=_content_swhid,
        discovery_date=date_with_us,
        **fields_copy,
    )

    assert md.discovery_date == truncated_date
    assert md.discovery_date.tzinfo == datetime.timezone.utc

    # Check that the timezone gets normalized. Timezones can be offset by a
    # non-integral number of seconds, so we need to handle that.
    timezone = datetime.timezone(offset=datetime.timedelta(hours=2))
    date_with_tz = truncated_date.astimezone(timezone)

    assert date_with_tz.tzinfo != datetime.timezone.utc

    md = RawExtrinsicMetadata(
        target=_content_swhid,
        discovery_date=date_with_tz,
        **fields_copy,
    )

    assert md.discovery_date == truncated_date
    assert md.discovery_date.tzinfo == datetime.timezone.utc
