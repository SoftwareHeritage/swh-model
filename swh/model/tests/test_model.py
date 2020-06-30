# Copyright (C) 2019-2020 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import copy
import datetime

import attr
from attrs_strict import AttributeTypeError
from hypothesis import given
from hypothesis.strategies import binary
import pytest

from swh.model.model import (
    BaseModel,
    Content,
    SkippedContent,
    Directory,
    Revision,
    Release,
    Snapshot,
    Origin,
    Timestamp,
    TimestampWithTimezone,
    MissingData,
    Person,
)
from swh.model.hashutil import hash_to_bytes, MultiHash
import swh.model.hypothesis_strategies as strategies
from swh.model.identifiers import (
    directory_identifier,
    revision_identifier,
    release_identifier,
    snapshot_identifier,
)
from swh.model.tests.test_identifiers import (
    directory_example,
    revision_example,
    release_example,
    snapshot_example,
)


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


# Origin, OriginVisit


@given(strategies.origins())
def test_todict_origins(origin):
    obj = origin.to_dict()

    assert "type" not in obj
    assert type(origin)(url=origin.url) == type(origin).from_dict(obj)


@given(strategies.origin_visits())
def test_todict_origin_visits(origin_visit):
    obj = origin_visit.to_dict()

    assert origin_visit == type(origin_visit).from_dict(obj)


@given(strategies.origin_visit_statuses())
def test_todict_origin_visit_statuses(origin_visit_status):
    obj = origin_visit_status.to_dict()

    assert origin_visit_status == type(origin_visit_status).from_dict(obj)


# Timestamp


@given(strategies.timestamps())
def test_timestamps_strategy(timestamp):
    attr.validate(timestamp)


def test_timestamp_seconds():
    attr.validate(Timestamp(seconds=0, microseconds=0))
    with pytest.raises(AttributeTypeError):
        Timestamp(seconds="0", microseconds=0)

    attr.validate(Timestamp(seconds=2 ** 63 - 1, microseconds=0))
    with pytest.raises(ValueError):
        Timestamp(seconds=2 ** 63, microseconds=0)

    attr.validate(Timestamp(seconds=-(2 ** 63), microseconds=0))
    with pytest.raises(ValueError):
        Timestamp(seconds=-(2 ** 63) - 1, microseconds=0)


def test_timestamp_microseconds():
    attr.validate(Timestamp(seconds=0, microseconds=0))
    with pytest.raises(AttributeTypeError):
        Timestamp(seconds=0, microseconds="0")

    attr.validate(Timestamp(seconds=0, microseconds=10 ** 6 - 1))
    with pytest.raises(ValueError):
        Timestamp(seconds=0, microseconds=10 ** 6)

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

    Timestamp.from_dict({"seconds": 0, "microseconds": 10 ** 6 - 1})
    with pytest.raises(ValueError):
        Timestamp.from_dict({"seconds": 0, "microseconds": 10 ** 6})


# TimestampWithTimezone


def test_timestampwithtimezone():
    ts = Timestamp(seconds=0, microseconds=0)
    tstz = TimestampWithTimezone(timestamp=ts, offset=0, negative_utc=False)
    attr.validate(tstz)
    assert tstz.negative_utc is False

    attr.validate(TimestampWithTimezone(timestamp=ts, offset=10, negative_utc=False))

    attr.validate(TimestampWithTimezone(timestamp=ts, offset=-10, negative_utc=False))

    tstz = TimestampWithTimezone(timestamp=ts, offset=0, negative_utc=True)
    attr.validate(tstz)
    assert tstz.negative_utc is True

    with pytest.raises(AttributeTypeError):
        TimestampWithTimezone(
            timestamp=datetime.datetime.now(), offset=0, negative_utc=False
        )

    with pytest.raises(AttributeTypeError):
        TimestampWithTimezone(timestamp=ts, offset="0", negative_utc=False)

    with pytest.raises(AttributeTypeError):
        TimestampWithTimezone(timestamp=ts, offset=1.0, negative_utc=False)

    with pytest.raises(AttributeTypeError):
        TimestampWithTimezone(timestamp=ts, offset=1, negative_utc=0)

    with pytest.raises(ValueError):
        TimestampWithTimezone(timestamp=ts, offset=1, negative_utc=True)

    with pytest.raises(ValueError):
        TimestampWithTimezone(timestamp=ts, offset=-1, negative_utc=True)


def test_timestampwithtimezone_from_datetime():
    tz = datetime.timezone(datetime.timedelta(minutes=+60))
    date = datetime.datetime(2020, 2, 27, 14, 39, 19, tzinfo=tz)

    tstz = TimestampWithTimezone.from_datetime(date)

    assert tstz == TimestampWithTimezone(
        timestamp=Timestamp(seconds=1582810759, microseconds=0,),
        offset=60,
        negative_utc=False,
    )


def test_timestampwithtimezone_from_iso8601():
    date = "2020-02-27 14:39:19.123456+0100"

    tstz = TimestampWithTimezone.from_iso8601(date)

    assert tstz == TimestampWithTimezone(
        timestamp=Timestamp(seconds=1582810759, microseconds=123456,),
        offset=60,
        negative_utc=False,
    )


def test_timestampwithtimezone_from_iso8601_negative_utc():
    date = "2020-02-27 13:39:19-0000"

    tstz = TimestampWithTimezone.from_iso8601(date)

    assert tstz == TimestampWithTimezone(
        timestamp=Timestamp(seconds=1582810759, microseconds=0,),
        offset=0,
        negative_utc=True,
    )


def test_person_from_fullname():
    """The author should have name, email and fullname filled.

    """
    actual_person = Person.from_fullname(b"tony <ynot@dagobah>")
    assert actual_person == Person(
        fullname=b"tony <ynot@dagobah>", name=b"tony", email=b"ynot@dagobah",
    )


def test_person_from_fullname_no_email():
    """The author and fullname should be the same as the input (author).

    """
    actual_person = Person.from_fullname(b"tony")
    assert actual_person == Person(fullname=b"tony", name=b"tony", email=None,)


def test_person_from_fullname_empty_person():
    """Empty person has only its fullname filled with the empty
    byte-string.

    """
    actual_person = Person.from_fullname(b"")
    assert actual_person == Person(fullname=b"", name=None, email=None,)


def test_git_author_line_to_author():
    # edge case out of the way
    with pytest.raises(TypeError):
        Person.from_fullname(None)

    tests = {
        b"a <b@c.com>": Person(name=b"a", email=b"b@c.com", fullname=b"a <b@c.com>",),
        b"<foo@bar.com>": Person(
            name=None, email=b"foo@bar.com", fullname=b"<foo@bar.com>",
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
            name=b"trailing", email=b"sp@c.e", fullname=b"trailing <sp@c.e> ",
        ),
        b"no<sp@c.e>": Person(name=b"no", email=b"sp@c.e", fullname=b"no<sp@c.e>",),
        b" more   <sp@c.es>": Person(
            name=b"more", email=b"sp@c.es", fullname=b" more   <sp@c.es>",
        ),
        b" <>": Person(name=None, email=None, fullname=b" <>",),
    }

    for person in sorted(tests):
        expected_person = tests[person]
        assert expected_person == Person.from_fullname(person)


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
    c = Content.from_dict(content_d)
    assert c.ctime == n


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


# ID computation


def test_directory_model_id_computation():
    dir_dict = directory_example.copy()
    del dir_dict["id"]

    dir_id = hash_to_bytes(directory_identifier(dir_dict))
    dir_model = Directory.from_dict(dir_dict)
    assert dir_model.id == dir_id


def test_revision_model_id_computation():
    rev_dict = revision_example.copy()
    del rev_dict["id"]

    rev_id = hash_to_bytes(revision_identifier(rev_dict))
    rev_model = Revision.from_dict(rev_dict)
    assert rev_model.id == rev_id


def test_revision_model_id_computation_with_no_date():
    """We can have revision with date to None

    """
    rev_dict = revision_example.copy()
    rev_dict["date"] = None
    rev_dict["committer_date"] = None
    del rev_dict["id"]

    rev_id = hash_to_bytes(revision_identifier(rev_dict))
    rev_model = Revision.from_dict(rev_dict)
    assert rev_model.date is None
    assert rev_model.committer_date is None
    assert rev_model.id == rev_id


def test_release_model_id_computation():
    rel_dict = release_example.copy()
    del rel_dict["id"]

    rel_id = hash_to_bytes(release_identifier(rel_dict))
    rel_model = Release.from_dict(rel_dict)
    assert isinstance(rel_model.date, TimestampWithTimezone)
    assert rel_model.id == hash_to_bytes(rel_id)


def test_snapshot_model_id_computation():
    snp_dict = snapshot_example.copy()
    del snp_dict["id"]

    snp_id = hash_to_bytes(snapshot_identifier(snp_dict))
    snp_model = Snapshot.from_dict(snp_dict)
    assert snp_model.id == snp_id


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
