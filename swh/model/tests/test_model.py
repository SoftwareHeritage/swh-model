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
    RawExtrinsicMetadata,
    MetadataTargetType,
    MetadataAuthority,
    MetadataAuthorityType,
    MetadataFetcher,
)
from swh.model.hashutil import hash_to_bytes, MultiHash
import swh.model.hypothesis_strategies as strategies
from swh.model.identifiers import (
    directory_identifier,
    revision_identifier,
    release_identifier,
    snapshot_identifier,
    parse_swhid,
    SWHID,
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


# Revision


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


_metadata_authority = MetadataAuthority(
    type=MetadataAuthorityType.FORGE, url="https://forge.softwareheritage.org",
)
_metadata_fetcher = MetadataFetcher(name="test-fetcher", version="0.0.1",)
_content_swhid = parse_swhid("swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2")
_origin_url = "https://forge.softwareheritage.org/source/swh-model.git"
_common_metadata_fields = dict(
    discovery_date=datetime.datetime.now(),
    authority=_metadata_authority,
    fetcher=_metadata_fetcher,
    format="json",
    metadata=b'{"foo": "bar"}',
)


def test_metadata_valid():
    """Checks valid RawExtrinsicMetadata objects don't raise an error."""

    # Simplest case
    RawExtrinsicMetadata(
        type=MetadataTargetType.ORIGIN, id=_origin_url, **_common_metadata_fields
    )

    # Object with an SWHID
    RawExtrinsicMetadata(
        type=MetadataTargetType.CONTENT, id=_content_swhid, **_common_metadata_fields
    )


def test_metadata_to_dict():
    """Checks valid RawExtrinsicMetadata objects don't raise an error."""

    common_fields = {
        "authority": {"type": "forge", "url": "https://forge.softwareheritage.org",},
        "fetcher": {"name": "test-fetcher", "version": "0.0.1",},
        "discovery_date": _common_metadata_fields["discovery_date"],
        "format": "json",
        "metadata": b'{"foo": "bar"}',
    }

    m = RawExtrinsicMetadata(
        type=MetadataTargetType.ORIGIN, id=_origin_url, **_common_metadata_fields
    )
    assert m.to_dict() == {
        "type": "origin",
        "id": _origin_url,
        **common_fields,
    }
    assert RawExtrinsicMetadata.from_dict(m.to_dict()) == m

    m = RawExtrinsicMetadata(
        type=MetadataTargetType.CONTENT, id=_content_swhid, **_common_metadata_fields
    )
    assert m.to_dict() == {
        "type": "content",
        "id": "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2",
        **common_fields,
    }
    assert RawExtrinsicMetadata.from_dict(m.to_dict()) == m


def test_metadata_invalid_id():
    """Checks various invalid values for the 'id' field."""

    # SWHID for an origin
    with pytest.raises(ValueError, match="expected an URL"):
        RawExtrinsicMetadata(
            type=MetadataTargetType.ORIGIN, id=_content_swhid, **_common_metadata_fields
        )

    # SWHID for an origin (even when passed as string)
    with pytest.raises(ValueError, match="expected an URL"):
        RawExtrinsicMetadata(
            type=MetadataTargetType.ORIGIN,
            id="swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2",
            **_common_metadata_fields,
        )

    # URL for a non-origin
    with pytest.raises(ValueError, match="Expected SWHID, got a string"):
        RawExtrinsicMetadata(
            type=MetadataTargetType.CONTENT, id=_origin_url, **_common_metadata_fields
        )

    # SWHID passed as string instead of SWHID
    with pytest.raises(ValueError, match="Expected SWHID, got a string"):
        RawExtrinsicMetadata(
            type=MetadataTargetType.CONTENT,
            id="swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2",
            **_common_metadata_fields,
        )

    # Object type does not match the SWHID
    with pytest.raises(
        ValueError, match="Expected SWHID type 'revision', got 'content'"
    ):
        RawExtrinsicMetadata(
            type=MetadataTargetType.REVISION,
            id=_content_swhid,
            **_common_metadata_fields,
        )

    # Non-core SWHID
    with pytest.raises(ValueError, match="Expected core SWHID"):
        RawExtrinsicMetadata(
            type=MetadataTargetType.CONTENT,
            id=SWHID(
                object_type="content",
                object_id="94a9ed024d3859793618152ea559a168bbcbb5e2",
                metadata={"foo": "bar"},
            ),
            **_common_metadata_fields,
        )


def test_metadata_validate_context_origin():
    """Checks validation of RawExtrinsicMetadata.origin."""

    # Origins can't have an 'origin' context
    with pytest.raises(
        ValueError, match="Unexpected 'origin' context for origin object"
    ):
        RawExtrinsicMetadata(
            type=MetadataTargetType.ORIGIN,
            id=_origin_url,
            origin=_origin_url,
            **_common_metadata_fields,
        )

    # but all other types can
    RawExtrinsicMetadata(
        type=MetadataTargetType.CONTENT,
        id=_content_swhid,
        origin=_origin_url,
        **_common_metadata_fields,
    )

    # SWHIDs aren't valid origin URLs
    with pytest.raises(ValueError, match="SWHID used as context origin URL"):
        RawExtrinsicMetadata(
            type=MetadataTargetType.CONTENT,
            id=_content_swhid,
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
            type=MetadataTargetType.ORIGIN,
            id=_origin_url,
            visit=42,
            **_common_metadata_fields,
        )

    # but all other types can
    RawExtrinsicMetadata(
        type=MetadataTargetType.CONTENT,
        id=_content_swhid,
        origin=_origin_url,
        visit=42,
        **_common_metadata_fields,
    )

    # Missing 'origin'
    with pytest.raises(ValueError, match="'origin' context must be set if 'visit' is"):
        RawExtrinsicMetadata(
            type=MetadataTargetType.CONTENT,
            id=_content_swhid,
            visit=42,
            **_common_metadata_fields,
        )

    # visit id must be positive
    with pytest.raises(ValueError, match="Nonpositive visit id"):
        RawExtrinsicMetadata(
            type=MetadataTargetType.CONTENT,
            id=_content_swhid,
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
            type=MetadataTargetType.ORIGIN,
            id=_origin_url,
            snapshot=SWHID(
                object_type="snapshot",
                object_id="94a9ed024d3859793618152ea559a168bbcbb5e2",
            ),
            **_common_metadata_fields,
        )

    # but content can
    RawExtrinsicMetadata(
        type=MetadataTargetType.CONTENT,
        id=_content_swhid,
        snapshot=SWHID(
            object_type="snapshot", object_id="94a9ed024d3859793618152ea559a168bbcbb5e2"
        ),
        **_common_metadata_fields,
    )

    # Non-core SWHID
    with pytest.raises(ValueError, match="Expected core SWHID"):
        RawExtrinsicMetadata(
            type=MetadataTargetType.CONTENT,
            id=_content_swhid,
            snapshot=SWHID(
                object_type="snapshot",
                object_id="94a9ed024d3859793618152ea559a168bbcbb5e2",
                metadata={"foo": "bar"},
            ),
            **_common_metadata_fields,
        )

    # SWHID type doesn't match the expected type of this context key
    with pytest.raises(
        ValueError, match="Expected SWHID type 'snapshot', got 'content'"
    ):
        RawExtrinsicMetadata(
            type=MetadataTargetType.CONTENT,
            id=_content_swhid,
            snapshot=SWHID(
                object_type="content",
                object_id="94a9ed024d3859793618152ea559a168bbcbb5e2",
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
            type=MetadataTargetType.ORIGIN,
            id=_origin_url,
            release=SWHID(
                object_type="release",
                object_id="94a9ed024d3859793618152ea559a168bbcbb5e2",
            ),
            **_common_metadata_fields,
        )

    # but content can
    RawExtrinsicMetadata(
        type=MetadataTargetType.CONTENT,
        id=_content_swhid,
        release=SWHID(
            object_type="release", object_id="94a9ed024d3859793618152ea559a168bbcbb5e2"
        ),
        **_common_metadata_fields,
    )

    # Non-core SWHID
    with pytest.raises(ValueError, match="Expected core SWHID"):
        RawExtrinsicMetadata(
            type=MetadataTargetType.CONTENT,
            id=_content_swhid,
            release=SWHID(
                object_type="release",
                object_id="94a9ed024d3859793618152ea559a168bbcbb5e2",
                metadata={"foo": "bar"},
            ),
            **_common_metadata_fields,
        )

    # SWHID type doesn't match the expected type of this context key
    with pytest.raises(
        ValueError, match="Expected SWHID type 'release', got 'content'"
    ):
        RawExtrinsicMetadata(
            type=MetadataTargetType.CONTENT,
            id=_content_swhid,
            release=SWHID(
                object_type="content",
                object_id="94a9ed024d3859793618152ea559a168bbcbb5e2",
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
            type=MetadataTargetType.ORIGIN,
            id=_origin_url,
            revision=SWHID(
                object_type="revision",
                object_id="94a9ed024d3859793618152ea559a168bbcbb5e2",
            ),
            **_common_metadata_fields,
        )

    # but content can
    RawExtrinsicMetadata(
        type=MetadataTargetType.CONTENT,
        id=_content_swhid,
        revision=SWHID(
            object_type="revision", object_id="94a9ed024d3859793618152ea559a168bbcbb5e2"
        ),
        **_common_metadata_fields,
    )

    # Non-core SWHID
    with pytest.raises(ValueError, match="Expected core SWHID"):
        RawExtrinsicMetadata(
            type=MetadataTargetType.CONTENT,
            id=_content_swhid,
            revision=SWHID(
                object_type="revision",
                object_id="94a9ed024d3859793618152ea559a168bbcbb5e2",
                metadata={"foo": "bar"},
            ),
            **_common_metadata_fields,
        )

    # SWHID type doesn't match the expected type of this context key
    with pytest.raises(
        ValueError, match="Expected SWHID type 'revision', got 'content'"
    ):
        RawExtrinsicMetadata(
            type=MetadataTargetType.CONTENT,
            id=_content_swhid,
            revision=SWHID(
                object_type="content",
                object_id="94a9ed024d3859793618152ea559a168bbcbb5e2",
            ),
            **_common_metadata_fields,
        )


def test_metadata_validate_context_path():
    """Checks validation of RawExtrinsicMetadata.path."""

    # Origins can't have a 'path' context
    with pytest.raises(ValueError, match="Unexpected 'path' context for origin object"):
        RawExtrinsicMetadata(
            type=MetadataTargetType.ORIGIN,
            id=_origin_url,
            path=b"/foo/bar",
            **_common_metadata_fields,
        )

    # but content can
    RawExtrinsicMetadata(
        type=MetadataTargetType.CONTENT,
        id=_content_swhid,
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
            type=MetadataTargetType.ORIGIN,
            id=_origin_url,
            directory=SWHID(
                object_type="directory",
                object_id="94a9ed024d3859793618152ea559a168bbcbb5e2",
            ),
            **_common_metadata_fields,
        )

    # but content can
    RawExtrinsicMetadata(
        type=MetadataTargetType.CONTENT,
        id=_content_swhid,
        directory=SWHID(
            object_type="directory",
            object_id="94a9ed024d3859793618152ea559a168bbcbb5e2",
        ),
        **_common_metadata_fields,
    )

    # Non-core SWHID
    with pytest.raises(ValueError, match="Expected core SWHID"):
        RawExtrinsicMetadata(
            type=MetadataTargetType.CONTENT,
            id=_content_swhid,
            directory=SWHID(
                object_type="directory",
                object_id="94a9ed024d3859793618152ea559a168bbcbb5e2",
                metadata={"foo": "bar"},
            ),
            **_common_metadata_fields,
        )

    # SWHID type doesn't match the expected type of this context key
    with pytest.raises(
        ValueError, match="Expected SWHID type 'directory', got 'content'"
    ):
        RawExtrinsicMetadata(
            type=MetadataTargetType.CONTENT,
            id=_content_swhid,
            directory=SWHID(
                object_type="content",
                object_id="94a9ed024d3859793618152ea559a168bbcbb5e2",
            ),
            **_common_metadata_fields,
        )
