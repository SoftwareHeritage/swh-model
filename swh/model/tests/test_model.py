# Copyright (C) 2019 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import copy
import datetime

from hypothesis import given
from hypothesis.strategies import binary
import pytest

from swh.model.model import (
    Content, SkippedContent, Directory, Revision, Release, Snapshot,
    Timestamp, TimestampWithTimezone,
    MissingData, Person
)
from swh.model.hashutil import hash_to_bytes, MultiHash
from swh.model.hypothesis_strategies import objects, origins, origin_visits
from swh.model.identifiers import (
    directory_identifier, revision_identifier, release_identifier,
    snapshot_identifier
)
from swh.model.tests.test_identifiers import (
    directory_example, revision_example, release_example, snapshot_example
)


@given(objects())
def test_todict_inverse_fromdict(objtype_and_obj):
    (obj_type, obj) = objtype_and_obj

    if obj_type in ('origin', 'origin_visit'):
        return

    obj_as_dict = obj.to_dict()
    obj_as_dict_copy = copy.deepcopy(obj_as_dict)

    # Check the composition of to_dict and from_dict is the identity
    assert obj == type(obj).from_dict(obj_as_dict)

    # Check from_dict() does not change the input dict
    assert obj_as_dict == obj_as_dict_copy

    # Check the composition of from_dict and to_dict is the identity
    assert obj_as_dict == type(obj).from_dict(obj_as_dict).to_dict()


@given(origins())
def test_todict_origins(origin):
    obj = origin.to_dict()

    assert 'type' not in obj
    assert type(origin)(url=origin.url) == type(origin).from_dict(obj)


@given(origin_visits())
def test_todict_origin_visits(origin_visit):
    obj = origin_visit.to_dict()

    assert origin_visit == type(origin_visit).from_dict(obj)


def test_timestampwithtimezone_from_datetime():
    tz = datetime.timezone(datetime.timedelta(minutes=+60))
    date = datetime.datetime(
        2020, 2, 27, 14, 39, 19, tzinfo=tz)

    tstz = TimestampWithTimezone.from_datetime(date)

    assert tstz == TimestampWithTimezone(
        timestamp=Timestamp(
            seconds=1582810759,
            microseconds=0,
        ),
        offset=60,
        negative_utc=False,
    )


def test_timestampwithtimezone_from_iso8601():
    date = '2020-02-27 14:39:19.123456+0100'

    tstz = TimestampWithTimezone.from_iso8601(date)

    assert tstz == TimestampWithTimezone(
        timestamp=Timestamp(
            seconds=1582810759,
            microseconds=123456,
        ),
        offset=60,
        negative_utc=False,
    )


def test_timestampwithtimezone_from_iso8601_negative_utc():
    date = '2020-02-27 13:39:19-0000'

    tstz = TimestampWithTimezone.from_iso8601(date)

    assert tstz == TimestampWithTimezone(
        timestamp=Timestamp(
            seconds=1582810759,
            microseconds=0,
        ),
        offset=0,
        negative_utc=True,
    )


def test_person_from_fullname():
    """The author should have name, email and fullname filled.

    """
    actual_person = Person.from_fullname(b'tony <ynot@dagobah>')
    assert actual_person == Person(
        fullname=b'tony <ynot@dagobah>',
        name=b'tony',
        email=b'ynot@dagobah',
    )


def test_person_from_fullname_no_email():
    """The author and fullname should be the same as the input (author).

    """
    actual_person = Person.from_fullname(b'tony')
    assert actual_person == Person(
        fullname=b'tony',
        name=b'tony',
        email=None,
    )


def test_person_from_fullname_empty_person():
    """Empty person has only its fullname filled with the empty
    byte-string.

    """
    actual_person = Person.from_fullname(b'')
    assert actual_person == Person(
        fullname=b'',
        name=None,
        email=None,
    )


def test_git_author_line_to_author():
    # edge case out of the way
    with pytest.raises(TypeError):
        Person.from_fullname(None)

    tests = {
        b'a <b@c.com>': Person(
            name=b'a',
            email=b'b@c.com',
            fullname=b'a <b@c.com>',
        ),
        b'<foo@bar.com>': Person(
            name=None,
            email=b'foo@bar.com',
            fullname=b'<foo@bar.com>',
        ),
        b'malformed <email': Person(
            name=b'malformed',
            email=b'email',
            fullname=b'malformed <email'
        ),
        b'malformed <"<br"@ckets>': Person(
            name=b'malformed',
            email=b'"<br"@ckets',
            fullname=b'malformed <"<br"@ckets>',
        ),
        b'trailing <sp@c.e> ': Person(
            name=b'trailing',
            email=b'sp@c.e',
            fullname=b'trailing <sp@c.e> ',
        ),
        b'no<sp@c.e>': Person(
            name=b'no',
            email=b'sp@c.e',
            fullname=b'no<sp@c.e>',
        ),
        b' more   <sp@c.es>': Person(
            name=b'more',
            email=b'sp@c.es',
            fullname=b' more   <sp@c.es>',
        ),
        b' <>': Person(
            name=None,
            email=None,
            fullname=b' <>',
        ),
    }

    for person in sorted(tests):
        expected_person = tests[person]
        assert expected_person == Person.from_fullname(person)


def test_content_get_hash():
    hashes = dict(
        sha1=b'foo', sha1_git=b'bar', sha256=b'baz', blake2s256=b'qux')
    c = Content(length=42, status='visible', **hashes)
    for (hash_name, hash_) in hashes.items():
        assert c.get_hash(hash_name) == hash_


def test_content_hashes():
    hashes = dict(
        sha1=b'foo', sha1_git=b'bar', sha256=b'baz', blake2s256=b'qux')
    c = Content(length=42, status='visible', **hashes)
    assert c.hashes() == hashes


def test_content_data():
    c = Content(
        length=42, status='visible', data=b'foo',
        sha1=b'foo', sha1_git=b'bar', sha256=b'baz', blake2s256=b'qux')
    assert c.with_data() == c


def test_content_data_missing():
    c = Content(
        length=42, status='visible',
        sha1=b'foo', sha1_git=b'bar', sha256=b'baz', blake2s256=b'qux')
    with pytest.raises(MissingData):
        c.with_data()


@given(binary(max_size=4096))
def test_content_from_data(data):
    c = Content.from_data(data)
    assert c.data == data
    assert c.length == len(data)
    assert c.status == 'visible'
    for key, value in MultiHash.from_data(data).digest().items():
        assert getattr(c, key) == value


@given(binary(max_size=4096))
def test_hidden_content_from_data(data):
    c = Content.from_data(data, status='hidden')
    assert c.data == data
    assert c.length == len(data)
    assert c.status == 'hidden'
    for key, value in MultiHash.from_data(data).digest().items():
        assert getattr(c, key) == value


@given(binary(max_size=4096))
def test_skipped_content_from_data(data):
    c = SkippedContent.from_data(data, reason='reason')
    assert c.reason == 'reason'
    assert c.length == len(data)
    assert c.status == 'absent'
    for key, value in MultiHash.from_data(data).digest().items():
        assert getattr(c, key) == value


def test_directory_model_id_computation():
    dir_dict = directory_example.copy()
    del dir_dict['id']

    dir_id = hash_to_bytes(directory_identifier(dir_dict))
    for dir_model in [Directory(**dir_dict), Directory.from_dict(dir_dict)]:
        assert dir_model.id == dir_id


def test_revision_model_id_computation():
    rev_dict = revision_example.copy()
    del rev_dict['id']

    rev_id = hash_to_bytes(revision_identifier(rev_dict))
    for rev_model in [Revision(**rev_dict), Revision.from_dict(rev_dict)]:
        assert rev_model.id == rev_id


def test_revision_model_id_computation_with_no_date():
    """We can have revision with date to None

    """
    rev_dict = revision_example.copy()
    rev_dict['date'] = None
    rev_dict['committer_date'] = None
    del rev_dict['id']

    rev_id = hash_to_bytes(revision_identifier(rev_dict))
    for rev_model in [Revision(**rev_dict), Revision.from_dict(rev_dict)]:
        assert rev_model.date is None
        assert rev_model.committer_date is None
        assert rev_model.id == rev_id


def test_release_model_id_computation():
    rel_dict = release_example.copy()
    del rel_dict['id']

    rel_id = hash_to_bytes(release_identifier(rel_dict))
    for rel_model in [Release(**rel_dict), Release.from_dict(rel_dict)]:
        assert rel_model.id == hash_to_bytes(rel_id)


def test_snapshot_model_id_computation():
    snp_dict = snapshot_example.copy()
    del snp_dict['id']

    snp_id = hash_to_bytes(snapshot_identifier(snp_dict))
    for snp_model in [Snapshot(**snp_dict), Snapshot.from_dict(snp_dict)]:
        assert snp_model.id == snp_id
