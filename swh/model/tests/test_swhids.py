# Copyright (C) 2015-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import itertools

import attr
import pytest

from swh.model.exceptions import ValidationError
from swh.model.hashutil import hash_to_bytes as _x
from swh.model.swhids import (
    SWHID_QUALIFIERS,
    CoreSWHID,
    ExtendedObjectType,
    ExtendedSWHID,
    ObjectType,
    QualifiedSWHID,
)

dummy_qualifiers = {"origin": "https://example.com", "lines": "42"}


# SWHIDs that are outright invalid, no matter the context
INVALID_SWHIDS = [
    "swh:1:cnt",
    "swh:1:",
    "swh:",
    "swh:1:cnt:",
    "foo:1:cnt:abc8bc9d7a6bcf6db04f476d29314f157507d505",
    "swh:2:dir:def8bc9d7a6bcf6db04f476d29314f157507d505",
    "swh:1:foo:fed8bc9d7a6bcf6db04f476d29314f157507d505",
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;invalid;malformed",
    "swh:1:snp:gh6959356d30f1a4e9b7f6bca59b9a336464c03d",
    "swh:1:snp:foo",
    # wrong qualifier: ori should be origin
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;ori=something;anchor=1;visit=1;path=/",  # noqa
    # wrong qualifier: anc should be anchor
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=something;anc=1;visit=1;path=/",  # noqa
    # wrong qualifier: vis should be visit
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=something;anchor=1;vis=1;path=/",  # noqa
    # wrong qualifier: pa should be path
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=something;anchor=1;visit=1;pa=/",  # noqa
    # wrong qualifier: line should be lines
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;line=10;origin=something;anchor=1;visit=1;path=/",  # noqa
    # wrong qualifier value: it contains space before of after
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=  https://some-url",  # noqa
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=something;anchor=some-anchor    ",  # noqa
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=something;anchor=some-anchor    ;visit=1",  # noqa
    # invalid swhid: whitespaces
    "swh :1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;ori=something;anchor=1;visit=1;path=/",  # noqa
    "swh: 1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;ori=something;anchor=1;visit=1;path=/",  # noqa
    "swh: 1: dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;ori=something;anchor=1;visit=1;path=/",  # noqa
    "swh:1: dir: 0b6959356d30f1a4e9b7f6bca59b9a336464c03d",
    "swh:1: dir: 0b6959356d30f1a4e9b7f6bca59b9a336464c03d; origin=blah",
    "swh:1: dir: 0b6959356d30f1a4e9b7f6bca59b9a336464c03d;lines=12",
    # other whitespaces
    "swh\t:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;lines=12",
    "swh:1\n:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;lines=12",
    "swh:1:\rdir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;lines=12",
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d\f;lines=12",
    "swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;lines=12\v",
]

SWHID_CLASSES = [CoreSWHID, QualifiedSWHID, ExtendedSWHID]


@pytest.mark.parametrize(
    "invalid_swhid,swhid_class", itertools.product(INVALID_SWHIDS, SWHID_CLASSES)
)
def test_swhid_parsing_error(invalid_swhid, swhid_class):
    """Tests SWHID strings that are invalid for all SWHID classes do raise
    a ValidationError"""
    with pytest.raises(ValidationError):
        swhid_class.from_string(invalid_swhid)


# string SWHIDs, and how they should be parsed by each of the classes,
# or None if the class does not support it
HASH = "94a9ed024d3859793618152ea559a168bbcbb5e2"
VALID_SWHIDS = [
    (
        f"swh:1:cnt:{HASH}",
        CoreSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
        ),
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
        ),
        ExtendedSWHID(
            object_type=ExtendedObjectType.CONTENT,
            object_id=_x(HASH),
        ),
    ),
    (
        f"swh:1:dir:{HASH}",
        CoreSWHID(
            object_type=ObjectType.DIRECTORY,
            object_id=_x(HASH),
        ),
        QualifiedSWHID(
            object_type=ObjectType.DIRECTORY,
            object_id=_x(HASH),
        ),
        ExtendedSWHID(
            object_type=ExtendedObjectType.DIRECTORY,
            object_id=_x(HASH),
        ),
    ),
    (
        f"swh:1:rev:{HASH}",
        CoreSWHID(
            object_type=ObjectType.REVISION,
            object_id=_x(HASH),
        ),
        QualifiedSWHID(
            object_type=ObjectType.REVISION,
            object_id=_x(HASH),
        ),
        ExtendedSWHID(
            object_type=ExtendedObjectType.REVISION,
            object_id=_x(HASH),
        ),
    ),
    (
        f"swh:1:rel:{HASH}",
        CoreSWHID(
            object_type=ObjectType.RELEASE,
            object_id=_x(HASH),
        ),
        QualifiedSWHID(
            object_type=ObjectType.RELEASE,
            object_id=_x(HASH),
        ),
        ExtendedSWHID(
            object_type=ExtendedObjectType.RELEASE,
            object_id=_x(HASH),
        ),
    ),
    (
        f"swh:1:snp:{HASH}",
        CoreSWHID(
            object_type=ObjectType.SNAPSHOT,
            object_id=_x(HASH),
        ),
        QualifiedSWHID(
            object_type=ObjectType.SNAPSHOT,
            object_id=_x(HASH),
        ),
        ExtendedSWHID(
            object_type=ExtendedObjectType.SNAPSHOT,
            object_id=_x(HASH),
        ),
    ),
    (
        f"swh:1:cnt:{HASH};origin=https://github.com/python/cpython;lines=1-18",
        None,  # CoreSWHID does not allow qualifiers
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
            origin="https://github.com/python/cpython",
            lines=(1, 18),
        ),
        None,  # Neither does ExtendedSWHID
    ),
    (
        f"swh:1:cnt:{HASH};origin=https://github.com/python/cpython;lines=1-18/",
        None,  # likewise
        None,
        None,  # likewise
    ),
    (
        f"swh:1:cnt:{HASH};origin=https://github.com/python/cpython;lines=18",
        None,  # likewise
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
            origin="https://github.com/python/cpython",
            lines=(18, None),
        ),
        None,  # likewise
    ),
    (
        f"swh:1:dir:{HASH};origin=deb://Debian/packages/linuxdoc-tools",
        None,  # likewise
        QualifiedSWHID(
            object_type=ObjectType.DIRECTORY,
            object_id=_x(HASH),
            origin="deb://Debian/packages/linuxdoc-tools",
        ),
        None,  # likewise
    ),
    (
        f"swh:1:ori:{HASH}",
        None,  # CoreSWHID does not allow origin pseudo-SWHIDs
        None,  # Neither does QualifiedSWHID
        ExtendedSWHID(
            object_type=ExtendedObjectType.ORIGIN,
            object_id=_x(HASH),
        ),
    ),
    (
        f"swh:1:emd:{HASH}",
        None,  # likewise for metadata pseudo-SWHIDs
        None,  # Neither does QualifiedSWHID
        ExtendedSWHID(
            object_type=ExtendedObjectType.RAW_EXTRINSIC_METADATA,
            object_id=_x(HASH),
        ),
    ),
    (
        f"swh:1:emd:{HASH};origin=https://github.com/python/cpython",
        None,  # CoreSWHID does not allow metadata pseudo-SWHIDs or qualifiers
        None,  # QualifiedSWHID does not allow metadata pseudo-SWHIDs
        None,  # ExtendedSWHID does not allow qualifiers
    ),
]


@pytest.mark.parametrize(
    "string,core,qualified,extended",
    [
        pytest.param(string, core, qualified, extended, id=string)
        for (string, core, qualified, extended) in VALID_SWHIDS
    ],
)
def test_parse_unparse_swhids(string, core, qualified, extended):
    """Tests parsing and serializing valid SWHIDs with the various SWHID classes."""
    classes = [CoreSWHID, QualifiedSWHID, ExtendedSWHID]
    for (cls, parsed_swhid) in zip(classes, [core, qualified, extended]):
        if parsed_swhid is None:
            # This class should not accept this SWHID
            with pytest.raises(ValidationError) as excinfo:
                cls.from_string(string)
            # Check string serialization for exception
            assert str(excinfo.value) is not None
        else:
            # This class should
            assert cls.from_string(string) == parsed_swhid

            # Also check serialization
            assert string == str(parsed_swhid)


@pytest.mark.parametrize(
    "core,extended",
    [
        pytest.param(core, extended, id=string)
        for (string, core, qualified, extended) in VALID_SWHIDS
        if core is not None
    ],
)
def test_core_to_extended(core, extended):
    assert core.to_extended() == extended


@pytest.mark.parametrize(
    "ns,version,type,id,qualifiers",
    [
        ("foo", 1, ObjectType.CONTENT, "abc8bc9d7a6bcf6db04f476d29314f157507d505", {}),
        ("swh", 2, ObjectType.CONTENT, "def8bc9d7a6bcf6db04f476d29314f157507d505", {}),
        ("swh", 1, ObjectType.DIRECTORY, "aaaa", {}),
    ],
)
def test_QualifiedSWHID_validation_error(ns, version, type, id, qualifiers):
    with pytest.raises(ValidationError):
        QualifiedSWHID(
            namespace=ns,
            scheme_version=version,
            object_type=type,
            object_id=_x(id),
            **qualifiers,
        )


@pytest.mark.parametrize(
    "object_type,qualifiers,expected",
    [
        # No qualifier:
        (ObjectType.CONTENT, {}, f"swh:1:cnt:{HASH}"),
        # origin:
        (ObjectType.CONTENT, {"origin": None}, f"swh:1:cnt:{HASH}"),
        (ObjectType.CONTENT, {"origin": 42}, ValueError),
        # visit:
        (
            ObjectType.CONTENT,
            {"visit": f"swh:1:snp:{HASH}"},
            f"swh:1:cnt:{HASH};visit=swh:1:snp:{HASH}",
        ),
        (
            ObjectType.CONTENT,
            {"visit": CoreSWHID(object_type=ObjectType.SNAPSHOT, object_id=_x(HASH))},
            f"swh:1:cnt:{HASH};visit=swh:1:snp:{HASH}",
        ),
        (ObjectType.CONTENT, {"visit": 42}, TypeError),
        (
            ObjectType.CONTENT,
            {"visit": f"swh:1:rel:{HASH}"},
            ValidationError,
        ),
        (
            ObjectType.CONTENT,
            {"visit": CoreSWHID(object_type=ObjectType.RELEASE, object_id=_x(HASH))},
            ValidationError,
        ),
        # anchor:
        (
            ObjectType.CONTENT,
            {"anchor": f"swh:1:snp:{HASH}"},
            f"swh:1:cnt:{HASH};anchor=swh:1:snp:{HASH}",
        ),
        (
            ObjectType.CONTENT,
            {"anchor": CoreSWHID(object_type=ObjectType.SNAPSHOT, object_id=_x(HASH))},
            f"swh:1:cnt:{HASH};anchor=swh:1:snp:{HASH}",
        ),
        (
            ObjectType.CONTENT,
            {"anchor": f"swh:1:dir:{HASH}"},
            f"swh:1:cnt:{HASH};anchor=swh:1:dir:{HASH}",
        ),
        (
            ObjectType.CONTENT,
            {"anchor": CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=_x(HASH))},
            f"swh:1:cnt:{HASH};anchor=swh:1:dir:{HASH}",
        ),
        (ObjectType.CONTENT, {"anchor": 42}, TypeError),
        (
            ObjectType.CONTENT,
            {"anchor": f"swh:1:cnt:{HASH}"},
            ValidationError,
        ),
        (
            ObjectType.CONTENT,
            {"anchor": CoreSWHID(object_type=ObjectType.CONTENT, object_id=_x(HASH))},
            ValidationError,
        ),
        # path:
        (
            ObjectType.CONTENT,
            {"path": b"/foo"},
            f"swh:1:cnt:{HASH};path=/foo",
        ),
        (
            ObjectType.CONTENT,
            {"path": b"/foo;bar"},
            f"swh:1:cnt:{HASH};path=/foo%3Bbar",
        ),
        (
            ObjectType.CONTENT,
            {"path": "/foo"},
            f"swh:1:cnt:{HASH};path=/foo",
        ),
        (
            ObjectType.CONTENT,
            {"path": "/foo;bar"},
            f"swh:1:cnt:{HASH};path=/foo%3Bbar",
        ),
        (ObjectType.CONTENT, {"path": 42}, Exception),
        # lines:
        (
            ObjectType.CONTENT,
            {"lines": (42, None)},
            f"swh:1:cnt:{HASH};lines=42",
        ),
        (
            ObjectType.CONTENT,
            {"lines": (21, 42)},
            f"swh:1:cnt:{HASH};lines=21-42",
        ),
        (
            ObjectType.CONTENT,
            {"lines": 42},
            TypeError,
        ),
        (
            ObjectType.CONTENT,
            {"lines": (None, 42)},
            ValueError,
        ),
        (
            ObjectType.CONTENT,
            {"lines": ("42", None)},
            ValueError,
        ),
    ],
)
def test_QualifiedSWHID_init(object_type, qualifiers, expected):
    """Tests validation and converters of qualifiers"""
    if isinstance(expected, type):
        assert issubclass(expected, Exception)
        with pytest.raises(expected):
            QualifiedSWHID(object_type=object_type, object_id=_x(HASH), **qualifiers)
    else:
        assert isinstance(expected, str)
        swhid = QualifiedSWHID(
            object_type=object_type, object_id=_x(HASH), **qualifiers
        )

        # Check the build object has the right serialization
        assert expected == str(swhid)

        # Check the internal state of the object is the same as if parsed from a string
        assert QualifiedSWHID.from_string(expected) == swhid


def test_QualifiedSWHID_hash():
    object_id = _x("94a9ed024d3859793618152ea559a168bbcbb5e2")

    assert hash(
        QualifiedSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id)
    ) == hash(QualifiedSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id))

    assert hash(
        QualifiedSWHID(
            object_type=ObjectType.DIRECTORY,
            object_id=object_id,
            **dummy_qualifiers,
        )
    ) == hash(
        QualifiedSWHID(
            object_type=ObjectType.DIRECTORY,
            object_id=object_id,
            **dummy_qualifiers,
        )
    )

    # Different order of the dictionary, so the underlying order of the tuple in
    # ImmutableDict is different.
    assert hash(
        QualifiedSWHID(
            object_type=ObjectType.DIRECTORY,
            object_id=object_id,
            origin="https://example.com",
            lines=(42, None),
        )
    ) == hash(
        QualifiedSWHID(
            object_type=ObjectType.DIRECTORY,
            object_id=object_id,
            lines=(42, None),
            origin="https://example.com",
        )
    )


def test_QualifiedSWHID_eq():
    object_id = _x("94a9ed024d3859793618152ea559a168bbcbb5e2")

    assert QualifiedSWHID(
        object_type=ObjectType.DIRECTORY, object_id=object_id
    ) == QualifiedSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id)

    assert QualifiedSWHID(
        object_type=ObjectType.DIRECTORY,
        object_id=object_id,
        **dummy_qualifiers,
    ) == QualifiedSWHID(
        object_type=ObjectType.DIRECTORY,
        object_id=object_id,
        **dummy_qualifiers,
    )

    assert QualifiedSWHID(
        object_type=ObjectType.DIRECTORY,
        object_id=object_id,
        **dummy_qualifiers,
    ) == QualifiedSWHID(
        object_type=ObjectType.DIRECTORY,
        object_id=object_id,
        **dummy_qualifiers,
    )


QUALIFIED_SWHIDS = [
    # origin:
    (
        f"swh:1:cnt:{HASH};origin=https://github.com/python/cpython",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
            origin="https://github.com/python/cpython",
        ),
    ),
    (
        f"swh:1:cnt:{HASH};origin=https://example.org/foo%3Bbar%25baz",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
            origin="https://example.org/foo%3Bbar%25baz",
        ),
    ),
    (
        f"swh:1:cnt:{HASH};origin=https://example.org?project=test",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
            origin="https://example.org?project=test",
        ),
    ),
    # visit:
    (
        f"swh:1:cnt:{HASH};visit=swh:1:snp:{HASH}",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
            visit=CoreSWHID(object_type=ObjectType.SNAPSHOT, object_id=_x(HASH)),
        ),
    ),
    (
        f"swh:1:cnt:{HASH};visit=swh:1:rel:{HASH}",
        None,
    ),
    # anchor:
    (
        f"swh:1:cnt:{HASH};anchor=swh:1:dir:{HASH}",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
            anchor=CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=_x(HASH)),
        ),
    ),
    (
        f"swh:1:cnt:{HASH};anchor=swh:1:rev:{HASH}",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
            anchor=CoreSWHID(object_type=ObjectType.REVISION, object_id=_x(HASH)),
        ),
    ),
    (
        f"swh:1:cnt:{HASH};anchor=swh:1:cnt:{HASH}",
        None,  # 'cnt' is not valid in anchor
    ),
    (
        f"swh:1:cnt:{HASH};anchor=swh:1:ori:{HASH}",
        None,  # 'ori' is not valid in a CoreSWHID
    ),
    # path:
    (
        f"swh:1:cnt:{HASH};path=/foo",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT, object_id=_x(HASH), path=b"/foo"
        ),
    ),
    (
        f"swh:1:cnt:{HASH};path=/foo%3Bbar",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT, object_id=_x(HASH), path=b"/foo;bar"
        ),
    ),
    (
        f"swh:1:cnt:{HASH};path=/foo%25bar",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT, object_id=_x(HASH), path=b"/foo%bar"
        ),
    ),
    (
        f"swh:1:cnt:{HASH};path=/foo/bar%3Dbaz",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT, object_id=_x(HASH), path=b"/foo/bar=baz"
        ),
    ),
    # lines
    (
        f"swh:1:cnt:{HASH};lines=1-18",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
            lines=(1, 18),
        ),
    ),
    (
        f"swh:1:cnt:{HASH};lines=18",
        QualifiedSWHID(
            object_type=ObjectType.CONTENT,
            object_id=_x(HASH),
            lines=(18, None),
        ),
    ),
    (
        f"swh:1:cnt:{HASH};lines=",
        None,
    ),
    (
        f"swh:1:cnt:{HASH};lines=aa",
        None,
    ),
    (
        f"swh:1:cnt:{HASH};lines=18-aa",
        None,
    ),
]


@pytest.mark.parametrize("string,parsed", QUALIFIED_SWHIDS)
def test_QualifiedSWHID_parse_serialize_qualifiers(string, parsed):
    """Tests parsing and serializing valid SWHIDs with the various SWHID classes."""
    if parsed is None:
        with pytest.raises(ValidationError):
            print(repr(QualifiedSWHID.from_string(string)))
    else:
        assert QualifiedSWHID.from_string(string) == parsed
        assert str(parsed) == string


def test_QualifiedSWHID_serialize_origin():
    """Checks that semicolon in origins are escaped."""
    string = f"swh:1:cnt:{HASH};origin=https://example.org/foo%3Bbar%25baz"
    swhid = QualifiedSWHID(
        object_type=ObjectType.CONTENT,
        object_id=_x(HASH),
        origin="https://example.org/foo;bar%25baz",
    )
    assert str(swhid) == string


def test_QualifiedSWHID_attributes():
    """Checks the set of QualifiedSWHID attributes match the SWHID_QUALIFIERS
    constant."""

    assert set(attr.fields_dict(QualifiedSWHID)) == {
        "namespace",
        "scheme_version",
        "object_type",
        "object_id",
        *SWHID_QUALIFIERS,
    }


@pytest.mark.parametrize(
    "ns,version,type,id",
    [
        ("foo", 1, ObjectType.CONTENT, "abc8bc9d7a6bcf6db04f476d29314f157507d505"),
        ("swh", 2, ObjectType.CONTENT, "def8bc9d7a6bcf6db04f476d29314f157507d505"),
        ("swh", 1, ObjectType.DIRECTORY, "aaaa"),
    ],
)
def test_CoreSWHID_validation_error(ns, version, type, id):
    with pytest.raises(ValidationError):
        CoreSWHID(
            namespace=ns,
            scheme_version=version,
            object_type=type,
            object_id=_x(id),
        )


def test_CoreSWHID_hash():
    object_id = _x("94a9ed024d3859793618152ea559a168bbcbb5e2")

    assert hash(
        CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id)
    ) == hash(CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id))

    assert hash(
        CoreSWHID(
            object_type=ObjectType.DIRECTORY,
            object_id=object_id,
        )
    ) == hash(
        CoreSWHID(
            object_type=ObjectType.DIRECTORY,
            object_id=object_id,
        )
    )

    # Different order of the dictionary, so the underlying order of the tuple in
    # ImmutableDict is different.
    assert hash(
        CoreSWHID(
            object_type=ObjectType.DIRECTORY,
            object_id=object_id,
        )
    ) == hash(
        CoreSWHID(
            object_type=ObjectType.DIRECTORY,
            object_id=object_id,
        )
    )


def test_CoreSWHID_eq():
    object_id = _x("94a9ed024d3859793618152ea559a168bbcbb5e2")

    assert CoreSWHID(
        object_type=ObjectType.DIRECTORY, object_id=object_id
    ) == CoreSWHID(object_type=ObjectType.DIRECTORY, object_id=object_id)

    assert CoreSWHID(
        object_type=ObjectType.DIRECTORY,
        object_id=object_id,
    ) == CoreSWHID(
        object_type=ObjectType.DIRECTORY,
        object_id=object_id,
    )

    assert CoreSWHID(
        object_type=ObjectType.DIRECTORY,
        object_id=object_id,
    ) == CoreSWHID(
        object_type=ObjectType.DIRECTORY,
        object_id=object_id,
    )


@pytest.mark.parametrize(
    "ns,version,type,id",
    [
        (
            "foo",
            1,
            ExtendedObjectType.CONTENT,
            "abc8bc9d7a6bcf6db04f476d29314f157507d505",
        ),
        (
            "swh",
            2,
            ExtendedObjectType.CONTENT,
            "def8bc9d7a6bcf6db04f476d29314f157507d505",
        ),
        ("swh", 1, ExtendedObjectType.DIRECTORY, "aaaa"),
    ],
)
def test_ExtendedSWHID_validation_error(ns, version, type, id):
    with pytest.raises(ValidationError):
        ExtendedSWHID(
            namespace=ns,
            scheme_version=version,
            object_type=type,
            object_id=_x(id),
        )


def test_ExtendedSWHID_hash():
    object_id = _x("94a9ed024d3859793618152ea559a168bbcbb5e2")

    assert hash(
        ExtendedSWHID(object_type=ExtendedObjectType.DIRECTORY, object_id=object_id)
    ) == hash(
        ExtendedSWHID(object_type=ExtendedObjectType.DIRECTORY, object_id=object_id)
    )

    assert hash(
        ExtendedSWHID(
            object_type=ExtendedObjectType.DIRECTORY,
            object_id=object_id,
        )
    ) == hash(
        ExtendedSWHID(
            object_type=ExtendedObjectType.DIRECTORY,
            object_id=object_id,
        )
    )

    # Different order of the dictionary, so the underlying order of the tuple in
    # ImmutableDict is different.
    assert hash(
        ExtendedSWHID(
            object_type=ExtendedObjectType.DIRECTORY,
            object_id=object_id,
        )
    ) == hash(
        ExtendedSWHID(
            object_type=ExtendedObjectType.DIRECTORY,
            object_id=object_id,
        )
    )


def test_ExtendedSWHID_eq():
    object_id = _x("94a9ed024d3859793618152ea559a168bbcbb5e2")

    assert ExtendedSWHID(
        object_type=ExtendedObjectType.DIRECTORY, object_id=object_id
    ) == ExtendedSWHID(object_type=ExtendedObjectType.DIRECTORY, object_id=object_id)

    assert ExtendedSWHID(
        object_type=ExtendedObjectType.DIRECTORY,
        object_id=object_id,
    ) == ExtendedSWHID(
        object_type=ExtendedObjectType.DIRECTORY,
        object_id=object_id,
    )

    assert ExtendedSWHID(
        object_type=ExtendedObjectType.DIRECTORY,
        object_id=object_id,
    ) == ExtendedSWHID(
        object_type=ExtendedObjectType.DIRECTORY,
        object_id=object_id,
    )


def test_object_types():
    """Checks ExtendedObjectType is a superset of ObjectType"""
    for member in ObjectType:
        assert getattr(ExtendedObjectType, member.name).value == member.value
