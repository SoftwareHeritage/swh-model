# Copyright (C) 2020 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from swh.model.identifiers import SWHID


def test_swhid_hash():
    object_id = "94a9ed024d3859793618152ea559a168bbcbb5e2"

    assert hash(SWHID(object_type="directory", object_id=object_id)) == hash(
        SWHID(object_type="directory", object_id=object_id)
    )

    assert hash(
        SWHID(
            object_type="directory",
            object_id=object_id,
            metadata={"foo": "bar", "baz": "qux"},
        )
    ) == hash(
        SWHID(
            object_type="directory",
            object_id=object_id,
            metadata={"foo": "bar", "baz": "qux"},
        )
    )

    # Different order of the dictionary, so the underlying order of the tuple in
    # ImmutableDict is different.
    assert hash(
        SWHID(
            object_type="directory",
            object_id=object_id,
            metadata={"foo": "bar", "baz": "qux"},
        )
    ) == hash(
        SWHID(
            object_type="directory",
            object_id=object_id,
            metadata={"baz": "qux", "foo": "bar"},
        )
    )


def test_swhid_eq():
    object_id = "94a9ed024d3859793618152ea559a168bbcbb5e2"

    assert SWHID(object_type="directory", object_id=object_id) == SWHID(
        object_type="directory", object_id=object_id
    )

    assert SWHID(
        object_type="directory",
        object_id=object_id,
        metadata={"foo": "bar", "baz": "qux"},
    ) == SWHID(
        object_type="directory",
        object_id=object_id,
        metadata={"foo": "bar", "baz": "qux"},
    )

    assert SWHID(
        object_type="directory",
        object_id=object_id,
        metadata={"foo": "bar", "baz": "qux"},
    ) == SWHID(
        object_type="directory",
        object_id=object_id,
        metadata={"baz": "qux", "foo": "bar"},
    )
