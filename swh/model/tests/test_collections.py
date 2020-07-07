# Copyright (C) 2020 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import pytest

from swh.model.collections import ImmutableDict


def test_immutabledict_empty():
    d = ImmutableDict()

    assert d == {}
    assert d != {"foo": "bar"}

    assert list(d) == []
    assert list(d.items()) == []


def test_immutabledict_one_item():
    d = ImmutableDict({"foo": "bar"})

    assert d == {"foo": "bar"}
    assert d != {}

    assert d["foo"] == "bar"
    with pytest.raises(KeyError, match="bar"):
        d["bar"]

    assert list(d) == ["foo"]
    assert list(d.items()) == [("foo", "bar")]


def test_immutabledict_from_iterable():
    d1 = ImmutableDict()
    d2 = ImmutableDict({"foo": "bar"})

    assert ImmutableDict([]) == d1
    assert ImmutableDict([("foo", "bar")]) == d2


def test_immutabledict_from_immutabledict():
    d1 = ImmutableDict()
    d2 = ImmutableDict({"foo": "bar"})

    assert ImmutableDict(d1) == d1
    assert ImmutableDict(d2) == d2


def test_immutabledict_immutable():
    d = ImmutableDict({"foo": "bar"})

    with pytest.raises(TypeError, match="item assignment"):
        d["bar"] = "baz"

    with pytest.raises(TypeError, match="item deletion"):
        del d["foo"]


def test_immutabledict_copy_pop():
    d = ImmutableDict({"foo": "bar", "baz": "qux"})

    assert d.copy_pop("foo") == ("bar", ImmutableDict({"baz": "qux"}))

    assert d.copy_pop("not a key") == (None, d)


def test_hash():
    assert hash(ImmutableDict()) == hash(ImmutableDict({}))
    assert hash(ImmutableDict({"foo": "bar"})) == hash(ImmutableDict({"foo": "bar"}))
    assert hash(ImmutableDict({"foo": "bar", "baz": "qux"})) == hash(
        ImmutableDict({"foo": "bar", "baz": "qux"})
    )
    assert hash(ImmutableDict({"foo": "bar", "baz": "qux"})) == hash(
        ImmutableDict({"baz": "qux", "foo": "bar"})
    )


def test_equality_order():
    assert ImmutableDict({"foo": "bar", "baz": "qux"}) == ImmutableDict(
        {"foo": "bar", "baz": "qux"}
    )
    assert ImmutableDict({"foo": "bar", "baz": "qux"}) == ImmutableDict(
        {"baz": "qux", "foo": "bar"}
    )
