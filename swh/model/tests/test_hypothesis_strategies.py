# Copyright (C) 2019 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime

import attr
from hypothesis import given, settings

from swh.model.hashutil import DEFAULT_ALGORITHMS
from swh.model.hypothesis_strategies import objects, object_dicts, snapshots
from swh.model.model import TargetType


target_types = ("content", "directory", "revision", "release", "snapshot", "alias")


@given(objects())
def test_generation(obj_type_and_obj):
    (obj_type, object_) = obj_type_and_obj
    attr.validate(object_)


def assert_nested_dict(obj):
    """Tests the object is a nested dict and contains no more class
    from swh.model.model."""
    if isinstance(obj, dict):
        for (key, value) in obj.items():
            assert isinstance(key, (str, bytes)), key
            assert_nested_dict(value)
    elif isinstance(obj, list):
        for value in obj:
            assert_nested_dict(value)
    elif isinstance(obj, (int, float, str, bytes, bool, type(None), datetime.datetime)):
        pass
    else:
        assert False, obj


@given(object_dicts())
def test_dicts_generation(obj_type_and_obj):
    (obj_type, object_) = obj_type_and_obj
    assert_nested_dict(object_)
    if obj_type == "content":
        COMMON_KEYS = set(DEFAULT_ALGORITHMS) | {"length", "status", "ctime"}
        if object_["status"] == "visible":
            assert set(object_) <= COMMON_KEYS | {"data"}
        elif object_["status"] == "absent":
            assert set(object_) == COMMON_KEYS | {"reason"}
        elif object_["status"] == "hidden":
            assert set(object_) <= COMMON_KEYS | {"data"}
        else:
            assert False, object_
    elif obj_type == "release":
        assert object_["target_type"] in target_types
    elif obj_type == "snapshot":
        for branch in object_["branches"].values():
            assert branch is None or branch["target_type"] in target_types


@given(objects())
def test_model_to_dicts(obj_type_and_obj):
    (obj_type, object_) = obj_type_and_obj
    obj_dict = object_.to_dict()
    assert_nested_dict(obj_dict)
    if obj_type == "content":
        COMMON_KEYS = set(DEFAULT_ALGORITHMS) | {"length", "status", "ctime"}
        if obj_dict["status"] == "visible":
            assert set(obj_dict) == COMMON_KEYS | {"data"}
        elif obj_dict["status"] == "absent":
            assert set(obj_dict) == COMMON_KEYS | {"reason"}
        elif obj_dict["status"] == "hidden":
            assert set(obj_dict) == COMMON_KEYS | {"data"}
        else:
            assert False, obj_dict
    elif obj_type == "release":
        assert obj_dict["target_type"] in target_types
    elif obj_type == "snapshot":
        for branch in obj_dict["branches"].values():
            assert branch is None or branch["target_type"] in target_types


_min_snp_size = 10
_max_snp_size = 100


@given(snapshots(min_size=_min_snp_size, max_size=_max_snp_size))
@settings(max_examples=1)
def test_snapshots_strategy(snapshot):

    branches = snapshot.branches

    assert len(branches) >= _min_snp_size
    assert len(branches) <= _max_snp_size

    aliases = []

    # check snapshot integrity
    for name, branch in branches.items():
        assert branch is None or branch.target_type.value in target_types
        if branch is not None and branch.target_type == TargetType.ALIAS:
            aliases.append(name)
            assert branch.target in branches

    # check no cycles between aliases
    for alias in aliases:
        processed_alias = set()
        current_alias = alias
        while (
            branches[current_alias] is not None
            and branches[current_alias].target_type == TargetType.ALIAS
        ):
            assert branches[current_alias].target not in processed_alias
            processed_alias.add(current_alias)
            current_alias = branches[current_alias].target


@given(snapshots(min_size=_min_snp_size, max_size=_min_snp_size))
@settings(max_examples=1)
def test_snapshots_strategy_fixed_size(snapshot):
    assert len(snapshot.branches) == _min_snp_size
