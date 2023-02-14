# Copyright (C) 2020-2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from __future__ import annotations

"""Utility data structures."""

from collections.abc import Mapping
import copy
from typing import Dict, Generic, Iterable, Optional, Tuple, TypeVar, Union

KT = TypeVar("KT")
VT = TypeVar("VT")


class ImmutableDict(Mapping, Generic[KT, VT]):
    """A frozen dictionary.

    This class behaves like a dictionary, but internally stores objects in a tuple,
    so it is both immutable and hashable."""

    _data: Dict[KT, VT]

    def __init__(
        self,
        data: Union[Iterable[Tuple[KT, VT]], ImmutableDict[KT, VT], Dict[KT, VT]] = {},
    ):
        if isinstance(data, dict):
            self._data = data
        elif isinstance(data, ImmutableDict):
            self._data = data._data
        else:
            self._data = {k: v for k, v in data}

    @property
    def data(self):
        return tuple(self._data.items())

    def __repr__(self):
        return f"ImmutableDict({dict(self.data)!r})"

    def __getitem__(self, key):
        return self._data[key]

    def __iter__(self):
        for (k, v) in self.data:
            yield k

    def __len__(self):
        return len(self._data)

    def items(self):
        yield from self.data

    def __hash__(self):
        return hash(tuple(sorted(self.data)))

    def copy_pop(self, popped_key) -> Tuple[Optional[VT], ImmutableDict[KT, VT]]:
        """Returns a copy of this ImmutableDict without the given key,
        as well as the value associated to the key."""
        new_items = copy.deepcopy(self._data)
        popped_value = new_items.pop(popped_key, None)  # type: ignore
        return (popped_value, ImmutableDict(new_items))
