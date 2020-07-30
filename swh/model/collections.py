# Copyright (C) 2020 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from collections.abc import Mapping
from typing import Dict, Generic, Iterable, Optional, Tuple, TypeVar, Union

KT = TypeVar("KT")
VT = TypeVar("VT")


class ImmutableDict(Mapping, Generic[KT, VT]):
    data: Tuple[Tuple[KT, VT], ...]

    def __init__(
        self,
        data: Union[
            Iterable[Tuple[KT, VT]], "ImmutableDict[KT, VT]", Dict[KT, VT]
        ] = {},
    ):
        if isinstance(data, dict):
            self.data = tuple(item for item in data.items())
        elif isinstance(data, ImmutableDict):
            self.data = data.data
        else:
            self.data = tuple(data)

    def __repr__(self):
        return f"ImmutableDict({dict(self.data)!r})"

    def __getitem__(self, key):
        for (k, v) in self.data:
            if k == key:
                return v
        raise KeyError(key)

    def __iter__(self):
        for (k, v) in self.data:
            yield k

    def __len__(self):
        return len(self.data)

    def items(self):
        yield from self.data

    def __hash__(self):
        return hash(tuple(sorted(self.data)))

    def copy_pop(self, popped_key) -> Tuple[Optional[VT], "ImmutableDict[KT, VT]"]:
        """Returns a copy of this ImmutableDict without the given key,
        as well as the value associated to the key."""
        popped_value = None
        new_items = []
        for (key, value) in self.data:
            if key == popped_key:
                popped_value = value
            else:
                new_items.append((key, value))

        return (popped_value, ImmutableDict(new_items))
