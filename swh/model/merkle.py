# Copyright (C) 2017-2020 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

"""Merkle tree data structure"""

import abc
from collections.abc import Mapping

from typing import Iterator, List, Set


def deep_update(left, right):
    """Recursively update the left mapping with deeply nested values from the right
    mapping.

    This function is useful to merge the results of several calls to
    :func:`MerkleNode.collect`.

    Arguments:
      left: a mapping (modified by the update operation)
      right: a mapping

    Returns:
      the left mapping, updated with nested values from the right mapping

    Example:
        >>> a = {
        ...     'key1': {
        ...         'key2': {
        ...              'key3': 'value1/2/3',
        ...         },
        ...     },
        ... }
        >>> deep_update(a, {
        ...     'key1': {
        ...         'key2': {
        ...              'key4': 'value1/2/4',
        ...         },
        ...     },
        ... }) == {
        ...     'key1': {
        ...         'key2': {
        ...             'key3': 'value1/2/3',
        ...             'key4': 'value1/2/4',
        ...         },
        ...     },
        ... }
        True
        >>> deep_update(a, {
        ...     'key1': {
        ...         'key2': {
        ...              'key3': 'newvalue1/2/3',
        ...         },
        ...     },
        ... }) == {
        ...     'key1': {
        ...         'key2': {
        ...             'key3': 'newvalue1/2/3',
        ...             'key4': 'value1/2/4',
        ...         },
        ...     },
        ... }
        True

    """
    for key, rvalue in right.items():
        if isinstance(rvalue, Mapping):
            new_lvalue = deep_update(left.get(key, {}), rvalue)
            left[key] = new_lvalue
        else:
            left[key] = rvalue
    return left


class MerkleNode(dict, metaclass=abc.ABCMeta):
    """Representation of a node in a Merkle Tree.

    A (generalized) `Merkle Tree`_ is a tree in which every node is labeled
    with a hash of its own data and the hash of its children.

    .. _Merkle Tree: https://en.wikipedia.org/wiki/Merkle_tree

    In pseudocode::

      node.hash = hash(node.data
                       + sum(child.hash for child in node.children))

    This class efficiently implements the Merkle Tree data structure on top of
    a Python :class:`dict`, minimizing hash computations and new data
    collections when updating nodes.

    Node data is stored in the :attr:`data` attribute, while (named) children
    are stored as items of the underlying dictionary.

    Addition, update and removal of objects are instrumented to automatically
    invalidate the hashes of the current node as well as its registered
    parents; It also resets the collection status of the objects so the updated
    objects can be collected.

    The collection of updated data from the tree is implemented through the
    :func:`collect` function and associated helpers.

    Attributes:
      data (dict): data associated to the current node
      parents (list): known parents of the current node
      collected (bool): whether the current node has been collected

    """

    __slots__ = ["parents", "data", "__hash", "collected"]

    """Type of the current node (used as a classifier for :func:`collect`)"""

    def __init__(self, data=None):
        super().__init__()
        self.parents = []
        self.data = data
        self.__hash = None
        self.collected = False

    def __eq__(self, other):
        return (
            isinstance(other, MerkleNode)
            and super().__eq__(other)
            and self.data == other.data
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def invalidate_hash(self):
        """Invalidate the cached hash of the current node."""
        if not self.__hash:
            return

        self.__hash = None
        self.collected = False
        for parent in self.parents:
            parent.invalidate_hash()

    def update_hash(self, *, force=False):
        """Recursively compute the hash of the current node.

        Args:
          force (bool): invalidate the cache and force the computation for
            this node and all children.
        """
        if self.__hash and not force:
            return self.__hash

        if force:
            self.invalidate_hash()

        for child in self.values():
            child.update_hash(force=force)

        self.__hash = self.compute_hash()
        return self.__hash

    @property
    def hash(self):
        """The hash of the current node, as calculated by
        :func:`compute_hash`.
        """
        return self.update_hash()

    @abc.abstractmethod
    def compute_hash(self):
        """Compute the hash of the current node.

        The hash should depend on the data of the node, as well as on hashes
        of the children nodes.
        """
        raise NotImplementedError("Must implement compute_hash method")

    def __setitem__(self, name, new_child):
        """Add a child, invalidating the current hash"""
        self.invalidate_hash()

        super().__setitem__(name, new_child)

        new_child.parents.append(self)

    def __delitem__(self, name):
        """Remove a child, invalidating the current hash"""
        if name in self:
            self.invalidate_hash()
            self[name].parents.remove(self)
            super().__delitem__(name)
        else:
            raise KeyError(name)

    def update(self, new_children):
        """Add several named children from a dictionary"""
        if not new_children:
            return

        self.invalidate_hash()

        for name, new_child in new_children.items():
            new_child.parents.append(self)
            if name in self:
                self[name].parents.remove(self)

        super().update(new_children)

    def get_data(self, **kwargs):
        """Retrieve and format the collected data for the current node, for use by
        :func:`collect`.

        Can be overridden, for instance when you want the collected data to
        contain information about the child nodes.

        Arguments:
          kwargs: allow subclasses to alter behaviour depending on how
            :func:`collect` is called.

        Returns:
          data formatted for :func:`collect`
        """
        return self.data

    def collect_node(self, **kwargs):
        """Collect the data for the current node, for use by :func:`collect`.

        Arguments:
          kwargs: passed as-is to :func:`get_data`.

        Returns:
          A :class:`dict` compatible with :func:`collect`.
        """
        if not self.collected:
            self.collected = True
            return {self.object_type: {self.hash: self.get_data(**kwargs)}}
        else:
            return {}

    def collect(self, **kwargs):
        """Collect the data for all nodes in the subtree rooted at `self`.

        The data is deduplicated by type and by hash.

        Arguments:
          kwargs: passed as-is to :func:`get_data`.

        Returns:
           A :class:`dict` with the following structure::

             {
               'typeA': {
                 node1.hash: node1.get_data(),
                 node2.hash: node2.get_data(),
               },
               'typeB': {
                 node3.hash: node3.get_data(),
                 ...
               },
               ...
             }
        """
        ret = self.collect_node(**kwargs)
        for child in self.values():
            deep_update(ret, child.collect(**kwargs))

        return ret

    def reset_collect(self):
        """Recursively unmark collected nodes in the subtree rooted at `self`.

        This lets the caller use :func:`collect` again.
        """
        self.collected = False

        for child in self.values():
            child.reset_collect()

    def iter_tree(self) -> Iterator["MerkleNode"]:
        """Yields all children nodes, recursively. Common nodes are
        deduplicated.
        """
        yield from self._iter_tree(set())

    def _iter_tree(self, seen: Set[bytes]) -> Iterator["MerkleNode"]:
        if self.hash not in seen:
            seen.add(self.hash)
            yield self
            for child in self.values():
                yield from child._iter_tree(seen=seen)


class MerkleLeaf(MerkleNode):
    """A leaf to a Merkle tree.

    A Merkle leaf is simply a Merkle node with children disabled.
    """

    __slots__ = []  # type: List[str]

    def __setitem__(self, name, child):
        raise ValueError("%s is a leaf" % self.__class__.__name__)

    def __getitem__(self, name):
        raise ValueError("%s is a leaf" % self.__class__.__name__)

    def __delitem__(self, name):
        raise ValueError("%s is a leaf" % self.__class__.__name__)

    def update(self, new_children):
        """Children update operation. Disabled for leaves."""
        raise ValueError("%s is a leaf" % self.__class__.__name__)
