# Copyright (C) 2017-2018  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import unittest

from swh.model.toposort import toposort


def is_toposorted_slow(revision_log):
    """Check (inefficiently) that the given revision log is in any topological
    order.

    Complexity: O(n^2).
        (Note: It's totally possible to write a O(n) is_toposorted function,
        but it requires computing the transitive closure of the input DAG,
        which requires computing a topological ordering of that DAG, which
        kind of defeats the purpose of writing unit tests for toposort().)

    Args:
        revision_log: Revision log as returned by
            swh.storage.Storage.revision_log().

    Returns:
        True if the revision log is topologically sorted.
    """
    rev_by_id = {r["id"]: r for r in revision_log}

    def all_parents(revision):
        for parent in revision["parents"]:
            yield parent
            yield from all_parents(rev_by_id[parent])

    visited = set()
    for rev in revision_log:
        visited.add(rev["id"])
        if not all(parent in visited for parent in all_parents(rev)):
            return False
    return True


class TestToposort(unittest.TestCase):
    def generate_log(self, graph):
        for node_id, parents in graph.items():
            yield {"id": node_id, "parents": tuple(parents)}

    def unordered_log(self, log):
        return {(d["id"], tuple(d["parents"])) for d in log}

    def check(self, graph):
        log = list(self.generate_log(graph))
        topolog = list(toposort(log))
        self.assertEqual(len(topolog), len(graph))
        self.assertEqual(self.unordered_log(topolog), self.unordered_log(log))
        self.assertTrue(is_toposorted_slow(toposort(log)))

    def test_linked_list(self):
        self.check({3: [2], 2: [1], 1: []})

    def test_fork(self):
        self.check({7: [6], 6: [4], 5: [3], 4: [2], 3: [2], 2: [1], 1: []})

    def test_fork_merge(self):
        self.check({8: [7, 5], 7: [6], 6: [4], 5: [3], 4: [2], 3: [2], 2: [1], 1: []})

    def test_two_origins(self):
        self.check({9: [8], 8: [7, 5], 7: [6], 6: [4], 5: [3], 4: [], 3: []})

    def test_three_way(self):
        self.check(
            {
                9: [8, 4, 2],
                8: [7, 5],
                7: [6],
                6: [4],
                5: [3],
                4: [2],
                3: [2],
                2: [1],
                1: [],
            }
        )
