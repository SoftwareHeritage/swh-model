# Copyright (C) 2017-2018  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import collections


def toposort(revision_log):
    """Perform a topological sort on a revision log graph.

    Complexity: O(N) (linear in the length of the revision log)

    Args:
        revision_log: Revision log as returned by
            swh.storage.Storage.revision_log().

    Yields:
        The revision log sorted by a topological order
    """
    in_degree = {}  # rev_id -> numbers of parents left to compute
    children = collections.defaultdict(list)  # rev_id -> children

    # Compute the in_degrees and the parents of all the revisions.
    # Add the roots to the processing queue.
    queue = collections.deque()
    for rev in revision_log:
        parents = rev['parents']
        in_degree[rev['id']] = len(parents)
        if not parents:
            queue.append(rev)
        for parent in parents:
            children[parent].append(rev)

    # Topological sort: yield the 'ready' nodes, decrease the in degree of
    # their children and add the 'ready' ones to the queue.
    while queue:
        rev = queue.popleft()
        yield rev
        for child in children[rev['id']]:
            in_degree[child['id']] -= 1
            if in_degree[child['id']] == 0:
                queue.append(child)
