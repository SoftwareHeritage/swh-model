# Copyright (C) 2017-2022 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import unittest

from swh.model import merkle


class MerkleTestNode(merkle.MerkleNode):
    object_type = "tested_merkle_node_type"

    def __init__(self, data):
        super().__init__(data)
        self.compute_hash_called = 0

    def compute_hash(self) -> bytes:
        self.compute_hash_called += 1
        child_data = [child + b"=" + self[child].hash for child in sorted(self)]
        return b"hash(" + b", ".join([self.data.get("value", b"")] + child_data) + b")"


class MerkleTestLeaf(merkle.MerkleLeaf):
    object_type = "tested_merkle_leaf_type"

    def __init__(self, data):
        super().__init__(data)
        self.compute_hash_called = 0

    def compute_hash(self):
        self.compute_hash_called += 1
        return b"hash(" + self.data.get("value", b"") + b")"


class TestMerkleLeaf(unittest.TestCase):
    def setUp(self):
        self.data = {"value": b"value"}
        self.instance = MerkleTestLeaf(self.data)

    def test_equality(self):
        leaf1 = MerkleTestLeaf(self.data)
        leaf2 = MerkleTestLeaf(self.data)
        leaf3 = MerkleTestLeaf({})

        self.assertEqual(leaf1, leaf2)
        self.assertNotEqual(leaf1, leaf3)

    def test_hash(self):
        self.assertEqual(self.instance.compute_hash_called, 0)
        instance_hash = self.instance.hash
        self.assertEqual(self.instance.compute_hash_called, 1)
        instance_hash2 = self.instance.hash
        self.assertEqual(self.instance.compute_hash_called, 1)
        self.assertEqual(instance_hash, instance_hash2)

    def test_data(self):
        self.assertEqual(self.instance.get_data(), self.data)

    def test_collect(self):
        collected = self.instance.collect()
        self.assertEqual(
            collected,
            {self.instance},
        )
        collected2 = self.instance.collect()
        self.assertEqual(collected2, set())
        self.instance.reset_collect()
        collected3 = self.instance.collect()
        self.assertEqual(collected, collected3)

    def test_leaf(self):
        with self.assertRaisesRegex(ValueError, "is a leaf"):
            self.instance[b"key1"] = "Test"

        with self.assertRaisesRegex(ValueError, "is a leaf"):
            del self.instance[b"key1"]

        with self.assertRaisesRegex(ValueError, "is a leaf"):
            self.instance[b"key1"]

        with self.assertRaisesRegex(ValueError, "is a leaf"):
            self.instance.update(self.data)


class TestMerkleNode(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.root = MerkleTestNode({"value": b"root"})
        self.nodes = {b"root": self.root}
        for i in (b"a", b"b", b"c"):
            value = b"root/" + i
            node = MerkleTestNode(
                {
                    "value": value,
                }
            )
            self.root[i] = node
            self.nodes[value] = node
            for j in (b"a", b"b", b"c"):
                value2 = value + b"/" + j
                node2 = MerkleTestNode(
                    {
                        "value": value2,
                    }
                )
                node[j] = node2
                self.nodes[value2] = node2
                for k in (b"a", b"b", b"c"):
                    value3 = value2 + b"/" + j
                    node3 = MerkleTestNode(
                        {
                            "value": value3,
                        }
                    )
                    node2[j] = node3
                    self.nodes[value3] = node3

    def test_equality(self):
        node1 = MerkleTestNode({"value": b"bar"})
        node2 = MerkleTestNode({"value": b"bar"})
        node3 = MerkleTestNode({})

        self.assertEqual(node1, node2)
        self.assertNotEqual(node1, node3, node1 == node3)

        node1[b"a"] = node3
        self.assertNotEqual(node1, node2)

        node2[b"a"] = node3
        self.assertEqual(node1, node2)

    def test_hash(self):
        for node in self.nodes.values():
            self.assertEqual(node.compute_hash_called, 0)

        # Root hash will compute hash for all the nodes
        hash = self.root.hash
        for node in self.nodes.values():
            self.assertEqual(node.compute_hash_called, 1)
            self.assertIn(node.data["value"], hash)

        # Should use the cached value
        hash2 = self.root.hash
        self.assertEqual(hash, hash2)
        for node in self.nodes.values():
            self.assertEqual(node.compute_hash_called, 1)

        # Should still use the cached value
        hash3 = self.root.update_hash(force=False)
        self.assertEqual(hash, hash3)
        for node in self.nodes.values():
            self.assertEqual(node.compute_hash_called, 1)

        # Force update of the cached value for a deeply nested node
        self.root[b"a"][b"b"].update_hash(force=True)
        for key, node in self.nodes.items():
            # update_hash rehashes all children
            if key.startswith(b"root/a/b"):
                self.assertEqual(node.compute_hash_called, 2)
            else:
                self.assertEqual(node.compute_hash_called, 1)

        hash4 = self.root.hash
        self.assertEqual(hash, hash4)
        for key, node in self.nodes.items():
            # update_hash also invalidates all parents
            if key in (b"root", b"root/a") or key.startswith(b"root/a/b"):
                self.assertEqual(node.compute_hash_called, 2)
            else:
                self.assertEqual(node.compute_hash_called, 1)

    def test_collect(self):
        collected = self.root.collect()
        self.assertEqual(collected, set(self.nodes.values()))
        for node in self.nodes.values():
            self.assertTrue(node.collected)
        collected2 = self.root.collect()
        self.assertEqual(collected2, set())

    def test_iter_tree_with_deduplication(self):
        nodes = list(self.root.iter_tree())
        self.assertCountEqual(nodes, self.nodes.values())

    def test_iter_tree_without_deduplication(self):
        # duplicate existing hash in merkle tree
        self.root[b"d"] = MerkleTestNode({"value": b"root/c/c/c"})
        nodes_dedup = list(self.root.iter_tree())
        nodes = list(self.root.iter_tree(dedup=False))
        assert nodes != nodes_dedup
        assert len(nodes) == len(nodes_dedup) + 1

    def test_get(self):
        for key in (b"a", b"b", b"c"):
            self.assertEqual(self.root[key], self.nodes[b"root/" + key])

        with self.assertRaisesRegex(KeyError, "b'nonexistent'"):
            self.root[b"nonexistent"]

    def test_del(self):
        hash_root = self.root.hash
        hash_a = self.nodes[b"root/a"].hash
        del self.root[b"a"][b"c"]
        hash_root2 = self.root.hash
        hash_a2 = self.nodes[b"root/a"].hash

        self.assertNotEqual(hash_root, hash_root2)
        self.assertNotEqual(hash_a, hash_a2)

        self.assertEqual(self.nodes[b"root/a/c"].parents, [])

        with self.assertRaisesRegex(KeyError, "b'nonexistent'"):
            del self.root[b"nonexistent"]

    def test_update(self):
        hash_root = self.root.hash
        hash_b = self.root[b"b"].hash
        new_children = {
            b"c": MerkleTestNode({"value": b"root/b/new_c"}),
            b"d": MerkleTestNode({"value": b"root/b/d"}),
        }

        # collect all nodes
        self.root.collect()

        self.root[b"b"].update(new_children)

        # Ensure everyone got reparented
        self.assertEqual(new_children[b"c"].parents, [self.root[b"b"]])
        self.assertEqual(new_children[b"d"].parents, [self.root[b"b"]])
        self.assertEqual(self.nodes[b"root/b/c"].parents, [])

        hash_root2 = self.root.hash
        self.assertNotEqual(hash_root, hash_root2)
        self.assertIn(b"root/b/new_c", hash_root2)
        self.assertIn(b"root/b/d", hash_root2)

        hash_b2 = self.root[b"b"].hash
        self.assertNotEqual(hash_b, hash_b2)

        for key, node in self.nodes.items():
            if key in (b"root", b"root/b"):
                self.assertEqual(node.compute_hash_called, 2)
            else:
                self.assertEqual(node.compute_hash_called, 1)

        # Ensure we collected root, root/b, and both new children
        collected_after_update = self.root.collect()
        self.assertEqual(
            collected_after_update,
            {
                self.nodes[b"root"],
                self.nodes[b"root/b"],
                new_children[b"c"],
                new_children[b"d"],
            },
        )

        # test that noop updates doesn't invalidate anything
        self.root[b"a"][b"b"].update({})
        self.assertEqual(self.root.collect(), set())
