# Copyright (C) 2018 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import os
import tempfile
import unittest

from click.testing import CliRunner

from swh.model import cli
from swh.model.tests.test_from_disk import DataMixin
from swh.model.hashutil import hash_to_hex


class TestIdentify(DataMixin, unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.runner = CliRunner()

    def test_content_id(self):
        self.make_contents(self.tmpdir_name)
        for filename, content in self.contents.items():
            path = os.path.join(self.tmpdir_name, filename)
            result = self.runner.invoke(cli.identify,
                                        ['--type', 'content', path])

            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.output.rstrip(),
                             'swh:1:cnt:' + hash_to_hex(content['sha1_git']))

    def test_directory_id(self):
        self.make_from_tarball(self.tmpdir_name)
        path = os.path.join(self.tmpdir_name, b'sample-folder')
        result = self.runner.invoke(cli.identify,
                                    ['--type', 'directory', path])

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.output.rstrip(),
                         'swh:1:dir:e8b0f1466af8608c8a3fb9879db172b887e80759')

    def test_auto_id(self):
        with tempfile.NamedTemporaryFile(prefix='swh.model.cli') as f:
            result = self.runner.invoke(cli.identify, [f.name])
            self.assertEqual(result.exit_code, 0)
            self.assertRegex(result.output, r'^swh:\d+:cnt:')

        with tempfile.TemporaryDirectory(prefix='swh.model.cli') as dirname:
            result = self.runner.invoke(cli.identify, [dirname])
            self.assertEqual(result.exit_code, 0)
            self.assertRegex(result.output, r'^swh:\d+:dir:')

    def test_verify_content(self):
        self.make_contents(self.tmpdir_name)
        for filename, content in self.contents.items():
            expected_id = 'swh:1:cnt:' + hash_to_hex(content['sha1_git'])

            # match
            path = os.path.join(self.tmpdir_name, filename)
            result = self.runner.invoke(cli.identify,
                                        ['--verify', expected_id, path])
            self.assertEqual(result.exit_code, 0)

            # mismatch
            with open(path, 'a') as f:
                f.write('trailing garbage to make verification fail')
            result = self.runner.invoke(cli.identify,
                                        ['--verify', expected_id, path])
            self.assertEqual(result.exit_code, 1)
