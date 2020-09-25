# Copyright (C) 2019 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from swh.model.model import BaseContent, Origin

from .generate_testdata import ORIGINS, gen_contents, gen_origins


def test_gen_origins_empty():
    origins = gen_origins(0)
    assert not origins


def test_gen_origins_one():
    origins = gen_origins(1)
    assert len(origins) == 1
    assert [Origin.from_dict(d) for d in origins]


def test_gen_origins_default():
    origins = gen_origins()
    assert len(origins) == 100
    models = [Origin.from_dict(d).url for d in origins]
    assert len(origins) == len(set(models))


def test_gen_origins_max():
    nmax = len(ORIGINS)
    origins = gen_origins(nmax + 1)
    assert len(origins) == nmax
    models = {Origin.from_dict(d).url for d in origins}
    # ensure we did not generate the same origin twice
    assert len(origins) == len(models)


def test_gen_contents_empty():
    contents = gen_contents(0)
    assert not contents


def test_gen_contents_one():
    contents = gen_contents(1)
    assert len(contents) == 1
    assert [BaseContent.from_dict(d) for d in contents]


def test_gen_contents_default():
    contents = gen_contents()
    assert len(contents) == 20
    models = {BaseContent.from_dict(d) for d in contents}
    # ensure we did not generate the same content twice
    assert len(contents) == len(models)
