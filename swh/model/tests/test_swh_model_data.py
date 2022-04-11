# Copyright (C) 2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import attr
import pytest

from swh.model.tests.swh_model_data import TEST_OBJECTS


@pytest.mark.parametrize("object_type, objects", TEST_OBJECTS.items())
def test_swh_model_data(object_type, objects):
    """checks model objects in swh_model_data are in correct shape"""
    assert objects
    for obj in objects:
        assert obj.object_type == object_type
        attr.validate(obj)


@pytest.mark.parametrize(
    "object_type",
    ("directory", "revision", "release", "snapshot"),
)
def test_swh_model_data_hash(object_type):
    for obj in TEST_OBJECTS[object_type]:
        assert (
            obj.compute_hash() == obj.id
        ), f"{obj.compute_hash().hex()} != {obj.id.hex()}"


def test_ensure_visit_status_date_consistency():
    """ensure origin-visit-status dates are more recent than their visit counterpart

    The origin-visit-status dates needs to be shifted slightly in the future from their
    visit dates counterpart. Otherwise, we are hitting storage-wise the "on conflict"
    ignore policy (because origin-visit-add creates an origin-visit-status with the same
    parameters from the origin-visit {origin, visit, date}...

    """
    visits = TEST_OBJECTS["origin_visit"]
    visit_statuses = TEST_OBJECTS["origin_visit_status"]
    for visit, visit_status in zip(visits, visit_statuses):
        assert visit.origin == visit_status.origin
        assert visit.visit == visit_status.visit
        assert visit.date < visit_status.date


def test_ensure_visit_status_snapshot_consistency():
    """ensure origin-visit-status snapshots exist in the test dataset"""
    snapshots = [snp.id for snp in TEST_OBJECTS["snapshot"]]
    for visit_status in TEST_OBJECTS["origin_visit_status"]:
        if visit_status.snapshot:
            assert visit_status.snapshot in snapshots
