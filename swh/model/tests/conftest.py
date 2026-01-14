# Copyright (C) 2025  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from hypothesis import HealthCheck, settings

# disable HealthCheck.too_slow hypothesis check for pypy tests
settings.register_profile("swh-model", suppress_health_check=[HealthCheck.too_slow])
settings.load_profile("swh-model")
