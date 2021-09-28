# Copyright (C) 2015-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from typing import Any, Dict
import warnings

from . import model

# Reexport for backward compatibility
from .git_objects import *  # noqa
from .hashutil import MultiHash, hash_to_hex

# Reexport for backward compatibility
from .swhids import *  # noqa

warnings.warn(
    "The swh.model.identifiers module is deprecated. "
    "SWHID-related classes were moved to swh.model.swhids, and identifier "
    "computation is now done directly with swh.model.model classes.",
    DeprecationWarning,
    stacklevel=2,
)

# The following are deprecated aliases of the variants defined in ObjectType
# while transitioning from SWHID to QualifiedSWHID
ORIGIN = "origin"
SNAPSHOT = "snapshot"
REVISION = "revision"
RELEASE = "release"
DIRECTORY = "directory"
CONTENT = "content"
RAW_EXTRINSIC_METADATA = "raw_extrinsic_metadata"


def content_identifier(content: Dict[str, Any]) -> Dict[str, bytes]:
    """Deprecated, use :class:`swh.model.Content` instead:
    ``content_identifier(d)`` is equivalent to:
    ``{k: hash_to_hex(v) for (k, v) in Content.from_data(d["data"]).hashes().items()}``
    """
    return MultiHash.from_data(content["data"]).digest()


def directory_identifier(directory: Dict[str, Any]) -> str:
    """Deprecated, use :class:`swh.model.Directory` instead:
    ``directory_identifier(d)`` is equivalent to:
    ``hash_to_hex(Directory.from_dict(d).id)``.

    See :func:`swh.model.git_objects.directory_git_object` for details of the
    format used to generate this identifier."""
    return hash_to_hex(model.Directory.from_dict(directory).id)


def revision_identifier(revision: Dict[str, Any]) -> str:
    """Deprecated, use :class:`swh.model.Revision` instead:
    ``revision_identifier(d)`` is equivalent to:
    ``hash_to_hex(Revision.from_dict(d).id)``.

    See :func:`swh.model.git_objects.revision_git_object` for details of the
    format used to generate this identifier."""
    return hash_to_hex(model.Revision.from_dict(revision).id)


def release_identifier(release: Dict[str, Any]) -> str:
    """Deprecated, use :class:`swh.model.Release` instead:
    ``release_identifier(d)`` is equivalent to:
    ``hash_to_hex(Release.from_dict(d).id)``.

    See :func:`swh.model.git_objects.release_git_object` for details of the
    format used to generate this identifier."""
    return hash_to_hex(model.Release.from_dict(release).id)


def snapshot_identifier(snapshot: Dict[str, Any]) -> str:
    """Deprecated, use :class:`swh.model.Snapshot` instead:
    ``snapshot_identifier(d)`` is equivalent to:
    ``hash_to_hex(Snapshot.from_dict(d).id)``.

    See :func:`swh.model.git_objects.snapshot_git_object` for details of the
    format used to generate this identifier."""
    return hash_to_hex(model.Snapshot.from_dict(snapshot).id)


def origin_identifier(origin):
    """Deprecated, use :class:`swh.model.Origin` instead:
    ``origin_identifier(url)`` is equivalent to:
    ``hash_to_hex(Origin(url=url).id)``.
    """

    return hash_to_hex(model.Origin.from_dict(origin).id)
