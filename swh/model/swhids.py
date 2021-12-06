# Copyright (C) 2015-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

"""
Classes to represent :ref:`SWH persistend IDentifiers <persistent-identifiers>`.

:class:`CoreSWHID` represents a SWHID with no qualifier, and :class:`QualifiedSWHID`
represents a SWHID that may have qualifiers.
:class:`ExtendedSWHID` extends the definition of SWHID to other object types,
and is used internally in Software Heritage; it does not support qualifiers.
"""

from __future__ import annotations

import enum
import re
from typing import Any, Dict, Generic, Optional, Tuple, Type, TypeVar, Union
import urllib.parse

import attr
from attrs_strict import type_validator

from .exceptions import ValidationError
from .hashutil import hash_to_bytes, hash_to_hex


class ObjectType(enum.Enum):
    """Possible object types of a QualifiedSWHID or CoreSWHID.

    The values of each variant is what is used in the SWHID's string representation."""

    SNAPSHOT = "snp"
    REVISION = "rev"
    RELEASE = "rel"
    DIRECTORY = "dir"
    CONTENT = "cnt"


class ExtendedObjectType(enum.Enum):
    """Possible object types of an ExtendedSWHID.

    The variants are a superset of :class:`ObjectType`'s"""

    SNAPSHOT = "snp"
    REVISION = "rev"
    RELEASE = "rel"
    DIRECTORY = "dir"
    CONTENT = "cnt"
    ORIGIN = "ori"
    RAW_EXTRINSIC_METADATA = "emd"


SWHID_NAMESPACE = "swh"
SWHID_VERSION = 1
SWHID_TYPES = ["snp", "rel", "rev", "dir", "cnt"]
EXTENDED_SWHID_TYPES = SWHID_TYPES + ["ori", "emd"]
SWHID_SEP = ":"
SWHID_CTXT_SEP = ";"
SWHID_QUALIFIERS = {"origin", "anchor", "visit", "path", "lines"}

SWHID_RE_RAW = (
    f"(?P<namespace>{SWHID_NAMESPACE})"
    f"{SWHID_SEP}(?P<scheme_version>{SWHID_VERSION})"
    f"{SWHID_SEP}(?P<object_type>{'|'.join(EXTENDED_SWHID_TYPES)})"
    f"{SWHID_SEP}(?P<object_id>[0-9a-f]{{40}})"
    f"({SWHID_CTXT_SEP}(?P<qualifiers>\\S+))?"
)
SWHID_RE = re.compile(SWHID_RE_RAW)


# type of the "object_type" attribute of the SWHID class; either
# ObjectType or ExtendedObjectType
_TObjectType = TypeVar("_TObjectType", ObjectType, ExtendedObjectType)

# the SWHID class itself (this is used so that X.from_string() can return X
# for all X subclass of _BaseSWHID)
_TSWHID = TypeVar("_TSWHID", bound="_BaseSWHID")


@attr.s(frozen=True, kw_only=True, repr=False)
class _BaseSWHID(Generic[_TObjectType]):
    """Common base class for CoreSWHID, QualifiedSWHID, and ExtendedSWHID.

    This is an "abstract" class and should not be instantiated directly;
    it only exists to deduplicate code between these three SWHID classes."""

    namespace = attr.ib(type=str, default=SWHID_NAMESPACE)
    """the namespace of the identifier, defaults to ``swh``"""

    scheme_version = attr.ib(type=int, default=SWHID_VERSION)
    """the scheme version of the identifier, defaults to 1"""

    # overridden by subclasses
    object_type: _TObjectType
    """the type of object the identifier points to"""

    object_id = attr.ib(type=bytes, validator=type_validator())
    """object's identifier"""

    @namespace.validator
    def check_namespace(self, attribute, value):
        if value != SWHID_NAMESPACE:
            raise ValidationError(
                "Invalid SWHID: invalid namespace: %(namespace)s",
                params={"namespace": value},
            )

    @scheme_version.validator
    def check_scheme_version(self, attribute, value):
        if value != SWHID_VERSION:
            raise ValidationError(
                "Invalid SWHID: invalid version: %(version)s", params={"version": value}
            )

    @object_id.validator
    def check_object_id(self, attribute, value):
        if len(value) != 20:
            raise ValidationError(
                "Invalid SWHID: invalid checksum: %(object_id)s",
                params={"object_id": hash_to_hex(value)},
            )

    def __str__(self) -> str:
        return SWHID_SEP.join(
            [
                self.namespace,
                str(self.scheme_version),
                self.object_type.value,
                hash_to_hex(self.object_id),
            ]
        )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}.from_string('{self}')"

    @classmethod
    def from_string(cls: Type[_TSWHID], s: str) -> _TSWHID:
        parts = _parse_swhid(s)
        if parts.pop("qualifiers"):
            raise ValidationError(f"{cls.__name__} does not support qualifiers.")
        try:
            return cls(**parts)
        except ValueError as e:
            raise ValidationError(
                "ValueError: %(args)s", params={"args": e.args}
            ) from None


@attr.s(frozen=True, kw_only=True, repr=False)
class CoreSWHID(_BaseSWHID[ObjectType]):
    """
    Dataclass holding the relevant info associated to a SoftWare Heritage
    persistent IDentifier (SWHID).

    Unlike `QualifiedSWHID`, it is restricted to core SWHIDs, ie. SWHIDs
    with no qualifiers.

    Raises:
        swh.model.exceptions.ValidationError: In case of invalid object type or id

    To get the raw SWHID string from an instance of this class,
    use the :func:`str` function:

    >>> swhid = CoreSWHID(
    ...     object_type=ObjectType.CONTENT,
    ...     object_id=bytes.fromhex('8ff44f081d43176474b267de5451f2c2e88089d0'),
    ... )
    >>> str(swhid)
    'swh:1:cnt:8ff44f081d43176474b267de5451f2c2e88089d0'

    And vice-versa with :meth:`CoreSWHID.from_string`:

    >>> swhid == CoreSWHID.from_string(
    ...     "swh:1:cnt:8ff44f081d43176474b267de5451f2c2e88089d0"
    ... )
    True
    """

    object_type = attr.ib(
        type=ObjectType, validator=type_validator(), converter=ObjectType
    )
    """the type of object the identifier points to"""

    def to_extended(self) -> ExtendedSWHID:
        """Converts this CoreSWHID into an ExtendedSWHID.

        As ExtendedSWHID is a superset of CoreSWHID, this is lossless."""
        return ExtendedSWHID(
            namespace=self.namespace,
            scheme_version=self.scheme_version,
            object_type=ExtendedObjectType(self.object_type.value),
            object_id=self.object_id,
        )


def _parse_core_swhid(swhid: Union[str, CoreSWHID, None]) -> Optional[CoreSWHID]:
    if swhid is None or isinstance(swhid, CoreSWHID):
        return swhid
    else:
        return CoreSWHID.from_string(swhid)


def _parse_lines_qualifier(
    lines: Union[str, Tuple[int, Optional[int]], None]
) -> Optional[Tuple[int, Optional[int]]]:
    try:
        if lines is None or isinstance(lines, tuple):
            return lines
        elif "-" in lines:
            (from_, to) = lines.split("-", 2)
            return (int(from_), int(to))
        else:
            return (int(lines), None)
    except ValueError:
        raise ValidationError(
            "Invalid format for the lines qualifier: %(lines)s", params={"lines": lines}
        )


def _parse_path_qualifier(path: Union[str, bytes, None]) -> Optional[bytes]:
    if path is None or isinstance(path, bytes):
        return path
    else:
        return urllib.parse.unquote_to_bytes(path)


@attr.s(frozen=True, kw_only=True, repr=False)
class QualifiedSWHID(_BaseSWHID[ObjectType]):
    """
    Dataclass holding the relevant info associated to a SoftWare Heritage
    persistent IDentifier (SWHID)

    Raises:
        swh.model.exceptions.ValidationError: In case of invalid object type or id

    To get the raw SWHID string from an instance of this class,
    use the :func:`str` function:

    >>> swhid = QualifiedSWHID(
    ...     object_type=ObjectType.CONTENT,
    ...     object_id=bytes.fromhex('8ff44f081d43176474b267de5451f2c2e88089d0'),
    ...     lines=(5, 10),
    ... )
    >>> str(swhid)
    'swh:1:cnt:8ff44f081d43176474b267de5451f2c2e88089d0;lines=5-10'

    And vice-versa with :meth:`QualifiedSWHID.from_string`:

    >>> swhid == QualifiedSWHID.from_string(
    ...     "swh:1:cnt:8ff44f081d43176474b267de5451f2c2e88089d0;lines=5-10"
    ... )
    True
    """

    object_type = attr.ib(
        type=ObjectType, validator=type_validator(), converter=ObjectType
    )
    """the type of object the identifier points to"""

    # qualifiers:

    origin = attr.ib(type=Optional[str], default=None, validator=type_validator())
    """the software origin where an object has been found or observed in the wild,
    as an URI"""

    visit = attr.ib(type=Optional[CoreSWHID], default=None, converter=_parse_core_swhid)
    """the core identifier of a snapshot corresponding to a specific visit
    of a repository containing the designated object"""

    anchor = attr.ib(
        type=Optional[CoreSWHID],
        default=None,
        validator=type_validator(),
        converter=_parse_core_swhid,
    )
    """a designated node in the Merkle DAG relative to which a path to the object
    is specified, as the core identifier of a directory, a revision, a release,
    or a snapshot"""

    path = attr.ib(
        type=Optional[bytes],
        default=None,
        validator=type_validator(),
        converter=_parse_path_qualifier,
    )
    """the absolute file path, from the root directory associated to the anchor node,
    to the object; when the anchor denotes a directory or a revision, and almost always
    when it’s a release, the root directory is uniquely determined;
    when the anchor denotes a snapshot, the root directory is the one pointed to by HEAD
    (possibly indirectly), and undefined if such a reference is missing"""

    lines = attr.ib(
        type=Optional[Tuple[int, Optional[int]]],
        default=None,
        validator=type_validator(),
        converter=_parse_lines_qualifier,
    )
    """lines: line number(s) of interest, usually within a content object"""

    @visit.validator
    def check_visit(self, attribute, value):
        if value and value.object_type != ObjectType.SNAPSHOT:
            raise ValidationError(
                "The 'visit' qualifier must be a 'snp' SWHID, not '%(type)s'",
                params={"type": value.object_type.value},
            )

    @anchor.validator
    def check_anchor(self, attribute, value):
        if value and value.object_type not in (
            ObjectType.DIRECTORY,
            ObjectType.REVISION,
            ObjectType.RELEASE,
            ObjectType.SNAPSHOT,
        ):
            raise ValidationError(
                "The 'visit' qualifier must be a 'dir', 'rev', 'rel', or 'snp' SWHID, "
                "not '%s(type)s'",
                params={"type": value.object_type.value},
            )

    def qualifiers(self) -> Dict[str, str]:
        origin = self.origin
        if origin:
            unescaped_origin = origin
            origin = origin.replace(";", "%3B")
            assert urllib.parse.unquote_to_bytes(
                origin
            ) == urllib.parse.unquote_to_bytes(
                unescaped_origin
            ), "Escaping ';' in the origin qualifier corrupted the origin URL."

        d: Dict[str, Optional[str]] = {
            "origin": origin,
            "visit": str(self.visit) if self.visit else None,
            "anchor": str(self.anchor) if self.anchor else None,
            "path": (
                urllib.parse.quote_from_bytes(self.path)
                if self.path is not None
                else None
            ),
            "lines": (
                "-".join(str(line) for line in self.lines if line is not None)
                if self.lines
                else None
            ),
        }
        return {k: v for (k, v) in d.items() if v is not None}

    def __str__(self) -> str:
        swhid = SWHID_SEP.join(
            [
                self.namespace,
                str(self.scheme_version),
                self.object_type.value,
                hash_to_hex(self.object_id),
            ]
        )
        qualifiers = self.qualifiers()
        if qualifiers:
            for k, v in qualifiers.items():
                swhid += "%s%s=%s" % (SWHID_CTXT_SEP, k, v)
        return swhid

    def __repr__(self) -> str:
        return super().__repr__()

    @classmethod
    def from_string(cls, s: str) -> QualifiedSWHID:
        parts = _parse_swhid(s)
        qualifiers = parts.pop("qualifiers")
        invalid_qualifiers = set(qualifiers) - SWHID_QUALIFIERS
        if invalid_qualifiers:
            raise ValidationError(
                "Invalid qualifier(s): %(qualifiers)s",
                params={"qualifiers": ", ".join(invalid_qualifiers)},
            )
        try:
            return QualifiedSWHID(**parts, **qualifiers)
        except ValueError as e:
            raise ValidationError(
                "ValueError: %(args)s", params={"args": e.args}
            ) from None


@attr.s(frozen=True, kw_only=True, repr=False)
class ExtendedSWHID(_BaseSWHID[ExtendedObjectType]):
    """
    Dataclass holding the relevant info associated to a SoftWare Heritage
    persistent IDentifier (SWHID).

    It extends  `CoreSWHID`, by allowing non-standard object types; and should
    only be used internally to Software Heritage.

    Raises:
        swh.model.exceptions.ValidationError: In case of invalid object type or id

    To get the raw SWHID string from an instance of this class,
    use the :func:`str` function:

    >>> swhid = ExtendedSWHID(
    ...     object_type=ExtendedObjectType.CONTENT,
    ...     object_id=bytes.fromhex('8ff44f081d43176474b267de5451f2c2e88089d0'),
    ... )
    >>> str(swhid)
    'swh:1:cnt:8ff44f081d43176474b267de5451f2c2e88089d0'

    And vice-versa with :meth:`CoreSWHID.from_string`:

    >>> swhid == ExtendedSWHID.from_string(
    ...     "swh:1:cnt:8ff44f081d43176474b267de5451f2c2e88089d0"
    ... )
    True
    """

    object_type = attr.ib(
        type=ExtendedObjectType,
        validator=type_validator(),
        converter=ExtendedObjectType,
    )
    """the type of object the identifier points to"""


def _parse_swhid(swhid: str) -> Dict[str, Any]:
    """Parse a Software Heritage identifier (SWHID) from string (see:
    :ref:`persistent-identifiers`.)

    This is for internal use; use :meth:`CoreSWHID.from_string`,
    :meth:`QualifiedSWHID.from_string`, or :meth:`ExtendedSWHID.from_string` instead,
    as they perform validation and build a dataclass.

    Args:
        swhid (str): A persistent identifier

    Raises:
        swh.model.exceptions.ValidationError: if passed string is not a valid SWHID

    """
    m = SWHID_RE.fullmatch(swhid)
    if not m:
        raise ValidationError(
            "Invalid SWHID: invalid syntax: %(swhid)s", params={"swhid": swhid}
        )
    parts: Dict[str, Any] = m.groupdict()

    qualifiers_raw = parts["qualifiers"]
    parts["qualifiers"] = {}
    if qualifiers_raw:
        for qualifier in qualifiers_raw.split(SWHID_CTXT_SEP):
            try:
                k, v = qualifier.split("=", maxsplit=1)
                parts["qualifiers"][k] = v
            except ValueError:
                raise ValidationError(
                    "Invalid SWHID: invalid qualifier: %(qualifier)s",
                    params={"qualifier": qualifier},
                )

    parts["scheme_version"] = int(parts["scheme_version"])
    parts["object_id"] = hash_to_bytes(parts["object_id"])
    return parts
