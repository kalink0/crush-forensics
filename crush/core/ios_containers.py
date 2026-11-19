# SPDX-License-Identifier: Apache-2.0
"""iOS data containers: the folders an app's data (or an app group's
shared data) lives in are named by a GUID; the app's bundle identifier
(or the group identifier) is in the folder's metadata plist written by
the mobile container manager, under MCMMetadataIdentifier.

    …/Containers/Data/Application/<GUID>/.com.apple.mobile_container_manager.metadata.plist
    …/Containers/Shared/AppGroup/<GUID>/.com.apple.mobile_container_manager.metadata.plist
"""
from __future__ import annotations

import plistlib

from crush.core.vfs import VFS, VFSNode

METADATA_PLIST = ".com.apple.mobile_container_manager.metadata.plist"
IDENTIFIER_KEY = "MCMMetadataIdentifier"

# The folders whose child folders are containers (compared case-insensitively).
_CONTAINER_PARENTS: tuple[tuple[str, str, str], ...] = (
    ("containers", "data", "application"),
    ("containers", "shared", "appgroup"),
)

# A metadata plist is a few hundred bytes; anything far larger isn't one.
_MAX_PLIST_SIZE = 1024 * 1024


def metadata_plist(node: VFSNode) -> VFSNode | None:
    """The metadata plist of *node* when *node* is an App or AppGroup
    container folder, else None."""
    if not node.is_dir:
        return None
    parts = [p for p in node.path.replace("\\", "/").split("/") if p]
    if len(parts) < 4 or tuple(p.lower() for p in parts[-4:-1]) not in _CONTAINER_PARENTS:
        return None
    for child in node.children:
        if not child.is_dir and child.name == METADATA_PLIST:
            return child
    return None


def is_container(node: VFSNode) -> bool:
    return metadata_plist(node) is not None


def read_identifier(node: VFSNode, vfs: VFS) -> str | None:
    """MCMMetadataIdentifier of the container folder *node* (the app's
    bundle identifier or the app group's identifier), or None when *node*
    is no container or its plist doesn't give one. Reads from the source:
    not for the UI thread."""
    plist_node = metadata_plist(node)
    if plist_node is None or plist_node.size > _MAX_PLIST_SIZE:
        return None
    try:
        data = plistlib.loads(vfs.read(plist_node))
    except Exception:  # noqa: BLE001 -- unreadable or no plist: no identifier
        return None
    if not isinstance(data, dict):
        return None
    identifier = data.get(IDENTIFIER_KEY)
    if not isinstance(identifier, str) or not identifier.strip():
        return None
    return identifier.strip()
