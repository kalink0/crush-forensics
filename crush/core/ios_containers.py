# SPDX-License-Identifier: Apache-2.0
"""iOS containers: the folders the mobile container manager creates are
named by a GUID, and each holds a metadata plist whose
MCMMetadataIdentifier names the container's owner: an app's bundle
identifier, an app group's or system group's identifier, an extension's
(PluginKit plugin's) identifier, or a system service's.

    …/Containers/Data/Application/<GUID>/.com.apple.mobile_container_manager.metadata.plist
    …/Containers/Shared/AppGroup/<GUID>/…
    …/Containers/Data/PluginKitPlugin/<GUID>/…
    …/Containers/Bundle/Application/<GUID>/…
    …/containers/Shared/SystemGroup/<GUID>/…  (and Data/System, Data/InternalDaemon)

Any folder that directly holds that plist is taken for a container,
wherever it is: the kinds of container differ between iOS versions.
"""
from __future__ import annotations

import plistlib

from crush.core.vfs import VFS, VFSNode

METADATA_PLIST = ".com.apple.mobile_container_manager.metadata.plist"
IDENTIFIER_KEY = "MCMMetadataIdentifier"

# A metadata plist is a few hundred bytes; anything far larger isn't one.
_MAX_PLIST_SIZE = 1024 * 1024


def metadata_plist(node: VFSNode) -> VFSNode | None:
    """The metadata plist of *node* when *node* is a container folder (one
    that directly holds the mobile container manager's metadata plist),
    else None."""
    if not node.is_dir:
        return None
    for child in node.children:
        if not child.is_dir and child.name == METADATA_PLIST:
            return child
    return None


def is_container(node: VFSNode) -> bool:
    return metadata_plist(node) is not None


def read_identifier(node: VFSNode, vfs: VFS) -> str | None:
    """MCMMetadataIdentifier of the container folder *node* (the identifier
    of the container's owner: app, group, extension or system service), or
    None when *node*
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
