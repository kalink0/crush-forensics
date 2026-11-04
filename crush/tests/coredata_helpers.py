# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Synthetic Core Data stores for the tests, built with sqlite3, plistlib
and zlib -- the layout follows what observed stores show (see
crush/parsers/coredata_store.py). No device data."""
from __future__ import annotations

import plistlib
import sqlite3
import uuid
import zlib
from pathlib import Path
from typing import Any

ASSET_UUID = uuid.UUID("7B085294-1111-4222-8333-944455556666")
DELETED_UUID = uuid.UUID("1FF60740-AAAA-4BBB-8CCC-DDDDEEEEFFFF")
EXTERNAL_NAME = "C101E52C-D5D7-4D9A-8077-101D8E71B5E5"
MISSING_NAME = "9738405E-23E6-4087-AF7F-A6B608480538"


class ArchiveBuilder:
    """A minimal NSKeyedArchiver writer: $objects with UIDs, class
    definitions once per class. Objects are dicts that can be filled in
    after they're referenced (the model graph is cyclic)."""

    def __init__(self) -> None:
        self.objects: list[Any] = ["$null"]
        self._classes: dict[str, plistlib.UID] = {}

    def add(self, obj: Any) -> plistlib.UID:
        self.objects.append(obj)
        return plistlib.UID(len(self.objects) - 1)

    def cls(self, name: str, chain: list[str] | None = None) -> plistlib.UID:
        if name not in self._classes:
            self._classes[name] = self.add({"$classname": name, "$classes": chain or [name, "NSObject"]})
        return self._classes[name]

    def obj(self, classname: str, **fields: Any) -> plistlib.UID:
        return self.add({**fields, "$class": self.cls(classname)})

    def get(self, uid: plistlib.UID) -> Any:
        return self.objects[uid.data]

    def array(self, items: list[Any], classname: str = "NSArray") -> plistlib.UID:
        return self.obj(classname, **{"NS.objects": items})

    def dictionary(self, keys: list[Any], values: list[Any], classname: str = "NSMutableDictionary") -> plistlib.UID:
        return self.obj(classname, **{"NS.keys": keys, "NS.objects": values})

    def build(self, root: plistlib.UID) -> bytes:
        archive = {
            "$archiver": "NSKeyedArchiver", "$version": 100000,
            "$top": {"root": root}, "$objects": self.objects,
        }
        return plistlib.dumps(archive, fmt=plistlib.FMT_BINARY, sort_keys=False)


NULL = plistlib.UID(0)

# (name, superentity, [attributes], [relationships])
# attribute: (name, NSAttributeType, NSFlagsKey)
# relationship: (name, destination, inverse, NSMaxCount, ordered)
ENTITIES: list[tuple[str, str | None, list[tuple[str, int, int]], list[tuple[str, str, str | None, int, bool]]]] = [
    ("GenericAlbum", None,
     [("title", 700, 0), ("trashedDate", 900, 0), ("uuid", 1100, 16), ("favorite", 800, 0)],
     [("assetsKey", "Asset", None, 1, False)]),
    ("Album", "GenericAlbum",
     [("maximumValue", 300, 0), ("name", 700, 16)],
     [("assets", "Asset", "albums", 0, True), ("parentFolder", "Folder", "childAlbums", 1, False)]),
    ("Folder", "GenericAlbum",
     [("maximumValue", 500, 0)],
     [("childAlbums", "Album", "parentFolder", 0, True)]),
    ("Asset", None,
     [("uuid", 1100, 16), ("dateCreated", 900, 0), ("filename", 700, 16), ("imageData", 1000, 4),
      ("title", 700, 0), ("weird", 4242, 0), ("hidden", 800, 0)],
     [("albums", "Album", "assets", 0, False), ("additional", "AdditionalAttributes", "asset", 1, False),
      ("contributors", "Contributor", None, 0, False)]),
    ("AdditionalAttributes", None, [("note", 700, 0)], [("asset", "Asset", "additional", 1, False)]),
    ("Contributor", None, [("email", 700, 0)], []),
]

Z_ENT = {
    "GenericAlbum": 1, "Album": 2, "Folder": 3, "Asset": 4, "AdditionalAttributes": 5, "Contributor": 6,
}


def model_archive(entities=ENTITIES, *, proxy_inherited: bool = False, unknown_class: bool = True) -> bytes:
    """The model as a keyed archive: NSEntities an NSKnownKeysDictionary1,
    subentities list inherited properties again (copies, or proxies)."""
    ab = ArchiveBuilder()
    model = ab.obj("NSManagedObjectModel")
    model_obj = ab.get(model)
    ent_uids: dict[str, plistlib.UID] = {}
    for name, _sup, _a, _r in entities:
        ent_uids[name] = ab.obj("NSEntityDescription", NSEntityName=name, NSManagedObjectModel=model)
    prop_uids: dict[tuple[str, str], plistlib.UID] = {}
    own: dict[str, list[tuple[str, plistlib.UID]]] = {}
    for name, _sup, attrs, rels in entities:
        own[name] = []
        for aname, atype, flags in attrs:
            uid = ab.obj(
                "NSAttributeDescription", NSPropertyName=aname, NSAttributeType=atype, NSFlagsKey=flags,
                NSEntity=ent_uids[name], NSIsOptional=True, _P=243,
                NSAttributeValueClassName="NSString" if atype == 700 else NULL,
                NSValueTransformerName=NULL, NSDefaultValue=NULL, NSRenamingIdentifier=aname,
            )
            prop_uids[(name, aname)] = uid
            own[name].append((aname, uid))
        for rname, dest, _inv, max_count, ordered in rels:
            fields = dict(
                NSPropertyName=rname, NSEntity=ent_uids[name], NSDestinationEntity=ent_uids[dest],
                NSMinCount=0, NSMaxCount=max_count, NSDeleteRule=1, _P=243,
                _NSDestinationEntityName=dest, NSIsOptional=True,
            )
            if ordered:
                fields["NSIsOrdered"] = True
            uid = ab.obj("NSRelationshipDescription", **fields)
            prop_uids[(name, rname)] = uid
            own[name].append((rname, uid))
    for name, _sup, _attrs, rels in entities:
        for rname, dest, inv, _m, _o in rels:
            rel = ab.get(prop_uids[(name, rname)])
            if inv:
                rel["NSInverseRelationship"] = prop_uids[(dest, inv)]
                rel["_NSInverseRelationshipName"] = inv
            else:
                rel["NSInverseRelationship"] = NULL
    if unknown_class:
        uid = ab.obj("NSSomeFutureDescription", NSPropertyName="futureThing", NSEntity=ent_uids["Contributor"])
        own["Contributor"].append(("futureThing", uid))
    by_name = {e[0]: e for e in entities}
    for name, sup, _a, _r in entities:
        listed = list(own[name])
        parent = sup
        while parent is not None:
            for pname, puid in own[parent]:
                if any(n == pname for n, _ in listed):
                    continue
                if proxy_inherited:
                    puid = ab.obj("_NSPropertyDescriptionProxy", NSUnderlyingProperty=puid,
                                  NSEntityDescription=ent_uids[name], NSReferenceID=1)
                listed.append((pname, puid))
            parent = by_name[parent][1]
        ent = ab.get(ent_uids[name])
        ent["NSProperties"] = ab.dictionary([n for n, _ in listed], [u for _, u in listed])
        subs = [e[0] for e in entities if e[1] == name]
        ent["NSSubentities"] = ab.dictionary(subs, [ent_uids[s] for s in subs])
        ent["NSSuperentity"] = ent_uids[sup] if sup else NULL
        ent["NSClassNameForEntity"] = NULL
        ent["NSUserInfo"] = ab.dictionary([], [], "NSDictionary")
        ent["NSFetchIndexDescriptions"] = ab.array([], "NSMutableArray")
        ent["NSCompoundIndexes"] = ab.array([], "NSMutableArray")
        ent["NSVersionHashModifier"] = NULL
        ent["NSRenamingIdentifier"] = name
    names = [e[0] for e in entities]
    keys = ab.array(names)
    mapping = ab.obj("NSKnownKeysMappingStrategy1", keys=keys, length=len(names), version=1)
    values = ab.array([ent_uids[n] for n in names])
    model_obj["NSEntities"] = ab.obj(
        "NSKnownKeysDictionary1", values=values, searchMapping=mapping, emptyToken="x", version=1,
    )
    model_obj["NSVersionIdentifiers"] = ab.array([], "NSSet")
    model_obj["NSFetchRequestTemplates"] = NULL
    return ab.build(model)


def deflate(data: bytes) -> bytes:
    co = zlib.compressobj(wbits=-15)
    return co.compress(data) + co.flush()


SCHEMA = [
    'CREATE TABLE Z_PRIMARYKEY (Z_ENT INTEGER PRIMARY KEY, Z_NAME VARCHAR, Z_SUPER INTEGER, Z_MAX INTEGER)',
    'CREATE TABLE Z_METADATA (Z_VERSION INTEGER PRIMARY KEY, Z_UUID VARCHAR(255), Z_PLIST BLOB)',
    'CREATE TABLE Z_MODELCACHE (Z_CONTENT BLOB)',
    'CREATE TABLE ZGENERICALBUM (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZFAVORITE INTEGER, '
    'ZMAXIMUMVALUE INTEGER, ZMAXIMUMVALUE1 FLOAT, ZPARENTFOLDER INTEGER, Z_FOK_PARENTFOLDER INTEGER, '
    'ZASSETSKEY INTEGER, ZTRASHEDDATE TIMESTAMP, ZTITLE VARCHAR, ZNAME VARCHAR, ZUUID VARCHAR)',
    'CREATE TABLE ZASSET (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZHIDDEN INTEGER, '
    'ZADDITIONAL INTEGER, ZDATECREATED TIMESTAMP, ZFILENAME VARCHAR, ZWEIRD INTEGER, ZUUID BLOB, ZIMAGEDATA BLOB, '
    'ZEXTRA BLOB)',
    'CREATE TABLE ZADDITIONALATTRIBUTES (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, '
    'ZASSET INTEGER, ZNOTE VARCHAR)',
    'CREATE TABLE ZCONTRIBUTOR (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, '
    'Z4CONTRIBUTORS INTEGER, ZEMAIL VARCHAR)',
    'CREATE TABLE Z_2ASSETS (Z_2ALBUMS INTEGER, Z_4ASSETS INTEGER, Z_FOK_4ASSETS INTEGER, '
    'PRIMARY KEY (Z_2ALBUMS, Z_4ASSETS))',
    'CREATE TABLE ACHANGE (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZCHANGETYPE INTEGER, '
    'ZENTITY INTEGER, ZENTITYPK INTEGER, ZTRANSACTIONID INTEGER, ZCOLUMNS BLOB, ZTOMBSTONE0 BLOB, '
    'ZTOMBSTONE1 BLOB, ZTOMBSTONE2 BLOB)',
    'CREATE TABLE ATRANSACTION (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZAUTHORTS INTEGER, '
    'ZBUNDLEIDTS INTEGER, ZCONTEXTNAMETS INTEGER, ZPROCESSIDTS INTEGER, ZTIMESTAMP FLOAT, ZAUTHOR VARCHAR, '
    'ZBUNDLEID VARCHAR, ZCONTEXTNAME VARCHAR, ZPROCESSID VARCHAR, ZQUERYGEN BLOB)',
    'CREATE TABLE ATRANSACTIONSTRING (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZNAME VARCHAR)',
    'CREATE TABLE ANSCKEVENT (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZCKRECORDNAME VARCHAR, '
    'ZSTARTEDAT TIMESTAMP)',
    'CREATE TABLE plain_notes (id INTEGER PRIMARY KEY, body TEXT, ref BLOB)',
]


def reference(name: str) -> bytes:
    return b"\x02" + name.encode("ascii") + b"\x00"


def build_store(
    path: Path,
    *,
    model: bytes | None | str = "default",
    proxy_inherited: bool = False,
    history: bool = True,
    asset_rows: int = 4,
    journal_mode: str = "delete",
) -> Path:
    """A store at *path* (any file name). *model*: "default", raw bytes for
    Z_MODELCACHE.Z_CONTENT, None for an empty Z_MODELCACHE, "drop" for no
    table at all."""
    conn = sqlite3.connect(path)
    conn.execute(f"PRAGMA journal_mode={journal_mode}")
    for sql in SCHEMA:
        conn.execute(sql)
    if not history:
        for table in ("ACHANGE", "ATRANSACTION", "ATRANSACTIONSTRING"):
            conn.execute(f"DROP TABLE {table}")
    pk_rows = [
        (1, "GenericAlbum", 0, 3), (2, "Album", 1, 0), (3, "Folder", 1, 0), (4, "Asset", 0, asset_rows + 7),
        (5, "AdditionalAttributes", 0, 1), (6, "Contributor", 0, 1),
        (16004, "NSCKEvent", 0, 1),
    ]
    if history:
        pk_rows += [(16001, "CHANGE", 0, 4), (16002, "TRANSACTION", 0, 2), (16003, "TRANSACTIONSTRING", 0, 2)]
    conn.executemany("INSERT INTO Z_PRIMARYKEY VALUES (?, ?, ?, ?)", pk_rows)
    meta = {
        "NSStoreType": "SQLite", "NSPersistenceFrameworkVersion": 1340,
        "NSStoreModelVersionHashes": {"Asset": b"\x01\x02\x03"},
        "VUIndex.inferredDeviceOwner": "owner@example.invalid",
    }
    conn.execute("INSERT INTO Z_METADATA VALUES (1, 'STORE-UUID', ?)", (plistlib.dumps(meta, fmt=plistlib.FMT_BINARY),))
    if model == "drop":
        conn.execute("DROP TABLE Z_MODELCACHE")
    elif model == "default":
        conn.execute("INSERT INTO Z_MODELCACHE VALUES (?)", (deflate(model_archive(proxy_inherited=proxy_inherited)),))
    elif model is not None:
        conn.execute("INSERT INTO Z_MODELCACHE VALUES (?)", (model,))
    # GenericAlbum (root row), Album, Folder; Album -> Folder 3 (ordered)
    conn.executemany(
        "INSERT INTO ZGENERICALBUM (Z_PK, Z_ENT, Z_OPT, ZFAVORITE, ZMAXIMUMVALUE, ZMAXIMUMVALUE1, ZPARENTFOLDER, "
        "Z_FOK_PARENTFOLDER, ZTRASHEDDATE, ZTITLE, ZNAME, ZUUID) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            (1, 1, 1, 1, None, None, None, None, 794000000, "Root", None, "U-1"),
            (2, 2, 1, 0, 42, None, 3, 1, 0, "Holiday", "holiday", "U-2"),
            (3, 3, 1, 7, None, 2.5, None, None, 794000000.5, "Folder", None, "U-3"),
        ],
    )
    image_data = {
        1: reference(EXTERNAL_NAME),            # reference, file present
        2: b"\x01\xff\xd8\xff\xe0JPEGDATA",      # inline value
        3: reference(MISSING_NAME),             # reference, no file
        4: b"\x02abc",                          # 0x02, not the reference shape
    }
    extra = {1: b"\x01notinline", 2: reference(EXTERNAL_NAME)}  # no property: not external storage
    asset_rows_data = []
    for i in range(1, asset_rows + 1):
        pk = i if i < 4 else i + 2  # keys 4 and 5 missing below the maximum
        asset_rows_data.append((
            pk, 4, 1, 1 if i % 2 else 0, 1 if i == 1 else (99 if i == 2 else None),
            786092798.4 if i == 1 else (786092798 if i == 2 else None),
            f"IMG_{i:04}.JPG", None, ASSET_UUID.bytes if i == 1 else (b"\x01\x02" if i == 2 else None),
            image_data.get(i), extra.get(i),
        ))
    conn.executemany(
        "INSERT INTO ZASSET (Z_PK, Z_ENT, Z_OPT, ZHIDDEN, ZADDITIONAL, ZDATECREATED, ZFILENAME, ZWEIRD, ZUUID, "
        "ZIMAGEDATA, ZEXTRA) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        asset_rows_data,
    )
    if asset_rows >= 3:
        # 2 is a gap below the maximum of Z_PK.
        conn.execute("UPDATE ZASSET SET ZHIDDEN = 5 WHERE Z_PK = 3")
    conn.execute("INSERT INTO ZADDITIONALATTRIBUTES VALUES (1, 5, 1, 1, 'note one')")
    conn.execute("INSERT INTO ZCONTRIBUTOR VALUES (1, 6, 1, 1, 'a@example.invalid')")
    conn.executemany("INSERT INTO Z_2ASSETS VALUES (?, ?, ?)", [(2, 1, 2), (2, 3, 1)])
    conn.execute("INSERT INTO ANSCKEVENT VALUES (1, 16004, 1, 'record-1', 786000000)")
    conn.execute("INSERT INTO plain_notes VALUES (1, 'hello', ?)", (reference(EXTERNAL_NAME),))
    if history:
        conn.executemany("INSERT INTO ATRANSACTIONSTRING VALUES (?, 16003, 1, ?)",
                         [(1, "com.example.app"), (2, "exampled")])
        conn.executemany(
            "INSERT INTO ATRANSACTION (Z_PK, Z_ENT, Z_OPT, ZAUTHORTS, ZBUNDLEIDTS, ZCONTEXTNAMETS, ZPROCESSIDTS, "
            "ZTIMESTAMP) VALUES (?, 16002, 1, ?, ?, ?, ?, ?)",
            [(1, None, 1, None, 2, 786092798.4), (2, None, 1, None, 2, 0)],
        )
        conn.executemany(
            "INSERT INTO ACHANGE (Z_PK, Z_ENT, Z_OPT, ZCHANGETYPE, ZENTITY, ZENTITYPK, ZTRANSACTIONID, ZCOLUMNS, "
            "ZTOMBSTONE0, ZTOMBSTONE1, ZTOMBSTONE2) VALUES (?, 16001, 1, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 0, 4, 1, 1, None, None, None, None),                       # insert, still there
                (2, 1, 2, 2, 1, b"\x05\x01", None, None, None),                 # update: bits 0, 2, 8
                (3, 2, 4, 9, 2, None, "IMG_0009.JPG", DELETED_UUID.bytes, "x"),  # delete: filename, uuid, beyond
                (4, 2, 2, 8, 2, None, 12345, "U-8", None),                      # delete Album: name gets int
            ],
        )
    conn.commit()
    conn.close()
    return path
