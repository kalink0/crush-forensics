# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Apple Core Data stores on SQLite: detection, the managed object model and
everything the Core Data views show, read without Qt.

Apple does not document this layout. Everything here that goes beyond the
public NSAttributeType enum is interpreted from observed stores, and the
parts that rest on a naming convention or an observed ordering say so in
their status (see the mapping, relationship and tombstone statuses).

Layout as observed:
- A store has the tables Z_PRIMARYKEY (Z_ENT, Z_NAME, Z_SUPER, Z_MAX) and
  Z_METADATA (Z_VERSION, Z_UUID, Z_PLIST).
- Z_MODELCACHE.Z_CONTENT holds the model: raw deflate, then a binary
  NSKeyedArchiver plist with root class NSManagedObjectModel. A compiled
  .mom file holds the same archive uncompressed.
- A root entity's rows are in table Z<NAME> (A<NAME> for Core Data's own
  entities such as the persistent history); a subentity shares its root's
  table, and Z_ENT in a row gives its concrete entity.

The model's object graph is cyclic (an entity lists its properties, each
property points back at its entity), so it is walked directly by UID here
instead of being resolved into a tree.
"""
from __future__ import annotations

import plistlib
import re
import uuid
import zlib
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from crush.core.issues import ParseIssue
from crush.parsers.nska_archive import is_keyed_archive, root_class, uid_index

# NSAttributeType, Apple's public enum (NSAttributeDescription.h).
ATTRIBUTE_TYPES: dict[int, str] = {
    0: "undefined",
    100: "int16",
    200: "int32",
    300: "int64",
    400: "decimal",
    500: "double",
    600: "float",
    700: "string",
    800: "boolean",
    900: "date",
    1000: "binary",
    1100: "UUID",
    1200: "URI",
    1800: "transformable",
    2000: "objectID",
    2100: "composite",
}
TYPE_BOOLEAN = 800
TYPE_DATE = 900
TYPE_BINARY = 1000
TYPE_UUID = 1100
TYPE_TRANSFORMABLE = 1800

# NSFlagsKey values seen on attributes (observed, not documented):
# 4 on the attributes whose values can be stored outside the database,
# 16 on the attributes whose values a delete keeps as tombstones.
FLAG_EXTERNAL = 4
FLAG_TOMBSTONE = 16

# Model class -> property kind shown to the analyst.
_PROPERTY_KINDS = {
    "NSAttributeDescription": "attribute",
    "NSDerivedAttributeDescription": "derived attribute",
    "NSCompositeAttributeDescription": "composite attribute",
    "NSRelationshipDescription": "relationship",
    "NSFetchedPropertyDescription": "fetched property",
    "NSExpressionDescription": "expression",
}
_ATTRIBUTE_KINDS = ("attribute", "derived attribute", "composite attribute")

# Classes whose objects are model parts of their own: the detail pane shows
# a reference to them instead of expanding them inside another object.
_DESCRIPTION_CLASSES = frozenset({
    "NSManagedObjectModel", "NSEntityDescription", *_PROPERTY_KINDS,
})

METADATA_TABLE = "Z_METADATA"
PRIMARYKEY_TABLE = "Z_PRIMARYKEY"
MODELCACHE_TABLE = "Z_MODELCACHE"
_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (PRIMARYKEY_TABLE, ("Z_ENT", "Z_NAME", "Z_SUPER", "Z_MAX")),
    (METADATA_TABLE, ("Z_VERSION", "Z_UUID", "Z_PLIST")),
)
_NULL = "$null"


def quote_ident(name: str) -> str:
    """*name* as an SQLite identifier, whatever characters it holds."""
    return '"' + name.replace('"', '""') + '"'


def table_columns(conn: Any, table: str) -> list[tuple[str, str]]:
    """(name, declared type) of every column of *table*, in table order."""
    rows = conn.execute(f"PRAGMA table_info({quote_ident(table)})").fetchall()
    return [(str(r[1]), str(r[2] or "")) for r in rows]


def schema_tables(conn: Any) -> list[str]:
    return [
        str(r[0]) for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
    ]


# -- Detection ---------------------------------------------------------------


@dataclass(frozen=True)
class Detection:
    """Which Core Data markers the database has. *detected*: all of them;
    *missing*: what's absent when only part is there (then no Core Data
    view is offered, and the status names it)."""

    detected: bool
    present: tuple[str, ...]
    missing: tuple[str, ...]

    @property
    def partial(self) -> bool:
        return not self.detected and bool(self.present)

    def status(self) -> ParseIssue | None:
        if self.detected:
            return None
        if self.partial:
            return ParseIssue("coredata.detection_incomplete", {
                "present": ", ".join(self.present), "missing": ", ".join(self.missing),
            })
        return None


def detect(conn: Any) -> Detection:
    """Both marker tables with their columns, by the schema alone -- never
    by the file's name."""
    tables = {t.upper(): t for t in schema_tables(conn)}
    present: list[str] = []
    missing: list[str] = []
    for table, columns in _MARKERS:
        actual = tables.get(table)
        if actual is None:
            missing.append(table)
            continue
        present.append(table)
        have = {name.upper() for name, _ in table_columns(conn, actual)}
        for column in columns:
            if column in have:
                present.append(f"{table}.{column}")
            else:
                missing.append(f"{table}.{column}")
    return Detection(detected=not missing, present=tuple(present), missing=tuple(missing))


# -- The model ---------------------------------------------------------------


@dataclass
class ModelProperty:
    """One entry of an entity's NSProperties, as stored. *kind* is the
    class's kind ("attribute", "relationship", ...) or, for a class this
    reader doesn't know, the class name itself (*known_class* False)."""

    index: int
    class_name: str
    kind: str
    known_class: bool
    name: str
    entity: str
    attribute_type: int | None = None
    value_class: str | None = None
    transformer: str | None = None
    flags: int | None = None
    optional: bool | None = None
    p_value: Any = None
    destination: str | None = None
    inverse: str | None = None
    min_count: int | None = None
    max_count: int | None = None
    delete_rule: int | None = None
    ordered: bool | None = None
    # Set when the entity lists the property through a proxy object (seen:
    # _NSPropertyDescriptionProxy for an inherited property): the proxy's
    # class, and the `$objects` index of the property it stands for.
    via_class: str | None = None
    underlying_index: int | None = None

    @property
    def is_attribute(self) -> bool:
        return self.kind in _ATTRIBUTE_KINDS

    @property
    def is_relationship(self) -> bool:
        return self.kind == "relationship"

    @property
    def to_many(self) -> bool:
        """NSMaxCount 1 is to-one; 0 (no limit) or more is to-many."""
        return self.max_count != 1

    def type_name(self) -> str | None:
        if self.attribute_type is None:
            return None
        return ATTRIBUTE_TYPES.get(self.attribute_type)

    def has_flag(self, flag: int) -> bool:
        return isinstance(self.flags, int) and bool(self.flags & flag)

    def delete_rule_text(self) -> str:
        if self.delete_rule is None:
            return ""
        return f"{DELETE_RULES.get(self.delete_rule, 'unknown')} ({self.delete_rule})"


@dataclass
class ModelEntity:
    index: int
    name: str
    superentity: str | None
    subentities: list[str] = field(default_factory=list)
    properties: list[ModelProperty] = field(default_factory=list)
    class_name: str | None = None
    abstract: bool | None = None


@dataclass
class CoreDataModel:
    """The managed object model read from one archive. *entities* by name,
    in archive order; *objects* the archive's `$objects` as stored, for the
    detail pane; *issues* what couldn't be read."""

    entities: dict[str, ModelEntity]
    objects: list[Any]
    root_index: int | None
    issues: list[ParseIssue] = field(default_factory=list)
    # Objects of a property class no entity's NSProperties reaches.
    unattached: list[ModelProperty] = field(default_factory=list)

    def entity(self, name: str | None) -> ModelEntity | None:
        return self.entities.get(name) if name is not None else None

    def chain(self, name: str) -> list[ModelEntity]:
        """*name* and its superentities, the entity itself first."""
        result: list[ModelEntity] = []
        seen: set[str] = set()
        current = self.entities.get(name)
        while current is not None and current.name not in seen:
            seen.add(current.name)
            result.append(current)
            current = self.entities.get(current.superentity) if current.superentity else None
        return result

    def all_properties(self, name: str) -> list[ModelProperty]:
        """The entity's own properties and every inherited one, once per
        name: a subentity's NSProperties lists the inherited ones again
        (as copies, or as proxies), the entity's own entry wins."""
        props: list[ModelProperty] = []
        seen: set[str] = set()
        for ent in self.chain(name):
            for prop in ent.properties:
                if prop.name not in seen:
                    seen.add(prop.name)
                    props.append(prop)
        return props

    def declared_in(self, entity: str, prop_name: str) -> str:
        """The topmost entity in *entity*'s superentity chain that lists a
        property called *prop_name* (*entity* itself when none above does)."""
        found = entity
        for ent in self.chain(entity):
            if any(p.name == prop_name for p in ent.properties):
                found = ent.name
        return found

    def descendants(self, name: str) -> list[str]:
        """Every entity below *name* (not *name* itself)."""
        out: list[str] = []
        pending = list(reversed(self.entities[name].subentities)) if name in self.entities else []
        seen: set[str] = {name}
        while pending:
            sub = pending.pop()
            if sub in seen:
                continue
            seen.add(sub)
            out.append(sub)
            ent = self.entities.get(sub)
            if ent is not None:
                pending.extend(reversed(ent.subentities))
        return out

    def property_rows(self) -> list[ModelProperty]:
        rows = [p for ent in self.entities.values() for p in ent.properties]
        return rows + self.unattached


class _Archive:
    """`$objects` with UID lookups that never raise: a reference that points
    nowhere is None."""

    def __init__(self, objects: list[Any]) -> None:
        self.objects = objects

    def get(self, value: Any) -> Any:
        index = uid_index(value)
        if index is None:
            return value
        if not 0 <= index < len(self.objects):
            return None
        obj = self.objects[index]
        return None if obj == _NULL else obj

    def class_name(self, obj: Any) -> str | None:
        if not isinstance(obj, dict) or "$class" not in obj:
            return None
        definition = self.get(obj["$class"])
        if isinstance(definition, dict):
            name = definition.get("$classname")
            return str(name) if name is not None else None
        return None

    def text(self, value: Any) -> str | None:
        obj = self.get(value)
        if isinstance(obj, str):
            return obj
        if isinstance(obj, dict) and "NS.string" in obj:
            inner = obj.get("NS.string")
            return inner if isinstance(inner, str) else None
        return None

    def items(self, value: Any) -> list[tuple[Any, Any]]:
        """(key, value) pairs of a collection, as UIDs or plain values: an
        NSArray/NSSet (key None), an NSDictionary, or Core Data's
        NSKnownKeysDictionary1 (keys in its searchMapping)."""
        obj = self.get(value)
        if not isinstance(obj, dict):
            return []
        if "NS.objects" in obj:
            stored = obj.get("NS.objects")
            values: list[Any] = stored if isinstance(stored, list) else []
            stored_keys = obj.get("NS.keys")
            if isinstance(stored_keys, list):
                return list(zip(stored_keys, values))
            return [(None, v) for v in values]
        if "values" in obj and "searchMapping" in obj:
            values = self._list(obj.get("values"))
            mapping = self.get(obj.get("searchMapping"))
            keys = self._list(mapping.get("keys")) if isinstance(mapping, dict) else []
            if len(keys) == len(values):
                return list(zip(keys, values))
            return [(None, v) for v in values]
        return []

    def _list(self, value: Any) -> list[Any]:
        """The items of an array, whether referenced (an NSArray object) or
        stored inline as a plain list."""
        obj = self.get(value)
        if isinstance(obj, dict):
            return [v for _, v in self.items(value)]
        return obj if isinstance(obj, list) else []


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _bool_or_none(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    return None


def parse_model_archive(raw: bytes) -> tuple[CoreDataModel | None, list[ParseIssue]]:
    """The model in *raw* (an NSKeyedArchiver plist, binary or XML).
    Returns (model, issues); model is None when there's none to read."""
    try:
        archive = plistlib.loads(raw)
    except Exception as exc:  # noqa: BLE001 -- plistlib raises several kinds
        return None, [ParseIssue("coredata.model_plist_unreadable", detail=str(exc))]
    if not is_keyed_archive(archive):
        return None, [ParseIssue("coredata.model_not_keyed_archive")]
    objects = archive.get("$objects")
    if not isinstance(objects, list):
        return None, [ParseIssue("coredata.model_not_keyed_archive")]
    issues: list[ParseIssue] = []
    root_name = root_class(archive)
    if root_name != "NSManagedObjectModel":
        issues.append(ParseIssue("coredata.model_root_class", {"found": root_name}))
    ar = _Archive(objects)
    top = archive.get("$top")
    root_index = uid_index(top.get("root")) if isinstance(top, dict) else None
    root = ar.get(top.get("root")) if isinstance(top, dict) else None

    entity_indexes: list[int] = []
    if isinstance(root, dict):
        for _key, value in ar.items(root.get("NSEntities")):
            index = uid_index(value)
            if index is not None:
                entity_indexes.append(index)
    # Entity descriptions anywhere in the archive count too, so none is lost
    # when the root's collection is unreadable.
    listed = set(entity_indexes)
    stray = [
        i for i, obj in enumerate(objects)
        if i not in listed and ar.class_name(obj) == "NSEntityDescription"
    ]
    if stray:
        issues.append(ParseIssue("coredata.model_entities_unlisted", {"count": len(stray)}))
    entities: dict[str, ModelEntity] = {}
    attached: set[int] = set()
    for index in entity_indexes + stray:
        obj = objects[index] if 0 <= index < len(objects) else None
        if not isinstance(obj, dict):
            continue
        name = ar.text(obj.get("NSEntityName")) or f"#{index}"
        superentity = ar.get(obj.get("NSSuperentity"))
        super_name = ar.text(superentity.get("NSEntityName")) if isinstance(superentity, dict) else None
        entity = ModelEntity(
            index=index,
            name=name,
            superentity=super_name,
            class_name=ar.text(obj.get("NSClassNameForEntity")),
            abstract=_bool_or_none(obj.get("NSIsAbstract")),
        )
        for key, value in ar.items(obj.get("NSSubentities")):
            sub = ar.get(value)
            sub_name = ar.text(sub.get("NSEntityName")) if isinstance(sub, dict) else None
            if sub_name is None:
                sub_name = ar.text(key)
            if sub_name:
                entity.subentities.append(sub_name)
        for key, value in ar.items(obj.get("NSProperties")):
            prop_index = uid_index(value)
            if prop_index is None:
                continue
            attached.add(prop_index)
            prop = _read_property(ar, prop_index, entity.name, fallback_name=ar.text(key))
            if prop.underlying_index is not None:
                attached.add(prop.underlying_index)
            entity.properties.append(prop)
        if name in entities:
            issues.append(ParseIssue("coredata.model_duplicate_entity", {"name": name}))
            name = f"{name} (#{index})"
            entity.name = name
        entities[name] = entity
    # Property objects no entity lists: still shown, never dropped.
    unattached = [
        _read_property(ar, i, ar_entity_name(ar, obj), fallback_name=None)
        for i, obj in enumerate(objects)
        if i not in attached and ar.class_name(obj) in _PROPERTY_KINDS
        and ar.class_name(obj) != "NSExpressionDescription"
    ]
    model = CoreDataModel(
        entities=entities, objects=objects, root_index=root_index,
        issues=issues, unattached=unattached,
    )
    for prop in model.property_rows():
        if prop.is_attribute and prop.attribute_type is not None and (
            prop.attribute_type not in ATTRIBUTE_TYPES
        ):
            issues.append(ParseIssue("coredata.unknown_attribute_type", {
                "entity": prop.entity, "property": prop.name, "type": prop.attribute_type,
            }))
        if not prop.known_class:
            issues.append(ParseIssue("coredata.model_unknown_class", {
                "entity": prop.entity, "property": prop.name, "class_name": prop.class_name,
            }))
    return model, issues


def ar_entity_name(ar: _Archive, obj: Any) -> str:
    entity = ar.get(obj.get("NSEntity")) if isinstance(obj, dict) else None
    return (ar.text(entity.get("NSEntityName")) if isinstance(entity, dict) else None) or ""


# A proxy an entity lists in place of a property it inherits: the property
# itself is NSUnderlyingProperty (observed in newer models).
_PROXY_CLASSES = frozenset({"_NSPropertyDescriptionProxy"})


def _read_property(ar: _Archive, index: int, entity: str, fallback_name: str | None) -> ModelProperty:
    obj = ar.objects[index] if 0 <= index < len(ar.objects) else None
    class_name = ar.class_name(obj) or (type(obj).__name__ if obj is not None else "?")
    via_class: str | None = None
    underlying_index: int | None = None
    if class_name in _PROXY_CLASSES and isinstance(obj, dict):
        target_index = uid_index(obj.get("NSUnderlyingProperty"))
        target = ar.get(obj.get("NSUnderlyingProperty"))
        target_class = ar.class_name(target)
        if target_index is not None and isinstance(target, dict) and target_class:
            via_class, underlying_index = class_name, target_index
            obj, class_name = target, target_class
    kind = _PROPERTY_KINDS.get(class_name)
    if not isinstance(obj, dict):
        obj = {}
    name = ar.text(obj.get("NSPropertyName")) or fallback_name or f"#{index}"
    prop = ModelProperty(
        index=index,
        class_name=class_name,
        kind=kind or class_name,
        known_class=kind is not None,
        name=name,
        entity=entity,
        optional=_bool_or_none(ar.get(obj.get("NSIsOptional"))),
        p_value=obj.get("_P"),
        via_class=via_class,
        underlying_index=underlying_index,
    )
    if "NSAttributeType" in obj:
        prop.attribute_type = _int_or_none(ar.get(obj.get("NSAttributeType")))
    prop.value_class = ar.text(obj.get("NSAttributeValueClassName"))
    prop.transformer = ar.text(obj.get("NSValueTransformerName"))
    if "NSFlagsKey" in obj:
        prop.flags = _int_or_none(ar.get(obj.get("NSFlagsKey")))
    if kind == "relationship" or "NSDestinationEntity" in obj:
        dest = ar.get(obj.get("NSDestinationEntity"))
        prop.destination = (
            ar.text(dest.get("NSEntityName")) if isinstance(dest, dict) else None
        ) or ar.text(obj.get("_NSDestinationEntityName"))
        inverse = ar.get(obj.get("NSInverseRelationship"))
        prop.inverse = (
            ar.text(inverse.get("NSPropertyName")) if isinstance(inverse, dict) else None
        ) or ar.text(obj.get("_NSInverseRelationshipName"))
        prop.min_count = _int_or_none(ar.get(obj.get("NSMinCount")))
        prop.max_count = _int_or_none(ar.get(obj.get("NSMaxCount")))
        prop.delete_rule = _int_or_none(ar.get(obj.get("NSDeleteRule")))
        prop.ordered = _bool_or_none(ar.get(obj.get("NSIsOrdered")))
    return prop


# NSDeleteRule (NSRelationshipDescription.h): public enum.
DELETE_RULES = {0: "no action", 1: "nullify", 2: "cascade", 3: "deny"}


@dataclass
class DetailNode:
    """One stored key of a model object for the detail pane: *value* is the
    value's text, *class_name* its class when it's an object, *ref* the
    `$objects` index it points to (None for a plain value)."""

    key: str
    value: str
    class_name: str = ""
    ref: int | None = None
    children: list[DetailNode] = field(default_factory=list)


def describe_object(model: CoreDataModel, index: int) -> list[DetailNode]:
    """Every key the object at *index* stores, nested values expanded. Model
    descriptions (entities, properties, the model) inside it are shown as a
    reference, not expanded; a value that leads back to an object already
    being shown is marked as such instead of repeating it."""
    ar = _Archive(model.objects)
    obj = model.objects[index] if 0 <= index < len(model.objects) else None
    if not isinstance(obj, dict):
        return [DetailNode("value", _plain_text(obj))]
    return _describe_fields(ar, obj, path={index})


def _plain_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.hex(" ")
    if value == _NULL:
        return "nil"
    return repr(value) if isinstance(value, str) else str(value)


def _describe_fields(ar: _Archive, obj: dict[str, Any], path: set[int]) -> list[DetailNode]:
    nodes: list[DetailNode] = []
    for key, value in obj.items():
        if key == "$class":
            nodes.append(DetailNode(key, ar.class_name(obj) or "?"))
            continue
        nodes.append(_describe_value(ar, str(key), value, path))
    return nodes


def _describe_value(ar: _Archive, key: str, value: Any, path: set[int]) -> DetailNode:
    index = uid_index(value)
    if index is None:
        if isinstance(value, list):
            node = DetailNode(key, f"[{len(value)}]")
            node.children = [_describe_value(ar, f"[{i}]", v, path) for i, v in enumerate(value)]
            return node
        if isinstance(value, dict):
            node = DetailNode(key, f"{{{len(value)}}}")
            node.children = [_describe_value(ar, str(k), v, path) for k, v in value.items()]
            return node
        return DetailNode(key, _plain_text(value))
    if not 0 <= index < len(ar.objects):
        return DetailNode(key, f"→ #{index} (beyond $objects)", ref=index)
    obj = ar.objects[index]
    if obj == _NULL:
        return DetailNode(key, "nil", ref=index)
    class_name = ar.class_name(obj)
    if class_name is None:
        return DetailNode(key, _plain_text(obj), ref=index)
    label = _object_label(ar, obj, class_name)
    if index in path:
        return DetailNode(key, f"↺ {label} (#{index}, already shown above)", class_name, index)
    if class_name in _DESCRIPTION_CLASSES:
        return DetailNode(key, f"→ {label} (#{index})", class_name, index)
    node = DetailNode(key, f"{label} (#{index})", class_name, index)
    items = ar.items(value)
    if items or "NS.objects" in obj:
        node.value = f"{label} (#{index}) [{len(items)}]"
        node.children = [
            _describe_value(
                ar, ar.text(k) or (_plain_text(k) if k is not None else f"[{i}]"), v, path | {index}
            )
            for i, (k, v) in enumerate(items)
        ]
        return node
    if "NS.string" in obj:
        node.value = repr(ar.text(value))
        return node
    node.children = _describe_fields(ar, obj, path | {index})
    return node


def _object_label(ar: _Archive, obj: dict[str, Any], class_name: str) -> str:
    name = ar.text(obj.get("NSEntityName")) or ar.text(obj.get("NSPropertyName"))
    return f"{class_name} {name!r}" if name else class_name


# -- Tables and columns ------------------------------------------------------


@dataclass(frozen=True)
class EntityInfo:
    """One Z_PRIMARYKEY row, with the table its rows are in."""

    ent: int
    name: str
    super_ent: int
    max_pk: Any
    root_ent: int
    table: str | None
    table_status: ParseIssue | None


@dataclass(frozen=True)
class ColumnLink:
    """Which columns a property's values may be in, from the naming
    convention Z + uppercase name -- a heuristic: *status* is "name match"
    (one column, no numbered sibling), "ambiguous" (all *candidates*, none
    chosen) or "no column found"."""

    status: str
    candidates: tuple[str, ...]

    @property
    def column(self) -> str | None:
        return self.candidates[0] if self.status == MAP_NAME_MATCH else None


MAP_NAME_MATCH = "name match"
MAP_AMBIGUOUS = "ambiguous"
MAP_NO_COLUMN = "no column found"


def link_columns(
    name: str, columns: Iterable[str], exact_names_in_table: set[str], prefix: str = "Z"
) -> ColumnLink:
    """Candidate columns for a property called *name*: prefix + uppercase
    name, and the same with a number appended (Core Data numbers columns
    whose names collide). A numbered column that is itself another
    property's exact name (in *exact_names_in_table*) is that property's,
    not a candidate."""
    exact = (prefix + name).upper()
    numbered_re = re.compile(re.escape(exact) + r"\d+")
    upper = {c.upper(): c for c in columns}
    numbered = [
        actual for up, actual in upper.items()
        if numbered_re.fullmatch(up) and up not in exact_names_in_table
    ]
    if exact in upper and not numbered:
        return ColumnLink(MAP_NAME_MATCH, (upper[exact],))
    if exact in upper or numbered:
        found = ([upper[exact]] if exact in upper else []) + sorted(numbered, key=_natural_key)
        return ColumnLink(MAP_AMBIGUOUS, tuple(found))
    return ColumnLink(MAP_NO_COLUMN, ())


def _natural_key(text: str) -> tuple[Any, ...]:
    return tuple(int(p) if p.isdigit() else p for p in re.split(r"(\d+)", text))


# -- Values ------------------------------------------------------------------

COCOA_FORMAT = "mac_abs"  # crush.core.ts_decode: seconds since 2001-01-01 UTC
DECODE_DATE = "date"
DECODE_BOOLEAN = "boolean"
DECODE_UUID = "UUID"


def is_timestamp_column(table: str, column: str, declared: str) -> bool:
    """Decision of the Core Data views: a column declared TIMESTAMP, and
    ATRANSACTION.ZTIMESTAMP (declared FLOAT in every observed store, its
    values Cocoa seconds), are read as Cocoa dates."""
    if declared.strip().upper().startswith("TIMESTAMP"):
        return True
    return table.upper() == "ATRANSACTION" and column.upper() == "ZTIMESTAMP"


def decode_value(kind: str, value: Any) -> tuple[str | None, ParseIssue | None]:
    """*value* read as *kind* (DECODE_DATE/_BOOLEAN/_UUID): (text, status).
    text None means it's shown as stored; status says why, when it doesn't
    fit the kind (or, for a date stored as 0, what that value is)."""
    from crush.core.ts_decode import decode_cell

    if value is None:
        return None, None
    if kind == DECODE_DATE:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None, ParseIssue("coredata.value_not_date", {"type": _storage_class(value)})
        text, problem = decode_cell(value, COCOA_FORMAT)
        if text is None:
            return None, problem or ParseIssue("coredata.value_not_date", {
                "type": _storage_class(value),
            })
        if value == 0:
            return text, ParseIssue("coredata.date_zero")
        return text, None
    if kind == DECODE_BOOLEAN:
        if isinstance(value, int) and not isinstance(value, bool) and value in (0, 1):
            return ("true" if value else "false"), None
        return None, ParseIssue("coredata.value_not_boolean", {"value": _short_repr(value)})
    if kind == DECODE_UUID:
        if isinstance(value, (bytes, bytearray, memoryview)):
            data = bytes(value)
            if len(data) == 16:
                return str(uuid.UUID(bytes=data)).upper(), None
            return None, ParseIssue("coredata.value_not_uuid", {"length": len(data)})
        return None, None  # stored as text (seen on VARCHAR columns): as stored
    return None, None


def _storage_class(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, (bytes, bytearray, memoryview)):
        return "BLOB"
    if isinstance(value, str):
        return "TEXT"
    if isinstance(value, float):
        return "REAL"
    return "INTEGER"


def _short_repr(value: Any) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"BLOB {len(bytes(value)):,} B"
    return repr(value)


def value_text(value: Any) -> str:
    """A stored value as the grid shows it."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<BLOB {len(bytes(value)):,} B>"
    return str(value)


# -- Externally stored values ------------------------------------------------

_UUID_TEXT = re.compile(rb"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
REFERENCE_LENGTH = 38
EXTERNAL_DATA_FOLDER = "_EXTERNAL_DATA"


def external_reference(value: Any) -> str | None:
    """The file name an external-value reference names: exactly 38 bytes,
    0x02 + a 36-character UUID + 0x00 (the only shape observed). None for
    anything else -- the first byte alone means nothing."""
    if not isinstance(value, (bytes, bytearray, memoryview)):
        return None
    data = bytes(value)
    if len(data) != REFERENCE_LENGTH or data[0] != 0x02 or data[-1] != 0x00:
        return None
    body = data[1:-1]
    if not _UUID_TEXT.fullmatch(body):
        return None
    return body.decode("ascii")


def inline_shape(value: Any) -> bool:
    """An external-storage attribute's value kept in the database: 0x01 +
    the content (observed shape)."""
    if not isinstance(value, (bytes, bytearray, memoryview)):
        return False
    data = bytes(value)
    return len(data) >= 1 and data[0] == 0x01


def support_folder_name(store_name: str) -> str:
    """"." + the store's file name without its last extension + "_SUPPORT"
    (observed next to ThreemaData.sqlite and CNContactMetadata.db)."""
    stem = store_name.rsplit(".", 1)[0] if "." in store_name.lstrip(".") else store_name
    return f".{stem}_SUPPORT"


@dataclass(frozen=True)
class SupportFile:
    """One file in the store's _SUPPORT folder: *rel_path* below the folder."""

    rel_path: str
    size: int
    status: Any = None


class SupportFolder:
    """The store's _SUPPORT folder as found (or not) in the source. *state*:
    "found", "not_found" (the store's own folder is in the source, this one
    isn't) or "unavailable" (the source doesn't hold the store's folder at
    all, e.g. a store file opened on its own). Files are read through
    *reader* -- the VFS the store came from, or the filesystem."""

    def __init__(
        self,
        state: str,
        location: str,
        files: list[SupportFile] | None = None,
        reader: Callable[[str], bytes] | None = None,
        head_reader: Callable[[str], bytes] | None = None,
        note: ParseIssue | None = None,
    ) -> None:
        self.state = state
        self.location = location
        self.files = files or []
        self._reader = reader
        self._head_reader = head_reader
        self.note = note

    def status(self) -> ParseIssue:
        if self.state == "found":
            return ParseIssue("coredata.support_found", {
                "path": self.location, "count": len(self.files),
            })
        if self.state == "not_found":
            return ParseIssue("coredata.support_not_found", {"path": self.location})
        return ParseIssue("coredata.support_unavailable", {
            "path": self.location, "reason": self.note or ParseIssue("coredata.support_no_parent"),
        })

    def read(self, rel_path: str) -> bytes:
        if self._reader is None:
            raise OSError("folder not available")
        return self._reader(rel_path)

    def head(self, rel_path: str) -> bytes:
        if self._head_reader is not None:
            return self._head_reader(rel_path)
        return self.read(rel_path)[:512]

    def external_file(self, name: str) -> SupportFile | None:
        wanted = f"{EXTERNAL_DATA_FOLDER}/{name}"
        return next((f for f in self.files if f.rel_path == wanted), None)


# -- The store ----------------------------------------------------------------

CHANGE_TYPES = {0: "insert", 1: "update", 2: "delete"}
HISTORY_ENTITIES = ("CHANGE", "TRANSACTION", "TRANSACTIONSTRING")
_HISTORY_STRING_REFS = (
    ("author", "ZAUTHORTS", "ZAUTHOR"),
    ("bundle", "ZBUNDLEIDTS", "ZBUNDLEID"),
    ("process", "ZPROCESSIDTS", "ZPROCESSID"),
    ("context", "ZCONTEXTNAMETS", "ZCONTEXTNAME"),
)
_TOMBSTONE_COLUMN = re.compile(r"ZTOMBSTONE(\d+)", re.IGNORECASE)


@dataclass(frozen=True)
class MetadataRow:
    version: Any
    store_uuid: Any
    plist_raw: Any
    plist: Any
    plist_issue: ParseIssue | None


@dataclass(frozen=True)
class RelationshipRule:
    """How a relationship's targets are found, if a rule established on
    observed stores applies. *kind*:
    - "to-one column": *key_column* in the source row holds the target's
      Z_PK (*ent_column*, when present, the target's Z_ENT)
    - "inverse column" / "destination column": rows of *table* (the
      destination's) whose *source_column* holds this object's Z_PK
    - "join table": rows of *table* whose *source_column* holds this
      object's Z_PK, *key_column* the target's
    *order_column* orders the targets (ordered relationships). *status*
    "resolved", or "ambiguous"/"unresolved" with *candidates* and *reason*
    -- then no link is offered."""

    kind: str
    status: str
    table: str | None = None
    key_column: str | None = None
    source_column: str | None = None
    order_column: str | None = None
    ent_column: str | None = None
    candidates: tuple[str, ...] = ()
    reason: ParseIssue | None = None

    @property
    def resolved(self) -> bool:
        return self.status == "resolved"


@dataclass(frozen=True)
class GridColumn:
    """One column of the Entities grid. *source* is the index of the
    table column whose stored value it shows (None for the derived entity
    name); *decode* a DECODE_* kind for a derived, decoded column."""

    header: str
    source: int | None
    decode: str | None = None
    derived: bool = False
    tooltip: Any = None

    @property
    def is_entity_name(self) -> bool:
        """The derived column naming each row's concrete entity."""
        return self.decode == "entity"

    @property
    def is_decoded(self) -> bool:
        """A derived column showing a stored value read by type."""
        return self.decode is not None and self.decode != "entity"


@dataclass
class RecordSet:
    entity: str
    table: str
    columns: list[tuple[str, str]]
    rows: list[tuple[Any, ...]]
    rowids: list[Any]
    grid: list[GridColumn]


@dataclass(frozen=True)
class PropertyValue:
    name: str
    kind: str
    type_text: str
    value: str
    raw: Any
    columns: tuple[str, ...]
    status: Any


@dataclass(frozen=True)
class RelatedTarget:
    entity: str | None
    ent: Any
    pk: Any
    exists: bool
    order: Any = None


@dataclass
class RelationshipValue:
    name: str
    destination: str | None
    to_many: bool
    rule: RelationshipRule
    targets: list[RelatedTarget] = field(default_factory=list)
    stored: Any = None
    status: Any = None


@dataclass(frozen=True)
class TombstoneSlot:
    slot: int
    column: str
    raw: Any
    attribute: str | None
    status: ParseIssue | None
    candidates: tuple[str, ...]


@dataclass
class HistoryRow:
    change_pk: Any
    transaction: Any
    timestamp_raw: Any
    timestamp: str | None
    timestamp_status: Any
    strings: dict[str, tuple[Any, Any, Any]]  # key -> (ref, resolved name, text column)
    change_type_raw: Any
    change_type: str | None
    entity_raw: Any
    entity_name: str | None
    entity_pk: Any
    columns_raw: Any
    columns_bits: tuple[int, ...] | None
    tombstones: list[TombstoneSlot]
    target_exists: bool | None
    raw: dict[str, Any]


@dataclass
class HistoryResult:
    rows: list[HistoryRow]
    issues: list[ParseIssue]
    tombstone_columns: list[str]


@dataclass(frozen=True)
class KeyFacts:
    entity: str
    ent: int
    table: str | None
    z_max: Any
    rows: int | None
    min_pk: Any
    max_pk: Any
    missing_count: int | None
    missing_ranges: str
    max_gap: Any
    status: Any


@dataclass(frozen=True)
class ExternalRow:
    """A reference found in a cell, or a _SUPPORT file no reference names
    (*table* None), or a value of unrecognised shape in an
    external-storage column (*kind* "unrecognised")."""

    kind: str
    table: str | None
    column: str | None
    rowid: Any
    pk: Any
    ent: Any
    name: str | None
    model_flag: str
    file: SupportFile | None
    status: Any


@dataclass
class ExternalScan:
    rows: list[ExternalRow]
    folder_status: ParseIssue
    issues: list[ParseIssue]


def _compatible(attr: ModelProperty, value: Any) -> bool:
    """Whether a tombstone value can be a value of *attr*'s type."""
    t = attr.attribute_type
    if value is None:
        return True
    if t in (100, 200, 300, TYPE_BOOLEAN):
        return isinstance(value, int)
    if t in (400, 500, 600, TYPE_DATE):
        return isinstance(value, (int, float)) or (t == 400 and isinstance(value, str))
    if t in (700, 1200):
        return isinstance(value, str)
    if t == TYPE_UUID:
        return (isinstance(value, bytes) and len(value) == 16) or isinstance(value, str)
    if t in (TYPE_BINARY, TYPE_TRANSFORMABLE):
        return isinstance(value, bytes)
    return True


def _set_bits(value: Any) -> tuple[int, ...] | None:
    """Bit numbers set in a BLOB: byte index × 8 + bit, least significant
    bit first (an assumption about the order, stated in the view)."""
    if not isinstance(value, (bytes, bytearray, memoryview)):
        return None
    data = bytes(value)
    return tuple(i * 8 + b for i, byte in enumerate(data) for b in range(8) if byte >> b & 1)


def _ranges(missing: list[int]) -> str:
    parts: list[str] = []
    start = prev = None
    for n in missing:
        if start is None:
            start = prev = n
        elif n == prev + 1:  # type: ignore[operator]
            prev = n
        else:
            parts.append(str(start) if start == prev else f"{start}–{prev}")
            start = prev = n
    if start is not None:
        parts.append(str(start) if start == prev else f"{start}–{prev}")
    return ", ".join(parts)


class CoreDataStore:
    """A detected store. Built once while the database is parsed (schema,
    metadata, model, links); the views' row data is read on demand through
    *connect*, which opens the same database state the table grid shows
    (WAL applied, the rollback-recovered image, SQLCipher with its key)."""

    def __init__(
        self,
        conn: Any,
        detection: Detection,
        connect: Callable[[], Any],
        support: SupportFolder | None = None,
    ) -> None:
        self.detection = detection
        self._connect = connect
        self.support = support
        self.issues: list[ParseIssue] = []
        self.tables: dict[str, list[tuple[str, str]]] = {}
        self._ui_conn: Any = None
        for table in schema_tables(conn):
            try:
                self.tables[table] = table_columns(conn, table)
            except Exception as exc:  # noqa: BLE001 -- sqlite3/sqlcipher3 errors
                self.issues.append(ParseIssue("coredata.table_unreadable", {"table": table}, str(exc)))
                self.tables[table] = []
        self._table_by_upper = {t.upper(): t for t in self.tables}
        self.metadata = self._read_metadata(conn)
        self.model: CoreDataModel | None = None
        self.model_status: ParseIssue | None = None
        self.model_issues: list[ParseIssue] = []
        self._read_model(conn)
        self.entities = self._read_entities(conn)
        self._by_name = {e.name: e for e in self.entities}
        self._by_ent: dict[Any, EntityInfo] = {e.ent: e for e in self.entities}
        self._exact_names: dict[str, set[str]] = {}
        if self.model is not None:
            for ent in self.model.entities.values():
                info = self._by_name.get(ent.name)
                table = info.table if info else None
                if table:
                    self._exact_names.setdefault(table, set()).update(
                        ("Z" + p.name).upper() for p in ent.properties
                    )

    # -- connections ---------------------------------------------------------

    def open(self) -> Any:
        """A new connection to the database state the grid shows. The
        caller closes it (each worker thread opens its own)."""
        return self._connect()

    def ui_conn(self) -> Any:
        if self._ui_conn is None:
            self._ui_conn = self._connect()
        return self._ui_conn

    def close(self) -> None:
        if self._ui_conn is not None:
            try:
                self._ui_conn.close()
            except Exception:  # noqa: BLE001 -- closing is best effort
                pass
            self._ui_conn = None

    # -- schema --------------------------------------------------------------

    def table(self, name: str | None) -> str | None:
        return self._table_by_upper.get(name.upper()) if name else None

    def columns(self, table: str | None) -> list[tuple[str, str]]:
        return self.tables.get(table or "", [])

    def column_names(self, table: str | None) -> list[str]:
        return [c for c, _ in self.columns(table)]

    def declared_type(self, table: str, column: str) -> str:
        return next((t for c, t in self.columns(table) if c.upper() == column.upper()), "")

    def _read_metadata(self, conn: Any) -> list[MetadataRow]:
        table = self.table(METADATA_TABLE)
        if table is None:
            return []
        try:
            rows = conn.execute(
                f"SELECT Z_VERSION, Z_UUID, Z_PLIST FROM {quote_ident(table)}"  # noqa: S608
            ).fetchall()
        except Exception as exc:  # noqa: BLE001
            self.issues.append(ParseIssue("coredata.metadata_unreadable", detail=str(exc)))
            return []
        result: list[MetadataRow] = []
        for version, store_uuid, plist_raw in (tuple(r) for r in rows):
            plist: Any = None
            issue: ParseIssue | None = None
            if isinstance(plist_raw, (bytes, bytearray, memoryview)):
                try:
                    plist = plistlib.loads(bytes(plist_raw))
                except Exception as exc:  # noqa: BLE001
                    issue = ParseIssue("coredata.plist_unreadable", detail=str(exc))
            elif plist_raw is None:
                issue = ParseIssue("coredata.plist_null")
            else:
                issue = ParseIssue("coredata.plist_not_blob", {"type": _storage_class(plist_raw)})
            result.append(MetadataRow(version, store_uuid, plist_raw, plist, issue))
        return result

    def framework_version(self) -> Any:
        for row in self.metadata:
            if isinstance(row.plist, dict) and "NSPersistenceFrameworkVersion" in row.plist:
                return row.plist["NSPersistenceFrameworkVersion"]
        return None

    def _read_model(self, conn: Any) -> None:
        table = self.table(MODELCACHE_TABLE)
        if table is None:
            self.model_status = ParseIssue("coredata.model_cache_missing")
            return
        try:
            rows = conn.execute(f"SELECT Z_CONTENT FROM {quote_ident(table)}").fetchall()  # noqa: S608
        except Exception as exc:  # noqa: BLE001
            self.model_status = ParseIssue("coredata.model_cache_unreadable", detail=str(exc))
            return
        blobs = [r[0] for r in rows if r[0] is not None]
        if not blobs:
            self.model_status = ParseIssue("coredata.model_cache_empty", {"rows": len(rows)})
            return
        blob = blobs[0]
        if len(blobs) > 1:
            self.model_issues.append(ParseIssue("coredata.model_cache_rows", {"rows": len(blobs)}))
        if not isinstance(blob, (bytes, bytearray, memoryview)):
            self.model_status = ParseIssue("coredata.model_cache_not_blob", {
                "type": _storage_class(blob),
            })
            return
        data = bytes(blob)
        try:
            raw = zlib.decompress(data, -15)
        except zlib.error as exc:
            self.model_status = ParseIssue("coredata.model_not_decompressible", {
                "head": data[:16].hex(" "), "size": len(data),
            }, str(exc))
            return
        model, issues = parse_model_archive(raw)
        self.model_issues.extend(issues)
        if model is None:
            self.model_status = issues[0] if issues else ParseIssue("coredata.model_not_keyed_archive")
            return
        self.model = model
        self.model_status = ParseIssue("coredata.model_read", {
            "entities": len(model.entities),
            "properties": sum(len(e.properties) for e in model.entities.values()),
        })

    def _read_entities(self, conn: Any) -> list[EntityInfo]:
        table = self.table(PRIMARYKEY_TABLE)
        if table is None:
            return []
        try:
            rows = [tuple(r) for r in conn.execute(
                f"SELECT Z_ENT, Z_NAME, Z_SUPER, Z_MAX FROM {quote_ident(table)} ORDER BY Z_ENT"  # noqa: S608
            ).fetchall()]
        except Exception as exc:  # noqa: BLE001
            self.issues.append(ParseIssue("coredata.primarykey_unreadable", detail=str(exc)))
            return []
        supers = {r[0]: r[2] for r in rows}

        def root_of(ent: Any) -> Any:
            seen: set[Any] = set()
            while supers.get(ent) not in (0, None) and ent not in seen:
                seen.add(ent)
                ent = supers[ent]
            return ent

        names = {r[0]: r[1] for r in rows}
        infos: list[EntityInfo] = []
        for ent, name, super_ent, max_pk in rows:
            root = root_of(ent)
            root_name = str(names.get(root, name))
            table_name, status = self._root_table(root_name)
            infos.append(EntityInfo(
                ent=ent, name=str(name), super_ent=super_ent, max_pk=max_pk, root_ent=root,
                table=table_name, table_status=status,
            ))
        return infos

    def _root_table(self, root_name: str) -> tuple[str | None, ParseIssue | None]:
        """Z + uppercase name; A + uppercase name for Core Data's own
        entities (history, CloudKit mirroring)."""
        z_table = self.table("Z" + root_name.upper())
        a_table = self.table("A" + root_name.upper())
        if z_table and a_table:
            return None, ParseIssue("coredata.table_ambiguous", {
                "entity": root_name, "tables": f"{z_table}, {a_table}",
            })
        if z_table or a_table:
            return z_table or a_table, None
        return None, ParseIssue("coredata.no_table", {
            "entity": root_name, "tables": f"Z{root_name.upper()}, A{root_name.upper()}",
        })

    def entity(self, name: str) -> EntityInfo | None:
        return self._by_name.get(name)

    def entity_by_ent(self, ent: Any) -> EntityInfo | None:
        return self._by_ent.get(ent)

    def children(self, ent: int) -> list[EntityInfo]:
        return [e for e in self.entities if e.super_ent == ent and e.ent != ent]

    def subtree(self, ent: int) -> list[int]:
        """*ent* and every entity below it, by Z_PRIMARYKEY.Z_SUPER."""
        out = [ent]
        pending = [ent]
        while pending:
            current = pending.pop()
            for child in self.children(current):
                if child.ent not in out:
                    out.append(child.ent)
                    pending.append(child.ent)
        return out

    def in_model(self, name: str) -> bool:
        return self.model is not None and name in self.model.entities

    def entity_status(self, name: str) -> ParseIssue | None:
        info = self.entity(name)
        if info is not None and info.table_status is not None:
            return info.table_status
        if self.model is None:
            return self.model_status
        if not self.in_model(name):
            return ParseIssue("coredata.entity_not_in_model", {"entity": name})
        return None

    # -- column links ----------------------------------------------------------

    def column_link(self, entity: str, prop: ModelProperty) -> ColumnLink:
        info = self.entity(entity)
        if info is None or info.table is None:
            return ColumnLink(MAP_NO_COLUMN, ())
        return link_columns(prop.name, self.column_names(info.table), self._exact_names.get(info.table, set()))

    def table_properties(self, table: str) -> list[tuple[str, ModelProperty]]:
        """(entity, property) for every entity whose rows are in *table*,
        each property once per entity."""
        if self.model is None:
            return []
        out: list[tuple[str, ModelProperty]] = []
        for info in self.entities:
            if info.table == table and info.name in self.model.entities:
                out.extend((info.name, p) for p in self.model.all_properties(info.name))
        return out

    def column_roles(self, table: str) -> dict[str, list[tuple[str, ModelProperty, str]]]:
        """Column (uppercase) -> [(entity, property, mapping status)] for
        every attribute and to-one relationship that names it as a candidate."""
        roles: dict[str, list[tuple[str, ModelProperty, str]]] = {}
        seen: set[tuple[str, str]] = set()
        for entity, prop in self.table_properties(table):
            if not (prop.is_attribute or (prop.is_relationship and not prop.to_many)):
                continue
            declared = self.model.declared_in(entity, prop.name) if self.model else entity
            if (declared, prop.name) in seen:
                continue
            seen.add((declared, prop.name))
            link = self.column_link(entity, prop)
            for column in link.candidates:
                roles.setdefault(column.upper(), []).append((declared, prop, link.status))
        return roles

    def decode_kind(self, table: str, column: str, prop: ModelProperty | None, status: str | None) -> str | None:
        if is_timestamp_column(table, column, self.declared_type(table, column)):
            return DECODE_DATE
        if prop is None or status != MAP_NAME_MATCH:
            return None
        if prop.attribute_type == TYPE_BOOLEAN:
            return DECODE_BOOLEAN
        if prop.attribute_type == TYPE_UUID:
            return DECODE_UUID
        return None

    def grid_columns(self, entity: str) -> list[GridColumn]:
        """The Entities grid's columns for *entity*'s rows: every column of
        the table as stored, in table order, named after the property it is
        linked to; a decoded column before a date, boolean or UUID column,
        and the entity name next to Z_ENT."""
        info = self.entity(entity)
        if info is None or info.table is None:
            return []
        roles = self.column_roles(info.table)
        grid: list[GridColumn] = []
        for index, (column, _declared) in enumerate(self.columns(info.table)):
            linked = roles.get(column.upper(), [])
            matches = [(e, p) for e, p, s in linked if s == MAP_NAME_MATCH]
            if column.upper() == "Z_ENT":
                grid.append(GridColumn(column, index))
                grid.append(GridColumn(
                    "entity", None, decode="entity", derived=True,
                    tooltip=ParseIssue("coredata.grid_entity_column"),
                ))
                continue
            if len(matches) == 1:
                _ent, prop = matches[0]
                kind = self.decode_kind(info.table, column, prop, MAP_NAME_MATCH)
                if kind is not None:
                    grid.append(GridColumn(
                        prop.name, index, decode=kind, derived=True,
                        tooltip=ParseIssue("coredata.grid_decoded_column", {
                            "kind": kind, "column": column,
                        }),
                    ))
                grid.append(GridColumn(
                    f"{prop.name} ({column})", index,
                    tooltip=ParseIssue("coredata.grid_name_match", {
                        "property": prop.name, "column": column,
                    }),
                ))
                continue
            kind = self.decode_kind(info.table, column, None, None)
            if kind is not None:
                grid.append(GridColumn(
                    f"{column} [{kind}]", index, decode=kind, derived=True,
                    tooltip=ParseIssue("coredata.grid_decoded_column", {"kind": kind, "column": column}),
                ))
            if linked:
                names = ", ".join(sorted({f"{e}.{p.name}" for e, p, _s in linked}))
                grid.append(GridColumn(
                    f"{column} (candidate: {names})", index,
                    tooltip=ParseIssue("coredata.grid_candidate", {"column": column, "properties": names}),
                ))
            else:
                grid.append(GridColumn(column, index))
        return grid

    # -- records ---------------------------------------------------------------

    def row_counts(self, conn: Any | None = None) -> dict[str, dict[Any, int]]:
        """Rows per stored Z_ENT value, per entity table (a table without
        Z_ENT: all rows under the key None)."""
        conn = conn or self.ui_conn()
        counts: dict[str, dict[Any, int]] = {}
        for table in sorted({e.table for e in self.entities if e.table}):
            has_ent = any(c.upper() == "Z_ENT" for c in self.column_names(table))
            try:
                if has_ent:
                    counts[table] = dict(conn.execute(
                        f"SELECT Z_ENT, COUNT(*) FROM {quote_ident(table)} GROUP BY Z_ENT"  # noqa: S608
                    ).fetchall())
                else:
                    counts[table] = {None: conn.execute(
                        f"SELECT COUNT(*) FROM {quote_ident(table)}"  # noqa: S608
                    ).fetchone()[0]}
            except Exception as exc:  # noqa: BLE001
                self.issues.append(ParseIssue("coredata.table_unreadable", {"table": table}, str(exc)))
        return counts

    def entity_row_count(self, name: str, counts: dict[str, dict[Any, int]]) -> int | None:
        """The rows the entity shows: a root every row of its table, a
        subentity its own and those of the entities below it."""
        info = self.entity(name)
        if info is None or info.table is None or info.table not in counts:
            return None
        per_ent = counts[info.table]
        if info.super_ent in (0, None):
            return sum(per_ent.values())
        return sum(per_ent.get(e, 0) for e in self.subtree(info.ent))

    def load_records(self, entity: str, conn: Any | None = None) -> RecordSet:
        """Every row the entity shows, no limit: a root entity every row of
        its table; a subentity the rows whose Z_ENT is it or below it."""
        info = self.entity(entity)
        if info is None or info.table is None:
            return RecordSet(entity, "", [], [], [], [])
        own = conn is None
        conn = conn or self.open()
        try:
            columns = self.columns(info.table)
            names = ", ".join(quote_ident(c) for c, _ in columns)
            sql = f"SELECT rowid, {names} FROM {quote_ident(info.table)}"  # noqa: S608
            params: list[Any] = []
            has_ent = any(c.upper() == "Z_ENT" for c, _ in columns)
            if info.super_ent not in (0, None) and has_ent:
                ents = self.subtree(info.ent)
                sql += f" WHERE Z_ENT IN ({', '.join('?' for _ in ents)})"
                params = list(ents)
            try:
                rows = conn.execute(sql + " ORDER BY rowid", params).fetchall()
                rowids = [r[0] for r in rows]
                data = [tuple(r)[1:] for r in rows]
            except Exception:  # noqa: BLE001 -- WITHOUT ROWID: no rowid column
                sql = sql.replace("SELECT rowid, ", "SELECT ", 1)
                rows = conn.execute(sql, params).fetchall()
                rowids = [None] * len(rows)
                data = [tuple(r) for r in rows]
        finally:
            if own:
                conn.close()
        return RecordSet(entity, info.table, columns, data, rowids, self.grid_columns(entity))

    def cell_text(self, records: RecordSet, row: tuple[Any, ...], col: GridColumn) -> tuple[str, Any]:
        """(display text, status) of one grid cell."""
        if col.decode == "entity":
            ent_index = next(
                (i for i, (c, _t) in enumerate(records.columns) if c.upper() == "Z_ENT"), None
            )
            ent = row[ent_index] if ent_index is not None else None
            info = self._by_ent.get(ent)
            if info is None:
                return "", ParseIssue("coredata.ent_unknown", {"ent": ent}) if ent is not None else None
            return info.name, None
        value = row[col.source] if col.source is not None else None
        if col.decode is not None:
            text, status = decode_value(col.decode, value)
            return (text if text is not None else value_text(value)), status
        return value_text(value), None

    def concrete_entity(self, records: RecordSet, row: tuple[Any, ...]) -> str:
        ent_index = next((i for i, (c, _t) in enumerate(records.columns) if c.upper() == "Z_ENT"), None)
        if ent_index is not None:
            info = self._by_ent.get(row[ent_index])
            if info is not None:
                return info.name
        return records.entity

    def property_values(self, records: RecordSet, row: tuple[Any, ...]) -> list[PropertyValue]:
        """The record's attributes by model type (decision: decoded only on
        a name match), and its columns no property names."""
        entity = self.concrete_entity(records, row)
        index_of = {c.upper(): i for i, (c, _t) in enumerate(records.columns)}
        out: list[PropertyValue] = []
        used: set[str] = set()
        props = self.model.all_properties(entity) if self.model and self.in_model(entity) else []
        for prop in props:
            if not prop.is_attribute:
                continue
            link = self.column_link(entity, prop)
            type_text = _type_text(prop)
            used.update(c.upper() for c in link.candidates)
            if link.status == MAP_NAME_MATCH:
                column = link.candidates[0]
                raw = row[index_of[column.upper()]]
                kind = self.decode_kind(records.table, column, prop, link.status)
                text, status = decode_value(kind, raw) if kind else (None, None)
                if prop.attribute_type in (TYPE_BINARY, TYPE_TRANSFORMABLE) and raw is not None:
                    status = status or (
                        ParseIssue("coredata.external_reference", {"name": external_reference(raw)})
                        if external_reference(raw) else None
                    )
                out.append(PropertyValue(
                    prop.name, prop.kind, type_text,
                    text if text is not None else value_text(raw), raw, (column,), status,
                ))
            elif link.status == MAP_AMBIGUOUS:
                raws = tuple(row[index_of[c.upper()]] for c in link.candidates)
                out.append(PropertyValue(
                    prop.name, prop.kind, type_text,
                    "; ".join(f"{c} = {value_text(v)}" for c, v in zip(link.candidates, raws)),
                    raws, link.candidates,
                    ParseIssue("coredata.mapping_ambiguous", {"columns": ", ".join(link.candidates)}),
                ))
            else:
                out.append(PropertyValue(
                    prop.name, prop.kind, type_text, "", None, (),
                    ParseIssue("coredata.mapping_no_column", {"column": ("Z" + prop.name).upper()}),
                ))
        for prop in props:
            if prop.is_relationship and not prop.to_many:
                used.update(c.upper() for c in self.column_link(entity, prop).candidates)
                rule = self.relationship_rule(entity, prop)
                if rule.ent_column:
                    used.add(rule.ent_column.upper())
        for i, (column, declared) in enumerate(records.columns):
            if column.upper() in used or column.upper() in ("Z_PK", "Z_ENT", "Z_OPT"):
                continue
            raw = row[i]
            kind = self.decode_kind(records.table, column, None, None)
            text, status = decode_value(kind, raw) if kind else (None, None)
            out.append(PropertyValue(
                column, "column", declared, text if text is not None else value_text(raw), raw,
                (column,), status or ParseIssue("coredata.column_unassigned"),
            ))
        return out

    # -- relationships ----------------------------------------------------------

    def relationship_rule(self, entity: str, prop: ModelProperty) -> RelationshipRule:
        """The rule (established on observed stores) that finds the
        relationship's targets, or why none applies."""
        if self.model is None:
            return RelationshipRule("unresolved", "unresolved", reason=ParseIssue("coredata.rel_no_model"))
        source = self.entity(entity)
        dest = self.entity(prop.destination) if prop.destination else None
        if source is None or source.table is None or dest is None or dest.table is None:
            return RelationshipRule("unresolved", "unresolved", reason=ParseIssue(
                "coredata.rel_no_table", {"destination": prop.destination or "?"},
            ))
        inverse = None
        if prop.inverse and prop.destination in self.model.entities:
            inverse = next(
                (q for q in self.model.all_properties(prop.destination) if q.name == prop.inverse), None
            )
        if not prop.to_many:
            link = link_columns(prop.name, self.column_names(source.table), self._exact_names.get(source.table, set()))
            if link.status != MAP_NAME_MATCH:
                return RelationshipRule(
                    "to-one column", "ambiguous" if link.candidates else "unresolved",
                    table=source.table, candidates=link.candidates,
                    reason=ParseIssue(
                        "coredata.mapping_ambiguous" if link.candidates else "coredata.mapping_no_column",
                        {"columns": ", ".join(link.candidates), "column": ("Z" + prop.name).upper()},
                    ),
                )
            column = link.candidates[0]
            ent_re = re.compile(r"Z(\d+)_" + re.escape(column[1:].upper()))
            ent_columns = [c for c in self.column_names(source.table) if ent_re.fullmatch(c.upper())]
            return RelationshipRule(
                "to-one column", "resolved", table=dest.table, key_column=column,
                ent_column=ent_columns[0] if len(ent_columns) == 1 else None,
            )
        if inverse is not None and not inverse.to_many:
            link = link_columns(inverse.name, self.column_names(dest.table), self._exact_names.get(dest.table, set()))
            if link.status != MAP_NAME_MATCH:
                return RelationshipRule(
                    "inverse column", "ambiguous" if link.candidates else "unresolved",
                    table=dest.table, candidates=link.candidates,
                    reason=ParseIssue(
                        "coredata.mapping_ambiguous" if link.candidates else "coredata.mapping_no_column",
                        {"columns": ", ".join(link.candidates), "column": ("Z" + inverse.name).upper()},
                    ),
                )
            order = None
            if prop.ordered:
                order = next(
                    (c for c in self.column_names(dest.table) if c.upper() == ("Z_FOK_" + inverse.name).upper()),
                    None,
                )
            return RelationshipRule(
                "inverse column", "resolved", table=dest.table, key_column="Z_PK",
                source_column=link.candidates[0], order_column=order,
            )
        e_info = self.entity(self.model.declared_in(entity, prop.name))
        if inverse is not None:
            d_info = self.entity(self.model.declared_in(prop.destination or "", inverse.name))
            if e_info is None or d_info is None:
                return RelationshipRule("join table", "unresolved", reason=ParseIssue("coredata.rel_no_table", {
                    "destination": prop.destination or "?",
                }))
            names = [f"Z_{e_info.ent}{prop.name.upper()}", f"Z_{d_info.ent}{inverse.name.upper()}"]
            found = sorted({t for t in (self.table(n) for n in names) if t})
            if len(found) != 1:
                return RelationshipRule(
                    "join table", "unresolved", candidates=tuple(found or names),
                    reason=ParseIssue("coredata.rel_join_table", {"tables": ", ".join(names), "found": len(found)}),
                )
            join = found[0]
            join_cols = self.column_names(join)
            if any(c.upper() == "REFLEXIVE" for c in join_cols):
                return RelationshipRule(
                    "join table", "unresolved", table=join, candidates=tuple(join_cols),
                    reason=ParseIssue("coredata.rel_reflexive", {"table": join}),
                )
            key_re = re.compile(re.escape(f"Z_{d_info.ent}{prop.name.upper()}") + r"\d*")
            src_re = re.compile(re.escape(f"Z_{e_info.ent}{inverse.name.upper()}") + r"\d*")
            keys = [c for c in join_cols if key_re.fullmatch(c.upper())]
            srcs = [c for c in join_cols if src_re.fullmatch(c.upper())]
            if len(keys) != 1 or len(srcs) != 1:
                return RelationshipRule(
                    "join table", "unresolved", table=join, candidates=tuple(join_cols),
                    reason=ParseIssue("coredata.rel_join_columns", {"table": join}),
                )
            order = None
            if prop.ordered:
                want = "Z_FOK_" + keys[0][2:].upper()
                order = next((c for c in join_cols if c.upper() == want), None)
            return RelationshipRule(
                "join table", "resolved", table=join, key_column=keys[0], source_column=srcs[0],
                order_column=order,
            )
        if e_info is None:
            return RelationshipRule("destination column", "unresolved", reason=ParseIssue("coredata.rel_no_table", {
                "destination": prop.destination or "?",
            }))
        dest_re = re.compile(re.escape(f"Z{e_info.ent}{prop.name.upper()}") + r"\d*")
        hits = [c for c in self.column_names(dest.table) if dest_re.fullmatch(c.upper())]
        if len(hits) != 1:
            return RelationshipRule(
                "destination column", "ambiguous" if hits else "unresolved", table=dest.table,
                candidates=tuple(hits), reason=ParseIssue("coredata.rel_destination_column", {
                    "column": f"Z{e_info.ent}{prop.name.upper()}", "table": dest.table,
                }),
            )
        return RelationshipRule(
            "destination column", "resolved", table=dest.table, key_column="Z_PK", source_column=hits[0],
        )

    def relationship_values(
        self, records: RecordSet, row: tuple[Any, ...], conn: Any | None = None,
    ) -> list[RelationshipValue]:
        entity = self.concrete_entity(records, row)
        if self.model is None or not self.in_model(entity):
            return []
        conn = conn or self.ui_conn()
        index_of = {c.upper(): i for i, (c, _t) in enumerate(records.columns)}
        pk_index = index_of.get("Z_PK")
        pk = row[pk_index] if pk_index is not None else None
        out: list[RelationshipValue] = []
        for prop in self.model.all_properties(entity):
            if not prop.is_relationship:
                continue
            rule = self.relationship_rule(entity, prop)
            value = RelationshipValue(prop.name, prop.destination, prop.to_many, rule)
            dest = self.entity(prop.destination) if prop.destination else None
            if not rule.resolved:
                value.stored = tuple(
                    (c, row[index_of[c.upper()]]) for c in rule.candidates if c.upper() in index_of
                )
                value.status = rule.reason
                out.append(value)
                continue
            try:
                if rule.kind == "to-one column":
                    target = row[index_of[rule.key_column.upper()]] if rule.key_column else None
                    value.stored = target
                    if target is not None and dest is not None:
                        value.targets = self._targets(conn, dest, [(target, None)])
                elif pk is not None and dest is not None:
                    order = f", {quote_ident(rule.order_column)}" if rule.order_column else ", NULL"
                    sql = (
                        f"SELECT {quote_ident(rule.key_column or 'Z_PK')}{order} "  # noqa: S608
                        f"FROM {quote_ident(rule.table or '')} WHERE {quote_ident(rule.source_column or '')} = ?"
                    )
                    if rule.order_column:
                        sql += f" ORDER BY {quote_ident(rule.order_column)}"
                    found = [(r[0], r[1]) for r in conn.execute(sql, (pk,)).fetchall()]
                    value.targets = self._targets(conn, dest, found)
            except Exception as exc:  # noqa: BLE001
                value.status = ParseIssue("coredata.rel_query_failed", detail=str(exc))
            missing = sum(1 for t in value.targets if not t.exists)
            if missing:
                value.status = ParseIssue("coredata.rel_target_missing", {"count": missing})
            out.append(value)
        return out

    def _targets(self, conn: Any, dest: EntityInfo, keys: list[tuple[Any, Any]]) -> list[RelatedTarget]:
        if not keys or dest.table is None:
            return []
        has_ent = any(c.upper() == "Z_ENT" for c in self.column_names(dest.table))
        found: dict[Any, Any] = {}
        pks = [k for k, _o in keys]
        for start in range(0, len(pks), 500):
            chunk = pks[start:start + 500]
            sql = (
                f"SELECT Z_PK, {'Z_ENT' if has_ent else 'NULL'} FROM {quote_ident(dest.table)} "  # noqa: S608
                f"WHERE Z_PK IN ({', '.join('?' for _ in chunk)})"
            )
            found.update({r[0]: r[1] for r in conn.execute(sql, chunk).fetchall()})
        subtree = set(self.subtree(dest.ent))
        targets = []
        for pk, order in keys:
            exists = pk in found
            ent = found.get(pk)
            info = self._by_ent.get(ent) if ent is not None else None
            if exists and has_ent and ent not in subtree:
                exists = False
            targets.append(RelatedTarget(info.name if info else dest.name, ent, pk, exists, order))
        return targets

    # -- history ------------------------------------------------------------

    def history_tables(self) -> dict[str, str | None]:
        return {
            name: (self.entity(name).table if self.entity(name) else None)  # type: ignore[union-attr]
            for name in HISTORY_ENTITIES
        }

    def history_status(self, conn: Any | None = None) -> ParseIssue:
        tables = self.history_tables()
        change = tables.get("CHANGE")
        if change is None:
            return ParseIssue("coredata.history_missing")
        conn = conn or self.ui_conn()
        try:
            count = conn.execute(f"SELECT COUNT(*) FROM {quote_ident(change)}").fetchone()[0]  # noqa: S608
        except Exception as exc:  # noqa: BLE001
            return ParseIssue("coredata.history_unreadable", detail=str(exc))
        if not count:
            return ParseIssue("coredata.history_empty", {"table": change})
        return ParseIssue("coredata.history_present", {"table": change, "count": count})

    def tombstone_attributes(self, entity: str) -> list[ModelProperty]:
        """The entity's attributes flagged for tombstones (NSFlagsKey 16),
        inherited ones included, sorted by property name -- the order that
        matched the tombstone slots in the observed stores."""
        if self.model is None or not self.in_model(entity):
            return []
        attrs = [p for p in self.model.all_properties(entity) if p.is_attribute and p.has_flag(FLAG_TOMBSTONE)]
        return sorted(attrs, key=lambda p: p.name)

    def load_history(self, conn: Any | None = None) -> HistoryResult:
        """One row per ACHANGE row, no limit."""
        tables = self.history_tables()
        change = tables.get("CHANGE")
        issues: list[ParseIssue] = []
        if change is None:
            return HistoryResult([], [ParseIssue("coredata.history_missing")], [])
        own = conn is None
        conn = conn or self.open()
        try:
            return self._load_history(conn, change, tables, issues)
        finally:
            if own:
                conn.close()

    def _load_history(
        self, conn: Any, change: str, tables: dict[str, str | None], issues: list[ParseIssue],
    ) -> HistoryResult:
        cols = self.column_names(change)
        upper = {c.upper(): c for c in cols}
        tomb_cols = sorted(
            (c for c in cols if _TOMBSTONE_COLUMN.fullmatch(c)),
            key=lambda c: int(_TOMBSTONE_COLUMN.fullmatch(c).group(1)),  # type: ignore[union-attr]
        )
        for wanted in ("ZCHANGETYPE", "ZENTITY", "ZENTITYPK", "ZTRANSACTIONID", "ZCOLUMNS"):
            if wanted not in upper:
                issues.append(ParseIssue("coredata.history_column_missing", {"table": change, "column": wanted}))
        rows = conn.execute(
            f"SELECT {', '.join(quote_ident(c) for c in cols)} FROM {quote_ident(change)} ORDER BY rowid"  # noqa: S608
        ).fetchall()
        transactions: dict[Any, dict[str, Any]] = {}
        tx_table = tables.get("TRANSACTION")
        if tx_table:
            tx_cols = self.column_names(tx_table)
            for r in conn.execute(
                f"SELECT {', '.join(quote_ident(c) for c in tx_cols)} FROM {quote_ident(tx_table)}"  # noqa: S608
            ).fetchall():
                rec = {c.upper(): v for c, v in zip(tx_cols, tuple(r))}
                transactions[rec.get("Z_PK")] = rec
        else:
            issues.append(ParseIssue("coredata.history_no_transactions"))
        strings: dict[Any, Any] = {}
        str_table = tables.get("TRANSACTIONSTRING")
        if str_table and any(c.upper() == "ZNAME" for c in self.column_names(str_table)):
            strings = dict(conn.execute(
                f"SELECT Z_PK, ZNAME FROM {quote_ident(str_table)}"  # noqa: S608
            ).fetchall())
        # Which entity rows still exist, per table (for "jump to object").
        existing: dict[str, set[Any]] = {}
        out: list[HistoryRow] = []
        for r in rows:
            rec = {c.upper(): v for c, v in zip(cols, tuple(r))}
            tx = transactions.get(rec.get("ZTRANSACTIONID"), {})
            ts_raw = tx.get("ZTIMESTAMP")
            ts_text, ts_status = decode_value(DECODE_DATE, ts_raw)
            resolved: dict[str, tuple[Any, Any, Any]] = {}
            for key, ref_col, text_col in _HISTORY_STRING_REFS:
                ref = tx.get(ref_col)
                resolved[key] = (ref, strings.get(ref) if ref is not None else None, tx.get(text_col))
            ent_raw = rec.get("ZENTITY")
            info = self._by_ent.get(ent_raw)
            entity_name = info.name if info else None
            ctype = rec.get("ZCHANGETYPE")
            target_exists: bool | None = None
            entity_pk = rec.get("ZENTITYPK")
            if info is not None and info.table:
                if info.table not in existing:
                    try:
                        existing[info.table] = {
                            row[0] for row in conn.execute(
                                f"SELECT Z_PK FROM {quote_ident(info.table)}"  # noqa: S608
                            ).fetchall()
                        }
                    except Exception:  # noqa: BLE001
                        existing[info.table] = set()
                target_exists = entity_pk in existing[info.table]
            slots = self._tombstones(entity_name, rec, tomb_cols)
            out.append(HistoryRow(
                change_pk=rec.get("Z_PK"),
                transaction=rec.get("ZTRANSACTIONID"),
                timestamp_raw=ts_raw,
                timestamp=ts_text,
                timestamp_status=ts_status,
                strings=resolved,
                change_type_raw=ctype,
                change_type=CHANGE_TYPES.get(ctype) if isinstance(ctype, int) else None,
                entity_raw=ent_raw,
                entity_name=entity_name,
                entity_pk=entity_pk,
                columns_raw=rec.get("ZCOLUMNS"),
                columns_bits=_set_bits(rec.get("ZCOLUMNS")),
                tombstones=slots,
                target_exists=target_exists,
                raw=rec,
            ))
        return HistoryResult(out, issues, tomb_cols)

    def _tombstones(self, entity: str | None, rec: dict[str, Any], tomb_cols: list[str]) -> list[TombstoneSlot]:
        attrs = self.tombstone_attributes(entity) if entity else []
        names = tuple(p.name for p in attrs)
        slots: list[TombstoneSlot] = []
        for column in tomb_cols:
            value = rec.get(column.upper())
            if value is None:
                continue
            n = int(_TOMBSTONE_COLUMN.fullmatch(column).group(1))  # type: ignore[union-attr]
            if entity is None or self.model is None or not self.in_model(entity):
                slots.append(TombstoneSlot(n, column, value, None, ParseIssue("coredata.tombstone_no_model"), names))
            elif n >= len(attrs):
                slots.append(TombstoneSlot(n, column, value, None, ParseIssue("coredata.tombstone_beyond", {
                    "slot": n, "count": len(attrs),
                }), names))
            elif not _compatible(attrs[n], value):
                slots.append(TombstoneSlot(n, column, value, None, ParseIssue("coredata.tombstone_type", {
                    "slot": n, "attribute": attrs[n].name, "type": _type_text(attrs[n]),
                    "stored": _storage_class(value),
                }), names))
            else:
                slots.append(TombstoneSlot(n, column, value, attrs[n].name, None, names))
        return slots

    # -- primary keys --------------------------------------------------------

    def load_keys(self, conn: Any | None = None) -> list[KeyFacts]:
        own = conn is None
        conn = conn or self.open()
        try:
            out: list[KeyFacts] = []
            for info in self.entities:
                if info.super_ent not in (0, None):
                    continue
                if info.table is None:
                    out.append(KeyFacts(info.name, info.ent, None, info.max_pk, None, None, None, None, "", None,
                                        info.table_status))
                    continue
                try:
                    pks = sorted(
                        r[0] for r in conn.execute(
                            f"SELECT Z_PK FROM {quote_ident(info.table)}"  # noqa: S608
                        ).fetchall() if isinstance(r[0], int)
                    )
                except Exception as exc:  # noqa: BLE001
                    out.append(KeyFacts(info.name, info.ent, info.table, info.max_pk, None, None, None, None, "",
                                        None, ParseIssue("coredata.table_unreadable", {"table": info.table}, str(exc))))
                    continue
                count = len(pks)
                if not pks:
                    out.append(KeyFacts(info.name, info.ent, info.table, info.max_pk, 0, None, None, None, "",
                                        None, None))
                    continue
                present = set(pks)
                missing = [n for n in range(1, pks[-1]) if n not in present]
                gap = info.max_pk - pks[-1] if isinstance(info.max_pk, int) else None
                out.append(KeyFacts(
                    info.name, info.ent, info.table, info.max_pk, count, pks[0], pks[-1], len(missing),
                    _ranges(missing), gap, None,
                ))
            return out
        finally:
            if own:
                conn.close()

    # -- external data ----------------------------------------------------------

    def external_columns(self, table: str) -> dict[str, list[tuple[str, ModelProperty, str]]]:
        """Columns of *table* that are candidates for an attribute flagged
        for external storage (NSFlagsKey 4): column (uppercase) -> roles."""
        return {
            column: [r for r in roles if r[1].has_flag(FLAG_EXTERNAL)]
            for column, roles in self.column_roles(table).items()
            if any(r[1].has_flag(FLAG_EXTERNAL) for r in roles)
        }

    def inline_action(self, table: str, column: str) -> tuple[bool, ParseIssue | None]:
        """Whether "open without the 0x01 prefix" is offered for a cell of
        *column*: only for a candidate of an external-storage attribute. The
        note says when the column mapping is ambiguous."""
        roles = self.external_columns(table).get(column.upper())
        if not roles:
            return False, None
        if all(s == MAP_NAME_MATCH for _e, _p, s in roles) and len(roles) == 1:
            return True, None
        return True, ParseIssue("coredata.inline_ambiguous", {
            "properties": ", ".join(f"{e}.{p.name}" for e, p, _s in roles),
        })

    def model_flag_text(self, table: str, column: str) -> str:
        roles = self.column_roles(table).get(column.upper(), [])
        flagged = [f"{e}.{p.name}" for e, p, _s in roles if p.has_flag(FLAG_EXTERNAL)]
        if flagged:
            return "external storage: " + ", ".join(flagged)
        if roles:
            return "not flagged: " + ", ".join(f"{e}.{p.name}" for e, p, _s in roles)
        return "no property"

    def scan_external(self, conn: Any | None = None) -> ExternalScan:
        """Every cell of every table with the reference shape, every value of
        another 0x02 shape in an external-storage column, and every file in
        the _SUPPORT folder no reference names. No row limit."""
        own = conn is None
        conn = conn or self.open()
        issues: list[ParseIssue] = []
        rows: list[ExternalRow] = []
        referenced: set[str] = set()
        try:
            for table, columns in self.tables.items():
                if not columns:
                    continue
                ext_cols = {c for c in self.external_columns(table)} if self.model else set()
                names = [c for c, _t in columns]
                upper = [c.upper() for c in names]
                pk_i = upper.index("Z_PK") if "Z_PK" in upper else None
                ent_i = upper.index("Z_ENT") if "Z_ENT" in upper else None
                cond = " OR ".join(
                    f"(typeof({quote_ident(c)}) = 'blob' AND substr({quote_ident(c)}, 1, 1) = X'02')"
                    for c in names
                )
                select = ", ".join(quote_ident(c) for c in names)
                try:
                    try:
                        result = conn.execute(
                            f"SELECT rowid, {select} FROM {quote_ident(table)} WHERE {cond}"  # noqa: S608
                        ).fetchall()
                        records = [(r[0], tuple(r)[1:]) for r in result]
                    except Exception:  # noqa: BLE001 -- WITHOUT ROWID
                        result = conn.execute(
                            f"SELECT {select} FROM {quote_ident(table)} WHERE {cond}"  # noqa: S608
                        ).fetchall()
                        records = [(None, tuple(r)) for r in result]
                except Exception as exc:  # noqa: BLE001
                    issues.append(ParseIssue("coredata.table_unreadable", {"table": table}, str(exc)))
                    continue
                for rowid, values in records:
                    pk = values[pk_i] if pk_i is not None else None
                    ent = values[ent_i] if ent_i is not None else None
                    for column, value in zip(names, values):
                        if not isinstance(value, bytes) or not value[:1] == b"\x02":
                            continue
                        name = external_reference(value)
                        flag = self.model_flag_text(table, column) if self.model else "no model"
                        if name is not None:
                            referenced.add(name)
                            file = self.support.external_file(name) if self.support else None
                            rows.append(ExternalRow(
                                "reference", table, column, rowid, pk, ent, name, flag, file,
                                self.file_status(name, file),
                            ))
                        elif column.upper() in ext_cols:
                            rows.append(ExternalRow(
                                "unrecognised", table, column, rowid, pk, ent, None, flag, None,
                                ParseIssue("coredata.external_unrecognised", {
                                    "length": len(value), "head": value[:8].hex(" "),
                                }),
                            ))
            if self.support is not None and self.support.state == "found":
                for file in self.support.files:
                    name = file.rel_path.rsplit("/", 1)[-1]
                    in_external = file.rel_path.startswith(EXTERNAL_DATA_FOLDER + "/")
                    if in_external and name in referenced:
                        continue
                    rows.append(ExternalRow(
                        "file", None, None, None, None, None, file.rel_path, "", file,
                        ParseIssue("coredata.external_unreferenced") if in_external
                        else ParseIssue("coredata.support_other_file"),
                    ))
        finally:
            if own:
                conn.close()
        folder = self.support.status() if self.support else ParseIssue("coredata.support_unavailable", {
            "path": "", "reason": ParseIssue("coredata.support_no_parent"),
        })
        return ExternalScan(rows, folder, issues)

    def plist_items(self, plist: Any) -> list[tuple[str, str]]:
        """Every leaf of a Z_PLIST as (key path, value text), nothing left out."""
        return [(key, plist_value_text(value)) for key, value in flatten_plist(plist)]

    def file_status(self, name: str, file: SupportFile | None) -> ParseIssue:
        if self.support is None or self.support.state != "found":
            return self.support.status() if self.support else ParseIssue("coredata.support_unavailable", {
                "path": "", "reason": ParseIssue("coredata.support_no_parent"),
            })
        if file is None:
            return ParseIssue("coredata.external_file_missing", {"name": name, "path": self.support.location})
        if file.status is not None:
            return ParseIssue("coredata.external_file_unreadable", {"name": name, "reason": file.status})
        return ParseIssue("coredata.external_file_found", {"size": file.size})

    def reference_name(self, value: Any) -> str | None:
        """The external file a cell value references (exact observed shape)."""
        return external_reference(value)

    def is_inline_value(self, value: Any) -> bool:
        return inline_shape(value)

    # -- model view ----------------------------------------------------------

    def model_rows(self) -> list[ModelRow]:
        if self.model is None:
            return []
        return model_rows(self.model, self)

    def describe(self, index: int | None) -> list[DetailNode]:
        if self.model is None or index is None:
            return []
        return describe_object(self.model, index)


class ModelSource:
    """A model on its own (a compiled .mom file): the Model view without a
    store, so without column candidates."""

    def __init__(self, model: CoreDataModel, issues: list[ParseIssue]) -> None:
        self.model = model
        self.model_issues = issues

    def model_rows(self) -> list[ModelRow]:
        return model_rows(self.model, None)

    def describe(self, index: int | None) -> list[DetailNode]:
        return describe_object(self.model, index) if index is not None else []


def _type_text(prop: ModelProperty) -> str:
    if prop.attribute_type is None:
        return ""
    name = ATTRIBUTE_TYPES.get(prop.attribute_type, "unknown")
    return f"{name} ({prop.attribute_type})"


@dataclass(frozen=True)
class ModelRow:
    entity: str
    ent: Any
    superentity: str | None
    table: str | None
    prop: ModelProperty
    declared_in: str
    candidates: tuple[tuple[str, str], ...]  # (column, declared type)
    mapping: str | None
    rule: RelationshipRule | None
    entity_index: int | None = None
    model_index: int | None = None


def model_rows(model: CoreDataModel, store: CoreDataStore | None) -> list[ModelRow]:
    """One row per property as each entity lists it (inherited ones
    included); *store* None (a .mom file): no column candidates."""
    rows: list[ModelRow] = []
    for ent in model.entities.values():
        info = store.entity(ent.name) if store else None
        table = info.table if info else None
        for prop in ent.properties:
            candidates: tuple[tuple[str, str], ...] = ()
            mapping: str | None = None
            rule: RelationshipRule | None = None
            if store is not None:
                if prop.is_relationship:
                    rule = store.relationship_rule(ent.name, prop)
                    if not prop.to_many:
                        link = store.column_link(ent.name, prop)
                        mapping = link.status
                        candidates = tuple((c, store.declared_type(table or "", c)) for c in link.candidates)
                elif prop.is_attribute:
                    link = store.column_link(ent.name, prop)
                    mapping = link.status
                    candidates = tuple((c, store.declared_type(table or "", c)) for c in link.candidates)
            rows.append(ModelRow(
                ent.name, info.ent if info else None, ent.superentity, table, prop,
                model.declared_in(ent.name, prop.name), candidates, mapping, rule,
                entity_index=ent.index, model_index=model.root_index,
            ))
        if not ent.properties:
            # An entity without properties still gets its row (its keys in
            # the detail pane), never dropped.
            placeholder = ModelProperty(
                index=ent.index, class_name="NSEntityDescription", kind="entity", known_class=True,
                name="", entity=ent.name,
            )
            rows.append(ModelRow(
                ent.name, info.ent if info else None, ent.superentity, table, placeholder, ent.name,
                (), None, None, entity_index=ent.index, model_index=model.root_index,
            ))
    for prop in model.unattached:
        owner = model.entities.get(prop.entity)
        rows.append(ModelRow(
            prop.entity or "", None, None, None, prop, prop.entity, (), None, None,
            entity_index=owner.index if owner else None, model_index=model.root_index,
        ))
    return rows


def plist_value_text(value: Any) -> str:
    """A plist leaf as text: data as hex, a date with its zone (plist dates
    are UTC), everything else as stored."""
    import datetime as _dt

    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex(" ") if value else "<0 B>"
    if isinstance(value, _dt.datetime):
        return value.isoformat(sep=" ") + (" UTC" if value.tzinfo is None else "")
    if isinstance(value, plistlib.UID):
        return f"UID({value.data})"
    if isinstance(value, (dict, list)):
        return "{}" if isinstance(value, dict) else "[]"
    return str(value)


def flatten_plist(value: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    """Every leaf of a plist value as (key path, value) -- nothing left out."""
    if isinstance(value, dict):
        if not value:
            yield prefix, {}
        for key, item in value.items():
            yield from flatten_plist(item, f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(value, list):
        if not value:
            yield prefix, []
        for i, item in enumerate(value):
            yield from flatten_plist(item, f"{prefix}[{i}]")
    else:
        yield prefix, value


def load_store(
    conn: Any, connect: Callable[[], Any], support: Callable[[], SupportFolder] | None = None,
) -> tuple[CoreDataStore | None, ParseIssue | None]:
    """The store in the database *conn* is open on, or None with the
    status when only part of the markers is there (None, None: no store)."""
    detection = detect(conn)
    if not detection.detected:
        return None, detection.status()
    folder = support() if support is not None else None
    return CoreDataStore(conn, detection, connect, folder), None
