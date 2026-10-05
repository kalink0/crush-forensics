// SPDX-License-Identifier: Apache-2.0
// Format reference site (scripts/build_format_pages.py): table filter and
// signature lookup. The page is complete without this script; it only adds
// filtering. Texts come from the page (#format-data .ui).
(function () {
  "use strict";

  // --- Signature lookup (no DOM; also run by crush/tests/test_format_pages.py) ---
  // Hex bytes -> every signature that contains them, at any position within
  // the signature, signatures with an unknown offset included. In the
  // page's order (category, name), no ranking. null for input that isn't
  // hex byte pairs.
  // Groups separated by spaces, commas, colons, semicolons or dashes, each
  // whole bytes ("37 7A", "377A", "0x37,0x7A"); "A B" is not two bytes.
  function parseHex(value) {
    var groups = value.replace(/0x/gi, " ").split(/[\s,:;-]+/).filter(Boolean);
    for (var i = 0; i < groups.length; i += 1) {
      if (!/^(?:[0-9A-Fa-f]{2})+$/.test(groups[i])) return null;
    }
    return groups.join("").toUpperCase();
  }

  function lookup(formats, value) {
    var needle = parseHex(value);
    if (needle === null) return null;
    var hits = [];
    if (!needle) return hits;
    formats.forEach(function (f) {
      f.signatures.forEach(function (sig) {
        var hex = sig[1];
        // Byte-aligned: a match must start on a byte boundary.
        for (var at = hex.indexOf(needle); at !== -1; at = hex.indexOf(needle, at + 1)) {
          if (at % 2 === 0) {
            hits.push({ format: f, offset: sig[0], hex: hex, description: sig[2],
                        start: at / 2, length: needle.length / 2 });
            break;
          }
        }
      });
    });
    return hits;
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { parseHex: parseHex, lookup: lookup };
  }
  if (typeof document === "undefined") return;

  var data = JSON.parse(document.getElementById("format-data").textContent);
  var ui = data.ui;

  function fmt(text, values) {
    return text.replace(/\{(\w+)\}/g, function (m, key) {
      return key in values ? String(values[key]) : m;
    });
  }

  // --- Table filter -------------------------------------------------------
  var rows = Array.prototype.slice.call(document.querySelectorAll("#formats tbody tr"));
  var text = document.getElementById("filter-text");
  var category = document.getElementById("filter-category");
  var support = document.getElementById("filter-support");
  var status = document.getElementById("filter-status");
  var count = document.getElementById("count");

  function applyFilter() {
    var needle = text.value.trim().toLowerCase();
    var visible = 0;
    rows.forEach(function (row) {
      var show = (!needle || row.dataset.search.indexOf(needle) !== -1) &&
        (!category.value || row.dataset.category === category.value) &&
        (!support.value || row.dataset.support === support.value) &&
        (!status.value || row.dataset.status === status.value);
      row.hidden = !show;
      if (show) visible += 1;
    });
    count.textContent = visible === rows.length
      ? fmt(ui.count, { total: rows.length })
      : fmt(ui.count_filtered, { visible: visible, total: rows.length });
  }

  [text, category, support, status].forEach(function (el) {
    el.addEventListener("input", applyFilter);
  });
  document.getElementById("tools").hidden = false;

  // --- Signature lookup -----------------------------------------------------
  var input = document.getElementById("sig-input");
  var result = document.getElementById("sig-result");

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function pairs(hex) {
    return hex ? hex.match(/../g).join(" ") : "";
  }

  // The signature as hex, the looked-up bytes marked.
  function signatureCode(hit) {
    var code = document.createElement("code");
    var hex = hit.hex, a = hit.start * 2, b = a + hit.length * 2;
    code.appendChild(document.createTextNode(pairs(hex.slice(0, a)) + (a ? " " : "")));
    var mark = document.createElement("mark");
    mark.textContent = pairs(hex.slice(a, b));
    code.appendChild(mark);
    code.appendChild(document.createTextNode((b < hex.length ? " " : "") + pairs(hex.slice(b))));
    return code;
  }

  function offsetText(offset) {
    return offset === null
      ? ui.offset_unknown
      : fmt(ui.offset_known, { offset: offset, offset_hex: offset.toString(16).toUpperCase() });
  }

  function search() {
    clear(result);
    if (!input.value.trim()) return;
    var hits = lookup(data.formats, input.value);
    if (hits === null) {
      result.textContent = ui.sig_invalid;
      return;
    }
    if (!hits.length) {
      result.textContent = ui.sig_none;
      return;
    }
    var head = document.createElement("p");
    head.textContent = fmt(ui.sig_hits, { count: hits.length });
    var list = document.createElement("ul");
    hits.forEach(function (hit) {
      var item = document.createElement("li");
      var link = document.createElement("a");
      link.href = hit.format.slug + "/";
      link.textContent = hit.format.name;
      item.appendChild(link);
      item.appendChild(document.createTextNode(" — " + offsetText(hit.offset) + ": "));
      item.appendChild(signatureCode(hit));
      if (hit.description) {
        var desc = document.createElement("div");
        desc.className = "help";
        desc.textContent = hit.description;
        item.appendChild(desc);
      }
      list.appendChild(item);
    });
    result.appendChild(head);
    result.appendChild(list);
  }

  input.addEventListener("input", search);
  document.getElementById("sig-search").hidden = false;
})();
