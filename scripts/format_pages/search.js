// SPDX-License-Identifier: Apache-2.0
// Format reference site (scripts/build_format_pages.py): table filter and
// signature search. The page is complete without this script; it only adds
// filtering. Texts come from the page (#format-data .ui).
(function () {
  "use strict";

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

  // --- Signature search -------------------------------------------------
  // Lists every signature with a known offset that the entered bytes match
  // at that offset. Picks no winner: that is not what Crush's
  // identification does, and the page says so.
  var input = document.getElementById("sig-input");
  var result = document.getElementById("sig-result");

  function parseHex(value) {
    var clean = value.replace(/0x/gi, "").replace(/[\s,:;-]/g, "");
    if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) return null;
    var bytes = [];
    for (var i = 0; i < clean.length; i += 2) bytes.push(parseInt(clean.substr(i, 2), 16));
    return bytes;
  }

  function matches(bytes, offset, hex) {
    var length = hex.length / 2;
    if (offset + length > bytes.length) return false;
    for (var i = 0; i < length; i += 1) {
      if (bytes[offset + i] !== parseInt(hex.substr(i * 2, 2), 16)) return false;
    }
    return true;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function search() {
    clear(result);
    if (!input.value.trim()) return;
    var bytes = parseHex(input.value);
    if (bytes === null) {
      result.textContent = ui.sig_invalid;
      return;
    }
    var hits = [];
    data.formats.forEach(function (f) {
      f.signatures.forEach(function (sig) {
        if (matches(bytes, sig[0], sig[1])) hits.push({ format: f, offset: sig[0], hex: sig[1] });
      });
    });
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
      var code = document.createElement("code");
      code.textContent = hit.hex.match(/../g).join(" ");
      item.appendChild(link);
      item.appendChild(document.createTextNode(
        " — " + fmt(ui.sig_hit, { offset: hit.offset, length: hit.hex.length / 2 }) + ": "
      ));
      item.appendChild(code);
      list.appendChild(item);
    });
    result.appendChild(head);
    result.appendChild(list);
  }

  input.addEventListener("input", search);
  document.getElementById("sig-search").hidden = false;
})();
