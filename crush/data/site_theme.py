# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Dark/light theme shared by every page of the GitHub Pages site: the
forensic audit report and its release history (crush/tests/forensic_report.py),
the format reference (scripts/build_format_pages.py) and the site index.

The colours are CSS variables. Dark is the default; a browser set to a light
colour scheme gets light; the toggle in the page header overrides either and
is remembered per browser (localStorage, shared by every page of the site).
Without JavaScript the page follows the browser's setting and the toggle
stays hidden. Nothing here loads anything from outside the page.
"""
from __future__ import annotations

import html

STORAGE_KEY = "crush-theme"

_DARK = """
  --bg:#0f1117;--surface:#1a1d27;--text:#e4e6eb;--muted:#a0a4ae;--faint:#7c8191;
  --border:#262a36;--border-strong:#343947;--link:#8b9cff;--header-bg:#0a0c12;
  --header-text:#f3f4f6;--code-bg:#232736;--input-bg:#12141c;--accent:#a5b4fc;
  --pass:#4ade80;--fail:#f87171;--skip:#8b90a0;--shadow:rgba(0,0,0,.45);
  --badge-pass-bg:#14532d;--badge-pass-fg:#bbf7d0;--badge-fail-bg:#7f1d1d;
  --badge-fail-fg:#fecaca;--row-failed:#2a1517;--warn-bg:#3b2f0a;--warn-fg:#fcd34d;
  --warn-border:#6b5414;color-scheme:dark;"""

_LIGHT = """
  --bg:#f0f2f5;--surface:#fff;--text:#1a1a2e;--muted:#555;--faint:#8a8f99;
  --border:#f3f4f6;--border-strong:#e5e7eb;--link:#4338ca;--header-bg:#1a1a2e;
  --header-text:#fff;--code-bg:#f9fafb;--input-bg:#fff;--accent:#6366f1;
  --pass:#16a34a;--fail:#dc2626;--skip:#9ca3af;--shadow:rgba(0,0,0,.08);
  --badge-pass-bg:#dcfce7;--badge-pass-fg:#166534;--badge-fail-bg:#fee2e2;
  --badge-fail-fg:#991b1b;--row-failed:#fff5f5;--warn-bg:#fef3c7;--warn-fg:#92400e;
  --warn-border:#fcd34d;color-scheme:light;"""

# The variables, plus the toggle's own look. Pages put it first in their CSS.
CSS = f"""
:root{{{_DARK}}}
@media (prefers-color-scheme: light){{:root:not([data-theme="dark"]){{{_LIGHT}}}}}
:root[data-theme="light"]{{{_LIGHT}}}
:root[data-theme="dark"]{{{_DARK}}}
header{{position:relative}}
.theme-toggle{{position:absolute;top:18px;right:20px;font:inherit;font-size:16px;
  line-height:1;padding:6px 9px;border-radius:6px;cursor:pointer;color:var(--header-text);
  background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.18)}}
.theme-toggle:hover{{background:rgba(255,255,255,.16)}}
.theme-toggle[hidden]{{display:none}}
"""

# In <head>, before the CSS applies: a remembered choice, so the page
# doesn't flash in the other theme first.
HEAD_SCRIPT = (
    "<script>try{var t=localStorage.getItem('" + STORAGE_KEY + "');"
    "if(t==='light'||t==='dark')document.documentElement.dataset.theme=t;}catch(e){}"
    "</script>"
)

_TOGGLE_SCRIPT = (
    "<script>(function(){var r=document.documentElement,"
    "b=document.getElementById('theme-toggle');if(!b)return;"
    "function cur(){return r.dataset.theme||(window.matchMedia&&"
    "matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');}"
    "function show(){b.textContent=cur()==='dark'?'\\u2600':'\\u263E';}"
    "b.addEventListener('click',function(){var n=cur()==='dark'?'light':'dark';"
    "r.dataset.theme=n;try{localStorage.setItem('" + STORAGE_KEY + "',n);}catch(e){}show();});"
    "show();b.hidden=false;})();</script>"
)


def toggle(label: str = "Switch between dark and light theme") -> str:
    """The toggle button for the page header, with its script. Hidden
    until the script runs."""
    text = html.escape(label, quote=True)
    return (
        f'<button type="button" id="theme-toggle" class="theme-toggle" hidden '
        f'title="{text}" aria-label="{text}"></button>{_TOGGLE_SCRIPT}'
    )
