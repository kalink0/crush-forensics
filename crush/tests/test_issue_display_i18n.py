# SPDX-License-Identifier: Apache-2.0
"""Parser metadata labels and ParseIssues are shown in the UI language;
wherever the same text is exported or copied, it stays English."""
from __future__ import annotations

import pytest
from PySide6.QtWidgets import QFormLayout, QLabel

import crush.ui.props_panel as props_module
from crush.core import issues
from crush.core.issues import ParseIssue, ParseIssueError
from crush.core.passwords import WrongPasswordError
from crush.core.vfs import VFSNode
from crush.ui.i18n import exception_text
from crush.viewers.generated_text import Gen


@pytest.fixture
def issue_translation():
    """Every ParseIssue template shown as «template»."""
    issues.set_translator(lambda context, text, code: f"«{text}»")
    yield
    issues.set_translator(None)


def test_gen_param_issue_shown_translated_exported_english(issue_translation) -> None:
    issue = ParseIssue("realm.table_ref_invalid")
    english, shown = Gen("{error}", error=issue).pair()
    assert english == str(issue)
    assert shown == f"«{str(issue)}»"


def test_properties_panel_translates_label_and_issue(qapp, issue_translation, monkeypatch) -> None:
    real = props_module.translate
    monkeypatch.setattr(
        props_module, "translate",
        lambda context, text, *a: f"‹{text}›" if context == "MetadataLabel" else real(context, text, *a),
    )
    panel = props_module.PropertiesPanel()
    node = VFSNode(name="x.bin", path="/x.bin", is_dir=False, size=1)
    panel.update_properties(node, {"Status": ParseIssue("realm.table_ref_invalid")})
    form = panel.findChild(QFormLayout)
    rows = {}
    for r in range(form.rowCount()):
        label = form.itemAt(r, QFormLayout.ItemRole.LabelRole)
        field = form.itemAt(r, QFormLayout.ItemRole.FieldRole)
        if label and field and isinstance(field.widget(), QLabel):
            rows[label.widget().text()] = field.widget().text()
    assert rows["‹Status›:"] == f"«{str(ParseIssue('realm.table_ref_invalid'))}»"


def test_exception_text_renders_the_carried_issue(issue_translation) -> None:
    issue = ParseIssue("password.realm_hmac")
    assert exception_text(WrongPasswordError(issue)) == f"«{str(issue)}»"
    assert exception_text(ParseIssueError(issue)) == f"«{str(issue)}»"
    assert exception_text(ValueError("plain library text")) == "plain library text"
    # The log keeps the English form.
    assert str(WrongPasswordError(issue)) == str(issue)
