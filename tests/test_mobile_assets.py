"""Guards for the phone layout. These read the HTML, CSS and JavaScript files
and catch the mistakes that once made the phone menu impossible to open:
the script and the stylesheet must agree on class names and element ids.
"""

import re
from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "web"
HTML = (WEB / "templates" / "index.html").read_text(encoding="utf-8")
CSS = (WEB / "static" / "css" / "style.css").read_text(encoding="utf-8")
JS = (WEB / "static" / "js" / "script.js").read_text(encoding="utf-8")


def test_page_scales_to_the_phone_screen():
    assert re.search(r'name="viewport"[^>]*width=device-width', HTML)


def test_menu_class_used_by_the_script_has_a_css_rule():
    # The script sets "sidebar-open" on <body>; the CSS must react to it.
    assert "'sidebar-open'" in JS
    assert re.search(r"body\.sidebar-open\s+\.sidebar\s*\{[^}]*translateX\(0\)", CSS)


# Elements the script handles safely when they are absent
# (it checks "if (elements.suspicious)" before using them).
OPTIONAL_IDS = {"suspiciousCount", "adminCreditForm", "adminToken", "adminFeedback", "adminGrantResult", "adminUserEmail", "adminScanAmount", "adminLoadOverview", "adminGrantReason", "adminGrantButton", "adminOverview", "adminPaymentBreakdown"}


def test_every_element_id_the_script_looks_up_exists_in_the_page():
    ids_in_html = set(re.findall(r'\bid="([^"]+)"', HTML))
    ids_in_js = set(re.findall(r"\$\('([A-Za-z0-9_-]+)'\)", JS))

    assert ids_in_js - ids_in_html - OPTIONAL_IDS == set()


def test_history_table_does_not_force_the_page_wider_than_a_phone():
    # .history-table has min-width: 780px for desktops; the phone layout
    # must switch it off, otherwise browsers zoom the whole page out.
    assert re.search(r"\.history-table\.responsive-table\s*\{\s*min-width:\s*0", CSS)


def test_tables_have_card_layout_and_labels():
    assert HTML.count("responsive-table") >= 2
    assert "labelTableCells(tbody, HISTORY_COLUMNS)" in JS
    assert "labelTableCells(tbody, RECENT_COLUMNS)" in JS
    assert "attr(data-label)" in CSS


def test_details_window_content_is_styled():
    for name in ("details-grid", "details-url", "details-indicators"):
        assert f".{name}" in CSS


def test_text_fields_are_16px_on_phones_so_iphones_do_not_zoom():
    assert re.search(r"input,\s*select,\s*textarea\s*\{\s*font-size:\s*16px", CSS)
