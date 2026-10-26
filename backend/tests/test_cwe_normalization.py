"""CWE-0 / placeholder normalization.

CWE-0 is a "no weakness assigned" placeholder some scanners (e.g. ZAP) emit.
Treating it as a real CWE would block the keyword mapper / NVD back-fill and
wrongly credit the cwe_mapping confidence factor, so it must normalize to None.
"""

import xml.etree.ElementTree as ET
from unittest.mock import MagicMock

import pytest

from app.utils.helpers import extract_cwe_id
from app.parsers.zap_parser import ZapParser


@pytest.mark.parametrize("raw,expected", [
    ("CWE-0", None),
    ("CWE-00", None),
    ("0", None),
    ("NVD-CWE-noinfo", None),
    ("NVD-CWE-Other", None),
    ("", None),
    ("CWE-79", "CWE-79"),
    ("CWE-1021", "CWE-1021"),
    ("cwe-89 blah", "CWE-89"),
])
def test_extract_cwe_id_rejects_placeholders(raw, expected):
    assert extract_cwe_id(raw) == expected


def _alert(name, cweid):
    xml = (f"<alertitem><alert>{name}</alert><name>{name}</name>"
           f"<riskdesc>High (High)</riskdesc><desc>d</desc><cweid>{cweid}</cweid>"
           f"<instances><instance><uri>http://x/a</uri><method>GET</method>"
           f"</instance></instances></alertitem>")
    return ET.fromstring(xml)


def test_zap_parser_drops_cweid_zero():
    p = ZapParser(MagicMock(id=1))
    assert p._parse_alert(_alert("User Agent Fuzzer", 0)).cwe_id is None


def test_zap_parser_keeps_real_cweid():
    p = ZapParser(MagicMock(id=1))
    assert p._parse_alert(_alert("SQL Injection", 89)).cwe_id == "CWE-89"
