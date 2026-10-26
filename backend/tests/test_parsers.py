"""Parser unit tests using sample report snippets."""

import json
import tempfile
import os
from app.parsers.zap_parser import ZapParser
from app.parsers.nuclei_parser import NucleiParser

# Fixtures `app` and `upload` are provided by tests/conftest.py.

ZAP_SAMPLE = """<?xml version="1.0"?>
<OWASPZAPReport version="2.14.0">
  <site name="http://testphp.vulnweb.com" host="testphp.vulnweb.com" port="80" ssl="false">
    <alerts>
      <alertitem>
        <pluginid>40012</pluginid>
        <alertRef>40012-1</alertRef>
        <alert>Cross Site Scripting (Reflected)</alert>
        <name>Cross Site Scripting (Reflected)</name>
        <riskcode>3</riskcode>
        <confidence>2</confidence>
        <riskdesc>High (2)</riskdesc>
        <confidencedesc>Medium (2)</confidencedesc>
        <desc>Cross-site Scripting attack.</desc>
        <instances>
          <instance>
            <uri>http://testphp.vulnweb.com/search.php</uri>
            <method>GET</method>
            <param>searchFor</param>
            <attack>&lt;script&gt;alert(1);&lt;/script&gt;</attack>
            <evidence>&lt;script&gt;alert(1);&lt;/script&gt;</evidence>
          </instance>
        </instances>
        <solution>Phase: Architecture and Design</solution>
        <reference>https://owasp.org/www-community/attacks/xss/</reference>
        <cweid>79</cweid>
        <wascid>8</wascid>
        <sourceid>1</sourceid>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>
"""

NUCLEI_SAMPLE = json.dumps({
    "template-id": "cve-2021-44228",
    "info": {
        "name": "Apache Log4j RCE",
        "severity": "critical",
        "description": "Log4Shell vulnerability.",
        "classification": {
            "cve-id": ["CVE-2021-44228"],
            "cwe-id": ["CWE-502"],
            "cvss-score": 10.0,
        },
    },
    "matched-at": "http://vulnerable.example.com:8080/app",
    "type": "http",
    "host": "vulnerable.example.com",
})


def test_zap_parser(app, upload):
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".xml", delete=False, encoding="utf-8"
    ) as f:
        f.write(ZAP_SAMPLE)
        tmp_path = f.name
    try:
        parser = ZapParser(upload)
        count = parser.parse(tmp_path)
        assert count == 1
    finally:
        os.unlink(tmp_path)


def test_nuclei_parser(app, upload):
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        f.write(NUCLEI_SAMPLE)
        tmp_path = f.name
    try:
        upload.scanner_type = "nuclei"
        parser = NucleiParser(upload)
        count = parser.parse(tmp_path)
        assert count == 1
    finally:
        os.unlink(tmp_path)
