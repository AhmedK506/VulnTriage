from app.parsers.zap_parser import ZapParser
from app.parsers.nuclei_parser import NucleiParser
from app.parsers.nessus_parser import NessusParser
from app.models.scanner_upload import ScannerUpload


def parse_scanner_file(upload: ScannerUpload, file_path: str, scanner_type: str) -> int:
    """
    Dispatch to the correct parser and persist raw Vulnerability rows.
    Returns the number of vulnerabilities parsed.
    """
    parsers = {
        "zap": ZapParser,
        "nuclei": NucleiParser,
        "nessus": NessusParser,
    }

    parser_cls = parsers.get(scanner_type)
    if not parser_cls:
        raise ValueError(f"No parser registered for scanner type: {scanner_type}")

    parser = parser_cls(upload)
    return parser.parse(file_path)
