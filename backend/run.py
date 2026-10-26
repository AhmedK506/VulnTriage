import os
from app import create_app, db
from app.models import (
    User, ScannerUpload, Vulnerability, NormalizedFinding,
    CweMapping, MlPrediction, ConfidenceScore, PocValidation, Report,
)

app = create_app(os.environ.get("FLASK_ENV", "development"))


@app.shell_context_processor
def make_shell_context():
    return {
        "db": db,
        "User": User,
        "ScannerUpload": ScannerUpload,
        "Vulnerability": Vulnerability,
        "NormalizedFinding": NormalizedFinding,
        "CweMapping": CweMapping,
        "MlPrediction": MlPrediction,
        "ConfidenceScore": ConfidenceScore,
        "PocValidation": PocValidation,
        "Report": Report,
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
