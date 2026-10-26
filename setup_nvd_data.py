"""
NVD Data Setup Script

Copies the three NVD translation XML files into ml_data/nvd/
so the model trainer can find them.

Usage (from the FYP root directory):
  python setup_nvd_data.py

The source paths below match your Downloads folder structure.
Edit SOURCE_FILES if you move the XML files.
"""

import os
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(BASE_DIR, "ml_data", "nvd")

SOURCE_FILES = [
    r"C:\Users\Dell\Downloads\nvdcve-2025trans.xml\nvdcve-2025trans.xml",
    r"C:\Users\Dell\Downloads\nvdcve-2024trans.xml\nvdcve-2024trans.xml",
    r"C:\Users\Dell\Downloads\nvdcve-2023trans.xml\nvdcve-2023trans.xml",
]


def main():
    os.makedirs(TARGET_DIR, exist_ok=True)
    print(f"Target directory: {TARGET_DIR}\n")

    copied = 0
    for src in SOURCE_FILES:
        if not os.path.isfile(src):
            print(f"  [SKIP] Not found: {src}")
            continue
        fname = os.path.basename(src)
        dst = os.path.join(TARGET_DIR, fname)
        size_mb = os.path.getsize(src) / (1024 * 1024)
        print(f"  Copying {fname} ({size_mb:.1f} MB) ...", end=" ", flush=True)
        shutil.copy2(src, dst)
        print("done")
        copied += 1

    print(f"\n{copied}/{len(SOURCE_FILES)} files copied to ml_data/nvd/")
    if copied == 0:
        print("ERROR: No files were copied. Check source paths above.")
        return

    print("\nNext step — train the model:")
    print("  cd backend")
    print("  python -m app.ml.model_trainer")


if __name__ == "__main__":
    main()
