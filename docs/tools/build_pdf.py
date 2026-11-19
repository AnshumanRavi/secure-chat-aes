"""
Build docs/SecureChat_Project_Report.pdf from docs/tools/report_template.html.

    python -m docs.tools.build_pdf             # (run docs.tools.make_screenshots first for fresh images)
    python -m docs.tools.build_pdf --preview   # also save PNG previews of every page

The HTML page is printed to an A4 PDF by Chromium (Qt WebEngine, part of PySide6),
so it uses real CSS layout, the Segoe UI font and vector diagrams. The full-bleed cover
and the body (with page margins and footers) are printed separately and joined with pypdf.
"""

import argparse
import os
import sys
from pathlib import Path

os.environ["QT_QPA_PLATFORM"] = "offscreen"
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu")

from PySide6.QtCore import QEventLoop, QMarginsF, QSize, QTimer, QUrl
from PySide6.QtGui import QPageLayout, QPageSize
from PySide6.QtPdf import QPdfDocument
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineSettings
from PySide6.QtWidgets import QApplication
from pypdf import PdfWriter

from common.config import PROJECT_ROOT

TEMPLATE = PROJECT_ROOT / "docs" / "tools" / "report_template.html"
OUTPUT = PROJECT_ROOT / "docs" / "SecureChat_Project_Report.pdf"
VALUES = {"{{DATE}}": "November 2026", "{{GITHUB}}": "github.com/AnshumanRavi/secure-chat-aes"}


def wait(signal=None, ms: int = 0) -> None:
    loop = QEventLoop()
    if signal is not None:
        signal.connect(lambda *_: loop.quit())
    if ms:
        QTimer.singleShot(ms, loop.quit)
    loop.exec()


def print_part(html: str, target: Path, margins_mm: QMarginsF) -> None:
    """Print one HTML document to a PDF with the given page margins (millimetres)."""
    page_file = PROJECT_ROOT / "_report_build.html"      # in the project root so image paths resolve
    page_file.write_text(html, encoding="utf-8")
    try:
        page = QWebEnginePage()
        page.settings().setAttribute(QWebEngineSettings.LocalContentCanAccessFileUrls, True)
        page.load(QUrl.fromLocalFile(str(page_file)))
        wait(page.loadFinished)
        wait(ms=1500)                                       # let images and fonts settle
        layout = QPageLayout(QPageSize(QPageSize.A4), QPageLayout.Portrait, margins_mm, QPageLayout.Millimeter)
        result = {}
        page.pdfPrintingFinished.connect(lambda path, ok: result.update(ok=ok))
        page.printToPdf(str(target), layout)
        while "ok" not in result:
            wait(ms=100)
    finally:
        page_file.unlink(missing_ok=True)
    if not result["ok"]:
        raise RuntimeError(f"Printing {target.name} failed")


def build(preview_dir: Path = None) -> Path:
    _app = QApplication.instance() or QApplication(sys.argv)     # must stay alive while WebEngine works
    html = TEMPLATE.read_text(encoding="utf-8")
    for key, value in VALUES.items():
        html = html.replace(key, value)
    cover_pdf, body_pdf = OUTPUT.with_suffix(".cover.pdf"), OUTPUT.with_suffix(".body.pdf")
    try:
        print_part(html.replace("<body>", '<body class="only-cover">'), cover_pdf, QMarginsF(0, 0, 0, 0))
        print_part(html.replace("<body>", '<body class="no-cover">'), body_pdf, QMarginsF(16, 16, 16, 17))
        writer = PdfWriter()
        for part in (cover_pdf, body_pdf):
            writer.append(str(part))
        writer.add_metadata({"/Title": "Secure Chat Application using AES Encryption",
                             "/Author": "Anshuman Ravi (2306022), NIT Patna",
                             "/Subject": "Applied Cryptography course project report"})
        with open(OUTPUT, "wb") as f:
            writer.write(f)
    finally:
        cover_pdf.unlink(missing_ok=True)
        body_pdf.unlink(missing_ok=True)

    document = QPdfDocument()
    document.load(str(OUTPUT))
    print(f"Wrote {OUTPUT.relative_to(PROJECT_ROOT)}: {document.pageCount()} pages, "
          f"{OUTPUT.stat().st_size / 1024 / 1024:.1f} MB")
    if preview_dir:
        preview_dir.mkdir(parents=True, exist_ok=True)
        for index in range(document.pageCount()):
            document.render(index, QSize(1240, 1754)).save(str(preview_dir / f"page_{index + 1:02d}.png"))
        print(f"Previews in {preview_dir}")
    return OUTPUT


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the project report PDF")
    parser.add_argument("--preview", metavar="FOLDER", help="also save a PNG of every page into FOLDER")
    args = parser.parse_args()
    build(Path(args.preview) if args.preview else None)
    sys.stdout.flush()
    os._exit(0)          # skip Qt WebEngine's slow/crashy teardown in offscreen mode


if __name__ == "__main__":
    main()
