import re
from io import BytesIO
import streamlit as st
import pandas as pd

# ---------- Controls (regex rules) ----------
CONTROLS = {
    "data_destruction": [
        r"certificate of data destruction",
        r"permanently destroyed",
        r"irreversibly destroyed",
        r"secure data wiping",
        r"physical destruction",
    ],
    "firewall_open_ports": [
        r"0\.0\.0\.0/0.*tcp:?\s*22",
        r"tcp:?\s*22.*0\.0\.0\.0/0",
        r"0\.0\.0\.0/0.*tcp:?\s*3389",
        r"tcp:?\s*3389.*0\.0\.0\.0/0",
    ],
    "mfa_required": [r"require mfa", r"duo push", r"mfa for all users"],
    "block_legacy_auth": [r"block legacy authentication"],
    "physical_access": [r"badge[- ]?only", r"biometric", r"restricted", r"access control"],
    "visitor_log": [r"visitor log", r"reason for visit", r"time in", r"time out"],
    "iam_least_privilege": [r"action.*s3:get\*", r"action.*s3:list\*"],
}
FAIL_PATTERNS = {
    "iam_least_privilege": [r"action.*\*.*resource.*\*"],  # overly-broad IAM
}

# ---------- Helpers ----------
def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").lower()

@st.cache_resource
def get_easyocr_reader():
    """Create once-per-session. If EasyOCR/torch not available, return None."""
    try:
        import easyocr
        return easyocr.Reader(["en"], verbose=False)
    except Exception:
        return None

def extract_text(file) -> str:
    """Route by extension and extract text (OCR for images, PyPDF2 for PDFs, plain decode for others)."""
    name = (file.name or "").lower()

    # Read raw bytes once
    data = file.read()
    file.seek(0)

    # Images → EasyOCR (if available)
    if name.endswith((".png", ".jpg", ".jpeg")):
        reader = get_easyocr_reader()
        if reader is None:
            st.warning("EasyOCR unavailable. Install `easyocr torch torchvision` in requirements.txt to OCR images.")
            return ""
        # EasyOCR expects a filepath; write a small temp file
        import tempfile, os
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
            tmp.write(data)
            tmp.flush()
            path = tmp.name
        try:
            out = reader.readtext(path, detail=0)
            return " ".join(out)
        finally:
            try: os.remove(path)
            except Exception: pass

    # PDFs → PyPDF2
    if name.endswith(".pdf"):
        try:
            from PyPDF2 import PdfReader
            import io
            reader = PdfReader(io.BytesIO(data))
            parts = [(p.extract_text() or "") for p in reader.pages]
            return "\n".join(parts)
        except Exception:
            st.warning("PyPDF2 not available or failed to read this PDF.")
            return ""

    # Plain text (txt/log/json/csv…)
    try:
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""

def evaluate(text: str) -> dict:
    t = normalize(text)
    out = {}
    for ctrl, pats in CONTROLS.items():
        hits = [p for p in pats if re.search(p, t)]
        fails = [p for p in FAIL_PATTERNS.get(ctrl, []) if re.search(p, t)]
        status = "NON_COMPLIANT" if fails else ("COMPLIANT" if hits else "INSUFFICIENT_EVIDENCE")
        out[ctrl] = {"status": status, "matches": hits + fails}
    return out

def results_to_dataframe(results_by_file: dict) -> pd.DataFrame:
    rows = []
    for fname, res in results_by_file.items():
        row = {"file": fname}
        for ctrl, outcome in res.items():
            row[f"{ctrl}_status"]  = outcome["status"]
            row[f"{ctrl}_matches"] = "; ".join(outcome["matches"])
        rows.append(row)
    return pd.DataFrame(rows)

# ---------- UI ----------
st.set_page_config(page_title="Security Control Checker", page_icon="🔎", layout="centered")
st.title("🔎 Security Control Checker")
st.write(
    "Upload **images/PDFs/TXT/JSON/LOG/CSV** → we extract text (OCR for images, PDF parser for PDFs), "
    "match against rules, and let you **download an Excel** of results."
)

uploads = st.file_uploader(
    "Upload one or more evidence files",
    type=["png","jpg","jpeg","pdf","txt","log","json","csv"],
    accept_multiple_files=True,
)

# Optional toggle: show OCR/text preview
show_preview = st.checkbox("Show extracted text preview (first 1000 chars)", value=False)

if uploads:
    results = {}
    for uf in uploads:
        with st.spinner(f"Processing: {uf.name}"):
            text = extract_text(uf)

        if not text.strip():
            st.warning(f"No text extracted from: {uf.name}")
            continue

        if show_preview:
            st.text_area(f"Extracted text preview — {uf.name}", text[:1000], height=180)

        res = evaluate(text)
        results[uf.name] = res

        # Per-file status summary
        cols = st.columns(3)
        compliant = sum(1 for r in res.values() if r["status"] == "COMPLIANT")
        noncomp  = sum(1 for r in res.values() if r["status"] == "NON_COMPLIANT")
        insuff   = sum(1 for r in res.values() if r["status"] == "INSUFFICIENT_EVIDENCE")
        cols[0].success(f"✅ Compliant: {compliant}")
        cols[1].error(f"❌ Non-compliant: {noncomp}")
        cols[2].info(f"ℹ️ Insufficient: {insuff}")

    if results:
        df = results_to_dataframe(results)
        st.subheader("📊 Results")
        st.dataframe(df, use_container_width=True)

        # Excel download
        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="results")
        st.download_button(
            "⬇️ Download results.xlsx",
            data=buf.getvalue(),
            file_name="results.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

st.caption("Tip: On Streamlit Cloud, include `easyocr`, `torch`, `torchvision`, `PyPDF2`, `pandas`, and `openpyxl` in requirements.txt.")
