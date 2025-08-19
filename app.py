import re
from io import BytesIO
from pathlib import Path
import streamlit as st
import pandas as pd

# Lazy imports (so Streamlit starts fast)
def _easyocr_text(file_bytes: bytes) -> str:
    import easyocr
    import tempfile, os
    # EasyOCR expects a path; write temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
        tmp.write(file_bytes)
        tmp.flush()
        path = tmp.name
    try:
        reader = easyocr.Reader(["en"], verbose=False)
        out = reader.readtext(path, detail=0)
        return " ".join(out)
    finally:
        try:
            os.remove(path)
        except Exception:
            pass

def _pdf_text(file_bytes: bytes) -> str:
    from PyPDF2 import PdfReader
    import io
    reader = PdfReader(io.BytesIO(file_bytes))
    parts = []
    for page in reader.pages:
        parts.append(page.extract_text() or "")
    return "\n".join(parts)

def _plain_text(file_bytes: bytes) -> str:
    try:
        return file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return ""

# --- Controls (regex rules) ---
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
    "iam_least_privilege": [r"action.*\*.*resource.*\*"],  # overly broad
}

def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").lower()

def extract_text(uploaded_file) -> str:
    name = uploaded_file.name.lower()
    data = uploaded_file.read()
    # Route by extension
    if name.endswith((".png", ".jpg", ".jpeg")):
        return _easyocr_text(data)
    elif name.endswith(".pdf"):
        return _pdf_text(data)
    else:
        # try plain text (txt, json, log, csv…)
        return _plain_text(data)

def evaluate(text: str) -> dict:
    t = normalize(text)
    out = {}
    for ctrl, pats in CONTROLS.items():
        hits = [p for p in pats if re.search(p, t)]
        fails = [p for p in FAIL_PATTERNS.get(ctrl, []) if re.search(p, t)]
        status = "NON_COMPLIANT" if fails else ("COMPLIANT" if hits else "INSUFFICIENT_EVIDENCE")
        out[ctrl] = {"status": status, "matches": hits + fails}
    return out

def build_results_df(results_by_file):
    rows = []
    for fname, res in results_by_file.items():
        row = {"file": fname}
        for ctrl, outcome in res.items():
            row[f"{ctrl}_status"] = outcome["status"]
            row[f"{ctrl}_matches"] = "; ".join(outcome["matches"])
        rows.append(row)
    df = pd.DataFrame(rows)
    return df

# ---- UI ----
st.set_page_config(page_title="Control Checker", page_icon="🔍", layout="centered")
st.title("🔍 Security Control Checker (OCR + Rules)")

st.write(
    "Upload **image/PDF/log/JSON/TXT** evidence. We'll extract text (EasyOCR/PyPDF2/plain), "
    "then check against common security controls and let you download an Excel of results."
)

uploads = st.file_uploader(
    "Upload one or more files",
    type=["png", "jpg", "jpeg", "pdf", "txt", "log", "json", "csv"],
    accept_multiple_files=True,
)

if uploads:
    results_by_file = {}
    with st.spinner("Processing..."):
        for uf in uploads:
            st.subheader(f"📄 {uf.name}")
            try:
                text = extract_text(uf)
            finally:
                uf.seek(0)  # reset after read so Streamlit keeps it accessible

            if not text.strip():
                st.warning("No text extracted — for images install `easyocr torch torchvision`; for PDFs install `PyPDF2`.")
                continue

            # show OCR/Extract preview
            st.text_area("Extracted Text (preview)", text[:1000], height=200)

            res = evaluate(text)
            results_by_file[uf.name] = res

            # show status per control
            for ctrl, outcome in res.items():
                status = outcome["status"]
                matches = ", ".join(outcome["matches"]) or "—"
                if status == "COMPLIANT":
                    st.success(f"{ctrl}: {status}  •  {matches}")
                elif status == "NON_COMPLIANT":
                    st.error(f"{ctrl}: {status}  •  {matches}")
                else:
                    st.info(f"{ctrl}: {status}  •  {matches}")

    if results_by_file:
        df = build_results_df(results_by_file)
        st.subheader("📊 Results Table")
        st.dataframe(df, use_container_width=True)

        # Excel download
        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="results")
        st.download_button(
            label="⬇️ Download results.xlsx",
            data=buf.getvalue(),
            file_name="results.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

st.caption("Tip: For best OCR on screenshots, crop tightly and ensure readable resolution.")
