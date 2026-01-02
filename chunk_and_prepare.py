import os
import json
import pandas as pd
from nltk.tokenize import sent_tokenize
from pdfminer.high_level import extract_text

def chunk_text(text, max_chars=800):
    sentences = sent_tokenize(text)
    chunks, cur = [], ""
    for s in sentences:
        if len(cur) + len(s) <= max_chars:
            cur += s + " "
        else:
            chunks.append(cur.strip())
            cur = s + " "
    if cur.strip():
        chunks.append(cur.strip())
    return chunks

# ---------------------------
# TXT / MD
# ---------------------------
def process_plain_txt(src_path, dest_dir):
    with open(src_path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    export_chunks(text, src_path, dest_dir)

# ---------------------------
# JSON
# ---------------------------
def process_json(src_path, dest_dir):
    try:
        with open(src_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        text = json.dumps(data, indent=2)
        export_chunks(text, src_path, dest_dir)
    except Exception as e:
        print(f"[ERROR] Could not process JSON {src_path}: {e}")

# ---------------------------
# PDF
# ---------------------------
def process_pdf(src_path, dest_dir):
    try:
        text = extract_text(src_path)
        export_chunks(text, src_path, dest_dir)
    except Exception as e:
        print(f"[ERROR] Could not process PDF {src_path}: {e}")

# ---------------------------
# XLSX / XLS
# ---------------------------
def process_excel(src_path, dest_dir):
    try:
        df = pd.read_excel(src_path, sheet_name=None)
        full_text = ""
        for sheet_name, sheet_df in df.items():
            full_text += f"\n--- Sheet: {sheet_name} ---\n"
            full_text += sheet_df.to_string() + "\n"
        export_chunks(full_text, src_path, dest_dir)
    except Exception as e:
        print(f"[ERROR] Could not process Excel {src_path}: {e}")


# ---------------------------
# Common export
# ---------------------------
def export_chunks(text, src_path, dest_dir):
    chunks = chunk_text(text)
    basename = os.path.basename(src_path).rsplit(".",1)[0]
    for i, c in enumerate(chunks):
        fn = os.path.join(dest_dir, f"{basename}_chunk_{i}.txt")
        with open(fn, "w", encoding="utf-8") as out:
            out.write(c)

# ---------------------------
# Router
# ---------------------------
def process_folder(folder, dest_dir):
    os.makedirs(dest_dir, exist_ok=True)
    for root, _, files in os.walk(folder):
        for file in files:
            path = os.path.join(root, file)
            lower = file.lower()

            if lower.endswith((".txt", ".md")):
                print(f"[TXT] Processing {path}")
                process_plain_txt(path, dest_dir)

            elif lower.endswith(".json"):
                print(f"[JSON] Processing {path}")
                process_json(path, dest_dir)

            elif lower.endswith(".pdf"):
                print(f"[PDF] Processing {path}")
                process_pdf(path, dest_dir)

            elif lower.endswith((".xlsx", ".xls")):
                print(f"[EXCEL] Processing {path}")
                process_excel(path, dest_dir)

            else:
                print(f"[SKIP] Unsupported file type: {path}")

# ---------------------------
# ENTRY POINT
# ---------------------------
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python chunk_and_prepare.py <source_folder> <dest_chunk_folder>")
        sys.exit(1)
    
    src = sys.argv[1]
    dst = sys.argv[2]
    process_folder(src, dst)