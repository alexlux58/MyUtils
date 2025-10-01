
import os
import re
import sys
import glob
import argparse
from typing import List, Tuple, Dict, Optional

import numpy as np
import pandas as pd
from PIL import Image, ImageOps, ImageFilter, ImageEnhance
import cv2
import pytesseract

WANTED_COLS = ["First Name", "Last Name", "Phone", "Email", "Tags"]

def log(msg: str):
    print(f"[contacts-ocr] {msg}", file=sys.stderr)

def preprocess_image(im: Image.Image, upscale: float = 2.5) -> Image.Image:
    """
    Enhanced image preprocessing for better OCR results.
    Applies multiple enhancement techniques to improve text clarity.
    """
    try:
        im = ImageOps.exif_transpose(im)
    except Exception:
        pass
    
    # Convert to grayscale
    im = im.convert("L")
    
    # Convert PIL to OpenCV format for advanced processing
    cv_image = np.array(im)
    
    # Apply bilateral filter to reduce noise while preserving edges
    cv_image = cv2.bilateralFilter(cv_image, 9, 75, 75)
    
    # Apply CLAHE (Contrast Limited Adaptive Histogram Equalization)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    cv_image = clahe.apply(cv_image)
    
    # Apply Otsu's thresholding for better text separation
    _, cv_image = cv2.threshold(cv_image, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    
    # Morphological operations to clean up the image
    kernel = np.ones((1, 1), np.uint8)
    cv_image = cv2.morphologyEx(cv_image, cv2.MORPH_CLOSE, kernel)
    
    # Convert back to PIL
    im = Image.fromarray(cv_image)
    
    # Resize with higher upscale factor for better OCR
    w, h = im.size
    im = im.resize((int(w * upscale), int(h * upscale)), Image.Resampling.LANCZOS)
    
    # Apply additional PIL enhancements
    # Increase contrast more aggressively
    enhancer = ImageEnhance.Contrast(im)
    im = enhancer.enhance(2.0)
    
    # Increase sharpness
    enhancer = ImageEnhance.Sharpness(im)
    im = enhancer.enhance(3.0)
    
    # Apply unsharp mask for better text definition
    im = im.filter(ImageFilter.UnsharpMask(radius=1, percent=300, threshold=1))
    
    return im

def preprocess_image_simple(im: Image.Image, upscale: float = 3.0) -> Image.Image:
    """
    Simple but effective preprocessing for OCR.
    Uses basic PIL operations for better compatibility.
    """
    try:
        im = ImageOps.exif_transpose(im)
    except Exception:
        pass
    
    # Convert to grayscale
    im = im.convert("L")
    
    # Apply aggressive autocontrast
    im = ImageOps.autocontrast(im, cutoff=0.5)
    
    # Apply equalize to improve contrast
    im = ImageOps.equalize(im)
    
    # Resize with high upscale
    w, h = im.size
    im = im.resize((int(w * upscale), int(h * upscale)), Image.Resampling.LANCZOS)
    
    # Apply aggressive contrast enhancement
    enhancer = ImageEnhance.Contrast(im)
    im = enhancer.enhance(3.0)
    
    # Apply aggressive sharpness
    enhancer = ImageEnhance.Sharpness(im)
    im = enhancer.enhance(4.0)
    
    # Apply unsharp mask
    im = im.filter(ImageFilter.UnsharpMask(radius=1, percent=400, threshold=0))
    
    return im

def ocr_dataframe(im: Image.Image) -> pd.DataFrame:
    """
    Enhanced OCR processing with better configuration for table recognition.
    """
    # Try multiple OCR configurations for better results
    configs = [
        "--oem 3 --psm 6",  # Uniform block of text
        "--oem 3 --psm 4",  # Single column of text
        "--oem 3 --psm 3"   # Fully automatic page segmentation
    ]
    
    best_df = None
    best_conf_score = 0
    
    for config in configs:
        try:
            df = pytesseract.image_to_data(im, output_type=pytesseract.Output.DATAFRAME, config=config)
            df = df[(df.conf != -1) & df.text.notna() & (df.text.astype(str).str.strip() != "")].copy()
            
            if not df.empty:
                # Calculate confidence score
                conf_score = df['conf'].mean()
                if conf_score > best_conf_score:
                    best_conf_score = conf_score
                    best_df = df.copy()
        except Exception as e:
            log(f"OCR config {config} failed: {e}")
            continue
    
    if best_df is None or best_df.empty:
        return pd.DataFrame()
    
    df = best_df
    df["cx"] = df["left"] + df["width"] / 2.0
    df["cy"] = df["top"] + df["height"] / 2.0
    df["line_id"] = df["block_num"].astype(str) + "-" + df["par_num"].astype(str) + "-" + df["line_num"].astype(str)
    return df

def merge_cells(tokens: pd.DataFrame, gap: int = 45):
    cells, cur, last_right = [], [], None
    for _, r in tokens.sort_values("left").iterrows():
        if last_right is None or r["left"] - last_right <= gap:
            cur.append(r)
        else:
            cells.append(pd.DataFrame(cur)); cur = [r]
        last_right = r["left"] + r["width"]
    if cur: cells.append(pd.DataFrame(cur))
    texts = [" ".join(c["text"].tolist()) for c in cells]
    centers = [float(np.mean(c["left"] + c["width"] / 2.0)) for c in cells]
    return texts, centers

def find_header_line(df: pd.DataFrame):
    if df.empty: 
        return None
    key_words = ["first", "last", "phone", "email", "tags"]
    best_score, best_g, best_top = -1, None, None
    for lid, g in df.groupby("line_id"):
        g = g.sort_values("left")
        txt = " ".join(g["text"].astype(str).tolist()).lower()
        score = sum(1 for k in key_words if k in txt)
        if score > best_score or (score == best_score and (best_top is None or g["top"].min() < best_top)):
            best_score, best_g, best_top = score, g, g["top"].min()
    return best_g if best_score >= 2 else None

def build_column_map_from_header(header_tokens: pd.DataFrame) -> Dict[str, float]:
    if header_tokens is None or header_tokens.empty:
        return {}
    h_texts, h_centers = merge_cells(header_tokens, gap=45)
    def idx_contains(target: str):
        tgt = target.lower()
        for i, t in enumerate(h_texts):
            if tgt in t.lower():
                return i
        return None
    idx_first = idx_contains("first")
    idx_last  = idx_contains("last")
    idx_email = idx_contains("email")
    idx_tags  = idx_contains("tag")
    idx_phone = idx_contains("phone")
    if idx_phone is None and idx_last is not None and (idx_last + 3) < len(h_texts):
        idx_phone = idx_last + 3
    col_map = {}
    for name, idx in [("First Name", idx_first), ("Last Name", idx_last),
                      ("Phone", idx_phone), ("Email", idx_email), ("Tags", idx_tags)]:
        if idx is not None:
            col_map[name] = h_centers[idx]
    return col_map

def cluster_rows(tokens: pd.DataFrame, header_bottom: float):
    below = tokens[tokens["top"] > header_bottom].copy()
    if below.empty:
        return []
    below = below.sort_values("top")
    row_thresh = float(np.median(below["height"])) * 1.25
    rows, cur, cur_y = [], [], None
    for _, t in below.iterrows():
        if cur_y is None or abs(t["cy"] - cur_y) <= row_thresh:
            cur.append(t)
            if cur_y is None:
                cur_y = t["cy"]
        else:
            rows.append(pd.DataFrame(cur)); cur, cur_y = [t], t["cy"]
    if cur: rows.append(pd.DataFrame(cur))
    return rows

def nearest_col_name(x: float, col_map: Dict[str, float]) -> str:
    names = list(col_map.keys())
    centers = [col_map[n] for n in names]
    idx = int(np.argmin([abs(x - c) for c in centers]))
    return names[idx]

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
def extract_email(s: str) -> str:
    if not s: return ""
    m = EMAIL_RE.findall(s)
    return m[0] if m else ""

def normalize_phone(s: str) -> str:
    if not s: return ""
    digits = re.sub(r"\D", "", s)
    if len(digits) >= 10:
        digits = digits[-10:]
        return f"({digits[0:3]}) {digits[3:6]}-{digits[6:10]}"
    return s.strip()

def parse_rows_with_colmap(tokens: pd.DataFrame, col_map: Dict[str, float], header_bottom: float) -> pd.DataFrame:
    rows = cluster_rows(tokens, header_bottom)
    out = []
    for r in rows:
        rec = {k: "" for k in WANTED_COLS}
        buckets = {k: [] for k in col_map.keys()}
        for _, t in r.iterrows():
            cname = nearest_col_name(t["cx"], col_map)
            if cname in buckets:
                buckets[cname].append((t["left"], str(t["text"])))
        for k in WANTED_COLS:
            if k in buckets and buckets[k]:
                rec[k] = " ".join([txt for _, txt in sorted(buckets[k], key=lambda z: z[0])]).strip()
        rec["Email"] = extract_email((rec.get("Email","") + " " + rec.get("Tags","")).strip())
        rec["Phone"] = normalize_phone(rec.get("Phone",""))
        if any(v.strip() for v in rec.values()):
            out.append(rec)
    return pd.DataFrame(out, columns=WANTED_COLS) if out else pd.DataFrame(columns=WANTED_COLS)

def process_image(path: str, base_col_map: Optional[Dict[str, float]]):
    im = Image.open(path)
    
    # Try advanced preprocessing first
    try:
        pim = preprocess_image(im)
        df = ocr_dataframe(pim)
        if not df.empty and df['conf'].mean() > 30:  # If confidence is reasonable
            log(f"Using advanced preprocessing (conf: {df['conf'].mean():.1f})")
        else:
            raise Exception("Low confidence, trying simple preprocessing")
    except Exception as e:
        log(f"Advanced preprocessing failed: {e}, trying simple method")
        pim = preprocess_image_simple(im)
        df = ocr_dataframe(pim)
    
    if df.empty:
        return pd.DataFrame(columns=WANTED_COLS), base_col_map or {}

    if base_col_map is None:
        header_tokens = find_header_line(df)
        if header_tokens is not None:
            col_map = build_column_map_from_header(header_tokens)
            header_bottom = float(header_tokens["top"].min() + header_tokens["height"].max())
        else:
            H = float(df["top"].max() + df["height"].max())
            header_bottom = H * 0.05
            page_left = float(df["left"].min())
            page_right = float((df["left"] + df["width"]).max())
            xs = np.linspace(page_left, page_right, num=6)[1:-1]
            col_map = {name: xs[i] for i, name in enumerate(WANTED_COLS) if i < len(xs)}
        out_df = parse_rows_with_colmap(df, col_map, header_bottom)
        return out_df, col_map
    else:
        H = float(df["top"].max() + df["height"].max())
        header_bottom = H * 0.05
        out_df = parse_rows_with_colmap(df, base_col_map, header_bottom)
        return out_df, base_col_map

def read_structured_table(path: str) -> pd.DataFrame:
    try:
        if path.lower().endswith(".csv"):
            df = pd.read_csv(path)
        else:
            df = pd.read_excel(path)
    except Exception as e:
        log(f"Failed to read table '{path}': {e}")
        return pd.DataFrame(columns=WANTED_COLS)
    cols = {c.lower(): c for c in df.columns}
    def get_col(*aliases):
        for a in aliases:
            if a in cols: return cols[a]
        return None
    out = pd.DataFrame()
    out["First Name"] = df.get(get_col("first name", "first", "firstname"), "")
    out["Last Name"]  = df.get(get_col("last name", "last", "lastname"), "")
    out["Phone"]      = df.get(get_col("phone", "phone number", "mobile"), "")
    out["Email"]      = df.get(get_col("email", "e-mail"), "")
    out["Tags"]       = df.get(get_col("tags", "tag"), "")
    out["Phone"] = out["Phone"].map(lambda x: normalize_phone(str(x)))
    out["Email"] = out["Email"].map(lambda x: extract_email(str(x)))
    return out

def main():
    ap = argparse.ArgumentParser(description="Extract contacts from images (and optional CSVs) into a master CSV.")
    ap.add_argument("--images", nargs="*", default=[], help="Paths to JPG/PNG/TIF images (header assumed on first).")
    ap.add_argument("--images-dir", default=None, help="Directory to scan for images.")
    ap.add_argument("--tables", nargs="*", default=[], help="Existing CSV/XLSX files to merge.")
    ap.add_argument("--out", required=True, help="Output CSV path.")
    ap.add_argument("--debug", action="store_true", help="Save per-image intermediate CSVs.")
    args = ap.parse_args()

    images = []
    images += [p for p in args.images if os.path.isfile(p)]
    if args.images_dir and os.path.isdir(args.images_dir):
        for ext in ("*.jpg","*.jpeg","*.png","*.tif","*.tiff","*.bmp","*.webp"):
            images += glob.glob(os.path.join(args.images_dir, ext))
    images = sorted(list(dict.fromkeys(images)))

    if not images and not args.tables:
        log("No inputs given. Use --images/--images-dir and/or --tables.")
        sys.exit(1)

    frames: List[pd.DataFrame] = []

    col_map = None
    for i, ip in enumerate(images):
        log(f"Processing image [{i+1}/{len(images)}]: {ip}")
        df_img, col_map = process_image(ip, col_map)
        if not df_img.empty:
            frames.append(df_img)
            if args.debug:
                tmp_out = os.path.splitext(args.out)[0] + f".parsed_{i+1}.csv"
                df_img.to_csv(tmp_out, index=False)
        else:
            log(f"  (no rows found in {ip})")

    for tp in args.tables:
        log(f"Merging table: {tp}")
        df_tab = read_structured_table(tp)
        if not df_tab.empty:
            frames.append(df_tab)

    if not frames:
        log("No rows extracted.")
        pd.DataFrame(columns=WANTED_COLS).to_csv(args.out, index=False)
        print(args.out)
        return

    combined = pd.concat(frames, ignore_index=True)
    combined["__key"] = (
        combined["First Name"].astype(str).str.lower().str.strip() + "|" +
        combined["Last Name"].astype(str).str.lower().str.strip() + "|" +
        combined["Email"].astype(str).str.lower().str.strip() + "|" +
        combined["Phone"].astype(str).str.strip()
    )
    combined = combined.drop_duplicates(subset="__key").drop(columns="__key")

    def clean_str(x): 
        return str(x).strip() if pd.notna(x) else ""
    for c in WANTED_COLS:
        combined[c] = combined[c].map(clean_str)

    combined.to_csv(args.out, index=False)
    print(args.out)

if __name__ == "__main__":
    main()
