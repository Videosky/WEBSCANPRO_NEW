# extract_features.py

import pandas as pd
import re
import string

# ---------------- CONFIG ----------------
INPUT_FILE = "metadata.csv"           # Output from your crawler
OUTPUT_FILE = "features_extracted.csv"

# ---------------- HELPER FUNCTIONS ----------------
def count_special_chars(s):
    if pd.isna(s):
        return 0
    return sum(1 for c in s if c in "<>'\"%&;()")

def count_digits(s):
    if pd.isna(s):
        return 0
    return sum(c.isdigit() for c in str(s))

def is_alpha_only(s):
    if pd.isna(s) or len(s) == 0:
        return False
    return str(s).isalpha()

def contains_sql_keyword(s):
    if pd.isna(s):
        return 0
    sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "UNION", "DROP", "WHERE", "OR", "AND"]
    s_upper = str(s).upper()
    return int(any(keyword in s_upper for keyword in sql_keywords))

def contains_html_tag(s):
    if pd.isna(s):
        return 0
    return int(bool(re.search(r"<(script|img|iframe|div|a|form)", str(s), re.IGNORECASE)))

# ---------------- LOAD DATA ----------------
df = pd.read_csv(INPUT_FILE)

# Use crawler data: url, param_name, default_value, input_type
df["input_value"] = df["default_value"].fillna("")

# ---------------- FEATURE EXTRACTION ----------------
df["input_length"] = df["input_value"].apply(len)
df["num_special_chars"] = df["input_value"].apply(count_special_chars)
df["num_digits"] = df["input_value"].apply(count_digits)
df["is_alpha_only"] = df["input_value"].apply(is_alpha_only)
df["param_type"] = df["input_type"]
df["contains_sql_keyword"] = df["input_value"].apply(contains_sql_keyword)
df["contains_html_tag"] = df["input_value"].apply(contains_html_tag)

# ---------------- SELECT AND SAVE ----------------
feature_cols = [
    "url",
    "param_name",
    "input_value",
    "input_length",
    "num_special_chars",
    "num_digits",
    "is_alpha_only",
    "param_type",
    "contains_sql_keyword",
    "contains_html_tag"
]

df[feature_cols].to_csv(OUTPUT_FILE, index=False)
print(f"✅ Features extracted and saved to {OUTPUT_FILE}")
