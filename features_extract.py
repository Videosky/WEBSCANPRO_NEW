import pandas as pd
import re
import string

# Load dataset (CSV or JSON)
try:
    df = pd.read_json("metadata.json")
    print("✅ Loaded metadata.json")
except FileNotFoundError:
    df = pd.read_csv("metadata.csv")
    print("✅ Loaded metadata.csv")

# Function to extract features from each input field
def extract_features(input_value, input_type):
    if pd.isna(input_value):
        input_value = ""

    # Input length
    input_length = len(input_value)

    # Count of special characters
    special_chars = len([c for c in input_value if c in "<>'\"%&;=(){}"])

    # Count digits
    num_digits = sum(c.isdigit() for c in input_value)

    # Check if only alphabets
    is_alpha_only = input_value.isalpha()

    # Check for SQL keywords
    sql_pattern = re.compile(r"(select|union|insert|update|delete|drop)", re.IGNORECASE)
    contains_sql_keyword = 1 if sql_pattern.search(input_value) else 0

    # Check for HTML tags
    html_pattern = re.compile(r"<[^>]+>")
    contains_html_tag = 1 if html_pattern.search(input_value) else 0

    return {
        "input_length": input_length,
        "num_special_chars": special_chars,
        "num_digits": num_digits,
        "is_alpha_only": is_alpha_only,
        "param_type": input_type,
        "contains_sql_keyword": contains_sql_keyword,
        "contains_html_tag": contains_html_tag
    }

# List to hold all rows
features_list = []

for _, row in df.iterrows():
    input_value = row.get("default_value", "")
    input_type = row.get("input_type", "")
    features = extract_features(input_value, input_type)
    
    # Add other info: url, parameter, input_value
    features.update({
        "url": row.get("url", ""),
        "parameter": row.get("param_name", ""),
        "input_value": input_value
    })
    
    features_list.append(features)

# Convert to DataFrame
features_df = pd.DataFrame(features_list)

# Save to CSV
features_df.to_csv("features_extracted.csv", index=False)
print("✅ Features extracted and saved to 'features_extracted.csv'")