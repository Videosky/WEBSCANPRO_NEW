# preprocess_data.py

import pandas as pd
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

# Config
INPUT_FILE = "features_extracted.csv"
OUTPUT_FILE = "cleaned_dataset.csv"

# Load data
df = pd.read_csv(INPUT_FILE)

# Handle missing
df["input_value"] = df["input_value"].fillna("")
df["param_type"] = df["param_type"].fillna("text")
df.dropna(subset=["url", "param_name"], inplace=True)

# Encode categorical
categorical_cols = ["url", "param_name", "param_type"]
le_dict = {}
for col in categorical_cols:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    le_dict[col] = le

# Normalize numeric
numeric_cols = ["input_length", "num_special_chars", "num_digits"]
scaler = MinMaxScaler()
df[numeric_cols] = scaler.fit_transform(df[numeric_cols])

# Save cleaned dataset
df.to_csv(OUTPUT_FILE, index=False)
print(f"✅ Cleaned dataset saved to {OUTPUT_FILE}")
