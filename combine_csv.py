import pandas as pd

# Paths to your feature CSVs
pe_csv = "scan_results.csv"        # PE (.exe) features CSV
txt_csv = "txt_dataset_features.csv"  # TXT features CSV
other_csv = "other_files.csv"      # Optional: features of other file types

# Load CSVs
df_pe = pd.read_csv(pe_csv)
df_txt = pd.read_csv(txt_csv)

# If you have other file types scanned, mark them Safe
try:
    df_other = pd.read_csv(other_csv)
    df_other['label'] = 0
except FileNotFoundError:
    df_other = pd.DataFrame()

# Add missing columns in TXT to match PE (and vice versa)
all_cols = list(set(df_pe.columns) | set(df_txt.columns) | set(df_other.columns))
for col in all_cols:
    if col not in df_pe.columns:
        df_pe[col] = 0
    if col not in df_txt.columns:
        df_txt[col] = 0
    if col not in df_other.columns and not df_other.empty:
        df_other[col] = 0

# Concatenate all
combined_df = pd.concat([df_pe, df_txt, df_other], ignore_index=True)

# Ensure label column exists
if 'label' not in combined_df.columns:
    raise ValueError("Make sure all CSVs have a 'label' column (0=Safe, 1=Harmful).")

# Save combined CSV
combined_df.to_csv("combined_features.csv", index=False)
print("Combined CSV saved as combined_features.csv")
