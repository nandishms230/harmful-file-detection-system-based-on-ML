import os
import pandas as pd
from utils import extract_features  # make sure utils.py is in the same folder

# Paths
dataset_folder = "txt_dataset"
safe_folder = os.path.join(dataset_folder, "safe_txt")
harmful_folder = os.path.join(dataset_folder, "harmful_txt")
output_csv = "txt_dataset_features.csv"

records = []

def process_folder(folder_path, label):
    files = [f for f in os.listdir(folder_path) if f.endswith(".txt")]
    for file in files:
        path = os.path.join(folder_path, file)
        features = extract_features(path)
        if features:
            feat_dict = {f"f{i}": v for i, v in enumerate(features["features"])}
            feat_dict["file"] = path
            feat_dict["label"] = label
            records.append(feat_dict)
            print(f"Processed: {path}")

# Process safe files
process_folder(safe_folder, label=0)

# Process harmful-looking files
process_folder(harmful_folder, label=1)

# Create DataFrame
df = pd.DataFrame(records)
df.to_csv(output_csv, index=False)
print(f"\nFeature extraction complete! CSV saved as: {output_csv}")
print(f"Total files processed: {len(records)}")
