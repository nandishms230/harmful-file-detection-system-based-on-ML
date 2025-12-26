import pandas as pd
import os

def load_ember_dataset(folder):
    print("Loading all parquet files...")

    parquet_files = [f for f in os.listdir(folder) if f.endswith(".parquet")]
    if not parquet_files:
        raise ValueError("No parquet files found!")

    dfs = []

    for file in parquet_files:
        path = os.path.join(folder, file)
        print("Reading:", file)
        df = pd.read_parquet(path)
        dfs.append(df)

    full_df = pd.concat(dfs, ignore_index=True)
    print("Dataset loaded!")
    print("Shape:", full_df.shape)

    # Split X and y
    X = full_df.drop("Label", axis=1)
    y = full_df["Label"]

    return X, y, full_df  # 3 values returned

if __name__ == "__main__":
    X, y, df = load_ember_dataset("ember")

    print("X shape:", X.shape)
    print("y shape:", y.shape)
