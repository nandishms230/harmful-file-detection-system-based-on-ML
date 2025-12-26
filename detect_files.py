import os
import pandas as pd
import joblib
from utils import extract_features
from multiprocessing import Pool, cpu_count

# EICAR test string for demo
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def detect_single_file(args):
    file_path, model_artifact, quarantine_path = args
    try:
        features = extract_features(file_path)
        if features is None:
            return {
                "file": file_path,
                "prediction": "Error",
                "probability": 0.0,
                "status": "Feature extraction failed"
            }

        # Automatically mark non-exe/txt files as safe
        ext = features["extension"]
        if ext not in [".exe", ".txt"]:
            return {
                "file": file_path,
                "prediction": "Safe",
                "probability": 0.0,
                "status": f"Unsupported file type ({ext}) marked safe"
            }

        # Check for EICAR
        with open(file_path, "rb") as f:
            data = f.read()
        if EICAR_SIGNATURE in data:
            return {
                "file": file_path,
                "prediction": "Harmful",
                "probability": 1.0,
                "status": "EICAR detected"
            }

        # Prepare DataFrame for model
        df = pd.DataFrame([features["features"]])
        df.columns = [f"feat_{i}" for i in range(len(features["features"]))]
        df["file_extension"] = features["extension"]
        df = pd.get_dummies(df, columns=["file_extension"])

        # Align columns with model
        trained_columns = model_artifact['columns']
        df = df.reindex(columns=trained_columns, fill_value=0)

        model = model_artifact['model']
        pred = model.predict(df)[0]
        proba = model.predict_proba(df)[0][1]

        status = "Safe"
        if int(pred) == 1:
            # Quarantine
            dest = os.path.join(quarantine_path, os.path.basename(file_path))
            try:
                import shutil
                shutil.move(file_path, dest)
                status = "Quarantined"
            except Exception as e:
                status = f"QuarantineFailed: {str(e)}"

        return {
            "file": file_path,
            "prediction": "Harmful" if int(pred) == 1 else "Safe",
            "probability": float(proba),
            "status": status
        }

    except Exception as e:
        return {
            "file": file_path,
            "prediction": "Error",
            "probability": 0.0,
            "status": f"Error: {str(e)}"
        }

def detect_files(folder_path, model_path='model.pkl', output_csv='scan_results.csv'):
    """Scan folder using the trained model, with multiprocessing."""
    print("Loading model...")
    model_artifact = joblib.load(model_path)
    print("Model loaded!")

    quarantine_path = os.path.join(folder_path, 'quarantine')
    os.makedirs(quarantine_path, exist_ok=True)

    # Collect files (skip quarantine)
    files_to_scan = []
    for root, dirs, files in os.walk(folder_path):
        if os.path.abspath(root).startswith(os.path.abspath(quarantine_path)):
            continue
        for file in files:
            files_to_scan.append(os.path.join(root, file))

    print(f"Scanning {len(files_to_scan)} files...")

    # Multiprocessing
    num_processes = min(cpu_count(), len(files_to_scan))
    with Pool(processes=num_processes) as pool:
        args_list = [(fp, model_artifact, quarantine_path) for fp in files_to_scan]
        results = pool.map(detect_single_file, args_list)

    # Save results
    df_results = pd.DataFrame(results)
    df_results.to_csv(output_csv, index=False)
    print(f"Results saved to {output_csv}")

    print("\n--- SCAN COMPLETE ---")
    for r in results:
        print(f"{r['file']} → {r['prediction']} ({r['probability']:.2f}) - {r['status']}")

    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python detect_files.py <folder_path> [model_path] [output_csv]")
        sys.exit(1)

    folder_path = sys.argv[1]
    model_path = sys.argv[2] if len(sys.argv) > 2 else "model.pkl"
    output_csv = sys.argv[3] if len(sys.argv) > 3 else "scan_results.csv"

    detect_files(folder_path, model_path, output_csv)
