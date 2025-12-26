import numpy as np
import hashlib
import os

def extract_features(file_path):
    """
    Extract features for files.
    - .exe and .txt files: full feature extraction
    - other types: minimal features, marked safe
    """
    ext = os.path.splitext(file_path)[1].lower()

    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Failed to read file {file_path}: {e}")
        return None

    # Minimal common features for all files
    features = {}
    features["size"] = len(data)
    features["sha256"] = int(hashlib.sha256(data).hexdigest(), 16) % (10**8)
    features["magic"] = int.from_bytes(data[:4], byteorder='little', signed=False) if len(data) >= 4 else 0

    # Entropy
    if len(data) > 0:
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = byte_counts / len(data)
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        features["entropy"] = entropy
    else:
        features["entropy"] = 0.0

    # Text-specific features (only for .txt)
    if ext == ".txt":
        try:
            text = data.decode(errors="ignore")
            lines = text.splitlines()
            features["num_lines"] = len(lines)
            features["unique_chars"] = len(set(text))
            printable_chars = sum(c.isprintable() for c in text)
            features["printable_ratio"] = printable_chars / max(len(text), 1)
        except:
            features["num_lines"] = 0
            features["unique_chars"] = 0
            features["printable_ratio"] = 0.0
    else:
        features["num_lines"] = 0
        features["unique_chars"] = 0
        features["printable_ratio"] = 0.0

    # Return feature vector
    feature_vector = np.array([
        features["size"],
        features["sha256"],
        features["magic"],
        features["entropy"],
        features["num_lines"],
        features["unique_chars"],
        features["printable_ratio"]
    ], dtype=float)

    return {"features": feature_vector, "extension": ext}
