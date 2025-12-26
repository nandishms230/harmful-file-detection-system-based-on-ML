import pandas as pd
import joblib
import lightgbm as lgb
from lightgbm import LGBMClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import os

# Load combined CSV
csv_path = "combined_features.csv"
if not os.path.exists(csv_path):
    raise FileNotFoundError(f"{csv_path} not found. Make sure you have a combined features CSV.")

data = pd.read_csv(csv_path)

X = data.drop("label", axis=1)
y = data["label"]

X = X.apply(pd.to_numeric, errors='coerce').fillna(0)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = LGBMClassifier(
    n_estimators=1000,
    learning_rate=0.05,
    num_leaves=31,
    random_state=42
)

# Fit model WITHOUT early stopping (for older versions)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print(f"Accuracy: {acc:.4f}")
print(f"Precision: {prec:.4f}")
print(f"Recall: {rec:.4f}")
print(f"F1 Score: {f1:.4f}")

# Save model + columns
artifact = {
    "model": model,
    "columns": X.columns.tolist(),
    "metrics": {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1}
}
joblib.dump(artifact, "model.pkl")
print("Model trained and saved as model.pkl")
