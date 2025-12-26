import pandas as pd
import joblib
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

def load_ember_parquet(path):
    print("Loading EMBER parquet...")
    df = pd.read_parquet(path)
    print("Loaded! Shape:", df.shape)

    # REMOVE unlabeled samples (-1)
    df = df[df["Label"] != -1]
    print("Removed -1 labels. New shape:", df.shape)

    X = df.drop("Label", axis=1)
    y = df["Label"]
    return X, y


def train_model(parquet_path, model_output="model.pkl"):
    X, y = load_ember_parquet(parquet_path)

    print("\nSplitting dataset...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print("Train shape:", X_train.shape)
    print("Test shape:", X_test.shape)

    params = {
        "objective": "binary",
        "metric": "binary_logloss",
        "boosting_type": "gbdt",
        "num_leaves": 80,
        "learning_rate": 0.05,
        "n_estimators": 500,
    }

    print("\nTraining LightGBM model...")
    model = lgb.LGBMClassifier(**params)

    model.fit(
        X_train,
        y_train,
        eval_set=[(X_test, y_test)],
        eval_metric="binary_logloss"
    )

    print("Training completed!")

    print("\nEvaluating...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    print(f"Accuracy: {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall: {rec:.4f}")
    print(f"F1 Score: {f1:.4f}")

    # Save dict with model, metrics, columns
    artifact = {
        'model': model,
        'metrics': {
            'accuracy': acc,
            'precision': prec,
            'recall': rec,
            'f1': f1
        },
        'columns': list(X.columns)
    }

    print("\nSaving model to:", model_output)
    joblib.dump(artifact, model_output)
    print("Model saved successfully!")


if __name__ == "__main__":
    parquet_file = "ember/train_ember_2018_v2_features.parquet"
    train_model(parquet_file)
