import os
import random
import string

# Dataset folder
dataset_folder = "txt_dataset"
safe_folder = os.path.join(dataset_folder, "safe_txt")
harmful_folder = os.path.join(dataset_folder, "harmful_txt")

os.makedirs(safe_folder, exist_ok=True)
os.makedirs(harmful_folder, exist_ok=True)

# Number of files
num_safe = 50
num_harmful = 50

# Helper functions
def random_text(size=200):
    return ''.join(random.choices(string.ascii_letters + string.digits + " \n", k=size))

def malicious_text(size=200):
    # Simulate malicious-looking patterns
    patterns = [
        "eval(", "exec(", "base64_decode(", "powershell", "rm -rf", "cmd.exe",
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        "<script>", "DROP TABLE"
    ]
    text = ''.join(random.choices(string.ascii_letters + string.digits + " \n", k=size))
    # Inject random malicious patterns
    for _ in range(random.randint(1,3)):
        insert = random.choice(patterns)
        pos = random.randint(0, size-1)
        text = text[:pos] + insert + text[pos:]
    return text

# Generate safe files
for i in range(num_safe):
    path = os.path.join(safe_folder, f"safe_{i+1}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(random_text(random.randint(100, 500)))

# Generate harmful-looking files
for i in range(num_harmful):
    path = os.path.join(harmful_folder, f"harmful_{i+1}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(malicious_text(random.randint(100, 500)))

print(f"Synthetic dataset created at {dataset_folder}!")
print(f"Safe files: {num_safe}, Harmful-looking files: {num_harmful}")
