import os
import yaml
import joblib
import random

model = joblib.load("triage_model.pkl")
triage_reports = []

def extract_features(file_path):
    size = os.path.getsize(file_path)
    entropy = random.uniform(0.1, 1.0)  # Simulated
    return [entropy, size]

input_dir = "crash_samples"
output_dir = "triage_reports"
os.makedirs(output_dir, exist_ok=True)

for filename in os.listdir(input_dir):
    path = os.path.join(input_dir, filename)
    features = extract_features(path)
    label = model.predict([features])[0]
    report = {
        "sample": filename,
        "classification": label,
        "features": {
            "entropy": features[0],
            "size": features[1]
        }
    }
    triage_reports.append(report)

    with open(os.path.join(output_dir, f"{filename}.yaml"), "w") as f:
        yaml.dump(report, f)

print("Triage reports generated.")
