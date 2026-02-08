import numpy as np
from sklearn.ensemble import RandomForestClassifier
from skl2onnx import to_onnx
import onnx

# 1. Generate Synthetic Data
# Features: [comment_density (0-1), avg_line_length (0-200), keyword_score (0-10)]
# Class 0: Human, Class 1: AI (Simplified logic for demo)

print("Generating synthetic training data...")
X_human = np.array([
    [0.1, 40.0, 0.0],
    [0.2, 50.0, 0.5],
    [0.05, 30.0, 0.0],
    [0.15, 60.0, 1.0],
    [0.3, 45.0, 0.0]
])
y_human = np.zeros(len(X_human))

X_ai = np.array([
    [0.5, 80.0, 5.0],   # AI often explains more? Or keeps lines formatted?
    [0.4, 70.0, 4.0],
    [0.6, 90.0, 6.0],
    [0.0, 120.0, 2.0],  # Long oneliners?
    [0.1, 80.0, 8.0]    # "Here is the code..."
])
y_ai = np.ones(len(X_ai))

X = np.vstack((X_human, X_ai)).astype(np.float32)
y = np.hstack((y_human, y_ai)).astype(np.int64)

# 2. Train Model
print("Training Random Forest Classifier...")
clf = RandomForestClassifier(n_estimators=10, max_depth=3, random_state=42)
clf.fit(X, y)

# 3. Export to ONNX
print("Exporting to ONNX...")
# Input type: float32, shape [None, 3]
onx = to_onnx(clf, X[:1], target_opset=12)

# 4. Save
output_path = "models/ai-classifier/model.onnx"
with open(output_path, "wb") as f:
    f.write(onx.SerializeToString())

print(f"Model saved to {output_path}")

# Verify
print("Verifying model...")
model = onnx.load(output_path)
onnx.checker.check_model(model)
print("Model check passed!")
