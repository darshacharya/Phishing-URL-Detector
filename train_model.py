# train_model.py

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

# Load the dataset
df = pd.read_csv("dataset.csv")

# Drop index column if it's there
if 'index' in df.columns:
    df = df.drop('index', axis=1)

# Separate features and labels
X = df.drop('Result', axis=1)
y = df['Result']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train Random Forest Classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# Save the model
os.makedirs("model", exist_ok=True)
joblib.dump(model, "model/phishing_model.pkl")
print("Model saved to model/phishing_model.pkl")
