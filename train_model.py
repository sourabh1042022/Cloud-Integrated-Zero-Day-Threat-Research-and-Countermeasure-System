import numpy as np
from sklearn.tree import DecisionTreeClassifier
import joblib


X = [
    [0.8, 1200],   
    [0.9, 1000],   
    [0.1, 100],    
    [0.4, 500],    
    [1.0, 1500],   
    [0.95, 1300],  
]
y = ["CRASH", "CRASH", "SAFE", "SAFE", "HANG", "HANG"]


model = DecisionTreeClassifier()
model.fit(X, y)

joblib.dump(model, "triage_model.pkl")
print("Model trained and saved.")
