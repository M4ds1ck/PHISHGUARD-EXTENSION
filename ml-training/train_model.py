#!/usr/bin/env python3
"""
train_model.py - Train a phishing detection neural network
Converts the model to TensorFlow.js format for browser usage

Requirements:
pip install tensorflow pandas numpy scikit-learn tensorflowjs
"""

import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow import keras
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import tensorflowjs as tfjs
import json

print("=" * 60)
print("PhishGuard ML Training Pipeline")
print("=" * 60)

# ============================================
# STEP 1: LOAD DATASET
# ============================================

print("\n[1/6] Loading dataset...")

# Option 1: Load from CSV (UCI/Kaggle dataset)
# Download from: https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset
try:
    df = pd.read_csv('phishing_dataset.csv')
    print(f"✓ Loaded {len(df)} samples")
except FileNotFoundError:
    print("✗ Error: phishing_dataset.csv not found!")
    print("\nDownload dataset from:")
    print("https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset")
    print("\nOr use UCI dataset:")
    print("https://archive.ics.uci.edu/ml/datasets/phishing+websites")
    exit(1)

# ============================================
# STEP 2: DATA PREPROCESSING
# ============================================

print("\n[2/6] Preprocessing data...")

# Assuming dataset has features in columns and 'label' column (0=legitimate, 1=phishing)
# Adjust column names based on your dataset

# Check if dataset has a label column
label_column = None
for col in ['label', 'class', 'target', 'phishing', 'Label', 'Class']:
    if col in df.columns:
        label_column = col
        break

if label_column is None:
    print("✗ Could not find label column!")
    print(f"Available columns: {df.columns.tolist()}")
    exit(1)

# Separate features and labels
X = df.drop(columns=[label_column])
y = df[label_column]

# Convert labels to binary (0 = legitimate, 1 = phishing)
y = y.apply(lambda x: 1 if x > 0 else 0)

print(f"✓ Features: {X.shape[1]} columns")
print(f"✓ Legitimate samples: {(y == 0).sum()}")
print(f"✓ Phishing samples: {(y == 1).sum()}")

# Handle missing values
X = X.fillna(0)

# ============================================
# STEP 3: SPLIT DATA
# ============================================

print("\n[3/6] Splitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"✓ Training samples: {len(X_train)}")
print(f"✓ Testing samples: {len(X_test)}")

# Normalize features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ============================================
# STEP 4: BUILD MODEL
# ============================================

print("\n[4/6] Building neural network...")

# Create a simple but effective neural network
model = keras.Sequential([
    keras.layers.Input(shape=(X_train_scaled.shape[1],)),
    keras.layers.Dense(64, activation='relu'),
    keras.layers.Dropout(0.3),
    keras.layers.Dense(32, activation='relu'),
    keras.layers.Dropout(0.2),
    keras.layers.Dense(16, activation='relu'),
    keras.layers.Dense(1, activation='sigmoid')
])

model.compile(
    optimizer='adam',
    loss='binary_crossentropy',
    metrics=['accuracy', 
             keras.metrics.Precision(name='precision'),
             keras.metrics.Recall(name='recall')]
)

print("✓ Model architecture:")
model.summary()

# ============================================
# STEP 5: TRAIN MODEL
# ============================================

print("\n[5/6] Training model...")

# Early stopping to prevent overfitting
early_stopping = keras.callbacks.EarlyStopping(
    monitor='val_loss',
    patience=10,
    restore_best_weights=True
)

# Train the model
history = model.fit(
    X_train_scaled, y_train,
    validation_split=0.2,
    epochs=100,
    batch_size=32,
    callbacks=[early_stopping],
    verbose=1
)

# ============================================
# STEP 6: EVALUATE MODEL
# ============================================

print("\n[6/6] Evaluating model...")

test_loss, test_acc, test_prec, test_rec = model.evaluate(X_test_scaled, y_test, verbose=0)

print(f"\n{'='*60}")
print("MODEL PERFORMANCE")
print(f"{'='*60}")
print(f"Accuracy:  {test_acc*100:.2f}%")
print(f"Precision: {test_prec*100:.2f}%")
print(f"Recall:    {test_rec*100:.2f}%")
print(f"F1 Score:  {2 * (test_prec * test_rec) / (test_prec + test_rec):.2f}")
print(f"{'='*60}")

# Test on some examples
predictions = model.predict(X_test_scaled[:10])
print("\nSample predictions:")
for i, (pred, actual) in enumerate(zip(predictions[:10], y_test.values[:10])):
    status = "✓" if (pred[0] > 0.5) == actual else "✗"
    print(f"{status} Sample {i+1}: Predicted={pred[0]:.3f}, Actual={actual}")

# ============================================
# STEP 7: CONVERT TO TENSORFLOW.JS
# ============================================

print("\n[7/7] Converting to TensorFlow.js format...")

# Create output directory
import os
os.makedirs('model_tfjs', exist_ok=True)

# Convert model
tfjs.converters.save_keras_model(model, 'model_tfjs')

# Save feature names and scaler parameters
feature_info = {
    'feature_names': X.columns.tolist(),
    'feature_count': len(X.columns),
    'scaler_mean': scaler.mean_.tolist(),
    'scaler_scale': scaler.scale_.tolist(),
    'model_version': '1.0',
    'trained_on': str(pd.Timestamp.now()),
    'performance': {
        'accuracy': float(test_acc),
        'precision': float(test_prec),
        'recall': float(test_rec)
    }
}

with open('model_tfjs/feature_info.json', 'w') as f:
    json.dump(feature_info, f, indent=2)

print("✓ Model saved to: model_tfjs/")
print("✓ Feature info saved to: model_tfjs/feature_info.json")

print("\n" + "="*60)
print("TRAINING COMPLETE!")
print("="*60)
print("\nNext steps:")
print("1. Copy the 'model_tfjs' folder to your extension directory")
print("2. Load the model in your extension using TensorFlow.js")
print("3. Test with real URLs")
print("\nModel files:")
print("  - model.json (model architecture)")
print("  - group1-shard1of1.bin (model weights)")
print("  - feature_info.json (feature metadata)")
print("="*60)