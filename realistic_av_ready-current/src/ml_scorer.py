# src/ml_scorer.py

from .ember_features import extract_features
import os
import joblib
import lightgbm as lgb

_models = {}

def load_weights(models_dir):
    try:
        
        lgb_model_path = os.path.join(models_dir, "malware_detector.txt")

        if os.path.exists(lgb_model_path):
            _models["rf"] = lgb.Booster(model_file=lgb_model_path)
            print("✅ Loaded LightGBM model from malware_detector.txt")
        else:
            print(f"❌ Model file not found: {lgb_model_path}")
            _models["rf"] = None

    except Exception as e:
        print(f"❌ Could not load ML model: {e}")
        _models["rf"] = None

    return _models




def score_file(path, ftype, yhits, rules, weights):
    feats = extract_features(path)

    model = weights.get("rf")
    proba, label = 0.0, "error"

    if model is not None:
        try:
            raw_pred = model.predict([feats])

            if isinstance(raw_pred, list) or len(raw_pred.shape) == 1:
                proba = raw_pred[0] if hasattr(raw_pred, "__len__") else float(raw_pred)
            else:
                proba = raw_pred[0][1]

            label = "malicious" if proba > 0.7 else "benign"

        except Exception as e:
            return {"label": "error", "prob": 0.0, "err": str(e)}

    return {
        "label": label,
        "prob": float(proba),
    }

