# src/load_model.py

import pickle

def load_model(model_path='model/phishing_detection_model.sav'):
    """Loads and returns the trained model."""
    with open(model_path, 'rb') as file:
        model = pickle.load(file)
    return model
