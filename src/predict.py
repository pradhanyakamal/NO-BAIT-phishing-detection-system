import pandas as pd
from src.load_model import load_model
from src.feature_extraction import extract_features  # Import the feature extraction function

def make_prediction(url):
    """Extract features from the URL and make a prediction."""
    model = load_model()  # Load your model
    features = extract_features(url)  # Call the function from feature_extraction.py
    
    # Convert the features into a DataFrame
    input_data = pd.DataFrame([features])
    
    # Make the prediction using the model
    prediction = model.predict(input_data)
    
    # Return the prediction result
    return " not safe" if prediction[0] == 1 else "safe"  # Assuming 0 = "safe", 1 = "not safe"
