import json
import pandas as pd
from flask import Flask, request, jsonify, render_template
from src.predict import make_prediction
from pathlib import Path
import csv

app = Flask(__name__)

# File paths for CSVs and history
phishing_file = "phishing.csv"
legitimate_file = "legitimate.csv"
history_file = Path("history.json")

# Helper function to load CSVs into sets for quick URL lookup
def load_url_sets():
    """Load phishing and legitimate URLs from CSV files."""
    phishing_urls = set(pd.read_csv(phishing_file, header=None).iloc[:, 0].str.strip().tolist())
    legitimate_urls = set(pd.read_csv(legitimate_file, header=None).iloc[:, 0].str.strip().tolist())
    return phishing_urls, legitimate_urls

# Ensure history file exists
if not history_file.exists():
    history_file.write_text("[]")

# Load URL sets
phishing_urls, legitimate_urls = load_url_sets()

# Helper functions
def write_urls_to_csv(file_path, urls):
    """Writes a set of URLs to a CSV file."""
    with open(file_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        for url in urls:
            writer.writerow([url])

def load_history():
    """Load the history data from history.json."""
    return json.loads(history_file.read_text())

def save_history(history):
    """Save history data to history.json."""
    history_file.write_text(json.dumps(history, indent=2))

@app.route('/')
def index():
    history = load_history()  # Load the latest history for display
    return render_template('index.html', history=history)

@app.route('/history')
def history():
    """Serve the history data for display in the frontend."""
    return jsonify(load_history())

@app.route('/learn')
def learn():
    return render_template('learn.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data['url'].strip()
    history = load_history()  # Reload history for latest data

    # Check if URL is already classified
    if url in phishing_urls:
        prediction = "phishing"
    elif url in legitimate_urls:
        prediction = "legitimate"
    else:
        prediction = make_prediction(url)  # Make a new prediction if not classified

    # Save the prediction to history
    history.append({"url": url, "prediction": prediction, "feedback": ""})
    save_history(history)

    return jsonify({"url": url, "prediction": prediction})

@app.route('/feedback', methods=['POST'])
def feedback():
    """Receive feedback for a URL and update lists accordingly."""
    data = request.get_json()
    if not data or 'url' not in data or 'feedback' not in data:
        return jsonify({"error": "URL and feedback are required"}), 400

    url = data['url'].strip()
    feedback = data['feedback'].strip().lower()
    history = load_history()

    # Find the existing history entry and update feedback
    for entry in history:
        if entry['url'] == url:
            entry['feedback'] = feedback  # Update the feedback field

    # Update URL lists based on feedback
    if feedback == "wrong":
        # Move to legitimate list if user says "wrong" and prediction was phishing
        if url in phishing_urls:
            phishing_urls.remove(url)
            legitimate_urls.add(url)
            message = f"Feedback noted: '{url}' is now marked as legitimate."
        else:
            # If not in phishing, add it to legitimate to respect user's feedback
            legitimate_urls.add(url)
            message = f"Feedback noted: '{url}' added to legitimate list."
        write_urls_to_csv(legitimate_file, legitimate_urls)
        write_urls_to_csv(phishing_file, phishing_urls)
    elif feedback == "right":
        message = f"Feedback noted: '{url}' classification confirmed."

    save_history(history)

    return jsonify({"message": message})

if __name__ == '__main__':
    app.run(debug=True)
