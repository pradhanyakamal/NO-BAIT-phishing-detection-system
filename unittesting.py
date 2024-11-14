import unittest
from app import app
import json
from src.load_model import load_model
import time

class BasicPhishingAppTests(unittest.TestCase):

    # Test 1: Check if the model loads correctly
    def test_model_loading(self):
        model = load_model()
        self.assertIsNotNone(model, "Model should load and not be None.")

    # Test 2: Test valid URL prediction
    def test_valid_url_prediction(self):
        with app.test_client() as client:
            response = client.post('/predict', json={'url': 'https://www.github.com'})
            data = response.get_json()
            self.assertIsNotNone(data)
            self.assertIn("prediction", data)
            self.assertIn(data["prediction"].strip(), ["legitimate", "illegitimate"])

    # Test 3: Test invalid URL prediction
    def test_invalid_url_prediction(self):
        with app.test_client() as client:
            response = client.post('/predict', json={'url': 'https://malicious-site.com'})
            data = response.get_json()
            self.assertIsNotNone(data)
            self.assertIn("prediction", data)
            self.assertEqual(data["prediction"].strip(), "phishing")


    # Test 4: Test special characters in URL input
    def test_special_character_url_input(self):
        with app.test_client() as client:
            response = client.post('/predict', json={'url': 'https://www.github.com'})
            data = response.get_json()
            self.assertIsNotNone(data)
            self.assertIn("prediction", data)

    # Test 5: Test prediction response format
    def test_prediction_response_format(self):
        with app.test_client() as client:
            response = client.post('/predict', json={'url': 'https://www.github.com'})
            data = response.get_json()
            self.assertIsInstance(data, dict)
            self.assertIn("prediction", data)
            self.assertIsInstance(data["prediction"], str)

    # Test 6: Test response for https URL
    def test_https_url_prediction(self):
        with app.test_client() as client:
            response = client.post('/predict', json={'url': 'https://www.github.com'})
            data = response.get_json()
            self.assertIsNotNone(data)
            self.assertIn("prediction", data)

    # Test 7: Test prediction execution time
    def test_prediction_execution_time(self):
        test_url = 'https://www.github.com'
        with app.test_client() as client:
            start_time = time.time()
            response = client.post('/predict', json={'url': test_url})
            end_time = time.time()
            self.assertLess(end_time - start_time, 5, "Prediction should complete in under 5 seconds.")

    # Test 8: Test for URL with subdomains
    def test_url_with_subdomains(self):
        with app.test_client() as client:
            response = client.post('/predict', json={'url': 'https://docs.google.com/document/d/1dmyGL2es8Ogxo-S5M88WSZAOgsenCJhrPuPvIQjdoAg/edit?tab=t.0'})
            data = response.get_json()
            self.assertIsNotNone(data)
            self.assertIn("prediction", data)

    # Test 9: Test URL with unusual port number
    def test_url_with_port_number(self):
        with app.test_client() as client:
            response = client.post('/predict', json={'url': 'http://example.com:8080'})
            data = response.get_json()
            self.assertIsNotNone(data)
            self.assertIn("prediction", data)

    # Test 10: Test prediction caching (if caching is implemented)
    def test_prediction_caching(self):
        test_url = 'http://example.com'
        with app.test_client() as client:
            response_1 = client.post('/predict', json={'url': test_url})
            data_1 = response_1.get_json()
            response_2 = client.post('/predict', json={'url': test_url})
            data_2 = response_2.get_json()
            self.assertEqual(data_1, data_2, "Cached prediction should match initial prediction.")

    # Test 11: Test response status code
    def test_response_status_code(self):
        with app.test_client() as client:
            response = client.post('/predict', json={'url': 'https://www.github.com'})
            self.assertEqual(response.status_code, 200, "Response status code should be 200.")

if __name__ == '__main__':
    unittest.main()
