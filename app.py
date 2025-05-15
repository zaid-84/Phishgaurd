

# from flask import Flask, render_template, request
# import pickle
# import numpy as np
# from urllib.parse import urlparse
# import re
# import tld
# from sklearn.preprocessing import StandardScaler

# # Initialize Flask app
# app = Flask(__name__)

# # Load trained model and scaler
# with open("phishing_model.pkl", "rb") as model_file:
#     model = pickle.load(model_file)
# with open("phishing_scaler.pkl", "rb") as scaler_file:
#     scaler = pickle.load(scaler_file)

# def extract_features(url):
#     """
#     Extract features from URLs matching the training model's expectations.
    
#     Returns:
#         list: A list of 16 numerical features in consistent order
#     """
#     # Initialize all features with default values
#     features = {
#         'length': 0,
#         'num_dots': 0,
#         'num_slashes': 0,
#         'num_digits': 0,
#         'num_special_chars': 0,
#         'has_https': 0,
#         'has_http': 0,
#         'has_at': 0,
#         'has_double_slash': 0,
#         'domain_length': 0,
#         'path_length': 0,
#         'num_subdomains': 0,
#         'tld_length': 0,
#         'is_common_tld': 0,
#         'has_query': 0,
#         'num_params': 0
#     }
    
#     try:
#         # Basic string features
#         features['length'] = len(url)
#         features['num_dots'] = url.count('.')
#         features['num_slashes'] = url.count('/')
#         features['num_digits'] = sum(c.isdigit() for c in url)
#         features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9.]', url))
        
#         # Protocol features
#         features['has_https'] = int(url.startswith('https'))
#         features['has_http'] = int(url.startswith('http'))
#         features['has_at'] = int('@' in url)
#         features['has_double_slash'] = int('//' in url[7:])
        
#         # URL parsing features
#         parsed = urlparse(url)
#         features['domain_length'] = len(parsed.netloc)
#         features['path_length'] = len(parsed.path)
#         features['num_subdomains'] = len(parsed.netloc.split('.')) - 1
        
#         # TLD features
#         try:
#             res = tld.get_tld(url, as_object=True)
#             features['tld_length'] = len(res.tld)
#             features['is_common_tld'] = int(res.tld in {'com', 'org', 'net', 'edu', 'gov'})
#         except:
#             pass  # Keep default values
        
#         # Query features
#         features['has_query'] = int(bool(parsed.query))
#         features['num_params'] = len(parsed.query.split('&')) if parsed.query else 0
        
#     except Exception as e:
#         print(f"Warning: Error extracting features from URL: {url[:100]}... Error: {str(e)}")
#         # Default values will be used for any features that weren't set
    
#     # Ensure consistent order of features matching the training model
#     ordered_features = [
#         'length', 'num_dots', 'num_slashes', 'num_digits', 'num_special_chars',
#         'has_https', 'has_http', 'has_at', 'has_double_slash', 'domain_length',
#         'path_length', 'num_subdomains', 'tld_length', 'is_common_tld',
#         'has_query', 'num_params'
#     ]
    
#     return [features[f] for f in ordered_features]

# @app.route('/')
# def home():
#     return render_template('index.html')

# @app.route('/predict', methods=['POST'])
# def predict():
#     if request.method == 'POST':
#         url = request.form.get('url', '').strip()
        
#         if not url:
#             return render_template('index.html', 
#                                 prediction_text="⚠️ Please enter a URL!")
        
#         try:
#             # Extract features and scale them
#             features = extract_features(url)
#             if len(features) != 16:
#                 raise ValueError(f"Expected 16 features, but got {len(features)}")
            
#             features_scaled = scaler.transform([features])
            
#             # Make prediction
#             prediction = model.predict(features_scaled)[0]
            
#             # Prepare result message
#             if prediction == 1:
#                 result = "✅ This URL appears to be safe!"
#             else:
#                 result = "⚠️ Warning: This URL may be a phishing attempt!"
            
#             return render_template('index.html', 
#                                 prediction_text=result,
#                                 analyzed_url=url)
            
#         except Exception as e:
#             return render_template('index.html', 
#                                 prediction_text=f"❌ Error analyzing URL: {str(e)}",
#                                 analyzed_url=url)

# if __name__ == "__main__":
#     app.run(debug=True)
from flask import Flask, render_template, request, send_file
import pickle
import numpy as np
from urllib.parse import urlparse
import re
import tld
from sklearn.preprocessing import StandardScaler
import os
from selenium.webdriver.chrome.options import Options
from selenium import webdriver
from selenium.webdriver.chrome.service import Service

import time

# Initialize Flask app
app = Flask(__name__)

# Load trained model and scaler
with open("phishing_model.pkl", "rb") as model_file:
    model = pickle.load(model_file)
with open("phishing_scaler.pkl", "rb") as scaler_file:
    scaler = pickle.load(scaler_file)

# Set path for ChromeDriver
CHROMEDRIVER_PATH = "chromedriver.exe"  

def extract_features(url):
    """Extract 16 numerical features from URLs."""
    features = {
        'length': len(url),
        'num_dots': url.count('.'),
        'num_slashes': url.count('/'),
        'num_digits': sum(c.isdigit() for c in url),
        'num_special_chars': len(re.findall(r'[^a-zA-Z0-9.]', url)),
        'has_https': int(url.startswith('https')),
        'has_http': int(url.startswith('http')),
        'has_at': int('@' in url),
        'has_double_slash': int('//' in url[7:]),
        'domain_length': len(urlparse(url).netloc),
        'path_length': len(urlparse(url).path),
        'num_subdomains': len(urlparse(url).netloc.split('.')) - 1,
        'tld_length': 0,
        'is_common_tld': 0,
        'has_query': int(bool(urlparse(url).query)),
        'num_params': len(urlparse(url).query.split('&')) if urlparse(url).query else 0
    }

    # Extract TLD features
    try:
        res = tld.get_tld(url, as_object=True)
        features['tld_length'] = len(res.tld)
        features['is_common_tld'] = int(res.tld in {'com', 'org', 'net', 'edu', 'gov'})
    except:
        pass

    # Return as list
    return [features[f] for f in features]

def capture_screenshot(url):
    """Visit URL and take a screenshot using Selenium."""
    try:
        options = Options()
        options.headless = True  # Run Chrome in headless mode (no UI)
        service = Service(CHROMEDRIVER_PATH)
        driver = webdriver.Chrome(service=service, options=options)

        driver.set_window_size(1280, 720)  # Set window size
        driver.get(url)  # Visit the URL
        time.sleep(3)  # Wait for page to load

        screenshot_path = f"static/screenshots/screenshot.png"
        driver.save_screenshot(screenshot_path)
        driver.quit()
        
        return screenshot_path
    except Exception as e:
        print(f"Error capturing screenshot: {e}")
        return None

@app.route('/')
def home():
    return render_template('index.html')
@app.route('/index')
def index():
    return render_template('index.html')
@app.route('/contact')
def conatct():
    return render_template('contact.html')
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()

        if not url:
            return render_template('index.html', prediction_text="⚠️ Please enter a URL!")

        try:
            # Extract features and scale them
            features = extract_features(url)
            features_scaled = scaler.transform([features])

            # Make prediction
            prediction = model.predict(features_scaled)[0]

            # Determine result
            if prediction == 1:
                result = "✅ This URL appears to be safe!"
            else:
                result = "⚠️ Warning: This URL may be a phishing attempt!"

            # Capture screenshot
            screenshot_path = capture_screenshot(url)

            return render_template('index.html', 
                                   prediction_text=result, 
                                   analyzed_url=url,
                                   screenshot_path=screenshot_path)
            
        except Exception as e:
            return render_template('index.html', prediction_text=f"❌ Error analyzing URL: {e}")

if __name__ == "__main__":
    # os.makedirs("static/screenshots", exist_ok=True)  # Create screenshot folder
    app.run(debug=True)
