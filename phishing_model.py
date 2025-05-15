# import pandas as pd
# from sklearn.model_selection import train_test_split
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.feature_extraction.text import CountVectorizer
# from sklearn.pipeline import make_pipeline
# import pickle
# import os

# # Define dataset path
# dataset_path = r'data/phishingdata.csv'  # Use raw string (r'...') or forward slashes

# # Check if the dataset exists
# if not os.path.exists(dataset_path):
#     raise FileNotFoundError(f"❌ Dataset not found at {dataset_path}. Please check the path!")

# # Load the phishing dataset
# df = pd.read_csv(dataset_path)

# # Ensure required columns exist
# if 'URL' not in df.columns or 'label' not in df.columns:
#     raise KeyError("❌ The dataset must contain 'URL' and 'Label' columns!")

# # Define features (URLs) and labels (0 for safe, 1 for phishing)
# X = df['URL']
# y = df['label']

# # Split the data into training and testing sets
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# # Create a machine learning pipeline
# model = make_pipeline(
#     CountVectorizer(),  # Convert URLs into numerical features using CountVectorizer
#     RandomForestClassifier(n_estimators=100, random_state=42)  # RandomForestClassifier
# )

# # Train the model
# print("✅ Training the model...")
# model.fit(X_train, y_train)
# print("✅ Model training complete!")

# # Save the trained model to a .pkl file
# model_filename = 'phishing_model.pkl'
# with open(model_filename, 'wb') as file:
#     pickle.dump(model, file)

# print(f"✅ Model saved successfully as '{model_filename}'")
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
import pickle
import os
import re
from urllib.parse import urlparse
import tld
from datetime import datetime

def extract_advanced_features(url):
    """Extract features from URLs."""
    features = {}
    features['length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_slashes'] = url.count('/')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9.]', url))
    features['has_https'] = int(url.startswith('https'))
    features['has_http'] = int(url.startswith('http'))
    features['has_at'] = int('@' in url)
    features['has_double_slash'] = int('//' in url[7:])
    
    try:
        parsed = urlparse(url)
        features['domain_length'] = len(parsed.netloc)
        features['path_length'] = len(parsed.path)
        features['num_subdomains'] = len(parsed.netloc.split('.')) - 1
        try:
            res = tld.get_tld(url, as_object=True)
            features['tld_length'] = len(res.tld)
            features['is_common_tld'] = int(res.tld in {'com', 'org', 'net', 'edu', 'gov'})
        except:
            features['tld_length'] = 0
            features['is_common_tld'] = 0
        features['has_query'] = int(bool(parsed.query))
        features['num_params'] = len(parsed.query.split('&')) if parsed.query else 0
    except:
        features['domain_length'] = 0
        features['path_length'] = 0
        features['num_subdomains'] = 0
        features['tld_length'] = 0
        features['is_common_tld'] = 0
        features['has_query'] = 0
        features['num_params'] = 0
    
    return list(features.values())

def load_and_preprocess_data(dataset_path):
    """Load and preprocess the phishing dataset."""
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")
    
    df = pd.read_csv(dataset_path)
    if 'URL' not in df.columns or 'label' not in df.columns:
        raise KeyError("Dataset must contain 'URL' and 'label' columns")
    
    print("Extracting features from URLs...")
    X_features = [extract_advanced_features(url) for url in df['URL']]
    X_features = np.array(X_features)
    
    print(f"Number of features extracted: {X_features.shape[1]}")
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_features)
    
    return X_scaled, df['label'], scaler

def train_model(X, y, n_jobs=-1):
    """Train an improved Random Forest model with optimized hyperparameters."""
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    param_grid = {
        'n_estimators': [100, 200, 300],
        'max_depth': [20, 30, None],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4],
        'max_features': ['sqrt', 'log2'],
        'class_weight': ['balanced', 'balanced_subsample']
    }
    
    rf = RandomForestClassifier(random_state=42)
    
    grid_search = GridSearchCV(rf, param_grid, cv=5, scoring='f1', verbose=2, n_jobs=n_jobs)
    grid_search.fit(X_train, y_train)
    
    best_model = grid_search.best_estimator_
    
    y_pred = best_model.predict(X_test)
    print("\nModel Performance:")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    return best_model

def save_model(model, scaler, base_filename):
    """Save the model and scaler with timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_filename = f"{base_filename}_model_{timestamp}.pkl"
    scaler_filename = f"{base_filename}_scaler_{timestamp}.pkl"
    
    with open(model_filename, 'wb') as f:
        pickle.dump(model, f)
    with open(scaler_filename, 'wb') as f:
        pickle.dump(scaler, f)
    
    print(f"Model saved as: {model_filename}")
    print(f"Scaler saved as: {scaler_filename}")
    
    return model_filename, scaler_filename

def main():
    dataset_path = 'data/phishingdata.csv'
    
    try:
        X_scaled, y, scaler = load_and_preprocess_data(dataset_path)
        model = train_model(X_scaled, y)  # Changed to only receive the model
        model_file, scaler_file = save_model(model, scaler, 'phishing_detector')  # Pass the scaler from load_and_preprocess_data
        print("✅ Model training and saving completed successfully!")
    except Exception as e:
        print(f"❌ An error occurred: {str(e)}")

if __name__ == "__main__":
    main()

# import pandas as pd
# from sklearn.model_selection import train_test_split, GridSearchCV
# from sklearn.ensemble import RandomForestClassifier
# import pickle
# import os
# import re
# import numpy as np

# # Define dataset path
# dataset_path = r'data/phishingdata.csv'  # Use raw string (r'...') or forward slashes

# # Check if the dataset exists
# if not os.path.exists(dataset_path):
#     raise FileNotFoundError(f"❌ Dataset not found at {dataset_path}. Please check the path!")

# # Load the phishing dataset
# df = pd.read_csv(dataset_path, encoding='utf-8')

# # Ensure required columns exist
# required_columns = {'URL', 'label'}
# if not required_columns.issubset(df.columns):
#     raise KeyError("❌ The dataset must contain 'URL' and 'label' columns!")

# # Drop any rows with missing values
# df.dropna(subset=['URL', 'label'], inplace=True)

# # Feature extraction function
# def extract_features(url):
#     url = str(url)  # Ensure URL is a string
#     url_length = len(url)
#     num_dots = url.count('.')
#     num_slashes = url.count('/')
#     num_digits = len(re.findall(r'\d', url))
#     has_https = int(url.lower().startswith('https'))  # Ensure case insensitivity
#     has_at = int('@' in url)
#     return [url_length, num_dots, num_slashes, num_digits, has_https, has_at]

# # Apply feature extraction
# X_features = np.array([extract_features(url) for url in df['URL']])

# # Ensure extracted features are numerical
# if not np.issubdtype(X_features.dtype, np.number):
#     raise ValueError("❌ Extracted features contain non-numeric values!")

# # Labels (0 for safe, 1 for phishing)
# y = df['label'].astype(int)  # Ensure labels are integers

# # Split the data into training and testing sets
# X_train, X_test, y_train, y_test = train_test_split(X_features, y, test_size=0.3, random_state=42)

# # Define the classifier
# model = RandomForestClassifier(n_estimators=100, random_state=42)

# # Hyperparameter tuning
# param_grid = {
#     'n_estimators': [50, 100, 200],
#     'max_depth': [10, 20, None],
#     'min_samples_split': [2, 5, 10],
# }

# grid_search = GridSearchCV(model, param_grid, cv=3, verbose=1, n_jobs=-1)
# print("✅ Tuning model hyperparameters using GridSearchCV...")
# grid_search.fit(X_train, y_train)
# print("✅ Hyperparameter tuning complete!")

# # Use the best model from grid search
# best_model = grid_search.best_estimator_

# # Train the final model
# print("✅ Training the final model...")
# best_model.fit(X_train, y_train)
# print("✅ Model training complete!")

# # Save the trained model to a .pkl file
# model_filename = 'phishing_model_improved.pkl'
# with open(model_filename, 'wb') as file:
#     pickle.dump(best_model, file)

# print(f"✅ Model saved successfully as '{model_filename}'")

# import pandas as pd
# import numpy as np
# from sklearn.model_selection import train_test_split, GridSearchCV
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.preprocessing import StandardScaler
# import pickle
# import os
# import re
# from urllib.parse import urlparse
# import tld
# from datetime import datetime

# # Feature extraction function
# def extract_advanced_features(url):
#     """Extracts numerical features from URLs for phishing detection."""
#     features = {}
    
#     # Basic URL properties
#     features['length'] = len(url)
#     features['num_dots'] = url.count('.')
#     features['num_slashes'] = url.count('/')
#     features['num_digits'] = sum(c.isdigit() for c in url)
#     features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9.]', url))
    
#     # Security indicators
#     features['has_https'] = int(url.startswith('https'))
#     features['has_http'] = int(url.startswith('http'))
#     features['has_at'] = int('@' in url)
#     features['has_double_slash'] = int('//' in url[7:])  # Excluding protocol slashes
    
#     # URL parsing
#     try:
#         parsed = urlparse(url)
#         features['domain_length'] = len(parsed.netloc)
#         features['path_length'] = len(parsed.path)
#         features['num_subdomains'] = len(parsed.netloc.split('.')) - 1
        
#         # TLD analysis
#         try:
#             res = tld.get_tld(url, as_object=True)
#             features['tld_length'] = len(res.tld)
#             features['is_common_tld'] = int(res.tld in {'com', 'org', 'net', 'edu', 'gov'})
#         except:
#             features['tld_length'] = 0
#             features['is_common_tld'] = 0
        
#         # Query parameters
#         features['has_query'] = int(bool(parsed.query))
#         features['num_params'] = len(parsed.query.split('&')) if parsed.query else 0
        
#     except:
#         features.update({
#             'domain_length': 0,
#             'path_length': 0,
#             'num_subdomains': 0,
#             'tld_length': 0,
#             'is_common_tld': 0,
#             'has_query': 0,
#             'num_params': 0
#         })
    
#     # Suspicious patterns
#     features['has_ip_pattern'] = int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)))
#     features['has_hex_chars'] = int(bool(re.search(r'%[0-9a-fA-F]{2}', url)))
#     features['has_suspicious_words'] = int(bool(re.search(r'(login|signin|account|bank|verify|secure|paypal)', url.lower())))
    
#     return list(features.values())

# # Load dataset
# dataset_path = 'data/phishingdata.csv'
# if not os.path.exists(dataset_path):
#     raise FileNotFoundError(f"Dataset not found at {dataset_path}")

# df = pd.read_csv(dataset_path)

# if 'URL' not in df.columns or 'label' not in df.columns:
#     raise KeyError("Dataset must contain 'URL' and 'label' columns")

# print("Extracting features from URLs...")
# X_features = [extract_advanced_features(url) for url in df['URL']]
# X_features = np.array(X_features)

# # Scale features
# scaler = StandardScaler()
# X_scaled = scaler.fit_transform(X_features)

# # Labels
# y = df['label']

# # Split data
# X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42, stratify=y)

# # Train model
# model = RandomForestClassifier(n_estimators=200, random_state=42)
# model.fit(X_train, y_train)

# # Save model and scaler
# with open("phishing_model.pkl", "wb") as model_file:
#     pickle.dump(model, model_file)

# with open("phishing_scaler.pkl", "wb") as scaler_file:
#     pickle.dump(scaler, scaler_file)

# print("✅ Model and scaler saved successfully!")


