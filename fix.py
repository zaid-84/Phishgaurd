import pandas as pd


df = pd.read_csv('data\phishingdata.csv')
print(df.columns)
# import pickle
# from sklearn.ensemble import RandomForestClassifier

# # Example model (replace with your actual trained model)
# model = RandomForestClassifier()

# # Save the model properly
# with open("phishing_model.pkl", "wb") as file:
#     pickle.dump(model, file)
# import pandas as pd
# import numpy as np
# from sklearn.model_selection import train_test_split, GridSearchCV
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.metrics import classification_report, confusion_matrix
# from sklearn.preprocessing import StandardScaler
# import pickle
# import os
# import re
# from urllib.parse import urlparse
# import tld
# from datetime import datetime

# def extract_advanced_features(url):
#     """Extract comprehensive features from URLs for phishing detection."""
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
#         # Domain features
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

# def load_and_preprocess_data(dataset_path):
#     """Load and preprocess the phishing dataset."""
#     if not os.path.exists(dataset_path):
#         raise FileNotFoundError(f"Dataset not found at {dataset_path}")
    
#     df = pd.read_csv(dataset_path)
    
#     if 'URL' not in df.columns or 'label' not in df.columns:
#         raise KeyError("Dataset must contain 'URL' and 'label' columns")
    
#     print("Extracting features from URLs...")
#     X_features = [extract_advanced_features(url) for url in df['URL']]
#     X_features = np.array(X_features)
    
#     # Scale features
#     scaler = StandardScaler()
#     X_scaled = scaler.fit_transform(X_features)
    
#     return X_scaled, df['label'], scaler

# def train_model(X, y, n_jobs=-1):
#     """Train an improved Random Forest model with optimized hyperparameters."""
#     # Split data
#     X_train, X_test, y_train, y_test = train_test_split(
#         X, y, test_size=0.2, random_state=42, stratify=y
#     )
    
#     # Define more comprehensive parameter grid
#     param_grid = {
#         'n_estimators': [100, 200, 300],
#         'max_depth': [20, 30, None],
#         'min_samples_split': [2, 5, 10],
#         'min_samples_leaf': [1, 2, 4],
#         'max_features': ['sqrt', 'log2'],
#         'class_weight': ['balanced', 'balanced_subsample']
#     }
    
#     # Initialize base model
#     rf = RandomForestClassifier(random_state=42)
    
#     # Perform grid search
#     print("Starting GridSearchCV...")
#     grid_search = GridSearchCV(
#         rf, param_grid, cv=5, scoring='f1',
#         verbose=2, n_jobs=n_jobs
#     )
    
#     grid_search.fit(X_train, y_train)
    
#     # Get best model
#     best_model = grid_search.best_estimator_
    
#     # Evaluate model
#     y_pred = best_model.predict(X_test)
#     print("\nModel Performance:")
#     print("\nClassification Report:")
#     print(classification_report(y_test, y_pred))
#     print("\nConfusion Matrix:")
#     print(confusion_matrix(y_test, y_pred))
    
#     return best_model, scaler

# def save_model(model, scaler, base_filename):
#     """Save the model and scaler with timestamp."""
#     timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
#     model_filename = f"{base_filename}_model_{timestamp}.pkl"
#     scaler_filename = f"{base_filename}_scaler_{timestamp}.pkl"
    
#     with open(model_filename, 'wb') as f:
#         pickle.dump(model, f)
#     with open(scaler_filename, 'wb') as f:
#         pickle.dump(scaler, f)
    
#     print(f"Model saved as: {model_filename}")
#     print(f"Scaler saved as: {scaler_filename}")

# def main():
#     dataset_path = 'data/phishingdata.csv'
    
#     try:
#         # Load and preprocess data
#         X_scaled, y, scaler = load_and_preprocess_data(dataset_path)
        
#         # Train model
#         print("Training model...")
#         model, scaler = train_model(X_scaled, y)
        
#         # Save model and scaler
#         save_model(model, scaler, 'phishing_detector')
        
#         print("✅ Model training and saving completed successfully!")
        
#     except Exception as e:
#         print(f"❌ An error occurred: {str(e)}")

# if __name__ == "__main__":
#     main()