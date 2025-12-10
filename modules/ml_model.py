"""
ML Model Module for Phishing Detection
Author: Mikayel Badalyan
"""

def tokenize_email(email_content):
    """
    Tokenize email content for NLP processing
    """
    # Placeholder for tokenization logic
    tokens = email_content.split()
    return tokens

def extract_features(email_content):
    """
    Extract features from email content for ML model
    """
    # Placeholder for feature extraction logic
    features = {
        'word_count': len(email_content.split()),
        'exclamation_count': email_content.count('!'),
        'question_count': email_content.count('?'),
        'urgent_keywords': email_content.lower().count('urgent') + email_content.lower().count('immediate')
    }
    return features

def predict_phishing(features):
    """
    Predict if email is phishing based on extracted features
    """
    # Placeholder for ML model prediction
    # In a real implementation, this would use a trained model
    risk_score = min(0.95, features['exclamation_count'] * 0.1 + 
                     features['urgent_keywords'] * 0.2 +
                     features['question_count'] * 0.05)
    
    return {
        'risk_score': risk_score,
        'is_phishing': risk_score > 0.5
    }

# Example usage:
if __name__ == "__main__":
    sample_email = "URGENT! Your account will be suspended immediately! Click here now!"
    tokens = tokenize_email(sample_email)
    features = extract_features(sample_email)
    prediction = predict_phishing(features)
    
    print(f"Tokens: {tokens}")
    print(f"Features: {features}")
    print(f"Prediction: {prediction}")