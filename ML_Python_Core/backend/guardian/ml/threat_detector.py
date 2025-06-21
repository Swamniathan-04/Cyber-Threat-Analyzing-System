import os
import pickle
import logging
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from typing import List, Dict, Any, Tuple

logger = logging.getLogger(__name__)

class ThreatDetector:
    def __init__(self):
        """Initialize the threat detector with a Random Forest classifier."""
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
    def train_model(self, texts: List[str], labels: List[int]) -> Dict[str, float]:
        """Train the model on the given texts and labels."""
        if not texts or not labels:
            raise ValueError("No training data provided")
            
        # Convert texts to features (using simple character n-grams for now)
        X = self._text_to_features(texts)
        y = np.array(labels)
        
        # Train the model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.model.fit(X, y)
        
        # Calculate metrics
        y_pred = self.model.predict(X)
        metrics = {
            'accuracy': accuracy_score(y, y_pred),
            'precision': precision_score(y, y_pred, average='weighted'),
            'recall': recall_score(y, y_pred, average='weighted'),
            'f1_score': f1_score(y, y_pred, average='weighted')
        }
        
        logger.info(f"Model training complete. Metrics: {metrics}")
        return metrics
        
    def predict(self, text: str) -> Tuple[int, float]:
        """Predict the class and confidence for a given text."""
        if not hasattr(self, 'model') or self.model is None:
            raise ValueError("Model not trained")
            
        # Convert text to features
        X = self._text_to_features([text])
        
        # Get prediction and probability
        prediction = self.model.predict(X)[0]
        confidence = np.max(self.model.predict_proba(X)[0])
        
        return prediction, confidence
        
    def _text_to_features(self, texts: List[str]) -> np.ndarray:
        """Convert texts to feature vectors using character n-grams."""
        # Simple character n-gram features (you can enhance this)
        n = 3  # trigrams
        features = []
        
        for text in texts:
            # Get character n-grams
            ngrams = [text[i:i+n] for i in range(len(text)-n+1)]
            
            # Create feature vector (simple one-hot encoding)
            feature_vector = np.zeros(256**n)  # For ASCII characters
            for ngram in ngrams:
                # Simple hash function for n-gram
                hash_val = sum(ord(c) * (256**i) for i, c in enumerate(ngram))
                feature_vector[hash_val % len(feature_vector)] = 1
                
            features.append(feature_vector)
            
        return np.array(features)
        
    def save_model(self, model_path: str) -> None:
        """Save the trained model to disk."""
        if not hasattr(self, 'model') or self.model is None:
            raise ValueError("No trained model to save")
            
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        # Save the model
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
            
        logger.info(f"Model saved to {model_path}")
        
    def load_model(self, model_path: str) -> None:
        """Load a trained model from disk."""
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
            
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
            
        logger.info(f"Model loaded from {model_path}") 