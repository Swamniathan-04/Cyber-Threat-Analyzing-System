# Cyber Threat Detection System 🛡️

## Summary
This project is a machine learning-based cyber threat detection system that analyzes raw text input to identify potential security threats. It uses a trained model to classify threats and provides detailed analysis results.

## About
The system is built using Python and Flask, with a focus on high precision and real-time analysis. It leverages TF-IDF vectorization and a RandomForest classifier to detect various types of cyber threats, including malware, phishing, DDoS, and more.

## Description
- **Backend:** Flask-based REST API that serves the trained model.
- **Model:** RandomForest classifier trained on multiple datasets (Phishing, CICIDS2017, EMBER).
- **Features:** TF-IDF vectorization, threat classification, confidence scoring, and risk level assessment.
- **Security:** JWT-based authentication for secure API access.
- **Real-time Analysis:** Provides instant threat analysis results.
- **Scalability:** Designed to handle large volumes of data efficiently.
- **User-Friendly:** Simple API endpoints for easy integration.

## How to Run
1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/Cyber-Threat-system.git
   cd Cyber-Threat-system
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Train the model:**
   ```bash
   cd ML_Python_Core/backend
   python train_model.py
   ```

4. **Start the Flask server:**
   ```bash
   python app.py
   ```

5. **Test the API:**
   ```bash
   python test_api.py
   ```

## Use Cases
- **Real-time Threat Analysis:** Analyze logs or network traffic for potential threats.
- **Security Monitoring:** Integrate with SIEM systems for automated threat detection.
- **Research & Education:** Use as a benchmark for cyber threat detection research.
- **Incident Response:** Quickly identify and respond to security incidents.

## Project Structure
```
Cyber-Threat-system/
├── ML_Python_Core/
│   ├── backend/
│   │   ├── app.py
│   │   ├── guardian_ai.py
│   │   ├── train_model.py
│   │   └── test_api.py
│   └── cyb datasets/
│       ├── Phising Dataset/
│       ├── CICIDS2017/
│       └── EMBER/
├── requirements.txt
└── README.md
```

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
This project is licensed under the MIT License - see the LICENSE file for details. 