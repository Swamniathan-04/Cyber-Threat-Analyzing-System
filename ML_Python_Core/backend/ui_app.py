import streamlit as st
import requests
import json

API_URL = "http://127.0.0.1:5000/api"

st.set_page_config(page_title="Cyber Threat Analyzing System", page_icon="🛡️", layout="centered")
st.title("🛡️ Cyber Threat Analyzing System UI")
st.markdown("""
Welcome to the interactive UI for your AI-powered cyber threat detection system!
""")

# --- Sidebar: Health Check ---
st.sidebar.header("🔎 System Health")
health_status = "Unknown"
try:
    health_resp = requests.get(f"{API_URL}/health")
    if health_resp.status_code == 200:
        health = health_resp.json()
        if health.get("status") == "healthy" and health.get("model_loaded"):
            health_status = "🟢 Healthy (Model Loaded)"
        else:
            health_status = "🟡 Unhealthy"
    else:
        health_status = "🔴 Unreachable"
except Exception:
    health_status = "🔴 Unreachable"
st.sidebar.write(f"**Status:** {health_status}")

# --- Main App: Threat Analysis ---
st.subheader("📝 Threat Analysis")
with st.form("analyze_form"):
    text = st.text_area("Paste log, message, or text to analyze:", height=150, placeholder="Enter suspicious text, logs, or any content you want to analyze for threats...")
    analyze_btn = st.form_submit_button("🔍 Analyze Threat")
    
    if analyze_btn:
        if not text.strip():
            st.warning("Please enter some text to analyze.")
        else:
            with st.spinner("Analyzing threat..."):
                try:
                    # For now, we'll use a dummy token or modify the backend to allow unauthenticated access
                    # You may need to temporarily modify your Flask app to allow unauthenticated access to /api/analyze
                    headers = {"Content-Type": "application/json"}
                    resp = requests.post(f"{API_URL}/analyze", headers=headers, json={"text": text})
                    
                    if resp.status_code == 200:
                        result = resp.json()
                        st.markdown("---")
                        st.markdown(f"### 🛡️ **Threat Analysis Result**")
                        
                        # Create columns for better layout
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.metric("Threat Type", result.get('threat_type', 'N/A'))
                            
                            risk_level = result.get('risk_level', 'N/A')
                            if risk_level == 'CRITICAL':
                                st.error(f"**Risk Level: {risk_level}** 🚨")
                            elif risk_level == 'HIGH':
                                st.warning(f"**Risk Level: {risk_level}**")
                            else:
                                st.info(f"**Risk Level: {risk_level}**")

                            st.metric("Confidence", f"{round(result.get('confidence', 0)*100, 2)}%")
                        
                        with col2:
                            st.metric("Specific Threat", result.get('specific_threat_name', 'N/A'))
                            st.metric("Processing Time", f"{result.get('processing_time', 'N/A')}s")
                            st.metric("Timestamp", result.get('timestamp', 'N/A')[:19] if result.get('timestamp') else 'N/A')
                        
                        # Model predictions with better visualization
                        st.markdown("#### 🔬 Model Predictions:")
                        predictions = result.get('model_predictions', {})
                        if 'main_model' in predictions:
                            pred_data = predictions['main_model']
                            # Create a bar chart for predictions
                            import pandas as pd
                            df = pd.DataFrame(list(pred_data.items()), columns=['Threat Type', 'Probability'])
                            df['Probability'] = df['Probability'] * 100
                            st.bar_chart(df.set_index('Threat Type'))
                        else:
                            st.json(predictions)
                        
                        if result.get('feature_importance'):
                            st.markdown("#### 📊 Feature Importance:")
                            st.json(result.get('feature_importance'))
                            
                    else:
                        st.error(f"Analysis failed: {resp.json().get('error', 'Unknown error')}")
                except Exception as e:
                    st.error(f"API error: {e}")
                    st.info("Make sure your Flask API server is running on http://127.0.0.1:5000")

# --- Additional Features ---
st.markdown("---")
st.subheader("🚀 Quick Examples")
example_texts = {
    "Suspicious Email": "URGENT: Your account has been compromised. Click here to verify: http://fake-bank.com/verify",
    "Malware Detection": "suspicious.exe downloaded from unknown source with elevated privileges",
    "Network Attack": "Multiple failed login attempts detected from IP 192.168.1.100",
    "Phishing Attempt": "Congratulations! You've won $1,000,000. Send your bank details to claim your prize!"
}

selected_example = st.selectbox("Choose an example:", list(example_texts.keys()))
if st.button("Load Example"):
    st.session_state.example_text = example_texts[selected_example]
    st.rerun()

if 'example_text' in st.session_state:
    st.text_area("Example loaded:", value=st.session_state.example_text, height=100, disabled=True)

st.markdown("---")
st.caption("Made with ❤️ using Streamlit | Cyber Threat Analyzing System 🛡️") 