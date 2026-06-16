
import streamlit as st
import pandas as pd
from sklearn.linear_model import LogisticRegression

# --- 1. SCREEN SETUP ---
st.set_page_config(page_title="Scam Buster AI v3", page_icon="🕵️‍♂️", layout="wide")

st.title("🕵️‍♂️ Scam Buster AI: Advanced Phishing Detector")
st.markdown("Analyze suspicious messages using our centralized multi-column intelligence dashboard.")
st.markdown("---")

# --- 2. DATASET & MACHINE LEARNING BRAIN ---
historical_vault = {
    "Urgency_Words_Count": [3, 0, 4, 0, 2, 0, 5, 1, 0, 1],
    "Suspicious_Links":    [2, 0, 0, 0, 3, 1, 4, 0, 0, 1],
    "Requests_Info":       [1, 0, 1, 0, 0, 0, 1, 1, 0, 0],
    "Bad_Sender":          [0, 0, 1, 0, 1, 0, 1, 1, 0, 1],
    "Message_Verdict":     [0, 2, 0, 2, 0, 1, 0, 0, 2, 1]  # 2 = Safe, 1 = Suspicious, 0 = Scam!
}
df = pd.DataFrame(historical_vault)

X = df[["Urgency_Words_Count", "Suspicious_Links", "Requests_Info", "Bad_Sender"]]
y = df["Message_Verdict"]

scam_ai = LogisticRegression()
scam_ai.fit(X, y)

# --- 3. 🏛️ CREATING THE 3-COLUMN LAYOUT ---
# We split the screen into 3 equal columns across the page
col_left, col_middle, col_right = st.columns(3)

# --- COLUMN 1: HISTORICAL DATA (LEFT) ---
with col_left:
    st.markdown("### 📊 Threat Database")
    st.write("Historical patterns analyzed by the ML engine:")
    
    visible_df = df.copy()
    visible_df["Message_Verdict"] = visible_df["Message_Verdict"].map({2: "🟢 Safe", 1: "🟡 Suspicious", 0: "🔴 Scam"})
    st.dataframe(visible_df, use_container_width=True)

# --- COLUMN 2: USER INPUT CONTROLS (MIDDLE) ---
with col_middle:
    st.markdown("### 📥 Extract Message Signals")
    st.write("Log the exact metrics found in the message:")
    
    count_urgency = st.number_input("🚨 Urgency Words Count:", min_value=0, max_value=10, value=0, step=1)
    count_links = st.number_input("🔗 Suspicious Links Count:", min_value=0, max_value=10, value=0, step=1)
    
    has_info = 1 if st.checkbox("🔑 Requests Personal Info?") else 0
    has_bad_sender = 1 if st.checkbox("📧 Poor Sender Credibility?") else 0
    
    st.markdown("---")
    # 🔘 The Trigger Button!
    run_scan = st.button("🔍 Run Scan Analysis", type="primary", use_container_width=True)

# --- COLUMN 3: LIVE DIAGNOSTICS & VERDICT CARD (RIGHT) ---
with col_right:
    st.markdown("### 🤖 AI Core")
    
    # Only calculate and display if the user explicitly clicked the button
    if run_scan:
        # 1. Package the live numbers
        live_message_packet = pd.DataFrame({
            "Urgency_Words_Count": [count_urgency],
            "Suspicious_Links":    [count_links],
            "Requests_Info":       [has_info],
            "Bad_Sender":          [has_bad_sender]
        })
        
        # 2. Run calculation
        ai_verdict = scam_ai.predict(live_message_packet)[0]
        probabilities = scam_ai.predict_proba(live_message_packet)[0]
        confidence_score = max(probabilities) * 100
        
        # 3. Output results
        st.markdown(f"**AI Calculation Confidence:** `{confidence_score:.1f}%`")
        st.markdown("#### 🎫 Current Verdict Card:")
        
        if ai_verdict == 2:
            st.success("## 🟢 VERDICT: SAFE")
            st.write("The message text score sits safely below our danger weight lines. No risk patterns matched.")
        elif ai_verdict == 1:
            st.warning("## 🟡 VERDICT: SUSPICIOUS")
            st.write("Isolated anomaly spikes detected. Avoid clicking links until source identity is verified.")
        else:
            st.error("## 🔴 VERDICT: SCAM HIGH ALERT")
            st.write("🚨 Threat threshold breached! High probability of an intentional malicious phishing exploit.")
            
    else:
        # Default placeholder box showing before clicking the button
        st.info("💡 **System Idle:** Enter data in the center panel and click 'Run Scan Analysis' to generate the AI threat verdict card.")