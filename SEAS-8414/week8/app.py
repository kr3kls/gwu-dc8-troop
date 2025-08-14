import streamlit as st
import pandas as pd
from pycaret.classification import load_model as load_clf_model, predict_model as predict_clf_model
from pycaret.clustering import load_model as load_clu_model, predict_model as predict_clu_model
from genai_prescriptions import generate_prescription
import os
import time
import json

# Page Configuration
st.set_page_config(
    page_title="GenAI-Powered Phishing SOAR",
    page_icon="🛡️",
    layout="wide"
)


# Load Models and Assets
@st.cache_resource
def load_assets():
    """Loads all necessary models, plots, and mappings from disk."""
    clf_model_path = 'models/phishing_url_detector'
    clu_model_path = 'models/threat_actor_profiler'
    plot_path = 'models/feature_importance.png'
    mapping_path = 'models/profile_mapping.json'

    clf_model, clu_model, plot, mapping = None, None, None, None

    if os.path.exists(clf_model_path + '.pkl'):
        clf_model = load_clf_model(clf_model_path, verbose=False)
    if os.path.exists(clu_model_path + '.pkl'):
        clu_model = load_clu_model(clu_model_path, verbose=False)
    if os.path.exists(plot_path):
        plot = plot_path
    if os.path.exists(mapping_path):
        with open(mapping_path, 'r') as f:
            mapping = json.load(f)

    return clf_model, clu_model, plot, mapping


clf_model, clu_model, feature_plot, profile_mapping = load_assets()

if not clf_model or not clu_model or not profile_mapping:
    st.error(
        "One or more assets (models, profile mapping) are not found. "
        "Please run `make train` from your terminal to generate all necessary files. "
        "Check container logs with `make logs` if the error persists."
    )
    st.stop()


# Sidebar for Inputs
with st.sidebar:
    st.title("🔬 URL Feature Input")
    st.write("Describe the characteristics of a suspicious URL below.")

    form_values = {
        'url_length': st.select_slider("URL Length", options=['Short', 'Normal', 'Long'], value='Long'),
        'ssl_state': st.select_slider("SSL Certificate Status", options=['Trusted', 'Suspicious', 'None'], value='Suspicious'),
        'sub_domain': st.select_slider("Sub-domain Complexity", options=['None', 'One', 'Many'], value='One'),
        'url_of_anchor': st.select_slider("Anchor URL Risk", options=['Safe', 'Suspicious', 'Malicious'], value='Suspicious'),
        'links_in_tags': st.select_slider("Links in HTML Tags", options=['Few', 'Some', 'Many'], value='Some'),
        'sfh': st.select_slider("Server Form Handler (SFH)", options=['Legitimate', 'Suspicious', 'Empty'], value='Suspicious'),
        'has_political_keyword': st.checkbox("URL contains political keywords", value=False),
        'prefix_suffix': st.checkbox("URL has a Prefix/Suffix (e.g.,'-')", value=True),
        'has_ip': st.checkbox("URL uses an IP Address", value=False),
        'short_service': st.checkbox("Is it a shortened URL", value=False),
        'at_symbol': st.checkbox("URL contains '@' symbol", value=False),
        'abnormal_url': st.checkbox("Is it an abnormal URL", value=True),
        'double_slash_redirecting': st.checkbox("URL uses '//' for redirection", value=False),
    }

    st.divider()
    genai_provider = st.selectbox("Select GenAI Provider", ["Gemini", "OpenAI", "Grok"])
    submitted = st.button("💥 Analyze & Initiate Response", use_container_width=True, type="primary")

# Main Page
st.title("🛡️ GenAI-Powered SOAR for Phishing URL Analysis")

if not submitted:
    st.info("Please provide the URL features in the sidebar and click 'Analyze' to begin.")
    if feature_plot:
        st.subheader("Model Feature Importance")
        st.image(feature_plot,
                 caption="Feature importance from the trained classification model. This shows which features the model weighs most heavily when making a prediction.")

else:
    # Data Mapping
    input_dict = {
        'having_IP_Address': 1 if form_values['has_ip'] else -1,
        'URL_Length': -1 if form_values['url_length'] == 'Short' else (0 if form_values['url_length'] == 'Normal' else 1),
        'Shortining_Service': 1 if form_values['short_service'] else -1,
        'having_At_Symbol': 1 if form_values['at_symbol'] else -1,
        'double_slash_redirecting': 1 if form_values['double_slash_redirecting'] else -1,
        'Prefix_Suffix': 1 if form_values['prefix_suffix'] else -1,
        'having_Sub_Domain': -1 if form_values['sub_domain'] == 'None' else (0 if form_values['sub_domain'] == 'One' else 1),
        'SSLfinal_State': -1 if form_values['ssl_state'] == 'None' else (0 if form_values['ssl_state'] == 'Suspicious' else 1),
        'Abnormal_URL': 1 if form_values['abnormal_url'] else -1,
        'has_political_keyword': 1 if form_values['has_political_keyword'] else -1,
        'URL_of_Anchor': -1 if form_values['url_of_anchor'] == 'Safe' else (0 if form_values['url_of_anchor'] == 'Suspicious' else 1),
        'Links_in_tags': -1 if form_values['links_in_tags'] == 'Few' else (0 if form_values['links_in_tags'] == 'Some' else 1),
        'SFH': 1 if form_values['sfh'] == 'Empty' else (0 if form_values['sfh'] == 'Suspicious' else -1),
    }
    input_data = pd.DataFrame([input_dict])

    # Analysis Workflow
    threat_profile = None
    with st.status("Executing SOAR playbook...", expanded=True) as status:
        st.write("▶️ **Step 1: Predictive Analysis** - Running features through classification model.")
        time.sleep(1)
        prediction = predict_clf_model(clf_model, data=input_data)
        is_malicious = prediction['prediction_label'].iloc[0] == 1

        verdict = "MALICIOUS" if is_malicious else "BENIGN"
        st.write(f"▶️ **Step 2: Verdict Interpretation** - Model predicts **{verdict}**.")
        time.sleep(1)

        if is_malicious:
            st.write("▶️ **Step 3: Threat Attribution** - Profiling attack patterns.")
            time.sleep(1)
            cluster_prediction = predict_clu_model(clu_model, data=input_data)
            predicted_cluster = cluster_prediction['Cluster'].iloc[0]
            threat_profile = profile_mapping.get(predicted_cluster)

            profile_name = "Unknown Profile"
            if threat_profile:
                profile_name = threat_profile.get('name', profile_name)

            st.write(f"▶️ **Step 4: Attribution Complete** - Profiled as **{profile_name}**.")
            time.sleep(1)

            st.write(f"▶️ **Step 5: Prescriptive Analytics** - Engaging **{genai_provider}** for action plan.")
            try:
                prescription = generate_prescription(genai_provider, {k: v for k, v in input_dict.items()})
                status.update(label="✅ SOAR Playbook Executed Successfully!", state="complete", expanded=False)
            except Exception as e:
                st.error(f"Failed to generate prescription: {e}")
                prescription = None
                status.update(label="🚨 Error during GenAI prescription!", state="error")
        else:
            prescription = None
            status.update(label="✅ Analysis Complete. No threat found.", state="complete", expanded=False)

    # Tabs for organization
    tab_list = ["📊 **Analysis Summary**", "🎭 **Threat Attribution**", "📈 **Visual Insights**", "📜 **Prescriptive Plan**"]
    tab1, tab2, tab3, tab4 = st.tabs(tab_list)

    with tab1:
        st.subheader("Verdict and Key Findings")
        if is_malicious:
            st.error("**Prediction: Malicious Phishing URL**", icon="🚨")
        else:
            st.success("**Prediction: Benign URL**", icon="✅")

        st.metric("Malicious Confidence Score",
                  f"{prediction['prediction_score'].iloc[0]:.2%}" if is_malicious else f"{1 - prediction['prediction_score'].iloc[0]:.2%}")
        st.caption("This score represents the model's confidence in its prediction.")

    with tab2:
        st.subheader("Predicted Threat Actor Profile")
        if threat_profile:
            st.info(f"**Profile:** {threat_profile.get('name', 'N/A')} {threat_profile.get('icon', '')}", icon="🎯")
            st.write("**Typical Motivations and Methods:**")
            st.markdown(threat_profile.get('description', 'No description available.'))
        else:
            st.info("Threat attribution is only performed on URLs classified as malicious.")

    with tab3:
        st.subheader("Visual Analysis")
        if feature_plot:
            st.write("#### Model Feature Importance (Global)")
            st.image(feature_plot,
                     caption="This plot shows which features the classification model found most important *overall* during its training.")
        else:
            st.warning("Feature importance plot not found.")

    with tab4:
        st.subheader("Actionable Response Plan")
        if prescription:
            st.success("A prescriptive response plan has been generated by the AI.", icon="🤖")
            st.write("#### Recommended Actions (for Security Analyst)")
            for i, action in enumerate(prescription.get("recommended_actions", []), 1):
                st.markdown(f"**{i}.** {action}")

            st.write("#### Communication Draft (for End-User/Reporter)")
            st.text_area("Draft", prescription.get("communication_draft", ""), height=150)

            with st.expander("Show Raw GenAI Output"):
                st.json(prescription)
        elif is_malicious and not prescription:
             st.error("An error occurred while generating the response plan.")
        else:
            st.info("No prescriptive plan was generated because the URL was classified as benign.")
