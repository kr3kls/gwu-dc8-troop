import pandas as pd
import numpy as np
from pycaret import classification
from pycaret import clustering
import os
import subprocess


def generate_synthetic_data(num_samples=600):
    """
    Generates a synthetic dataset of URL features, simulating benign traffic
    and three distinct phishing threat actor profiles with more pronounced characteristics.
    """
    print("Generating synthetic dataset with more distinct threat actor profiles...")

    features = [
        'having_IP_Address', 'URL_Length', 'Shortining_Service',
        'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix',
        'having_Sub_Domain', 'SSLfinal_State', 'URL_of_Anchor', 'Links_in_tags',
        'SFH', 'Abnormal_URL', 'has_political_keyword'
    ]

    num_benign = num_samples // 2
    num_phishing_samples = num_samples - num_benign
    num_per_profile = num_phishing_samples // 3
    remainder = num_phishing_samples % 3

    sizes = [num_per_profile] * 3
    for i in range(remainder):
        sizes[i] += 1

    size_state, size_crime, size_hacktivist = sizes[0], sizes[1], sizes[2]

    # Profile 1 - State-Sponsored: Emphasize valid SSL, deceptive domains (Prefix_Suffix), and avoiding obvious red flags.
    state_sponsored_data = {
        'having_IP_Address': np.random.choice([1, -1], size_state, p=[0.05, 0.95]),
        'URL_Length': np.random.choice([1, 0, -1], size_state, p=[0.4, 0.5, 0.1]),
        'Shortining_Service': np.random.choice([1, -1], size_state, p=[0.05, 0.95]),
        'having_At_Symbol': np.random.choice([1, -1], size_state, p=[0.05, 0.95]),
        'double_slash_redirecting': np.random.choice([1, -1], size_state, p=[0.1, 0.9]),
        'Prefix_Suffix': np.random.choice([1, -1], size_state, p=[0.9, 0.1]),
        'having_Sub_Domain': np.random.choice([1, 0, -1], size_state, p=[0.7, 0.2, 0.1]),
        'SSLfinal_State': np.random.choice([-1, 0, 1], size_state, p=[0.05, 0.05, 0.9]),
        'URL_of_Anchor': np.random.choice([-1, 0, 1], size_state, p=[0.6, 0.3, 0.1]),
        'Links_in_tags': np.random.choice([-1, 0, 1], size_state, p=[0.5, 0.4, 0.1]),
        'SFH': np.random.choice([-1, 0, 1], size_state, p=[0.5, 0.3, 0.2]),
        'Abnormal_URL': np.random.choice([1, -1], size_state, p=[0.1, 0.9]),
        'has_political_keyword': np.random.choice([1, -1], size_state, p=[0.1, 0.9])
    }
    df_state_sponsored = pd.DataFrame(state_sponsored_data)
    df_state_sponsored['profile'] = 'state_sponsored'

    # Profile 2 - Organized Cybercrime: Emphasize IPs, shorteners, bad SSL, and abnormal structures.
    organized_crime_data = {
        'having_IP_Address': np.random.choice([1, -1], size_crime, p=[0.9, 0.1]),
        'URL_Length': np.random.choice([1, 0, -1], size_crime, p=[0.6, 0.3, 0.1]),
        'Shortining_Service': np.random.choice([1, -1], size_crime, p=[0.9, 0.1]),
        'having_At_Symbol': np.random.choice([1, -1], size_crime, p=[0.6, 0.4]),
        'double_slash_redirecting': np.random.choice([1, -1], size_crime, p=[0.7, 0.3]),
        'Prefix_Suffix': np.random.choice([1, -1], size_crime, p=[0.7, 0.3]),
        'having_Sub_Domain': np.random.choice([1, 0, -1], size_crime, p=[0.2, 0.3, 0.5]),
        'SSLfinal_State': np.random.choice([-1, 0, 1], size_crime, p=[0.8, 0.15, 0.05]),
        'URL_of_Anchor': np.random.choice([-1, 0, 1], size_crime, p=[0.7, 0.2, 0.1]),
        'Links_in_tags': np.random.choice([-1, 0, 1], size_crime, p=[0.6, 0.2, 0.2]),
        'SFH': np.random.choice([-1, 0, 1], size_crime, p=[0.8, 0.1, 0.1]),
        'Abnormal_URL': np.random.choice([1, -1], size_crime, p=[0.9, 0.1]),
        'has_political_keyword': np.random.choice([1, -1], size_crime, p=[0.05, 0.95])
    }
    df_organized_crime = pd.DataFrame(organized_crime_data)
    df_organized_crime['profile'] = 'organized_crime'

    # Profile 3 - Hacktivist: Emphasize political keywords and long URLs.
    hacktivist_data = {
        'having_IP_Address': np.random.choice([1, -1], size_hacktivist, p=[0.3, 0.7]),
        'URL_Length': np.random.choice([1, 0, -1], size_hacktivist, p=[0.8, 0.1, 0.1]),
        'Shortining_Service': np.random.choice([1, -1], size_hacktivist, p=[0.4, 0.6]),
        'having_At_Symbol': np.random.choice([1, -1], size_hacktivist, p=[0.7, 0.3]),
        'double_slash_redirecting': np.random.choice([1, -1], size_hacktivist, p=[0.5, 0.5]),
        'Prefix_Suffix': np.random.choice([1, -1], size_hacktivist, p=[0.4, 0.6]),
        'having_Sub_Domain': np.random.choice([1, 0, -1], size_hacktivist, p=[0.4, 0.4, 0.2]),
        'SSLfinal_State': np.random.choice([-1, 0, 1], size_hacktivist, p=[0.7, 0.2, 0.1]),
        'URL_of_Anchor': np.random.choice([-1, 0, 1], size_hacktivist, p=[0.2, 0.6, 0.2]),
        'Links_in_tags': np.random.choice([-1, 0, 1], size_hacktivist, p=[0.3, 0.5, 0.2]),
        'SFH': np.random.choice([-1, 0, 1], size_hacktivist, p=[0.6, 0.3, 0.1]),
        'Abnormal_URL': np.random.choice([1, -1], size_hacktivist, p=[0.7, 0.3]),
        'has_political_keyword': np.random.choice([1, -1], size_hacktivist, p=[0.95, 0.05])
    }
    df_hacktivist = pd.DataFrame(hacktivist_data)
    df_hacktivist['profile'] = 'hacktivist'

    # Benign Data: Emphasize legitimate features to create a strong contrast with phishing profiles.
    benign_data = {
        'having_IP_Address': np.random.choice([1, -1], num_benign, p=[0.01, 0.99]),
        'URL_Length': np.random.choice([1, 0, -1], num_benign, p=[0.1, 0.7, 0.2]),
        'Shortining_Service': np.random.choice([1, -1], num_benign, p=[0.01, 0.99]),
        'having_At_Symbol': np.random.choice([1, -1], num_benign, p=[0.01, 0.99]),
        'double_slash_redirecting': np.random.choice([1, -1], num_benign, p=[0.01, 0.99]),
        'Prefix_Suffix': np.random.choice([1, -1], num_benign, p=[0.01, 0.99]),
        'having_Sub_Domain': np.random.choice([1, 0, -1], num_benign, p=[0.1, 0.4, 0.5]),
        'SSLfinal_State': np.random.choice([-1, 0, 1], num_benign, p=[0.02, 0.08, 0.9]),
        'URL_of_Anchor': np.random.choice([-1, 0, 1], num_benign, p=[0.05, 0.15, 0.8]),
        'Links_in_tags': np.random.choice([-1, 0, 1], num_benign, p=[0.05, 0.15, 0.8]),
        'SFH': np.random.choice([-1, 0, 1], num_benign, p=[0.02, 0.08, 0.9]),
        'Abnormal_URL': np.random.choice([1, -1], num_benign, p=[0.01, 0.99]),
        'has_political_keyword': np.random.choice([1, -1], num_benign, p=[0.01, 0.99])
    }
    df_benign = pd.DataFrame(benign_data)
    df_benign['profile'] = 'benign'

    # Combine all dataframes
    df_phishing = pd.concat([df_state_sponsored, df_organized_crime, df_hacktivist], ignore_index=True)

    # Assign labels: 1 for any phishing, 0 for benign
    df_phishing['label'] = 1
    df_benign['label'] = 0

    final_df = pd.concat([df_phishing, df_benign], ignore_index=True)

    # Shuffle the dataset and return
    return final_df.sample(frac=1).reset_index(drop=True)


def train():
    """
    Trains and saves a classification model to detect phishing URLs and a 
    clustering model to profile different types of phishing attacks.
    """
    classification_model_path = 'models/phishing_url_detector'
    clustering_model_path = 'models/threat_actor_profiler'
    plot_path = 'models/feature_importance.png'

    os.makedirs('models', exist_ok=True)
    os.makedirs('data', exist_ok=True)

    data = generate_synthetic_data()
    data.to_csv('data/phishing_synthetic.csv', index=False)

    # 1. CLASSIFICATION WORKFLOW
    print("\n--- Starting Classification Workflow ---")
    s_class = classification.setup(data, target='label', session_id=42, 
                                   ignore_features=['profile'], verbose=False)
    best_model = classification.compare_models(n_select=1, include=['rf', 'et', 'lightgbm'])
    final_classifier = classification.finalize_model(best_model)

    classification.plot_model(final_classifier, plot='feature', save=True)
    if os.path.exists('Feature Importance.png'):
        os.rename('Feature Importance.png', plot_path)

    classification.save_model(final_classifier, classification_model_path)
    print(f"Classification model saved to {classification_model_path}.pkl")

    # 2. CLUSTERING WORKFLOW
    print("\n--- Starting Clustering Workflow ---")
    phishing_data = data[data['label'] == 1].copy()
    phishing_features = phishing_data.drop(['label', 'profile'], axis=1)

    s_clust = clustering.setup(phishing_features, session_id=123, verbose=False)
    kmeans = clustering.create_model('kmeans', num_clusters=3)
    clustering.save_model(kmeans, clustering_model_path)
    print(f"Clustering model saved to {clustering_model_path}.pkl")

    # 3. AUTOMATED PROFILE LABELING
    print("\n--- Starting Automated Profile Labeling ---")
    try:
        # Ensure analyze_clusters.py is executable
        if os.name != 'nt': # For Linux/macOS
            subprocess.run(['chmod', '+x', 'analyze_clusters.py'], check=True)

        # Run the analysis script to generate the mapping
        subprocess.run(['python', 'analyze_clusters.py'], check=True)
        print("Profile mapping generated successfully.")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error running cluster analysis script: {e}")
        print("Please ensure 'analyze_clusters.py' is in the same directory.")

    print("\nTraining complete.")


if __name__ == "__main__":
    train()
