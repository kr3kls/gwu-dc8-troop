import pandas as pd
from pycaret.clustering import load_model, predict_model
import json
import os

def analyze_and_map_clusters():
    """
    Loads the trained clustering model and the dataset to automatically map
    cluster labels to human-readable threat actor profiles.
    """
    print("Loading assets for cluster analysis...")
    
    # Define paths
    model_path = 'models/threat_actor_profiler'
    data_path = 'data/phishing_synthetic.csv'
    output_path = 'models/profile_mapping.json'
    
    # Check if files exist
    if not os.path.exists(model_path + '.pkl') or not os.path.exists(data_path):
        print("Error: Model or data file not found. Run train_model.py first.")
        return

    # Load the clustering model and the full dataset
    model = load_model(model_path, verbose=False)
    data = pd.read_csv(data_path)

    # Filter for only the phishing data, which was used for clustering
    phishing_data = data[data['label'] == 1].copy()

    # Use the model to predict the cluster for each phishing data point
    predictions = predict_model(model, data=phishing_data)
    predictions['profile'] = phishing_data['profile'].values
    
    # Create a crosstab to see the distribution of true profiles in each predicted cluster
    # This is the core of the automated labeling logic
    crosstab = pd.crosstab(predictions['Cluster'], predictions['profile'])
    print("\nCluster Analysis Crosstab:")
    print(crosstab)

    # Determine the dominant profile for each cluster
    cluster_to_profile = crosstab.idxmax(axis="columns")
    
    # Static descriptions to be merged with the dynamic mapping
    profile_descriptions = {
        'state_sponsored': {
            'name': "State-Sponsored Actor",
            'icon': "🕵️",
            'description': "This profile matches the tactics of sophisticated state-sponsored actors. Their attacks are subtle, well-crafted, and designed for stealth and persistence. They often use valid SSL certificates to appear legitimate and employ deceptive prefixes or suffixes in domain names to mimic trusted brands. They actively avoid 'noisy' indicators like IP addresses in URLs."
        },
        'organized_crime': {
            'name': "Organized Cybercrime",
            'icon': "💸",
            'description': "This activity aligns with financially motivated cybercrime groups. Their methods are often high-volume and technically straightforward, prioritizing quantity over sophistication. They commonly use IP addresses directly in URLs, rely heavily on URL shortening services, and employ abnormal URL structures to evade simple filters."
        },
        'hacktivist': {
            'name': "Hacktivist",
            'icon': "📢",
            'description': "This threat profile is characteristic of hacktivists, who are motivated by political or social causes. Their attacks are often opportunistic and designed to spread a message. The key indicator for this profile is the presence of political keywords in the URL, and they may use a mix of other tactics, such as long URLs, to convey their message."
        }
    }

    # Create the final mapping
    final_mapping = {}
    for cluster_label, profile_id in cluster_to_profile.items():
        if profile_id in profile_descriptions:
            final_mapping[cluster_label] = profile_descriptions[profile_id]
        else:
            final_mapping[cluster_label] = {
                'name': profile_id.replace('_', ' ').title(),
                'icon': "❓",
                'description': "No description available."
            }
            
    print("\nGenerated Profile Mapping:")
    # Use json.dumps for logging
    print(json.dumps(final_mapping, indent=2))

    # Save the mapping to JSON file for Streamlit
    with open(output_path, 'w') as f:
        json.dump(final_mapping, f, indent=4)
        
    print(f"\nSuccessfully saved profile mapping to {output_path}")

if __name__ == "__main__":
    analyze_and_map_clusters()