#!/usr/bin/env python3
import argparse
import json
import os
import pandas as pd
import sys
from pycaret.classification import load_model as load_clf_model, predict_model as predict_clf_model
from pycaret.clustering import load_model as load_clu_model, predict_model as predict_clu_model
from typing import Dict, Tuple


FEATURES = [
    'having_IP_Address', 'URL_Length', 'Shortining_Service',
    'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix',
    'having_Sub_Domain', 'SSLfinal_State', 'URL_of_Anchor', 'Links_in_tags',
    'SFH', 'Abnormal_URL', 'has_political_keyword'
]

# Representative test vectors (most-probable feature values from synthetic distributions)
SAMPLES: Dict[str, Tuple[Dict[str, int], int, str]] = {
    "benign": (
        {
            'having_IP_Address': -1, 'URL_Length': 0, 'Shortining_Service': -1,
            'having_At_Symbol': -1, 'double_slash_redirecting': -1, 'Prefix_Suffix': -1,
            'having_Sub_Domain': 0, 'SSLfinal_State': 1, 'URL_of_Anchor': 1,
            'Links_in_tags': 1, 'SFH': 1, 'Abnormal_URL': -1, 'has_political_keyword': -1
        },
        0,
        ""
    ),
    "state_sponsored": (
        {
            'having_IP_Address': -1, 'URL_Length': 0, 'Shortining_Service': -1,
            'having_At_Symbol': -1, 'double_slash_redirecting': -1, 'Prefix_Suffix': 1,
            'having_Sub_Domain': 1, 'SSLfinal_State': 1, 'URL_of_Anchor': -1,
            'Links_in_tags': -1, 'SFH': -1, 'Abnormal_URL': -1, 'has_political_keyword': -1
        },
        1,
        "State-Sponsored Actor"
    ),
    "organized_crime": (
        {
            'having_IP_Address': 1, 'URL_Length': 1, 'Shortining_Service': 1,
            'having_At_Symbol': 1, 'double_slash_redirecting': 1, 'Prefix_Suffix': 1,
            'having_Sub_Domain': -1, 'SSLfinal_State': -1, 'URL_of_Anchor': -1,
            'Links_in_tags': -1, 'SFH': -1, 'Abnormal_URL': 1, 'has_political_keyword': -1
        },
        1,
        "Organized Cybercrime"
    ),
    "hacktivist": (
        {
            'having_IP_Address': -1, 'URL_Length': 1, 'Shortining_Service': -1,
            'having_At_Symbol': 1, 'double_slash_redirecting': 1, 'Prefix_Suffix': -1,
            'having_Sub_Domain': 1, 'SSLfinal_State': -1, 'URL_of_Anchor': 0,
            'Links_in_tags': 0, 'SFH': -1, 'Abnormal_URL': 1, 'has_political_keyword': 1
        },
        1,
        "Hacktivist"
    ),
}

CLF_PATH = "models/phishing_url_detector"
CLU_PATH = "models/threat_actor_profiler"
MAPPING_PATH = "models/profile_mapping.json"


def ensure_assets():
    missing = []
    if not os.path.exists(CLF_PATH + ".pkl"):
        missing.append(CLF_PATH + ".pkl")
    if not os.path.exists(CLU_PATH + ".pkl"):
        missing.append(CLU_PATH + ".pkl")
    if not os.path.exists(MAPPING_PATH):
        missing.append(MAPPING_PATH)

    if missing:
        print("❌ Missing assets:")
        for m in missing:
            print("   -", m)
        print("\nRun `python train_model.py` first to generate models and mapping.")
        sys.exit(2)


def load_assets():
    clf = load_clf_model(CLF_PATH, verbose=False)
    clu = load_clu_model(CLU_PATH, verbose=False)
    with open(MAPPING_PATH, "r") as f:
        mapping = json.load(f)
    return clf, clu, mapping


def to_df(features_dict: Dict[str, int]) -> pd.DataFrame:
    # Enforce exact column order and presence
    for k in FEATURES:
        if k not in features_dict:
            raise ValueError(f"Feature '{k}' missing from sample.")
    return pd.DataFrame([features_dict], columns=FEATURES)


def run_case(name: str, x: Dict[str, int], expected_label: int, expected_profile_name: str,
             clf, clu, mapping, strict: bool) -> Dict[str, str]:
    df = to_df(x)

    # Classification
    pred = predict_clf_model(clf, data=df)
    pred_label = int(pred["prediction_label"].iloc[0])
    pred_score = float(pred["prediction_score"].iloc[0])

    result = {
        "case": name,
        "expected_label": str(expected_label),
        "pred_label": str(pred_label),
        "score": f"{pred_score:.4f}",
        "cluster": "",
        "profile": "",
        "pass": "✗"
    }

    # First check: benign vs malicious
    if pred_label == expected_label:
        result["pass"] = "✓"

    # If malicious, do clustering + mapping checks
    if pred_label == 1:
        clu_pred = predict_clu_model(clu, data=df)
        cluster = clu_pred["Cluster"].iloc[0]
        result["cluster"] = str(cluster)

        prof = mapping.get(str(cluster)) or mapping.get(cluster)
        if prof:
            result["profile"] = prof.get("name", "")
            if strict and expected_profile_name and result["profile"] == expected_profile_name:
                result["pass"] = "✓"
        else:
            result["profile"] = "(unmapped)"

    return result


def main():
    ap = argparse.ArgumentParser(description="Run deterministic tests against trained models.")
    ap.add_argument("--strict", action="store_true",
                    help="Fail if a malicious sample's attributed profile name doesn't match the expected one.")
    args = ap.parse_args()

    ensure_assets()
    clf, clu, mapping = load_assets()

    rows = []
    any_fail = False
    for name, (x, y, prof_name) in SAMPLES.items():
        row = run_case(name, x, y, prof_name, clf, clu, mapping, strict=args.strict)
        rows.append(row)
        if row["pass"] != "✓":
            any_fail = True

    # Print results table
    df = pd.DataFrame(rows, columns=["case", "expected_label", "pred_label", "score", "cluster", "profile", "pass"])
    print("\n=== Test Results ===")
    print(df.to_string(index=False))

    if any_fail:
        print("\n❌ One or more checks failed.")
        sys.exit(1)
    else:
        print("\n✅ All checks passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
