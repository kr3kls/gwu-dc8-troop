import aiohttp
import argparse
import asyncio
import h2o
import math
import matplotlib.pyplot as plt
import numpy as np
import os
import pandas as pd
import shap
import sys
from dotenv import load_dotenv
from pathlib import Path

# Load variables from .env into environment
load_dotenv()

# Set Gemini variables
GEMINI_MODEL = "gemini-2.5-flash-preview-05-20"
GEMINI_URL_TMPL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


# Method to get entropy of URL
def _get_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    ln = float(len(s))
    return -sum((cnt / ln) * math.log(cnt / ln, 2) for cnt in counts.values())


# Method to find and load model
def _resolve_mojo() -> Path:
    models_dir = Path(__file__).parent / "models"
    zips = sorted(models_dir.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not zips:
        print(f"ERROR: No MOJO .zip found in {models_dir}", file=sys.stderr)
        sys.exit(2)
    return zips[0]


# Method to get probability from h2o dataframe
def _get_prob_column_for_class(preds_df, cls_name: str):
    cols = list(preds_df.columns)

    # Class name is a column name
    if cls_name in cols:
        return cls_name

    # Check for case issues
    lower_map = {c.lower(): c for c in cols}
    if cls_name.lower() in lower_map:
        return lower_map[cls_name.lower()]

    # Default to last probability column
    prob_cols = [c for c in cols if c != "predict"]
    return prob_cols[-1] if prob_cols else None


# Method to compute shap
def _compute_shap_for_instance(mojo_model, length_val: int, entropy_val: float, out_png: Path):
    """Returns (shap_values_row, expected_value). Also writes a force plot PNG."""
    train_csv = Path(__file__).parent / "dga_dataset_train.csv"
    if train_csv.exists():
        df = pd.read_csv(train_csv, usecols=["length", "entropy"])
        bg = df.sample(n=min(50, len(df)), random_state=1)
    else:
        bg = pd.DataFrame({
            "length": [length_val - 2, length_val - 1, length_val, length_val + 1, length_val + 2],
            "entropy": [entropy_val - 0.2, entropy_val - 0.1, entropy_val, entropy_val + 0.1, entropy_val + 0.2],
        })

    X_cols = ["length", "entropy"]
    X_instance = pd.DataFrame([{"length": length_val, "entropy": entropy_val}])

    def predict_wrapper(data):
        h2_df = h2o.H2OFrame(pd.DataFrame(data, columns=X_cols))
        pr = mojo_model.predict(h2_df).as_data_frame(use_multi_thread=True)
        col = _get_prob_column_for_class(pr, "dga") or pr.columns[-1]
        return pr[col].values

    explainer = shap.KernelExplainer(predict_wrapper, bg)
    shap_vals = explainer.shap_values(X_instance)       # (1, n_features)
    shap_row = np.array(shap_vals)[0]                   # (n_features,)
    expected = float(np.atleast_1d(explainer.expected_value)[0])

    shap.force_plot(expected, shap_row, X_instance.iloc[0, :], show=False, matplotlib=True)
    plt.tight_layout()
    plt.savefig(out_png, dpi=150)
    plt.close()

    return shap_row, expected


# Method to format strength of prediction
def _format_strength(abs_contrib: float, total_abs: float) -> str:
    if total_abs == 0:
        return "neutral"
    share = abs_contrib / total_abs
    if share >= 0.6:
        return "strongly"
    if share >= 0.3:
        return "moderately"
    return "slightly"


# Method to build explainable AI findings
def _build_xai_findings(domain: str,
                        label: str,
                        prob_dga: float,
                        feature_names: list[str],
                        feature_values: list[float],
                        shap_contribs: np.ndarray) -> str:
    label_lower = label.lower()
    confidence = prob_dga if label_lower == "dga" else (1.0 - prob_dga)
    confidence_pct = f"{confidence * 100:.1f}%"

    order = np.argsort(-np.abs(shap_contribs))
    total_abs = float(np.sum(np.abs(shap_contribs)))

    lines = []
    alert_line = "Potential DGA domain detected." if label_lower == "dga" else "Domain appears legitimate."
    lines.append(f"- Alert: {alert_line}")
    lines.append(f"- Domain: '{domain}'")
    lines.append(f"- AI Model Explanation (from SHAP): The model flagged this domain with {confidence_pct} confidence. The classification was primarily driven by:")

    for idx in order:
        fname = feature_names[idx]
        fval = feature_values[idx]
        contrib = shap_contribs[idx]
        direction = "towards 'dga'" if contrib > 0 else "towards 'legit'"
        strength = _format_strength(abs(contrib), total_abs)
        val_str = f"{fval:.4f}" if fname == "entropy" else f"{fval}"
        lines.append(f"  - A {fname!r} value of {val_str} ({strength} pushed the prediction {direction}).")

    return "\n".join(lines)


# Method to generate playbook with Gemini
async def generate_playbook_with_gemini(xai_findings: str) -> str:
    """
    Calls Gemini with xai_findings and returns a short numbered playbook.
    Reads API key from env var GEMINI_API_KEY.
    """
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return "Error: GEMINI_API_KEY is not set in the environment."

    prompt = (
        "As a SOC Manager, create a simple, step-by-step incident response playbook for a Tier 1 analyst. "
        "Use ONLY the information in the alert details and explanation below. "
        "Do NOT explain the AI model; provide prescriptive actions only. "
        "Return a numbered list of 3-4 concise steps.\n\n"
        f"Alert Details & AI Explanation:\n{xai_findings}"
    )

    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}]
            }
        ]
    }

    url = f"{GEMINI_URL_TMPL.format(model=GEMINI_MODEL)}?key={api_key}"
    headers = {"Content-Type": "application/json"}

    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload, headers=headers, timeout=60) as resp:
            if resp.status != 200:
                body = await resp.text()
                return f"Error: Gemini HTTP {resp.status}: {body}"
            result = await resp.json()
            try:
                text = result["candidates"][0]["content"]["parts"][0]["text"]
                return text.strip()
            except Exception:
                return "Error: Unexpected Gemini response: " + str(result)


# Main method
def main():
    parser = argparse.ArgumentParser(description="Analyze a domain, explain with SHAP, and generate a T1 playbook.")
    parser.add_argument("--domain", required=True, help="Domain to analyze (e.g., example.com)")
    args = parser.parse_args()

    domain = args.domain.strip()
    length_val = len(domain)
    entropy_val = _get_entropy(domain)

    h2o.init(max_mem_size="1G", nthreads=-1)
    h2o.no_progress()

    try:
        mojo_path = _resolve_mojo()
        mojo_model = h2o.import_mojo(str(mojo_path))

        frame = h2o.H2OFrame({"length": [length_val], "entropy": [entropy_val]})
        preds = mojo_model.predict(frame).as_data_frame(use_multi_thread=True)

        row = preds.iloc[0]
        label = str(row.get("predict"))
        prob_cols = [c for c in preds.columns if c != "predict"]
        dga_col = _get_prob_column_for_class(preds, "dga") or prob_cols[-1]
        prob_dga = float(row[dga_col])
        probs_str = ", ".join(f"{c}={float(row[c]):.4f}" for c in prob_cols)

        print(f"\nAnalyzing domain: {domain}")
        print(f"Features -> length={length_val}, entropy={entropy_val:.4f}")
        print(f"Prediction -> class={label} ({probs_str})\n")

        # Build XAI findings if dga
        xai_findings = None

        if label.lower() == "dga":
            out_png = Path(__file__).parent / f"explain_{domain.replace('.', '_')}_shap_force.png"
            shap_row, _expected = _compute_shap_for_instance(mojo_model, length_val, entropy_val, out_png)

            feature_names = ["length", "entropy"]
            feature_values = [length_val, entropy_val]

            xai_findings = _build_xai_findings(
                domain=domain,
                label=label,
                prob_dga=prob_dga,
                feature_names=feature_names,
                feature_values=feature_values,
                shap_contribs=shap_row,
            )

            # Save findings for audit or reuse
            out_txt = Path(__file__).parent / f"xai_findings_{domain.replace('.', '_')}.txt"
            out_txt.write_text(xai_findings, encoding="utf-8")
            print(xai_findings, "\n")
            print(f"XAI findings saved to: {out_txt}")
            print(f"SHAP force plot saved to: {out_png}\n")

            # GenAI step: generate the T1 playbook
            print("--- Requesting Prescriptive Incident Response Playbook (Gemini) ---")
            playbook = asyncio.run(generate_playbook_with_gemini(xai_findings))
            out_playbook = Path(__file__).parent / f"playbook_{domain.replace('.', '_')}.txt"
            out_playbook.write_text(playbook, encoding="utf-8")
            print(playbook, "\n")
            print(f"Playbook saved to: {out_playbook}\n")
        else:
            print("Prediction is 'legit', skipping GenAI playbook.\n")

    finally:
        h2o.cluster().shutdown(prompt=False)


if __name__ == "__main__":
    main()
