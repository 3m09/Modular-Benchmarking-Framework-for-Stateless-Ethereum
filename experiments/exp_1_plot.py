import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import re
import argparse

def load_and_match_data(txt_file, csv_file='results_latest.csv'):
    """Parses the text config, loads the CSV, and merges them on common columns."""
    # 1. Parse the text file
    with open(txt_file, 'r') as f:
        lines = [line.strip() for line in f if line.strip()]

    if not lines:
        raise ValueError(f"{txt_file} is empty.")

    header_match = re.search(r'\((.*?)\)', lines[0])
    if not header_match:
        raise ValueError("Could not find column headers in the first line of the text file.")
    
    headers = [h.strip() for h in header_match.group(1).split(',')]
    
    data = []
    for line in lines[1:]:
        parts = [p.strip() for p in line.split(',')]
        data.append(dict(zip(headers, parts[:len(headers)])))

    # --- THE FIX: Robustly convert 'none' (case-insensitive) to empty string ---
    df_txt = pd.DataFrame(data).replace(to_replace=r'(?i)^\s*none\s*$', value='', regex=True)

    # 2. Load and clean the CSV file
    df_csv = pd.read_csv(csv_file)
    metrics = ['proof_size', 'proving_time', 'verification_time']
    for metric in metrics:
        if metric in df_csv.columns:
            df_csv[metric] = pd.to_numeric(df_csv[metric], errors='coerce')
    
    df_csv = df_csv.dropna(subset=['proof_size'])

    # 3. Match the datasets
    common_cols = list(set(df_txt.columns).intersection(set(df_csv.columns)))
    if not common_cols:
        raise ValueError("No common columns found between the text file and the CSV.")

    # Standardize types before merging to prevent int64/object mismatch errors
    numeric_configs = ['WIDTH', 'NUM_KEYS_TO_PROVE', 'NUM_KEYS_TREE']
    
    for col in common_cols:
        if col in numeric_configs:
            df_txt[col] = pd.to_numeric(df_txt[col], errors='coerce').fillna(-1)
            df_csv[col] = pd.to_numeric(df_csv[col], errors='coerce').fillna(-1)
        else:
            df_txt[col] = df_txt[col].fillna('').astype(str)
            df_csv[col] = df_csv[col].fillna('').astype(str)

    print(f"Matching datasets based on: {common_cols}")

    # Group the CSV by common parameters and average the numeric metrics
    df_csv_agg = df_csv.groupby(common_cols, dropna=False, as_index=False).mean(numeric_only=True)
    
    # Merge the required configurations (from txt) with the aggregated results (from csv)
    matched_df = pd.merge(df_txt, df_csv_agg, on=common_cols, how='inner')
    
    if len(matched_df) < len(df_txt):
        print(f"Warning: Missing results for {len(df_txt) - len(matched_df)} run configurations.")

    return matched_df


def plot_proof_size(df):
    """Plots the minimum proof size vs. keys to prove on a log-log scale."""
    if df is None or df.empty:
        print("No matched data available to plot.")
        return

    plt.figure(figsize=(10, 6))
    sns.set_theme(style="whitegrid")

    # Group by prover and key count, then find the index of the minimum proof size
    best_indices = df.groupby(['PROVER_TYPE', 'NUM_KEYS_TO_PROVE'])['proof_size'].idxmin()
    best_runs_df = df.loc[best_indices]

    unique_provers = sorted(best_runs_df['PROVER_TYPE'].unique())
    
    for prover in unique_provers:
        subset = best_runs_df[best_runs_df['PROVER_TYPE'] == prover].sort_values(by='NUM_KEYS_TO_PROVE')
        # Filter out the fallback -1 values
        subset = subset[subset['NUM_KEYS_TO_PROVE'] > 0] 
        if not subset.empty:
            plt.plot(subset['NUM_KEYS_TO_PROVE'], subset['proof_size'], label=prover, linewidth=2, marker='o')

    # Log-Log formatting
    plt.xscale('log', base=2)
    plt.yscale('log', base=10)
    
    x_ticks = sorted(best_runs_df[best_runs_df['NUM_KEYS_TO_PROVE'] > 0]['NUM_KEYS_TO_PROVE'].unique())
    plt.xticks(x_ticks, [int(x) for x in x_ticks])
    
    plt.xlabel('Number of keys to prove', fontsize=12, fontweight='bold')
    plt.ylabel('Proof size (bytes)', fontsize=12, fontweight='bold')
    plt.title(' Proof Size vs. Batch Size (Log-Log Scale)', fontsize=14, fontweight='bold')
    
    plt.legend(title='Prover Type')
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Match run configs and visualize proof sizes.")
    parser.add_argument("txt_file", nargs='?', help="Path to the text file containing the runs config")
    parser.add_argument("--csv_file", default="results_latest.csv", help="Path to the results CSV file")
    
    args = parser.parse_args()
    
    txt_path = args.txt_file or input("Enter the text file name (e.g., runs.txt): ")
    csv_path = args.csv_file

    try:
        matched_data = load_and_match_data(txt_file=txt_path, csv_file=csv_path)
        plot_proof_size(matched_data)
    except Exception as e:
        print(f"An error occurred: {e}")