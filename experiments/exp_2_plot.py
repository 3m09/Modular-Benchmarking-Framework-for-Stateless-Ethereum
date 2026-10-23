import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import re
import argparse

def load_and_match_data(txt_file, csv_file='results_latest.csv'):
    """Parses the text config, loads the CSV, and merges them on common columns."""
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
        # Skip separator lines like '-------------------'
        if line.startswith('-'):
            continue
        parts = [p.strip() for p in line.split(',')]
        data.append(dict(zip(headers, parts[:len(headers)])))

    # Robustly convert 'none' (case-insensitive) to empty string
    df_txt = pd.DataFrame(data).replace(to_replace=r'(?i)^\s*none\s*$', value='', regex=True)

    # Load CSV and skip corrupted rows (e.g. your row 137 error)
    df_csv = pd.read_csv(csv_file, on_bad_lines='skip')
    
    metrics = ['proof_size', 'proving_time', 'verification_time']
    for metric in metrics:
        if metric in df_csv.columns:
            df_csv[metric] = pd.to_numeric(df_csv[metric], errors='coerce')
    
    df_csv = df_csv.dropna(subset=['proof_size'])

    common_cols = list(set(df_txt.columns).intersection(set(df_csv.columns)))
    if not common_cols:
        raise ValueError("No common columns found between the text file and the CSV.")

    # Standardize types before merging
    numeric_configs = ['WIDTH', 'NUM_KEYS_TO_PROVE', 'NUM_KEYS_TREE']
    for col in common_cols:
        if col in numeric_configs:
            df_txt[col] = pd.to_numeric(df_txt[col], errors='coerce').fillna(-1)
            df_csv[col] = pd.to_numeric(df_csv[col], errors='coerce').fillna(-1)
        else:
            df_txt[col] = df_txt[col].fillna('').astype(str)
            df_csv[col] = df_csv[col].fillna('').astype(str)

    print(f"Matching datasets based on: {common_cols}")

    df_csv_agg = df_csv.groupby(common_cols, dropna=False, as_index=False).mean(numeric_only=True)
    matched_df = pd.merge(df_txt, df_csv_agg, on=common_cols, how='inner')
    
    if len(matched_df) < len(df_txt):
        print(f"Warning: Missing results for {len(df_txt) - len(matched_df)} run configurations.")
    
    output_file = "exp2_out.txt"

    with open(output_file, "w") as f:
        f.write(matched_df.to_string(index=False))

    print(f"Matched results written to {output_file}")

    return matched_df


def plot_proof_size_vs_width(df):
    """Plots the proof size vs. Tree Width in two separate windows for Merkle and Verkle."""
    if df is None or df.empty:
        print("No matched data available to plot.")
        return

    sns.set_theme(style="whitegrid")

    # --- Window 1: Merkle Family ---
    df_merkle = df[df['TREE_TYPE'] == 'merkle']
    if not df_merkle.empty:
        plt.figure(1, figsize=(8, 6)) # Figure 1
        
        # Find the best (minimum) proof size for each prover and width combination
        best_merkle_idx = df_merkle.groupby(['PROVER_TYPE', 'WIDTH'])['proof_size'].idxmin()
        best_merkle = df_merkle.loc[best_merkle_idx]

        for prover in sorted(best_merkle['PROVER_TYPE'].unique()):
            subset = best_merkle[best_merkle['PROVER_TYPE'] == prover].sort_values(by='WIDTH')
            subset = subset[subset['WIDTH'] > 0] # Filter fallbacks
            
            if not subset.empty:
                plt.plot(subset['WIDTH'], subset['proof_size'], label=prover, linewidth=2, marker='o')

        plt.yscale('log', base=10)
        
        valid_widths = best_merkle[best_merkle['WIDTH'] > 0]
        if not valid_widths.empty:
            x_ticks = sorted(valid_widths['WIDTH'].unique())
            plt.xticks(x_ticks, [int(x) for x in x_ticks])
        
        plt.xlabel('Tree Width', fontsize=12, fontweight='bold')
        plt.ylabel('Proof size (bytes)', fontsize=12, fontweight='bold')
        plt.title('Merkle Family: Proof Size vs. Tree Width', fontsize=14, fontweight='bold')
        plt.legend(title='Prover Type')
        plt.tight_layout()

    # --- Window 2: Verkle Family ---
    df_verkle = df[df['TREE_TYPE'] == 'verkle']
    if not df_verkle.empty:
        plt.figure(2, figsize=(8, 6)) # Figure 2
        
        # Find the best (minimum) proof size for each prover and width combination
        best_verkle_idx = df_verkle.groupby(['PROVER_TYPE', 'WIDTH'])['proof_size'].idxmin()
        best_verkle = df_verkle.loc[best_verkle_idx]

        for prover in sorted(best_verkle['PROVER_TYPE'].unique()):
            subset = best_verkle[best_verkle['PROVER_TYPE'] == prover].sort_values(by='WIDTH')
            subset = subset[subset['WIDTH'] > 0] # Filter fallbacks
            
            if not subset.empty:
                plt.plot(subset['WIDTH'], subset['proof_size'], label=prover, linewidth=2, marker='o')

        plt.yscale('log', base=10)
        
        valid_widths = best_verkle[best_verkle['WIDTH'] > 0]
        if not valid_widths.empty:
            x_ticks = sorted(valid_widths['WIDTH'].unique())
            plt.xticks(x_ticks, [int(x) for x in x_ticks])
        
        plt.xlabel('Tree Width', fontsize=12, fontweight='bold')
        plt.ylabel('Proof size (bytes)', fontsize=12, fontweight='bold')
        plt.title('Verkle Family: Proof Size vs. Tree Width', fontsize=14, fontweight='bold')
        plt.legend(title='Prover Type')
        plt.tight_layout()

    # Show both windows simultaneously
    if not df_merkle.empty or not df_verkle.empty:
        plt.show()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Match run configs and visualize proof size vs width.")
    parser.add_argument("txt_file", nargs='?', help="Path to the text file containing the runs config")
    parser.add_argument("--csv_file", default="results_latest.csv", help="Path to the results CSV file")
    
    args = parser.parse_args()
    
    txt_path = args.txt_file or input("Enter the text file name (e.g., runs.txt): ")
    csv_path = args.csv_file

    try:
        matched_data = load_and_match_data(txt_file=txt_path, csv_file=csv_path)
        plot_proof_size_vs_width(matched_data)
    except Exception as e:
        print(f"An error occurred: {e}")