import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import re
import argparse

def load_and_match_data(txt_file, csv_file='results_latest.csv', strategy='average'):
    """Parses the text config, loads the CSV, and merges them using the chosen duplicate strategy."""
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

    # Load CSV and skip corrupted rows
    df_csv = pd.read_csv(csv_file, on_bad_lines='skip')
    
    metrics = ['proof_size', 'proving_time', 'verification_time']
    for metric in metrics:
        if metric in df_csv.columns:
            df_csv[metric] = pd.to_numeric(df_csv[metric], errors='coerce')
    
    # Target verification_time for this specific experiment
    df_csv = df_csv.dropna(subset=['verification_time'])

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
    print(f"Handling duplicate runs using strategy: '{strategy}'")

    # --- DUPLICATE HANDLING LOGIC ---
    if strategy in ['earliest', 'latest']:
        if 'datetime' not in df_csv.columns:
            print("Warning: 'datetime' column not found in CSV. Falling back to 'average' strategy.")
            df_csv_agg = df_csv.groupby(common_cols, dropna=False, as_index=False).mean(numeric_only=True)
        else:
            df_csv['datetime'] = pd.to_datetime(df_csv['datetime'], errors='coerce')
            df_csv_sorted = df_csv.sort_values('datetime', na_position='first')
            keep_rule = 'first' if strategy == 'earliest' else 'last'
            df_csv_agg = df_csv_sorted.drop_duplicates(subset=common_cols, keep=keep_rule)
    else:
        df_csv_agg = df_csv.groupby(common_cols, dropna=False, as_index=False).mean(numeric_only=True)

    matched_df = pd.merge(df_txt, df_csv_agg, on=common_cols, how='inner')
    
    if len(matched_df) < len(df_txt):
        print(f"Warning: Missing results for {len(df_txt) - len(matched_df)} run configurations.")

    return matched_df


def plot_verification_time(df):
    """Plots Verification Time vs Number of Keys to Prove in a single plot for all provers."""
    if df is None or df.empty:
        print("No matched data available to plot.")
        return

    plt.figure(figsize=(10, 6))
    sns.set_theme(style="whitegrid")

    unique_provers = sorted(df['PROVER_TYPE'].unique())

    for prover in unique_provers:
        # Group by NUM_KEYS_TO_PROVE to ensure a clean curve along the X-axis
        subset = df[df['PROVER_TYPE'] == prover].groupby('NUM_KEYS_TO_PROVE')['verification_time'].mean().reset_index()
        subset = subset[subset['NUM_KEYS_TO_PROVE'] > 0].sort_values(by='NUM_KEYS_TO_PROVE')
        
        if not subset.empty:
            plt.plot(subset['NUM_KEYS_TO_PROVE'], subset['verification_time'], label=prover, linewidth=2, marker='o')

    # Log-Log formatting
    plt.xscale('log', base=2)
    plt.yscale('log', base=10)
    
    plt.xlabel('Number of keys to prove', fontsize=12, fontweight='bold')
    plt.ylabel('Verification Time', fontsize=12, fontweight='bold')
    plt.title('Verification Time vs. Number of Keys to Prove', fontsize=14, fontweight='bold')
    
    plt.legend(title='Prover Scheme', bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Match run configs and visualize verification times.")
    parser.add_argument("txt_file", nargs='?', help="Path to the text file containing the runs config")
    parser.add_argument("--csv_file", default="results_latest.csv", help="Path to the results CSV file")
    
    parser.add_argument(
        "--strategy", 
        choices=['average', 'earliest', 'latest'], 
        default='average', 
        help="How to handle multiple matching results for the same config. Default is 'average'."
    )
    
    args = parser.parse_args()
    
    txt_path = args.txt_file or input("Enter the text file name (e.g., runs.txt): ")

    try:
        matched_data = load_and_match_data(txt_file=txt_path, csv_file=args.csv_file, strategy=args.strategy)
        plot_verification_time(matched_data)
    except Exception as e:
        print(f"An error occurred: {e}")