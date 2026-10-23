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
    
    # Drop row only if ALL three metrics are missing
    df_csv = df_csv.dropna(subset=['proof_size', 'proving_time', 'verification_time'], how='all')

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


def plot_metrics_vs_width(df):
    """Generates 6 plots (3 windows with 2 subplots each) separating Merkle and Verkle families."""
    if df is None or df.empty:
        print("No matched data available to plot.")
        return

    sns.set_theme(style="whitegrid")
    
    # Separate data by tree family
    df_merkle = df[df['TREE_TYPE'] == 'merkle']
    df_verkle = df[df['TREE_TYPE'] == 'verkle']

    def plot_family_subplot(ax, data, family_name, metric, y_label):
        """Helper function to plot a single subplot cleanly."""
        if data.empty:
            ax.set_title(f"{family_name}: No data")
            return
            
        unique_provers = sorted(data['PROVER_TYPE'].unique())
        valid_widths = data[data['WIDTH'] > 0]['WIDTH'].unique()
        x_ticks = sorted(valid_widths)

        for prover in unique_provers:
            subset = data[data['PROVER_TYPE'] == prover].groupby('WIDTH')[metric].mean().reset_index()
            subset = subset[subset['WIDTH'] > 0].sort_values(by='WIDTH').dropna()
            if not subset.empty:
                ax.plot(subset['WIDTH'], subset[metric], label=prover, linewidth=2, marker='o')

        ax.set_yscale('log', base=10)
        if len(x_ticks) > 0:
            ax.set_xticks(x_ticks)
            ax.set_xticklabels([int(x) for x in x_ticks])
            
        ax.set_xlabel('Tree Width', fontsize=12, fontweight='bold')
        ax.set_ylabel(y_label, fontsize=12, fontweight='bold')
        ax.set_title(f'{family_name}', fontsize=12, fontweight='bold')
        ax.legend(title='Prover Scheme')

    # ==========================================
    # Window 1: Proof Size vs Width
    # ==========================================
    fig1, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig1.suptitle('Proof Size vs. Tree Width', fontsize=16, fontweight='bold')
    plot_family_subplot(ax1, df_merkle, 'Merkle Family', 'proof_size', 'Proof Size (bytes)')
    plot_family_subplot(ax2, df_verkle, 'Verkle Family', 'proof_size', 'Proof Size (bytes)')
    fig1.tight_layout()

    # ==========================================
    # Window 2: Proving Time vs Width
    # ==========================================
    fig2, (ax3, ax4) = plt.subplots(1, 2, figsize=(14, 6))
    fig2.suptitle('Proving Time vs. Tree Width', fontsize=16, fontweight='bold')
    plot_family_subplot(ax3, df_merkle, 'Merkle Family', 'proving_time', 'Proving Time')
    plot_family_subplot(ax4, df_verkle, 'Verkle Family', 'proving_time', 'Proving Time')
    fig2.tight_layout()

    # ==========================================
    # Window 3: Verification Time vs Width
    # ==========================================
    fig3, (ax5, ax6) = plt.subplots(1, 2, figsize=(14, 6))
    fig3.suptitle('Verification Time vs. Tree Width', fontsize=16, fontweight='bold')
    plot_family_subplot(ax5, df_merkle, 'Merkle Family', 'verification_time', 'Verification Time')
    plot_family_subplot(ax6, df_verkle, 'Verkle Family', 'verification_time', 'Verification Time')
    fig3.tight_layout()

    # Display all 3 windows (6 plots total)
    plt.show()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Visualize metrics vs tree width.")
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
        plot_metrics_vs_width(matched_data)
    except Exception as e:
        print(f"An error occurred: {e}")