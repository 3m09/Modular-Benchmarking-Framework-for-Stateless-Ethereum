# import pandas as pd
# import matplotlib.pyplot as plt
# import seaborn as sns
# import re
# import argparse

# def load_and_match_data(txt_file, csv_file='results_latest.csv'):
#     """Parses the text config, loads the CSV, and merges them on common columns."""
#     with open(txt_file, 'r') as f:
#         lines = [line.strip() for line in f if line.strip()]

#     if not lines:
#         raise ValueError(f"{txt_file} is empty.")

#     header_match = re.search(r'\((.*?)\)', lines[0])
#     if not header_match:
#         raise ValueError("Could not find column headers in the first line of the text file.")
    
#     headers = [h.strip() for h in header_match.group(1).split(',')]
    
#     data = []
#     for line in lines[1:]:
#         if line.startswith('-'):
#             continue
#         parts = [p.strip() for p in line.split(',')]
#         data.append(dict(zip(headers, parts[:len(headers)])))

#     # Robustly convert 'none' (case-insensitive) to empty string
#     df_txt = pd.DataFrame(data).replace(to_replace=r'(?i)^\s*none\s*$', value='', regex=True)

#     # Load CSV and skip corrupted rows
#     df_csv = pd.read_csv(csv_file, on_bad_lines='skip')
    
#     metrics = ['proof_size', 'proving_time', 'verification_time']
#     for metric in metrics:
#         if metric in df_csv.columns:
#             df_csv[metric] = pd.to_numeric(df_csv[metric], errors='coerce')
    
#     df_csv = df_csv.dropna(subset=['proving_time'])

#     common_cols = list(set(df_txt.columns).intersection(set(df_csv.columns)))
#     if not common_cols:
#         raise ValueError("No common columns found between the text file and the CSV.")

#     # Standardize types before merging
#     numeric_configs = ['WIDTH', 'NUM_KEYS_TO_PROVE', 'NUM_KEYS_TREE']
#     for col in common_cols:
#         if col in numeric_configs:
#             df_txt[col] = pd.to_numeric(df_txt[col], errors='coerce').fillna(-1)
#             df_csv[col] = pd.to_numeric(df_csv[col], errors='coerce').fillna(-1)
#         else:
#             df_txt[col] = df_txt[col].fillna('').astype(str)
#             df_csv[col] = df_csv[col].fillna('').astype(str)

#     print(f"Matching datasets based on: {common_cols}")

#     # Group by common parameters and average all numeric metrics (handles duplicate tuples)
#     df_csv_agg = df_csv.groupby(common_cols, dropna=False, as_index=False).mean(numeric_only=True)
#     matched_df = pd.merge(df_txt, df_csv_agg, on=common_cols, how='inner')
    
#     if len(matched_df) < len(df_txt):
#         print(f"Warning: Missing results for {len(df_txt) - len(matched_df)} run configurations.")

#     return matched_df


# def plot_all_experiments(df):
#     """Generates all three requested plots."""
#     if df is None or df.empty:
#         print("No matched data available to plot.")
#         return

#     sns.set_theme(style="whitegrid")

#     # ==========================================
#     # PLOT 1: Baseline Comparison (Specific Widths)
#     # ==========================================
#     plt.figure(1, figsize=(10, 6))
    
#     mask_p1 = (
#         ((df['PROVER_TYPE'] == 'merkle') & (df['WIDTH'] == 16)) |
#         ((df['PROVER_TYPE'] == 'merkle_optimized') & (df['WIDTH'] == 16)) |
#         ((df['PROVER_TYPE'] == 'verkle') & (df['WIDTH'] == 256)) |
#         ((df['PROVER_TYPE'] == 'verkle_multiproof') & (df['WIDTH'] == 256)) |
#         ((df['PROVER_TYPE'] == 'zksnarkmerkle') & (df['WIDTH'] == 4)) |
#         ((df['PROVER_TYPE'] == 'zkstarkmerkle') & (df['WIDTH'] == 16))
#     )
#     df_p1 = df[mask_p1]

#     for prover in sorted(df_p1['PROVER_TYPE'].unique()):
#         # Average across any remaining variables (like NUM_KEYS_TO_PROVE)
#         subset = df_p1[df_p1['PROVER_TYPE'] == prover].groupby('NUM_KEYS_TREE')['proving_time'].mean().reset_index()
#         subset = subset[subset['NUM_KEYS_TREE'] > 0].sort_values(by='NUM_KEYS_TREE')
#         if not subset.empty:
#             plt.plot(subset['NUM_KEYS_TREE'], subset['proving_time'], label=prover, linewidth=2, marker='o')

#     plt.xscale('log', base=2)
#     plt.yscale('log', base=10)
#     plt.xlabel('Number of keys in tree', fontsize=12, fontweight='bold')
#     plt.ylabel('Proving Time', fontsize=12, fontweight='bold')
#     plt.title('Plot 1: Proving Time vs Number of Keys (Fixed Widths)', fontsize=14, fontweight='bold')
#     plt.legend(title='Prover Type')
#     plt.tight_layout()


#     # ==========================================
#     # PLOT 2: Merkle vs Verkle Families (Varying Widths)
#     # ==========================================
#     fig2, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
#     fig2.suptitle('Plot 2: Family Proving Time by Width', fontsize=16, fontweight='bold')

#     # Subplot 2A: Merkle Family (No ZK)
#     df_merkle = df[(df['TREE_TYPE'] == 'merkle') & (~df['PROVER_TYPE'].str.contains('zk'))]
#     for (prover, width), grp in df_merkle.groupby(['PROVER_TYPE', 'WIDTH']):
#         subset = grp.groupby('NUM_KEYS_TREE')['proving_time'].mean().reset_index()
#         subset = subset[subset['NUM_KEYS_TREE'] > 0].sort_values(by='NUM_KEYS_TREE')
#         if not subset.empty:
#             ax1.plot(subset['NUM_KEYS_TREE'], subset['proving_time'], label=f"{prover} (W={width})", marker='o')
            
#     ax1.set_xscale('log', base=2)
#     ax1.set_yscale('log', base=10)
#     ax1.set_title('Merkle Family', fontsize=12, fontweight='bold')
#     ax1.set_xlabel('Number of keys in tree')
#     ax1.set_ylabel('Proving Time')
#     ax1.legend()

#     # Subplot 2B: Verkle Family
#     df_verkle = df[df['TREE_TYPE'] == 'verkle']
#     for (prover, width), grp in df_verkle.groupby(['PROVER_TYPE', 'WIDTH']):
#         subset = grp.groupby('NUM_KEYS_TREE')['proving_time'].mean().reset_index()
#         subset = subset[subset['NUM_KEYS_TREE'] > 0].sort_values(by='NUM_KEYS_TREE')
#         if not subset.empty:
#             ax2.plot(subset['NUM_KEYS_TREE'], subset['proving_time'], label=f"{prover} (W={width})", marker='o')
            
#     ax2.set_xscale('log', base=2)
#     ax2.set_yscale('log', base=10)
#     ax2.set_title('Verkle Family', fontsize=12, fontweight='bold')
#     ax2.set_xlabel('Number of keys in tree')
#     ax2.legend()
#     fig2.tight_layout()


#     # ==========================================
#     # PLOT 3: ZK Family (Varying Widths)
#     # ==========================================
#     fig3, (ax3, ax4) = plt.subplots(1, 2, figsize=(14, 6))
#     fig3.suptitle('Plot 3: Zero Knowledge Proving Time by Width', fontsize=16, fontweight='bold')

#     # Subplot 3A: zk-SNARK Merkle
#     df_zksnark = df[df['PROVER_TYPE'] == 'zksnarkmerkle']
#     for width, grp in df_zksnark.groupby('WIDTH'):
#         subset = grp.groupby('NUM_KEYS_TREE')['proving_time'].mean().reset_index()
#         subset = subset[subset['NUM_KEYS_TREE'] > 0].sort_values(by='NUM_KEYS_TREE')
#         if not subset.empty:
#             ax3.plot(subset['NUM_KEYS_TREE'], subset['proving_time'], label=f"W={width}", marker='o')
            
#     ax3.set_xscale('log', base=2)
#     ax3.set_yscale('log', base=10)
#     ax3.set_title('zk-SNARK Merkle', fontsize=12, fontweight='bold')
#     ax3.set_xlabel('Number of keys in tree')
#     ax3.set_ylabel('Proving Time')
#     ax3.legend(title='Width')

#     # Subplot 3B: zk-STARK Merkle
#     df_zkstark = df[df['PROVER_TYPE'] == 'zkstarkmerkle']
#     for width, grp in df_zkstark.groupby('WIDTH'):
#         subset = grp.groupby('NUM_KEYS_TREE')['proving_time'].mean().reset_index()
#         subset = subset[subset['NUM_KEYS_TREE'] > 0].sort_values(by='NUM_KEYS_TREE')
#         if not subset.empty:
#             ax4.plot(subset['NUM_KEYS_TREE'], subset['proving_time'], label=f"W={width}", marker='o')
            
#     ax4.set_xscale('log', base=2)
#     ax4.set_yscale('log', base=10)
#     ax4.set_title('zk-STARK Merkle', fontsize=12, fontweight='bold')
#     ax4.set_xlabel('Number of keys in tree')
#     ax4.legend(title='Width')
#     fig3.tight_layout()

#     # Display all 3 windows at once
#     plt.show()


# if __name__ == "__main__":
#     parser = argparse.ArgumentParser(description="Match run configs and visualize proving times.")
#     parser.add_argument("txt_file", nargs='?', help="Path to the text file containing the runs config")
#     parser.add_argument("--csv_file", default="results_latest.csv", help="Path to the results CSV file")
    
#     args = parser.parse_args()
    
#     txt_path = args.txt_file or input("Enter the text file name (e.g., runs.txt): ")
#     csv_path = args.csv_file

#     try:
#         matched_data = load_and_match_data(txt_file=txt_path, csv_file=csv_path)
#         plot_all_experiments(matched_data)
#     except Exception as e:
#         print(f"An error occurred: {e}")

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
    
    df_csv = df_csv.dropna(subset=['proving_time'])

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
            # Convert to proper datetime objects for accurate sorting
            df_csv['datetime'] = pd.to_datetime(df_csv['datetime'], errors='coerce')
            
            # Sort by datetime, then drop duplicates keeping either the first or last
            df_csv_sorted = df_csv.sort_values('datetime', na_position='first')
            keep_rule = 'first' if strategy == 'earliest' else 'last'
            df_csv_agg = df_csv_sorted.drop_duplicates(subset=common_cols, keep=keep_rule)
    else:
        # Default average strategy
        df_csv_agg = df_csv.groupby(common_cols, dropna=False, as_index=False).mean(numeric_only=True)

    # Merge the text configurations with the aggregated/filtered CSV data
    matched_df = pd.merge(df_txt, df_csv_agg, on=common_cols, how='inner')
    
    if len(matched_df) < len(df_txt):
        print(f"Warning: Missing results for {len(df_txt) - len(matched_df)} run configurations.")

    return matched_df


def plot_all_experiments(df):
    """Generates all three requested plots."""
    if df is None or df.empty:
        print("No matched data available to plot.")
        return

    sns.set_theme(style="whitegrid")

    # ==========================================
    # PLOT 1: Baseline Comparison (Specific Widths)
    # ==========================================
    plt.figure(1, figsize=(10, 6))
    
    mask_p1 = (
        ((df['PROVER_TYPE'] == 'merkle') & (df['WIDTH'] == 16)) |
        ((df['PROVER_TYPE'] == 'merkle_optimized') & (df['WIDTH'] == 16)) |
        ((df['PROVER_TYPE'] == 'verkle') & (df['WIDTH'] == 256)) |
        ((df['PROVER_TYPE'] == 'verkle_multiproof') & (df['WIDTH'] == 256)) |
        ((df['PROVER_TYPE'] == 'zksnarkmerkle') & (df['WIDTH'] == 4)) |
        ((df['PROVER_TYPE'] == 'zkstarkmerkle') & (df['WIDTH'] == 16))
    )
    df_p1 = df[mask_p1]

    for prover in sorted(df_p1['PROVER_TYPE'].unique()):
        # Group to handle any remaining minor variations (like keys to prove) safely
        subset = df_p1[df_p1['PROVER_TYPE'] == prover].groupby('NUM_KEYS_TREE')['proving_time'].mean().reset_index()
        subset = subset[subset['NUM_KEYS_TREE'] > 0].sort_values(by='NUM_KEYS_TREE')
        if not subset.empty:
            plt.plot(subset['NUM_KEYS_TREE'], subset['proving_time'], label=prover, linewidth=2, marker='o')

    plt.xscale('log', base=2)
    plt.yscale('log', base=10)
    plt.xlabel('Number of keys in tree', fontsize=12, fontweight='bold')
    plt.ylabel('Proving Time', fontsize=12, fontweight='bold')
    plt.title('Plot 1: Proving Time vs Number of Keys (Fixed Widths)', fontsize=14, fontweight='bold')
    plt.legend(title='Prover Type')
    plt.tight_layout()

    # ==========================================
    # PLOT 2: Merkle vs Verkle Families (Varying Widths)
    # ==========================================
    fig2, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig2.suptitle('Plot 2: Family Proving Time by Width', fontsize=16, fontweight='bold')

    # Subplot 2A: Merkle Family (No ZK)
    df_merkle = df[(df['TREE_TYPE'] == 'merkle') & (~df['PROVER_TYPE'].str.contains('zk'))]
    for (prover, width), grp in df_merkle.groupby(['PROVER_TYPE', 'WIDTH']):
        subset = grp.groupby('NUM_KEYS_TREE')['proving_time'].mean().reset_index()
        subset = subset[subset['NUM_KEYS_TREE'] > 0].sort_values(by='NUM_KEYS_TREE')
        if not subset.empty:
            ax1.plot(subset['NUM_KEYS_TREE'], subset['proving_time'], label=f"{prover} (W={width})", marker='o')
            
    ax1.set_xscale('log', base=2)
    ax1.set_yscale('log', base=10)
    ax1.set_title('Merkle Family', fontsize=12, fontweight='bold')
    ax1.set_xlabel('Number of keys in tree')
    ax1.set_ylabel('Proving Time')
    ax1.legend()

    # Subplot 2B: Verkle Family
    df_verkle = df[df['TREE_TYPE'] == 'verkle']
    for (prover, width), grp in df_verkle.groupby(['PROVER_TYPE', 'WIDTH']):
        subset = grp.groupby('NUM_KEYS_TREE')['proving_time'].mean().reset_index()
        subset = subset[subset['NUM_KEYS_TREE'] > 0].sort_values(by='NUM_KEYS_TREE')
        if not subset.empty:
            ax2.plot(subset['NUM_KEYS_TREE'], subset['proving_time'], label=f"{prover} (W={width})", marker='o')
            
    ax2.set_xscale('log', base=2)
    ax2.set_yscale('log', base=10)
    ax2.set_title('Verkle Family', fontsize=12, fontweight='bold')
    ax2.set_xlabel('Number of keys in tree')
    ax2.legend()
    fig2.tight_layout()

    # ==========================================
    # PLOT 3: ZK Family (Varying Widths)
    # ==========================================
    fig3, (ax3, ax4) = plt.subplots(1, 2, figsize=(14, 6))
    fig3.suptitle('Plot 3: Zero Knowledge Proving Time by Width', fontsize=16, fontweight='bold')

    # Subplot 3A: zk-SNARK Merkle
    df_zksnark = df[df['PROVER_TYPE'] == 'zksnarkmerkle']
    for width, grp in df_zksnark.groupby('WIDTH'):
        subset = grp.groupby('NUM_KEYS_TREE')['proving_time'].mean().reset_index()
        subset = subset[subset['NUM_KEYS_TREE'] > 0].sort_values(by='NUM_KEYS_TREE')
        if not subset.empty:
            ax3.plot(subset['NUM_KEYS_TREE'], subset['proving_time'], label=f"W={width}", marker='o')
            
    ax3.set_xscale('log', base=2)
    ax3.set_yscale('log', base=10)
    ax3.set_title('zk-SNARK Merkle', fontsize=12, fontweight='bold')
    ax3.set_xlabel('Number of keys in tree')
    ax3.set_ylabel('Proving Time')
    ax3.legend(title='Width')

    # Subplot 3B: zk-STARK Merkle
    df_zkstark = df[df['PROVER_TYPE'] == 'zkstarkmerkle']
    for width, grp in df_zkstark.groupby('WIDTH'):
        subset = grp.groupby('NUM_KEYS_TREE')['proving_time'].mean().reset_index()
        subset = subset[subset['NUM_KEYS_TREE'] > 0].sort_values(by='NUM_KEYS_TREE')
        if not subset.empty:
            ax4.plot(subset['NUM_KEYS_TREE'], subset['proving_time'], label=f"W={width}", marker='o')
            
    ax4.set_xscale('log', base=2)
    ax4.set_yscale('log', base=10)
    ax4.set_title('zk-STARK Merkle', fontsize=12, fontweight='bold')
    ax4.set_xlabel('Number of keys in tree')
    ax4.legend(title='Width')
    fig3.tight_layout()

    # Display all 3 windows at once
    plt.show()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Match run configs and visualize proving times.")
    parser.add_argument("txt_file", nargs='?', help="Path to the text file containing the runs config")
    parser.add_argument("--csv_file", default="results_latest.csv", help="Path to the results CSV file")
    
    # --- NEW STRATEGY ARGUMENT ---
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
        plot_all_experiments(matched_data)
    except Exception as e:
        print(f"An error occurred: {e}")