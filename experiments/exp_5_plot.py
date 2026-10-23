import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import re
import argparse
import sys

class DataMatcher:
    def __init__(self, txt_file, csv_file='results_latest.csv'):
        self.txt_file = txt_file
        self.csv_file = csv_file
        self.matched_data = None

    def parse_txt_file(self):
        with open(self.txt_file, 'r') as f:
            lines = f.readlines()

        if not lines:
            raise ValueError(f"{self.txt_file} is empty.")

        header_match = re.search(r'\((.*?)\)', lines[0])
        if not header_match:
            raise ValueError("Could not find column headers in the first line of the text file.")
        
        headers = [h.strip() for h in header_match.group(1).split(',')]
        
        data = []
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            
            parts = [p.strip() for p in line.split(',')]
            row_dict = dict(zip(headers, parts[:len(headers)]))
            data.append(row_dict)

        df = pd.DataFrame(data)
        
        numeric_cols = ['WIDTH', 'NUM_KEYS_TO_PROVE', 'NUM_KEYS_TREE']
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')
                
        return df

    def load_and_match(self):
        df_txt = self.parse_txt_file()
        df_csv = pd.read_csv(self.csv_file)

        metrics = ['proof_size', 'proving_time', 'verification_time']
        for metric in metrics:
            if metric in df_csv.columns:
                df_csv[metric] = pd.to_numeric(df_csv[metric], errors='coerce')

        df_csv = df_csv.dropna(subset=['proof_size', 'verification_time', 'proving_time'])

        common_cols = list(set(df_txt.columns).intersection(set(df_csv.columns)))
        
        df_txt = df_txt.replace('none', '')
        for col in common_cols:
            df_csv[col] = df_csv[col].fillna('')

        print(f"Matching based on common columns: {common_cols}\n")

        matched_rows = []
        
        for index, txt_row in df_txt.iterrows():
            query_conditions = []
            for col in common_cols:
                val = txt_row[col]
                if pd.isna(val):
                    val = ''
                if isinstance(val, str):
                    query_conditions.append(f"`{col}` == '{val}'")
                else:
                    query_conditions.append(f"`{col}` == {val}")
            
            query_str = " and ".join(query_conditions)
            
            try:
                matches = df_csv.query(query_str)
                if not matches.empty:
                    base_row = matches.iloc[0].to_dict()
                    numeric_means = matches.select_dtypes(include=[np.number]).mean().to_dict()
                    base_row.update(numeric_means)
                    matched_rows.append(base_row)
            except Exception as e:
                pass

        self.matched_data = pd.DataFrame(matched_rows).drop_duplicates().reset_index(drop=True)
        return self.matched_data


class DataVisualizer:
    def __init__(self, data):
        self.df = data
        # Convert times from seconds to milliseconds for visualization
        if 'verification_time' in self.df.columns:
            self.df['verification_time_ms'] = self.df['verification_time'] * 1000
        if 'proving_time' in self.df.columns:
            self.df['proving_time_ms'] = self.df['proving_time'] * 1000

    def filter_canonical_config(self):
        """Filters the dataset to match the canonical configuration for the thesis signature experiment."""
        
        # 1. Filter to tree size 1024 and batch size 64
        filtered = self.df[
            (self.df['NUM_KEYS_TREE'] == 1024) & 
            (self.df['NUM_KEYS_TO_PROVE'] == 64)
        ].copy()

        # 2. Filter to the specific best-performing widths defined in the parameters
        target_configs = [
            {'PROVER_TYPE': 'merkle', 'WIDTH': 16},
            {'PROVER_TYPE': 'merkle_optimized', 'WIDTH': 16},
            {'PROVER_TYPE': 'zksnarkmerkle', 'WIDTH': 4},
            {'PROVER_TYPE': 'verkle', 'WIDTH': 256},
            {'PROVER_TYPE': 'verkle_optimized', 'WIDTH': 256},
            {'PROVER_TYPE': 'verkle_multiproof', 'WIDTH': 256}
        ]

        final_rows = []
        for config in target_configs:
            match = filtered[
                (filtered['PROVER_TYPE'] == config['PROVER_TYPE']) & 
                (filtered['WIDTH'] == config['WIDTH'])
            ]
            if not match.empty:
                # Take the first one in case there are duplicates
                final_rows.append(match.iloc[0])
            else:
                print(f"Warning: Canonical config not found for {config['PROVER_TYPE']} at width {config['WIDTH']}.")

        return pd.DataFrame(final_rows)

    def _get_pareto_frontier(self, df, x_col, y_col):
        """Calculates the Pareto frontier (minimizing both X and Y)."""
        # Sort by X ascending
        sorted_df = df.sort_values(by=x_col)
        pareto_front = []
        min_y = float('inf')
        
        for index, row in sorted_df.iterrows():
            if row[y_col] < min_y:
                pareto_front.append(row)
                min_y = row[y_col]
                
        return pd.DataFrame(pareto_front)

    def plot_verification_vs_size(self):
        """Plot 1: Proof Size vs Verification Time with Pareto Frontier."""
        canonical_df = self.filter_canonical_config()
        if canonical_df.empty:
            print("No data fits the canonical configuration. Cannot plot Plot 1.")
            return

        plt.figure(figsize=(10, 6))
        sns.set_theme(style="whitegrid")

        # Scatter plot for all canonical systems
        ax = sns.scatterplot(
            data=canonical_df, 
            x='proof_size', 
            y='verification_time_ms', 
            hue='PROVER_TYPE',
            s=150, # Marker size
            palette='tab10',
            edgecolor='black',
            linewidth=1
        )

        # Calculate and plot the Pareto frontier line
        pareto_df = self._get_pareto_frontier(canonical_df, 'proof_size', 'verification_time_ms')
        
        plt.plot(
            pareto_df['proof_size'], 
            pareto_df['verification_time_ms'], 
            color='red', 
            linestyle='--', 
            linewidth=2, 
            label='Pareto Frontier'
        )

        # Annotate the points for clarity
        for _, row in canonical_df.iterrows():
            plt.annotate(
                row['PROVER_TYPE'], 
                (row['proof_size'], row['verification_time_ms']),
                textcoords="offset points", 
                xytext=(0, 10), 
                ha='center',
                fontsize=9
            )

        plt.xscale('log')
        plt.yscale('log')
        plt.xlabel('Proof Size (bytes) - Lower is better', fontsize=12, fontweight='bold')
        plt.ylabel('Verification Time (ms) - Lower is better', fontsize=12, fontweight='bold')
        plt.title('Plot 1: Bandwidth vs. Verification Cost (Batch Size 64)', fontsize=14, fontweight='bold')
        
        # Merge legends
        handles, labels = ax.get_legend_handles_labels()
        plt.legend(handles, labels, title='System (Pareto & Provers)', bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout()
        plt.show()

    def plot_proving_vs_size(self):
        """Plot 2: Proving Time vs Proof Size."""
        canonical_df = self.filter_canonical_config()
        if canonical_df.empty:
            print("No data fits the canonical configuration. Cannot plot Plot 2.")
            return

        plt.figure(figsize=(10, 6))
        sns.set_theme(style="whitegrid")

        # Scatter plot for proving time vs proof size
        ax = sns.scatterplot(
            data=canonical_df, 
            x='proving_time_ms', 
            y='proof_size', 
            hue='PROVER_TYPE',
            s=150,
            palette='Set2',
            edgecolor='black',
            linewidth=1
        )

        # Annotate the points
        for _, row in canonical_df.iterrows():
            plt.annotate(
                row['PROVER_TYPE'], 
                (row['proving_time_ms'], row['proof_size']),
                textcoords="offset points", 
                xytext=(0, 10), 
                ha='center',
                fontsize=9
            )

        plt.xscale('log')
        plt.yscale('log')
        plt.xlabel('Proving Time (ms) - Offline Cost', fontsize=12, fontweight='bold')
        plt.ylabel('Proof Size (bytes) - Transmission Cost', fontsize=12, fontweight='bold')
        plt.title('Plot 2: Offline Cost vs. Transmission Cost (Batch Size 64)', fontsize=14, fontweight='bold')
        
        plt.legend(title='Prover Type', bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout()
        plt.show()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Thesis Pareto and Tradeoff plots.")
    parser.add_argument("txt_file", nargs='?', help="Path to the text file containing the runs config")
    parser.add_argument("--csv_file", default="results_latest.csv", help="Path to the primary results CSV file")
    
    args = parser.parse_args()
    
    if not args.txt_file:
        txt_path = input("Enter the text file name (e.g., runs.txt): ")
        csv_path = 'results_latest.csv'
    else:
        txt_path = args.txt_file
        csv_path = args.csv_file

    try:
        matcher = DataMatcher(txt_file=txt_path, csv_file=csv_path)
        matched_df = matcher.load_and_match()

        visualizer = DataVisualizer(matched_df)
        
        # Generate the two requested plots
        print("\nGenerating Plot 1: Pareto Frontier (Proof Size vs Verification Time)...")
        visualizer.plot_verification_vs_size()
        
        print("\nGenerating Plot 2: Proving Time vs Proof Size...")
        visualizer.plot_proving_vs_size()
        
    except Exception as e:
        print(f"An error occurred: {e}")