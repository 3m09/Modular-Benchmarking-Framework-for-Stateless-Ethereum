"""
Every figure and table of the paper from results/paper_results.csv.

    python experiments/paper_plots.py [results/paper_results.csv] [--out results/figures]

Only verified rows are used; points are the mean over repetitions, error bars
one standard deviation. Also writes summary.csv (all means/sds) and
summary_table.tex.
"""
import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

SCHEMES = [  # prover, label, colour (categorical slots 1-5), marker
    ("merkle", "MPT", "#2a78d6", "o"),
    ("merkle_optimized", "MPT (dedup.)", "#eb6834", "s"),
    ("verkle_eip6800", "Verkle (KZG)", "#1baf7a", "^"),
    ("zksnarkmerkle", "zk-SNARK (Groth16)", "#eda100", "D"),
    ("zkstarkmerkle", "zk-STARK (RISC Zero)", "#e87ba4", "v"),
]
LABEL = {p: l for p, l, _, _ in SCHEMES}
STYLE = {p: dict(color=c, marker=m) for p, _, c, m in SCHEMES}
SEQ = ["#a9c9f0", "#5c9ae6", "#2a78d6", "#174f94"]   # blue ramp, light -> dark (ordinal series)
METRICS = [("proof_size", "Proof size (bytes)"), ("proving_time", "Proving time (s)"),
           ("verification_time", "Verification time (s)")]

plt.rcParams.update({
    "font.family": "serif", "font.size": 7, "axes.titlesize": 7.5, "axes.labelsize": 7,
    "legend.fontsize": 6.2, "xtick.labelsize": 6.2, "ytick.labelsize": 6.2,
    "axes.edgecolor": "#8a8984", "axes.linewidth": 0.6, "axes.grid": True,
    "grid.color": "#e4e3df", "grid.linewidth": 0.5, "lines.linewidth": 1.4,
    "lines.markersize": 3.6, "errorbar.capsize": 1.5, "savefig.bbox": "tight",
    "savefig.pad_inches": 0.02, "pdf.fonttype": 42,
})


def load(path):
    df = pd.read_csv(path)
    bad = df[df["verified"].astype(str) != "True"]
    if len(bad):
        print(f"excluding {len(bad)} unverified/failed rows:")
        print(bad[["experiment", "prover", "width", "num_keys_tree", "num_keys_prove", "rep", "error"]].to_string())
    df = df[df["verified"].astype(str) == "True"].copy()
    keys = ["experiment", "tree_type", "hash_fn", "width", "num_keys_tree", "prover", "num_keys_prove"]
    agg = df.groupby(keys, dropna=False).agg(
        reps=("rep", "count"),
        **{f"{m}_{s}": (m, s) for m, _ in METRICS for s in ("mean", "std")},
    ).reset_index()
    return agg


def shared_legend(fig, ax):
    """One legend row above all panels, so no legend covers data."""
    handles, labels = ax.get_legend_handles_labels()
    fig.tight_layout(w_pad=1.2, rect=(0, 0, 1, 0.9))
    fig.legend(handles, labels, loc="upper center", ncol=len(labels), frameon=False,
               bbox_to_anchor=(0.5, 1.0), handlelength=2.2, columnspacing=1.6)


def errline(ax, sub, x, metric, label=None, **style):
    sub = sub.sort_values(x)
    ax.errorbar(sub[x], sub[f"{metric}_mean"], yerr=sub[f"{metric}_std"].fillna(0), label=label, **style)


def fig_batch(agg, out):
    d = agg[agg.experiment == "batch"]
    fig, axes = plt.subplots(1, 3, figsize=(7.0, 2.1))
    for ax, (metric, ylabel) in zip(axes, METRICS):
        for prover, label, _, _ in SCHEMES:
            sub = d[d.prover == prover]
            if len(sub):
                errline(ax, sub, "num_keys_prove", metric, label=label, **STYLE[prover])
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_xlabel("Accounts proven per batch")
        ax.set_ylabel(ylabel)
        ax.set_xticks([1, 4, 16, 64, 256], ["1", "4", "16", "64", "256"])
    shared_legend(fig, axes[0])
    fig.savefig(out / "fig_batch.pdf")
    plt.close(fig)


def fig_tree_size(agg, out):
    d = agg[(agg.experiment == "tree_size") & (agg.num_keys_prove == 16)]
    fig, axes = plt.subplots(1, 3, figsize=(7.0, 2.1))
    for ax, (metric, ylabel) in zip(axes, METRICS):
        for prover, label, _, _ in SCHEMES:
            sub = d[d.prover == prover]
            if len(sub):
                errline(ax, sub, "num_keys_tree", metric, label=label, **STYLE[prover])
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_xlabel("Accounts in tree")
        ax.set_ylabel(ylabel)
        ticks = sorted(d.num_keys_tree.unique())
        ax.set_xticks(ticks, [f"$2^{{{int(t).bit_length() - 1}}}$" for t in ticks])
    shared_legend(fig, axes[0])
    fig.savefig(out / "fig_tree_size.pdf")
    plt.close(fig)


def fig_width(agg, out):
    d = agg[agg.experiment == "width"]
    fig, axes = plt.subplots(2, 3, figsize=(7.0, 3.6), sharex="row")
    rows = [("merkle", "MPT"), ("verkle_eip6800", "Verkle (KZG)")]
    batches = sorted(d.num_keys_prove.unique())
    for r, (prover, name) in enumerate(rows):
        for c, (metric, ylabel) in enumerate(METRICS):
            ax = axes[r, c]
            for i, k in enumerate(batches):
                sub = d[(d.prover == prover) & (d.num_keys_prove == k)]
                if len(sub):
                    errline(ax, sub, "width", metric, label=f"{k} account{'s' if k > 1 else ''}",
                            color=SEQ[min(i + 1, len(SEQ) - 1)], marker=STYLE[prover]["marker"])
            ax.set_xscale("log", base=2)
            ax.set_yscale("log")
            widths = sorted(d[d.prover == prover].width.unique())
            ax.set_xticks(widths, [str(w) for w in widths])
            ax.set_xlabel(f"{name} width (branching factor)")
            ax.set_ylabel(ylabel)
        if axes[r, 2].get_legend_handles_labels()[0]:
            axes[r, 2].legend(loc="center left", frameon=False, title=name, title_fontsize=6.2,
                              bbox_to_anchor=(1.02, 0.5))
    fig.tight_layout(h_pad=1.0, w_pad=1.2)
    fig.savefig(out / "fig_width.pdf")
    plt.close(fig)


def pareto(points):
    """Indices of points not dominated in both coordinates (smaller is better)."""
    front = []
    for i, (x, y) in enumerate(points):
        if not any((x2 <= x and y2 <= y) and (x2 < x or y2 < y) for j, (x2, y2) in enumerate(points) if j != i):
            front.append(i)
    return front


def fig_pareto(agg, out, batch=64):
    d = agg[(agg.experiment == "batch") & (agg.num_keys_prove == batch)]
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.3))
    for ax, ymetric, ylabel in [(axes[0], "verification_time", "Verification time (s)"),
                               (axes[1], "proving_time", "Proving time (s)")]:
        pts, names = [], []
        for prover, label, _, _ in SCHEMES:
            sub = d[d.prover == prover]
            if not len(sub):
                continue
            x, y = sub.proof_size_mean.iloc[0], sub[f"{ymetric}_mean"].iloc[0]
            ax.errorbar([x], [y], xerr=[sub.proof_size_std.fillna(0).iloc[0]],
                        yerr=[sub[f"{ymetric}_std"].fillna(0).iloc[0]], linestyle="none",
                        markersize=5.5, label=label, markeredgecolor="#fcfcfb", markeredgewidth=0.8,
                        **STYLE[prover])
            ax.annotate(label, (x, y), xytext=(4, 3), textcoords="offset points", fontsize=5.8, color="#52514e")
            pts.append((x, y))
        front = sorted((pts[i] for i in pareto(pts)), key=lambda p: p[0])
        ax.plot([p[0] for p in front], [p[1] for p in front], linestyle="--", color="#8a8984",
                linewidth=0.8, zorder=0, label="Pareto frontier")
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel(f"Proof size for {batch} accounts (bytes)")
        ax.set_ylabel(ylabel)
        ax.margins(x=0.25, y=0.25)
    axes[0].legend(loc="lower left", frameon=False)
    fig.tight_layout(w_pad=1.5)
    fig.savefig(out / f"fig_pareto_{batch}.pdf")
    plt.close(fig)


def fmt_size(b):
    return f"{b:,.0f}\\,B" if b < 10_000 else f"{b / 1000:,.1f}\\,kB"


def fmt_time(s):
    if s < 1e-3:
        return f"{s * 1e6:.0f}\\,$\\mu$s"
    if s < 1:
        return f"{s * 1e3:.1f}\\,ms"
    return f"{s:.2f}\\,s" if s < 100 else f"{s:.0f}\\,s"


def summary_table(agg, out, batches=(1, 8, 128)):
    d = agg[agg.experiment == "batch"]
    lines = [r"\begin{tabular}{ll" + "r" * len(batches) + "}", r"\toprule",
             "Metric & Scheme & " + " & ".join(f"$k={k}$" for k in batches) + r" \\", r"\midrule"]
    for m, (metric, name) in enumerate([("proof_size", "Proof size"), ("proving_time", "Proving"),
                                        ("verification_time", "Verification")]):
        present = [s for s in SCHEMES if len(d[d.prover == s[0]])]
        for i, (prover, label, _, _) in enumerate(present):
            cells = []
            for k in batches:
                sub = d[(d.prover == prover) & (d.num_keys_prove == k)]
                if not len(sub):
                    cells.append("--")
                    continue
                v = sub[f"{metric}_mean"].iloc[0]
                cells.append(fmt_size(v) if metric == "proof_size" else fmt_time(v))
            head = rf"\multirow{{{len(present)}}}{{*}}{{{name}}}" if i == 0 else ""
            lines.append(f"{head} & {label} & " + " & ".join(cells) + r" \\")
        if m < 2:
            lines.append(r"\midrule")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (out / "summary_table.tex").write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", nargs="?", default="results/paper_results.csv")
    parser.add_argument("--out", default="results/figures")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    agg = load(args.csv)
    agg.to_csv(out / "summary.csv", index=False)
    fig_batch(agg, out)
    fig_tree_size(agg, out)
    fig_width(agg, out)
    for k in (8, 64):
        fig_pareto(agg, out, k)
    summary_table(agg, out)
    print("written to", out)


if __name__ == "__main__":
    main()
