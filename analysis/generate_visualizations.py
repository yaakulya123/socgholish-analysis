#!/usr/bin/env python3
"""
Visualization Generator for SocGholish Analysis Results
Generates publication-quality graphs and charts for the journal paper.
"""

import json
import sys
import os

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
from collections import Counter

# Publication-quality settings
plt.rcParams.update({
    'font.size': 11,
    'font.family': 'serif',
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.1,
})


def load_results(results_file):
    """Load analysis results from JSON."""
    with open(results_file, 'r') as f:
        return json.load(f)


def plot_file_type_distribution(results, output_dir):
    """Fig 1: Sample Distribution by File Type with summary metrics."""
    import statistics

    valid = [r for r in results if 'error' not in r]
    types = Counter(r.get('file_type', 'unknown') for r in valid)

    labels = list(types.keys())
    counts = list(types.values())

    sorted_pairs = sorted(zip(labels, counts), key=lambda x: -x[1])
    labels, counts = zip(*sorted_pairs)

    label_map = {
        'javascript': 'JavaScript',
        'html_document': 'HTML',
        'powershell': 'PowerShell',
        'PE_executable': 'PE Executable',
        'unknown': 'Other',
    }
    clean_labels = [label_map.get(l, l) for l in labels]

    colors = ['#2E5090', '#C44D2B', '#1A7A6D', '#6C4BA0', '#607D8B']

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5.5),
                                    gridspec_kw={'width_ratios': [1.3, 1]})

    # Left panel: bar chart
    bars = ax1.bar(clean_labels, counts, color=colors[:len(clean_labels)],
                   edgecolor='black', linewidth=0.5, width=0.6)

    for bar, count in zip(bars, counts):
        ax1.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 1.5,
                 str(count), ha='center', va='bottom', fontweight='bold', fontsize=12)

    ax1.set_xlabel('File Type', fontsize=12)
    ax1.set_ylabel('Sample Count', fontsize=12)
    ax1.set_title('Sample Distribution by File Type', fontsize=13, fontweight='bold')
    ax1.set_ylim(0, max(counts) * 1.15)
    ax1.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax1.grid(axis='y', alpha=0.3)
    ax1.set_axisbelow(True)

    # Right panel: summary metrics table
    ax2.axis('off')

    # Compute metrics
    all_ent = [r['entropy'] for r in valid]
    js = [r for r in valid if r.get('file_type') == 'javascript']
    pe = [r for r in valid if r.get('file_type') == 'PE_executable']
    js_ent = [r['entropy'] for r in js]
    pe_ent = [r['entropy'] for r in pe]
    all_conf = [r.get('confidence_score', 0) for r in valid]
    all_obf = [r.get('obfuscation_indicators_count', 0) for r in valid]
    sus_mal = sum(1 for r in valid if r.get('classification') in ('suspicious', 'malicious'))

    rows = [
        ['Total Samples', '160'],
        ['Date Range', 'Jun 2021 -- Mar 2026'],
        ['Mean Entropy (all)', f'{statistics.mean(all_ent):.3f}'],
        ['Mean Entropy (JS)', f'{statistics.mean(js_ent):.2f} \u00b1 {statistics.stdev(js_ent):.2f}'],
        ['Mean Entropy (PE)', f'{statistics.mean(pe_ent):.2f} \u00b1 {statistics.stdev(pe_ent):.2f}'],
        ['Mean Obfuscation', f'{statistics.mean(all_obf):.2f}'],
        ['Mean Confidence', f'{statistics.mean(all_conf):.3f}'],
        ['Detection Rate', f'{100*sus_mal/len(valid):.1f}%'],
        ['Unique SHA-256', f'{len(set(r["sha256"] for r in valid))}'],
    ]

    # Title right above the table
    ax2.text(0.47, 0.95, 'Dataset Summary Metrics', ha='center', va='top',
             fontsize=13, fontweight='bold', transform=ax2.transAxes)

    table = ax2.table(cellText=rows, colLabels=['Metric', 'Value'],
                      cellLoc='left', loc='upper center',
                      colWidths=[0.55, 0.4],
                      bbox=[0.0, 0.02, 0.95, 0.88])
    table.auto_set_font_size(False)
    table.set_fontsize(11)

    # Style the table
    for (row, col), cell in table.get_celld().items():
        cell.set_edgecolor('#CCCCCC')
        if row == 0:
            cell.set_facecolor('#2E5090')
            cell.set_text_props(color='white', fontweight='bold')
        elif row % 2 == 0:
            cell.set_facecolor('#F5F7FA')
        else:
            cell.set_facecolor('white')

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig_file_type_distribution.png'))
    plt.close()
    print("[+] Generated: File Type Distribution")


def plot_entropy_distribution(results, output_dir):
    """Fig 2: Entropy Distribution Across Samples."""
    entropies = []
    file_types = []
    for r in results:
        if 'error' not in r and 'entropy' in r:
            entropies.append(r['entropy'])
            file_types.append(r.get('file_type', 'unknown'))

    if not entropies:
        print("[!] No entropy data available")
        return

    # Scatter plot with color by file type
    type_colors = {
        'javascript': '#2196F3',
        'html_document': '#FF9800',
        'powershell': '#4CAF50',
        'PE_executable': '#E91E63',
        'unknown': '#9E9E9E',
    }

    fig, ax = plt.subplots(figsize=(10, 5))

    for ft in set(file_types):
        indices = [i for i, t in enumerate(file_types) if t == ft]
        ft_entropies = [entropies[i] for i in indices]
        ft_indices = list(range(1, len(ft_entropies) + 1))

        label_map = {'javascript': 'JavaScript', 'html_document': 'HTML',
                      'powershell': 'PowerShell', 'PE_executable': 'Executable', 'unknown': 'Other'}
        color = type_colors.get(ft, '#9E9E9E')
        marker = {'javascript': 'o', 'html_document': 's', 'powershell': '^',
                   'PE_executable': 'D', 'unknown': 'x'}.get(ft, 'o')

        ax.scatter(range(len(ft_entropies)), ft_entropies,
                   c=color, marker=marker, label=label_map.get(ft, ft),
                   s=50, edgecolors='black', linewidth=0.5, zorder=3)

    avg_entropy = sum(entropies) / len(entropies)
    ax.axhline(y=avg_entropy, color='red', linestyle='--', alpha=0.7,
               label=f'Average: {avg_entropy:.2f}')

    ax.set_xlabel('Sample Index')
    ax.set_ylabel('Entropy Value')
    ax.set_title('Entropy Distribution Across SocGholish Sample Set')
    ax.legend(loc='upper right')
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig_entropy_distribution.png'))
    plt.close()
    print("[+] Generated: Entropy Distribution")


def plot_entropy_histogram(results, output_dir):
    """Fig 3: Entropy Histogram showing distribution ranges."""
    entropies = [r['entropy'] for r in results if 'error' not in r and 'entropy' in r]

    if not entropies:
        return

    fig, ax = plt.subplots(figsize=(8, 5))
    n, bins, patches = ax.hist(entropies, bins=20, color='#2196F3',
                                edgecolor='black', linewidth=0.5, alpha=0.8)

    ax.axvline(x=np.mean(entropies), color='red', linestyle='--',
               label=f'Mean: {np.mean(entropies):.2f}')
    ax.axvline(x=np.median(entropies), color='green', linestyle='-.',
               label=f'Median: {np.median(entropies):.2f}')

    ax.set_xlabel('Shannon Entropy')
    ax.set_ylabel('Number of Samples')
    ax.set_title('Entropy Value Distribution of SocGholish Samples')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig_entropy_histogram.png'))
    plt.close()
    print("[+] Generated: Entropy Histogram")


def plot_obfuscation_analysis(results, output_dir):
    """Fig 4: Obfuscation Indicator Distribution."""
    obf_counts = [r.get('obfuscation_indicators_count', 0)
                  for r in results if 'error' not in r]

    if not obf_counts:
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Histogram
    ax1.hist(obf_counts, bins=range(0, max(obf_counts)+2), color='#FF5722',
             edgecolor='black', linewidth=0.5, alpha=0.8)
    ax1.set_xlabel('Number of Obfuscation Indicators')
    ax1.set_ylabel('Number of Samples')
    ax1.set_title('Obfuscation Indicator Frequency')
    ax1.grid(True, alpha=0.3)

    # Pie chart of obfuscation levels
    no_obf = sum(1 for c in obf_counts if c == 0)
    low_obf = sum(1 for c in obf_counts if 1 <= c <= 3)
    med_obf = sum(1 for c in obf_counts if 4 <= c <= 6)
    high_obf = sum(1 for c in obf_counts if c > 6)

    sizes = [no_obf, low_obf, med_obf, high_obf]
    labels_pie = ['None (0)', 'Low (1-3)', 'Medium (4-6)', 'High (7+)']
    colors = ['#4CAF50', '#FFC107', '#FF9800', '#F44336']
    # Remove zero categories
    non_zero = [(s, l, c) for s, l, c in zip(sizes, labels_pie, colors) if s > 0]
    if non_zero:
        sizes, labels_pie, colors = zip(*non_zero)
        ax2.pie(sizes, labels=labels_pie, colors=colors, autopct='%1.1f%%',
                startangle=90, pctdistance=0.85)
        ax2.set_title('Obfuscation Level Distribution')

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig_obfuscation_analysis.png'))
    plt.close()
    print("[+] Generated: Obfuscation Analysis")


def plot_confidence_scores(results, output_dir):
    """Fig 5: Classification Confidence Score Distribution."""
    scores = [r.get('confidence_score', 0) for r in results if 'error' not in r]

    if not scores:
        return

    fig, ax = plt.subplots(figsize=(8, 5))

    n, bins, patches = ax.hist(scores, bins=20, color='#9C27B0',
                                edgecolor='black', linewidth=0.5, alpha=0.8)

    # Color bins by classification threshold
    for patch, left_edge in zip(patches, bins[:-1]):
        if left_edge >= 0.5:
            patch.set_facecolor('#F44336')  # Malicious
        elif left_edge >= 0.3:
            patch.set_facecolor('#FF9800')  # Suspicious
        else:
            patch.set_facecolor('#4CAF50')  # Benign

    ax.axvline(x=0.5, color='red', linestyle='--', label='Malicious threshold (0.5)')
    ax.axvline(x=0.3, color='orange', linestyle='-.', label='Suspicious threshold (0.3)')

    ax.set_xlabel('Confidence Score')
    ax.set_ylabel('Number of Samples')
    ax.set_title('Malware Classification Confidence Score Distribution')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig_confidence_scores.png'))
    plt.close()
    print("[+] Generated: Confidence Scores")


def plot_classification_summary(results, output_dir):
    """Fig 6: Classification Results Pie Chart."""
    classifications = Counter(r.get('classification', 'unknown')
                               for r in results if 'error' not in r)

    labels = list(classifications.keys())
    sizes = list(classifications.values())

    color_map = {
        'malicious': '#F44336',
        'suspicious': '#FF9800',
        'benign': '#4CAF50',
        'unknown': '#9E9E9E',
    }
    colors = [color_map.get(l, '#9E9E9E') for l in labels]

    fig, ax = plt.subplots(figsize=(7, 7))
    wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors,
                                       autopct='%1.1f%%', startangle=90,
                                       pctdistance=0.85, textprops={'fontsize': 12})
    for autotext in autotexts:
        autotext.set_fontweight('bold')

    ax.set_title('SocGholish Sample Classification Results')

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig_classification_summary.png'))
    plt.close()
    print("[+] Generated: Classification Summary")


def plot_url_analysis(results, output_dir):
    """Fig 7: URL Detection Distribution."""
    url_counts = [r.get('urls_count', 0) for r in results if 'error' not in r]

    if not url_counts:
        return

    fig, ax = plt.subplots(figsize=(8, 5))

    ax.hist(url_counts, bins=30, color='#00BCD4', edgecolor='black',
            linewidth=0.5, alpha=0.8)

    avg_urls = sum(url_counts) / len(url_counts)
    ax.axvline(x=avg_urls, color='red', linestyle='--',
               label=f'Average: {avg_urls:.1f}')

    ax.set_xlabel('Number of URLs Detected')
    ax.set_ylabel('Number of Samples')
    ax.set_title('URL Detection Distribution Across SocGholish Samples')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig_url_distribution.png'))
    plt.close()
    print("[+] Generated: URL Distribution")


def plot_feature_correlation_heatmap(results, output_dir):
    """Fig 8: Feature Correlation Heatmap."""
    features = ['entropy', 'obfuscation_indicators_count', 'script_commands',
                'urls_count', 'confidence_score', 'file_size']

    data = []
    for r in results:
        if 'error' not in r:
            row = [r.get(f, 0) for f in features]
            if isinstance(row[0], (int, float)):
                data.append(row)

    if len(data) < 5:
        print("[!] Not enough data for correlation heatmap")
        return

    data = np.array(data, dtype=float)

    # Calculate correlation matrix
    corr = np.corrcoef(data.T)

    fig, ax = plt.subplots(figsize=(8, 7))

    feature_labels = ['Entropy', 'Obfuscation', 'Script Cmds',
                       'URLs', 'Confidence', 'File Size']

    im = ax.imshow(corr, cmap='RdYlBu_r', vmin=-1, vmax=1)

    ax.set_xticks(range(len(feature_labels)))
    ax.set_yticks(range(len(feature_labels)))
    ax.set_xticklabels(feature_labels, rotation=45, ha='right')
    ax.set_yticklabels(feature_labels)

    # Add correlation values
    for i in range(len(feature_labels)):
        for j in range(len(feature_labels)):
            text = ax.text(j, i, f'{corr[i, j]:.2f}',
                           ha='center', va='center', fontsize=9,
                           color='white' if abs(corr[i, j]) > 0.5 else 'black')

    plt.colorbar(im, label='Correlation Coefficient')
    ax.set_title('Feature Correlation Analysis')

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig_correlation_heatmap.png'))
    plt.close()
    print("[+] Generated: Feature Correlation Heatmap")


def plot_file_size_vs_entropy(results, output_dir):
    """Fig 9: File Size vs Entropy scatter plot."""
    sizes = []
    entropies = []
    file_types = []

    for r in results:
        if 'error' not in r and 'entropy' in r and 'file_size' in r:
            sizes.append(r['file_size'])
            entropies.append(r['entropy'])
            file_types.append(r.get('file_type', 'unknown'))

    if not sizes:
        return

    type_colors = {
        'javascript': '#2196F3', 'html_document': '#FF9800',
        'powershell': '#4CAF50', 'PE_executable': '#E91E63', 'unknown': '#9E9E9E',
    }
    label_map = {
        'javascript': 'JavaScript', 'html_document': 'HTML',
        'powershell': 'PowerShell', 'PE_executable': 'Executable', 'unknown': 'Other',
    }

    fig, ax = plt.subplots(figsize=(9, 6))

    for ft in set(file_types):
        idx = [i for i, t in enumerate(file_types) if t == ft]
        ax.scatter([sizes[i]/1024 for i in idx], [entropies[i] for i in idx],
                   c=type_colors.get(ft, '#9E9E9E'),
                   label=label_map.get(ft, ft),
                   s=60, edgecolors='black', linewidth=0.5, alpha=0.7)

    ax.set_xlabel('File Size (KB)')
    ax.set_ylabel('Shannon Entropy')
    ax.set_title('File Size vs. Entropy Analysis')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig_size_vs_entropy.png'))
    plt.close()
    print("[+] Generated: File Size vs Entropy")


def generate_all_visualizations(results_file, output_dir):
    """Generate all visualizations."""
    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] Loading results from {results_file}")
    results = load_results(results_file)
    print(f"[*] Loaded {len(results)} results")

    print(f"\n[*] Generating visualizations to {output_dir}\n")

    plot_file_type_distribution(results, output_dir)
    plot_entropy_distribution(results, output_dir)
    plot_entropy_histogram(results, output_dir)
    plot_obfuscation_analysis(results, output_dir)
    plot_confidence_scores(results, output_dir)
    plot_classification_summary(results, output_dir)
    plot_url_analysis(results, output_dir)
    plot_feature_correlation_heatmap(results, output_dir)
    plot_file_size_vs_entropy(results, output_dir)

    print(f"\n[+] All visualizations generated successfully!")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 generate_visualizations.py <results.json> [output_dir]")
        sys.exit(1)

    results_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else './figures'

    generate_all_visualizations(results_file, output_dir)
