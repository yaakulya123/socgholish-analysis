#!/usr/bin/env python3
"""
Advanced Visualization Generator for SocGholish Analysis
Generates architecture diagrams, advanced charts, and publication-quality figures.
"""

import json
import sys
import os
import math

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Circle, Arc
from matplotlib.lines import Line2D
import numpy as np
from collections import Counter, defaultdict

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

# Color palette
COLORS = {
    'primary': '#2C3E50',
    'secondary': '#E74C3C',
    'accent1': '#3498DB',
    'accent2': '#2ECC71',
    'accent3': '#F39C12',
    'accent4': '#9B59B6',
    'accent5': '#1ABC9C',
    'light_bg': '#ECF0F1',
    'dark_bg': '#34495E',
    'warning': '#E67E22',
    'danger': '#C0392B',
    'safe': '#27AE60',
}


def draw_rounded_box(ax, x, y, w, h, text, color, text_color='white',
                     fontsize=9, fontweight='bold', alpha=1.0, radius=0.3):
    """Draw a rounded rectangle with centered text."""
    box = FancyBboxPatch((x, y), w, h,
                         boxstyle=f"round,pad=0.02,rounding_size={radius}",
                         facecolor=color, edgecolor='white',
                         linewidth=1.5, alpha=alpha, zorder=2)
    ax.add_patch(box)
    ax.text(x + w/2, y + h/2, text, ha='center', va='center',
            fontsize=fontsize, fontweight=fontweight, color=text_color,
            zorder=3, wrap=True)
    return box


def draw_arrow(ax, x1, y1, x2, y2, color='#7f8c8d', style='->', lw=1.5):
    """Draw an arrow between two points."""
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle=style, color=color, lw=lw,
                               connectionstyle='arc3,rad=0'),
                zorder=1)


# =========================================================================
# FIGURE 1: SocGholish Attack Chain / Kill Chain Diagram
# =========================================================================
def plot_attack_chain(output_dir):
    fig, ax = plt.subplots(1, 1, figsize=(14, 8))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 8)
    ax.axis('off')

    # Title
    ax.text(7, 7.6, 'SocGholish Attack Chain — MITRE ATT&CK Mapping',
            ha='center', va='center', fontsize=15, fontweight='bold',
            color=COLORS['primary'])

    # Phase boxes (top row - the kill chain stages)
    phases = [
        ('Initial Access\n(T1189)', '#E74C3C'),
        ('Execution\n(T1059)', '#E67E22'),
        ('Defense Evasion\n(T1027)', '#F39C12'),
        ('C2 Comm.\n(T1071)', '#3498DB'),
        ('Payload\nDelivery', '#9B59B6'),
        ('Impact\n(T1486)', '#2C3E50'),
    ]

    phase_w = 1.8
    phase_h = 0.9
    start_x = 0.7
    phase_y = 6.2
    gap = 0.35

    for i, (label, color) in enumerate(phases):
        x = start_x + i * (phase_w + gap)
        draw_rounded_box(ax, x, phase_y, phase_w, phase_h, label, color,
                         fontsize=9, fontweight='bold')
        # Phase number
        ax.text(x + phase_w/2, phase_y + phase_h + 0.15, f'Phase {i+1}',
                ha='center', va='bottom', fontsize=8, color='#7f8c8d',
                fontweight='bold')
        # Arrows between phases
        if i < len(phases) - 1:
            draw_arrow(ax, x + phase_w, phase_y + phase_h/2,
                      x + phase_w + gap, phase_y + phase_h/2,
                      color='#95a5a6', style='->', lw=2)

    # Detail boxes (second row)
    details_row1 = [
        ('Compromised\nWebsite with\nInjected JS', '#fadbd8', '#E74C3C'),
        ('Fake Browser\nUpdate Prompt\n(Social Eng.)', '#fdebd0', '#E67E22'),
        ('Obfuscated\nJavaScript\n(Encoding)', '#fef9e7', '#F39C12'),
        ('HTTP/HTTPS\nBeacon to\nC2 Server', '#d6eaf8', '#3498DB'),
        ('NetSupport RAT\nCobaltStrike\nWastedLocker', '#e8daef', '#9B59B6'),
        ('Ransomware\nData Exfil.\nPersistence', '#d5d8dc', '#2C3E50'),
    ]

    detail_y = 4.6
    for i, (label, bg_color, border_color) in enumerate(details_row1):
        x = start_x + i * (phase_w + gap)
        box = FancyBboxPatch((x, detail_y), phase_w, 1.1,
                             boxstyle="round,pad=0.02,rounding_size=0.15",
                             facecolor=bg_color, edgecolor=border_color,
                             linewidth=1.5, linestyle='--', zorder=2)
        ax.add_patch(box)
        ax.text(x + phase_w/2, detail_y + 0.55, label, ha='center', va='center',
                fontsize=7.5, color=COLORS['primary'], zorder=3)
        # Vertical arrow from phase to detail
        draw_arrow(ax, x + phase_w/2, phase_y, x + phase_w/2, detail_y + 1.1,
                  color=border_color, style='->', lw=1.5)

    # Bottom section: Our Analysis Coverage
    ax.text(7, 3.9, 'Our Analysis Framework Coverage',
            ha='center', va='center', fontsize=12, fontweight='bold',
            color=COLORS['accent2'])

    # Analysis components
    analysis_items = [
        ('Static Analysis\n\n• Entropy Calculation\n• Obfuscation Detection\n• String Extraction\n• Pattern Matching',
         1.0, 1.0, 3.5, 2.4, '#d5f5e3', '#27AE60'),
        ('Feature\nExtraction\n\n• 70+ Features\n• API Call Analysis\n• Network Indicators\n• Code Metrics',
         5.25, 1.0, 3.5, 2.4, '#d6eaf8', '#2980B9'),
        ('ML Classification\n\n• Random Forest\n• Confidence Scoring\n• Threat Categorization\n• Behavioral Analysis',
         9.5, 1.0, 3.5, 2.4, '#fdebd0', '#E67E22'),
    ]

    for label, x, y, w, h, bg, border in analysis_items:
        box = FancyBboxPatch((x, y), w, h,
                             boxstyle="round,pad=0.02,rounding_size=0.2",
                             facecolor=bg, edgecolor=border,
                             linewidth=2, zorder=2)
        ax.add_patch(box)
        ax.text(x + w/2, y + h/2, label, ha='center', va='center',
                fontsize=8, color=COLORS['primary'], zorder=3,
                linespacing=1.3)

    # Arrows between analysis stages
    draw_arrow(ax, 4.5, 2.2, 5.25, 2.2, color='#27AE60', style='->', lw=2)
    draw_arrow(ax, 8.75, 2.2, 9.5, 2.2, color='#2980B9', style='->', lw=2)

    # Coverage arrows from detail row to analysis
    for i in range(3):
        x = start_x + i * (phase_w + gap) + phase_w/2
        draw_arrow(ax, x, detail_y, 2.75, 3.4,
                  color='#27AE60', style='->', lw=1)
    for i in range(3, 5):
        x = start_x + i * (phase_w + gap) + phase_w/2
        draw_arrow(ax, x, detail_y, 7.0, 3.4,
                  color='#2980B9', style='->', lw=1)

    # Dataset label
    ax.text(7, 0.4, 'Dataset: 160 SocGholish Samples (132 JS | 26 EXE | 1 PS1 | 1 HTML)',
            ha='center', va='center', fontsize=10, fontweight='bold',
            color=COLORS['dark_bg'],
            bbox=dict(boxstyle='round,pad=0.4', facecolor=COLORS['light_bg'],
                     edgecolor=COLORS['dark_bg'], linewidth=1.5))

    plt.savefig(os.path.join(output_dir, 'fig_attack_chain.png'))
    plt.close()
    print('[+] Generated: SocGholish Attack Chain Diagram')


# =========================================================================
# FIGURE 2: Analysis Framework Architecture
# =========================================================================
def plot_framework_architecture(output_dir):
    fig, ax = plt.subplots(1, 1, figsize=(14, 10))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 10)
    ax.axis('off')

    ax.text(7, 9.6, 'SocGholish Analysis Framework — System Architecture',
            ha='center', va='center', fontsize=15, fontweight='bold',
            color=COLORS['primary'])

    # Layer 1: Data Acquisition
    layer_bg = FancyBboxPatch((0.3, 8.0), 13.4, 1.3,
                              boxstyle="round,pad=0.05,rounding_size=0.2",
                              facecolor='#fadbd8', edgecolor='#E74C3C',
                              linewidth=2, alpha=0.3, zorder=0)
    ax.add_patch(layer_bg)
    ax.text(0.6, 9.1, 'DATA ACQUISITION', fontsize=9, fontweight='bold',
            color='#C0392B', rotation=0)

    draw_rounded_box(ax, 1.0, 8.2, 2.5, 0.8, 'MalwareBazaar\nAPI Client', '#E74C3C', fontsize=8)
    draw_rounded_box(ax, 4.0, 8.2, 2.5, 0.8, 'Sample\nDownloader\n& Extractor', '#C0392B', fontsize=8)
    draw_rounded_box(ax, 7.0, 8.2, 2.5, 0.8, 'Tag Aggregator\n(SocGholish,\nFakeUpdates, TA569)', '#E74C3C', fontsize=8)
    draw_rounded_box(ax, 10.0, 8.2, 3.3, 0.8, 'Sandbox\nEnvironment\n(Remote Server)', '#922B21', fontsize=8)

    draw_arrow(ax, 3.5, 8.6, 4.0, 8.6, color='white', lw=2)
    draw_arrow(ax, 6.5, 8.6, 7.0, 8.6, color='white', lw=2)
    draw_arrow(ax, 9.5, 8.6, 10.0, 8.6, color='white', lw=2)

    # Layer 2: File-Type Routing
    layer_bg2 = FancyBboxPatch((0.3, 6.2), 13.4, 1.5,
                               boxstyle="round,pad=0.05,rounding_size=0.2",
                               facecolor='#fdebd0', edgecolor='#F39C12',
                               linewidth=2, alpha=0.3, zorder=0)
    ax.add_patch(layer_bg2)
    ax.text(0.6, 7.5, 'FILE-TYPE ROUTING', fontsize=9, fontweight='bold',
            color='#E67E22')

    draw_rounded_box(ax, 2.5, 6.9, 2.2, 0.6, 'File Type\nDetector', '#F39C12', fontsize=8)
    draw_arrow(ax, 4.7, 7.2, 5.5, 7.2, color='#E67E22', lw=2)

    # File type boxes
    ft_items = [
        ('JavaScript\nAnalyzer', '#E67E22', 5.5, 7.3),
        ('PE/EXE\nAnalyzer', '#D35400', 7.8, 7.3),
        ('PowerShell\nAnalyzer', '#CA6F1E', 10.1, 7.3),
        ('HTML\nAnalyzer', '#BA4A00', 12.0, 7.3),
    ]
    for label, color, x, y in ft_items:
        draw_rounded_box(ax, x, y - 0.6, 1.8, 0.55, label, color, fontsize=7)
        draw_arrow(ax, 4.7, 7.1, x, y - 0.3, color='#E67E22', lw=1)

    # Big down arrow
    draw_arrow(ax, 7, 6.2, 7, 5.8, color='#7f8c8d', style='->', lw=2.5)

    # Layer 3: Analysis Engine
    layer_bg3 = FancyBboxPatch((0.3, 3.3), 13.4, 2.4,
                               boxstyle="round,pad=0.05,rounding_size=0.2",
                               facecolor='#d6eaf8', edgecolor='#2980B9',
                               linewidth=2, alpha=0.3, zorder=0)
    ax.add_patch(layer_bg3)
    ax.text(0.6, 5.5, 'ANALYSIS ENGINE', fontsize=9, fontweight='bold',
            color='#2471A3')

    # Analysis modules
    modules = [
        ('Entropy\nCalculation\n(Shannon)', 0.8, 3.6, 2.0, 1.4, '#2980B9'),
        ('Obfuscation\nDetection\n• eval/exec\n• base64\n• char codes', 3.1, 3.6, 2.2, 1.4, '#3498DB'),
        ('String\nExtraction\n• URLs/IPs\n• Domains\n• Reg Keys', 5.6, 3.6, 2.2, 1.4, '#2E86C1'),
        ('API Call\nAnalysis\n• Network\n• File I/O\n• Process', 8.1, 3.6, 2.2, 1.4, '#2471A3'),
        ('SocGholish\nPattern\nMatching\n• Signatures\n• Behaviors', 10.6, 3.6, 2.8, 1.4, '#1B4F72'),
    ]
    for label, x, y, w, h, color in modules:
        draw_rounded_box(ax, x, y, w, h, label, color, fontsize=7)

    # Big down arrow
    draw_arrow(ax, 7, 3.3, 7, 2.9, color='#7f8c8d', style='->', lw=2.5)

    # Layer 4: Output
    layer_bg4 = FancyBboxPatch((0.3, 0.5), 13.4, 2.2,
                               boxstyle="round,pad=0.05,rounding_size=0.2",
                               facecolor='#d5f5e3', edgecolor='#27AE60',
                               linewidth=2, alpha=0.3, zorder=0)
    ax.add_patch(layer_bg4)
    ax.text(0.6, 2.5, 'OUTPUT & CLASSIFICATION', fontsize=9, fontweight='bold',
            color='#1E8449')

    outputs = [
        ('Feature Vector\nConstruction\n(70+ features)', 1.0, 0.8, 2.5, 1.4, '#27AE60'),
        ('Confidence\nScoring\nEngine', 4.0, 0.8, 2.2, 1.4, '#2ECC71'),
        ('Threat\nClassification\n(Malicious/\nSuspicious/\nBenign)', 6.8, 0.8, 2.2, 1.4, '#1E8449'),
        ('Report\nGeneration\n• JSON/CSV\n• Visualizations\n• Summary', 9.8, 0.8, 3.5, 1.4, '#196F3D'),
    ]
    for label, x, y, w, h, color in outputs:
        draw_rounded_box(ax, x, y, w, h, label, color, fontsize=7.5)

    draw_arrow(ax, 3.5, 1.5, 4.0, 1.5, color='#27AE60', lw=2)
    draw_arrow(ax, 6.2, 1.5, 6.8, 1.5, color='#27AE60', lw=2)
    draw_arrow(ax, 9.0, 1.5, 9.8, 1.5, color='#27AE60', lw=2)

    plt.savefig(os.path.join(output_dir, 'fig_framework_architecture.png'))
    plt.close()
    print('[+] Generated: Framework Architecture Diagram')


# =========================================================================
# FIGURE 3: Per-Sample Detection Heatmap
# =========================================================================
def plot_detection_heatmap(results, output_dir):
    fig, ax = plt.subplots(figsize=(14, 8))

    # Select features for heatmap
    features = ['entropy', 'obfuscation_indicators_count', 'urls_count',
                'suspicious_function_count', 'eval_count', 'function_count',
                'var_count', 'string_fromcharcode']
    feature_labels = ['Entropy', 'Obfuscation\nIndicators', 'URLs\nDetected',
                      'Suspicious\nFunctions', 'eval()\nCount', 'Function\nCount',
                      'Variable\nCount', 'fromCharCode\nCount']

    # Build matrix - sort by entropy
    sorted_results = sorted(results, key=lambda r: r.get('entropy', 0), reverse=True)

    # Take top 50 most interesting samples
    matrix = []
    labels = []
    for r in sorted_results[:50]:
        row = []
        for f in features:
            val = r.get(f, 0)
            if val is None:
                val = 0
            row.append(float(val))
        matrix.append(row)
        name = r['filename'][:20] + '...' if len(r['filename']) > 20 else r['filename']
        labels.append(name)

    matrix = np.array(matrix)

    # Normalize each column to 0-1
    for j in range(matrix.shape[1]):
        col = matrix[:, j]
        cmin, cmax = col.min(), col.max()
        if cmax > cmin:
            matrix[:, j] = (col - cmin) / (cmax - cmin)
        else:
            matrix[:, j] = 0

    im = ax.imshow(matrix, cmap='YlOrRd', aspect='auto', interpolation='nearest')

    ax.set_xticks(range(len(feature_labels)))
    ax.set_xticklabels(feature_labels, fontsize=8, ha='center')
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=6, fontfamily='monospace')

    ax.set_title('Per-Sample Feature Detection Heatmap (Top 50 by Entropy)',
                 fontsize=13, fontweight='bold', pad=15)
    ax.set_xlabel('Analysis Features', fontsize=11)
    ax.set_ylabel('Sample (truncated hash)', fontsize=11)

    cbar = plt.colorbar(im, ax=ax, shrink=0.8)
    cbar.set_label('Normalized Feature Intensity', fontsize=10)

    plt.savefig(os.path.join(output_dir, 'fig_detection_heatmap.png'))
    plt.close()
    print('[+] Generated: Per-Sample Detection Heatmap')


# =========================================================================
# FIGURE 4: Radar/Spider Chart - File Type Behavioral Profiles
# =========================================================================
def plot_radar_comparison(results, output_dir):
    # Group by file type
    groups = defaultdict(list)
    for r in results:
        ft = r.get('file_type', 'unknown')
        groups[ft].append(r)

    categories = ['Avg Entropy', 'Obfuscation', 'URLs/IPs', 'Suspicious\nFunctions',
                  'Script\nCommands', 'Code\nComplexity']
    N = len(categories)

    # Compute averages per group
    profiles = {}
    for ft, samples in groups.items():
        if len(samples) < 1:
            continue
        avg_entropy = np.mean([s.get('entropy', 0) for s in samples]) / 8.0  # normalize to 0-1
        avg_obf = min(np.mean([s.get('obfuscation_indicators_count', 0) for s in samples]) / 5.0, 1.0)
        avg_urls = min(np.mean([s.get('urls_count', 0) for s in samples]) / 20.0, 1.0)
        avg_susp = min(np.mean([s.get('suspicious_function_count', 0) for s in samples]) / 10.0, 1.0)
        avg_script = min(np.mean([s.get('script_commands', 0) for s in samples]) / 5.0, 1.0)
        avg_complexity = min(np.mean([s.get('function_count', 0) + s.get('var_count', 0)
                                      for s in samples]) / 50.0, 1.0)
        profiles[ft] = [avg_entropy, avg_obf, avg_urls, avg_susp, avg_script, avg_complexity]

    angles = [n / float(N) * 2 * math.pi for n in range(N)]
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(9, 9), subplot_kw=dict(polar=True))

    colors_map = {
        'javascript': '#3498DB',
        'PE_executable': '#E74C3C',
        'powershell': '#F39C12',
        'html_document': '#2ECC71',
    }

    for ft, values in profiles.items():
        values_plot = values + values[:1]
        color = colors_map.get(ft, '#95a5a6')
        ax.plot(angles, values_plot, 'o-', linewidth=2, color=color,
                label=f'{ft} (n={len(groups[ft])})')
        ax.fill(angles, values_plot, alpha=0.15, color=color)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=10)
    ax.set_ylim(0, 1)
    ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(['0.2', '0.4', '0.6', '0.8', '1.0'], fontsize=8, color='#7f8c8d')
    ax.set_title('Behavioral Profile Comparison by File Type',
                 fontsize=14, fontweight='bold', pad=25)
    ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1), fontsize=9)

    plt.savefig(os.path.join(output_dir, 'fig_radar_comparison.png'))
    plt.close()
    print('[+] Generated: Radar Behavioral Profile Comparison')


# =========================================================================
# FIGURE 5: Threat Scoring Distribution (Violin + Swarm)
# =========================================================================
def plot_threat_score_violin(results, output_dir):
    fig, axes = plt.subplots(1, 3, figsize=(14, 5))

    # Group by file type for violin plots
    js_entropy = [r['entropy'] for r in results if r.get('file_type') == 'javascript']
    exe_entropy = [r['entropy'] for r in results if r.get('file_type') == 'PE_executable']

    js_obf = [r.get('obfuscation_indicators_count', 0) for r in results if r.get('file_type') == 'javascript']
    exe_obf = [r.get('obfuscation_indicators_count', 0) for r in results if r.get('file_type') == 'PE_executable']

    js_conf = [r.get('confidence_score', 0) for r in results if r.get('file_type') == 'javascript']
    exe_conf = [r.get('confidence_score', 0) for r in results if r.get('file_type') == 'PE_executable']

    # Entropy violin
    data_entropy = [d for d in [js_entropy, exe_entropy] if d]
    labels_e = ['JavaScript', 'PE Executable'][:len(data_entropy)]
    vp1 = axes[0].violinplot(data_entropy, showmeans=True, showmedians=True)
    for i, body in enumerate(vp1['bodies']):
        body.set_facecolor(['#3498DB', '#E74C3C'][i])
        body.set_alpha(0.7)
    axes[0].set_xticks(range(1, len(labels_e)+1))
    axes[0].set_xticklabels(labels_e, fontsize=9)
    axes[0].set_title('Entropy Distribution', fontsize=11, fontweight='bold')
    axes[0].set_ylabel('Shannon Entropy', fontsize=10)
    axes[0].grid(axis='y', alpha=0.3)

    # Obfuscation violin
    data_obf = [d for d in [js_obf, exe_obf] if d]
    labels_o = ['JavaScript', 'PE Executable'][:len(data_obf)]
    vp2 = axes[1].violinplot(data_obf, showmeans=True, showmedians=True)
    for i, body in enumerate(vp2['bodies']):
        body.set_facecolor(['#3498DB', '#E74C3C'][i])
        body.set_alpha(0.7)
    axes[1].set_xticks(range(1, len(labels_o)+1))
    axes[1].set_xticklabels(labels_o, fontsize=9)
    axes[1].set_title('Obfuscation Indicators', fontsize=11, fontweight='bold')
    axes[1].set_ylabel('Indicator Count', fontsize=10)
    axes[1].grid(axis='y', alpha=0.3)

    # Confidence violin
    data_conf = [d for d in [js_conf, exe_conf] if d]
    labels_c = ['JavaScript', 'PE Executable'][:len(data_conf)]
    vp3 = axes[2].violinplot(data_conf, showmeans=True, showmedians=True)
    for i, body in enumerate(vp3['bodies']):
        body.set_facecolor(['#3498DB', '#E74C3C'][i])
        body.set_alpha(0.7)
    axes[2].set_xticks(range(1, len(labels_c)+1))
    axes[2].set_xticklabels(labels_c, fontsize=9)
    axes[2].set_title('Confidence Scores', fontsize=11, fontweight='bold')
    axes[2].set_ylabel('Score', fontsize=10)
    axes[2].grid(axis='y', alpha=0.3)

    fig.suptitle('JS vs PE Executable — Statistical Comparison',
                 fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig_violin_comparison.png'))
    plt.close()
    print('[+] Generated: Violin Plot Comparison (JS vs EXE)')


# =========================================================================
# FIGURE 6: Network Indicator Analysis (Bubble Chart)
# =========================================================================
def plot_network_bubble(results, output_dir):
    fig, ax = plt.subplots(figsize=(12, 8))

    entropies = []
    url_counts = []
    sizes_raw = []
    colors_list = []
    labels = []

    color_map = {'javascript': '#3498DB', 'PE_executable': '#E74C3C',
                 'powershell': '#F39C12', 'html_document': '#2ECC71'}

    for r in results:
        entropy = r.get('entropy', 0)
        urls = r.get('urls_count', 0)
        fsize = r.get('file_size', 0)
        ft = r.get('file_type', 'unknown')

        entropies.append(entropy)
        url_counts.append(urls)
        sizes_raw.append(fsize)
        colors_list.append(color_map.get(ft, '#95a5a6'))

    # Scale bubble sizes
    sizes = np.array(sizes_raw, dtype=float)
    if sizes.max() > 0:
        sizes = (sizes / sizes.max()) * 500 + 20

    scatter = ax.scatter(entropies, url_counts, s=sizes, c=colors_list,
                         alpha=0.6, edgecolors='white', linewidth=0.5, zorder=2)

    ax.set_xlabel('Shannon Entropy', fontsize=12, fontweight='bold')
    ax.set_ylabel('URLs Detected', fontsize=12, fontweight='bold')
    ax.set_title('Network Indicator Analysis\n(Bubble Size = File Size)',
                 fontsize=14, fontweight='bold')
    ax.grid(True, alpha=0.3)

    # Legend
    legend_elements = [
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#3498DB',
               markersize=10, label=f'JavaScript (n={sum(1 for c in colors_list if c=="#3498DB")})'),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#E74C3C',
               markersize=10, label=f'PE Executable (n={sum(1 for c in colors_list if c=="#E74C3C")})'),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#F39C12',
               markersize=10, label='PowerShell (n=1)'),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#2ECC71',
               markersize=10, label='HTML (n=1)'),
    ]
    ax.legend(handles=legend_elements, loc='upper right', fontsize=9)

    # Annotate interesting clusters
    high_url = [(e, u) for e, u in zip(entropies, url_counts) if u > 50]
    if high_url:
        ax.annotate('High network\nactivity cluster',
                    xy=(np.mean([h[0] for h in high_url]), np.mean([h[1] for h in high_url])),
                    xytext=(7, max(url_counts)*0.8),
                    arrowprops=dict(arrowstyle='->', color='#E74C3C', lw=1.5),
                    fontsize=9, color='#E74C3C', fontweight='bold')

    plt.savefig(os.path.join(output_dir, 'fig_network_bubble.png'))
    plt.close()
    print('[+] Generated: Network Indicator Bubble Chart')


# =========================================================================
# FIGURE 7: Obfuscation Technique Breakdown (Stacked Horizontal Bar)
# =========================================================================
def plot_obfuscation_breakdown(results, output_dir):
    fig, ax = plt.subplots(figsize=(12, 6))

    # Count obfuscation techniques per file type
    groups = defaultdict(lambda: {
        'eval_usage': 0, 'base64_encoding': 0, 'string_fromcharcode': 0,
        'hex_encoding': 0, 'unicode_escape': 0, 'long_strings': 0,
        'total': 0
    })

    for r in results:
        ft = r.get('file_type', 'unknown')
        groups[ft]['total'] += 1
        if r.get('eval_count', 0) > 0:
            groups[ft]['eval_usage'] += 1
        if len(r.get('base64_strings', [])) > 0:
            groups[ft]['base64_encoding'] += 1
        if r.get('string_fromcharcode', 0) > 0:
            groups[ft]['string_fromcharcode'] += 1
        if len(r.get('hex_strings', [])) > 0:
            groups[ft]['hex_encoding'] += 1
        if len(r.get('unicode_escapes', [])) > 0:
            groups[ft]['unicode_escape'] += 1
        if r.get('obfuscation_indicators_count', 0) > 2:
            groups[ft]['long_strings'] += 1

    file_types = list(groups.keys())
    techniques = ['eval_usage', 'base64_encoding', 'string_fromcharcode',
                  'hex_encoding', 'unicode_escape', 'long_strings']
    tech_labels = ['eval() Usage', 'Base64 Encoding', 'String.fromCharCode',
                   'Hex Encoding', 'Unicode Escape', 'Heavy Obfuscation (3+)']
    tech_colors = ['#E74C3C', '#3498DB', '#F39C12', '#9B59B6', '#2ECC71', '#2C3E50']

    y_pos = np.arange(len(file_types))
    bar_height = 0.6

    left = np.zeros(len(file_types))
    for tech, label, color in zip(techniques, tech_labels, tech_colors):
        values = [groups[ft][tech] for ft in file_types]
        ax.barh(y_pos, values, bar_height, left=left, label=label,
                color=color, edgecolor='white', linewidth=0.5)
        left += values

    ax.set_yticks(y_pos)
    ax.set_yticklabels([f'{ft}\n(n={groups[ft]["total"]})' for ft in file_types], fontsize=10)
    ax.set_xlabel('Number of Samples', fontsize=12, fontweight='bold')
    ax.set_title('Obfuscation Technique Breakdown by File Type',
                 fontsize=14, fontweight='bold')
    ax.legend(loc='upper right', fontsize=8, ncol=2)
    ax.grid(axis='x', alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig_obfuscation_breakdown.png'))
    plt.close()
    print('[+] Generated: Obfuscation Technique Breakdown')


# =========================================================================
# FIGURE 8: Entropy Density Comparison (KDE Plot)
# =========================================================================
def plot_entropy_kde(results, output_dir):
    fig, ax = plt.subplots(figsize=(10, 6))

    js_entropy = sorted([r['entropy'] for r in results if r.get('file_type') == 'javascript'])
    exe_entropy = sorted([r['entropy'] for r in results if r.get('file_type') == 'PE_executable'])

    def kde(data, x_grid, bandwidth=0.15):
        """Simple Gaussian KDE."""
        kde_vals = np.zeros_like(x_grid)
        for d in data:
            kde_vals += np.exp(-0.5 * ((x_grid - d) / bandwidth) ** 2)
        kde_vals /= (len(data) * bandwidth * np.sqrt(2 * np.pi))
        return kde_vals

    x = np.linspace(3, 9, 500)

    if js_entropy:
        js_kde = kde(js_entropy, x, bandwidth=0.12)
        ax.fill_between(x, js_kde, alpha=0.3, color='#3498DB')
        ax.plot(x, js_kde, color='#3498DB', linewidth=2,
                label=f'JavaScript (n={len(js_entropy)}, μ={np.mean(js_entropy):.2f})')

    if exe_entropy:
        exe_kde = kde(exe_entropy, x, bandwidth=0.2)
        ax.fill_between(x, exe_kde, alpha=0.3, color='#E74C3C')
        ax.plot(x, exe_kde, color='#E74C3C', linewidth=2,
                label=f'PE Executable (n={len(exe_entropy)}, μ={np.mean(exe_entropy):.2f})')

    # Reference lines
    ax.axvline(x=5.0, color='#27AE60', linestyle='--', alpha=0.7, linewidth=1)
    ax.text(5.05, ax.get_ylim()[1]*0.9, 'Low obfuscation\nthreshold',
            fontsize=8, color='#27AE60')

    ax.axvline(x=7.0, color='#E74C3C', linestyle='--', alpha=0.7, linewidth=1)
    ax.text(7.05, ax.get_ylim()[1]*0.9, 'High entropy\n(packed/encrypted)',
            fontsize=8, color='#E74C3C')

    ax.set_xlabel('Shannon Entropy', fontsize=12, fontweight='bold')
    ax.set_ylabel('Density', fontsize=12, fontweight='bold')
    ax.set_title('Entropy Distribution Density — JavaScript vs PE Executables',
                 fontsize=14, fontweight='bold')
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig_entropy_kde.png'))
    plt.close()
    print('[+] Generated: Entropy KDE Density Plot')


# =========================================================================
# FIGURE 9: Sample Timeline (if dates available) or Size Distribution
# =========================================================================
def plot_size_distribution_advanced(results, output_dir):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # Left: Log-scale file size histogram by type
    js_sizes = [r['file_size'] for r in results if r.get('file_type') == 'javascript']
    exe_sizes = [r['file_size'] for r in results if r.get('file_type') == 'PE_executable']

    bins = np.logspace(np.log10(min(s for s in js_sizes + exe_sizes if s > 0)),
                       np.log10(max(js_sizes + exe_sizes)), 30)

    ax1.hist(js_sizes, bins=bins, alpha=0.7, color='#3498DB', label=f'JavaScript (n={len(js_sizes)})',
             edgecolor='white')
    if exe_sizes:
        ax1.hist(exe_sizes, bins=bins, alpha=0.7, color='#E74C3C', label=f'PE Executable (n={len(exe_sizes)})',
                 edgecolor='white')
    ax1.set_xscale('log')
    ax1.set_xlabel('File Size (bytes, log scale)', fontsize=11, fontweight='bold')
    ax1.set_ylabel('Count', fontsize=11, fontweight='bold')
    ax1.set_title('File Size Distribution (Log Scale)', fontsize=12, fontweight='bold')
    ax1.legend(fontsize=9)
    ax1.grid(True, alpha=0.3)

    # Right: Cumulative distribution
    all_sizes = sorted([r['file_size'] for r in results])
    js_sizes_sorted = sorted(js_sizes)
    exe_sizes_sorted = sorted(exe_sizes) if exe_sizes else []

    ax2.plot(js_sizes_sorted, np.linspace(0, 1, len(js_sizes_sorted)),
             color='#3498DB', linewidth=2, label='JavaScript')
    if exe_sizes_sorted:
        ax2.plot(exe_sizes_sorted, np.linspace(0, 1, len(exe_sizes_sorted)),
                 color='#E74C3C', linewidth=2, label='PE Executable')
    ax2.set_xscale('log')
    ax2.set_xlabel('File Size (bytes, log scale)', fontsize=11, fontweight='bold')
    ax2.set_ylabel('Cumulative Proportion', fontsize=11, fontweight='bold')
    ax2.set_title('Cumulative Size Distribution (CDF)', fontsize=12, fontweight='bold')
    ax2.legend(fontsize=9)
    ax2.grid(True, alpha=0.3)

    fig.suptitle('File Size Analysis — SocGholish Sample Corpus',
                 fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig_size_analysis.png'))
    plt.close()
    print('[+] Generated: Advanced File Size Analysis')


# =========================================================================
# FIGURE 10: Multi-Feature Scatter Matrix
# =========================================================================
def plot_scatter_matrix(results, output_dir):
    features = ['entropy', 'obfuscation_indicators_count', 'urls_count', 'file_size']
    labels = ['Entropy', 'Obfuscation Count', 'URLs Detected', 'File Size']
    n = len(features)

    fig, axes = plt.subplots(n, n, figsize=(12, 12))

    color_map = {'javascript': '#3498DB', 'PE_executable': '#E74C3C',
                 'powershell': '#F39C12', 'html_document': '#2ECC71'}

    data = {f: [] for f in features}
    colors = []
    for r in results:
        for f in features:
            data[f].append(r.get(f, 0))
        colors.append(color_map.get(r.get('file_type', ''), '#95a5a6'))

    for i in range(n):
        for j in range(n):
            ax = axes[i][j]
            if i == j:
                # Diagonal: histogram
                js_vals = [data[features[i]][k] for k in range(len(results))
                           if results[k].get('file_type') == 'javascript']
                exe_vals = [data[features[i]][k] for k in range(len(results))
                            if results[k].get('file_type') == 'PE_executable']
                if js_vals:
                    ax.hist(js_vals, bins=20, alpha=0.6, color='#3498DB', density=True)
                if exe_vals:
                    ax.hist(exe_vals, bins=10, alpha=0.6, color='#E74C3C', density=True)
            else:
                ax.scatter(data[features[j]], data[features[i]],
                          c=colors, alpha=0.5, s=15, edgecolors='none')

            if j == 0:
                ax.set_ylabel(labels[i], fontsize=8)
            else:
                ax.set_yticklabels([])
            if i == n - 1:
                ax.set_xlabel(labels[j], fontsize=8)
            else:
                ax.set_xticklabels([])

            ax.tick_params(labelsize=6)

    fig.suptitle('Multi-Feature Scatter Matrix — SocGholish Samples',
                 fontsize=14, fontweight='bold', y=1.01)

    # Legend
    legend_elements = [
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#3498DB', markersize=8, label='JavaScript'),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#E74C3C', markersize=8, label='PE Executable'),
    ]
    fig.legend(handles=legend_elements, loc='lower center', ncol=2, fontsize=10,
               bbox_to_anchor=(0.5, -0.02))

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'fig_scatter_matrix.png'))
    plt.close()
    print('[+] Generated: Multi-Feature Scatter Matrix')


# =========================================================================
# FIGURE 11: Threat Classification Sankey-style Flow
# =========================================================================
def plot_classification_flow(results, output_dir):
    fig, ax = plt.subplots(figsize=(14, 7))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 7)
    ax.axis('off')

    ax.text(7, 6.7, 'SocGholish Classification Flow — From Sample to Verdict',
            ha='center', va='center', fontsize=14, fontweight='bold',
            color=COLORS['primary'])

    # Count flows
    flows = defaultdict(lambda: defaultdict(int))
    for r in results:
        ft = r.get('file_type', 'unknown')
        cls = r.get('classification', 'benign')
        flows[ft][cls] += 1

    # Stage 1: File Types (left)
    ft_counts = Counter(r.get('file_type', 'unknown') for r in results)
    ft_colors = {'javascript': '#3498DB', 'PE_executable': '#E74C3C',
                 'powershell': '#F39C12', 'html_document': '#2ECC71'}

    y_positions_left = {}
    y = 5.5
    for ft, count in ft_counts.most_common():
        h = max(count / len(results) * 4, 0.4)
        color = ft_colors.get(ft, '#95a5a6')
        draw_rounded_box(ax, 0.5, y - h, 3.0, h, f'{ft}\n(n={count})',
                         color, fontsize=9)
        y_positions_left[ft] = y - h/2
        y -= h + 0.15

    # Stage 2: Analysis (middle)
    draw_rounded_box(ax, 5.5, 3.5, 3.0, 2.5, 'Analysis\nEngine\n\n• Entropy\n• Obfuscation\n• Patterns\n• Features',
                     '#2C3E50', fontsize=9)

    # Stage 3: Classifications (right)
    cls_counts = Counter(r.get('classification', 'benign') for r in results)
    cls_colors = {'malicious': '#E74C3C', 'suspicious': '#F39C12', 'benign': '#27AE60'}

    y_positions_right = {}
    y = 5.5
    for cls in ['malicious', 'suspicious', 'benign']:
        count = cls_counts.get(cls, 0)
        if count == 0:
            continue
        h = max(count / len(results) * 4, 0.4)
        color = cls_colors.get(cls, '#95a5a6')
        draw_rounded_box(ax, 10.5, y - h, 3.0, h,
                         f'{cls.upper()}\n(n={count})',
                         color, fontsize=10, fontweight='bold')
        y_positions_right[cls] = y - h/2
        y -= h + 0.15

    # Draw flow arrows (left to middle)
    for ft, ypos in y_positions_left.items():
        draw_arrow(ax, 3.5, ypos, 5.5, 4.75,
                  color=ft_colors.get(ft, '#95a5a6'), style='->', lw=1.5)

    # Draw flow arrows (middle to right)
    for cls, ypos in y_positions_right.items():
        draw_arrow(ax, 8.5, 4.75, 10.5, ypos,
                  color=cls_colors.get(cls, '#95a5a6'), style='->', lw=2)

    # Stats at bottom
    ax.text(7, 0.5, f'Total: {len(results)} samples  |  '
            f'Detection Rate: {(cls_counts.get("malicious",0)+cls_counts.get("suspicious",0))/len(results)*100:.1f}%  |  '
            f'Avg Confidence: {np.mean([r.get("confidence_score",0) for r in results]):.3f}',
            ha='center', va='center', fontsize=11, fontweight='bold',
            color=COLORS['dark_bg'],
            bbox=dict(boxstyle='round,pad=0.4', facecolor=COLORS['light_bg'],
                     edgecolor=COLORS['dark_bg'], linewidth=1.5))

    plt.savefig(os.path.join(output_dir, 'fig_classification_flow.png'))
    plt.close()
    print('[+] Generated: Classification Flow Diagram')


# =========================================================================
# MAIN
# =========================================================================
def main():
    if len(sys.argv) < 3:
        print("Usage: python generate_advanced_figures.py <results.json> <output_dir>")
        sys.exit(1)

    results_file = sys.argv[1]
    output_dir = sys.argv[2]

    print(f'[*] Loading results from {results_file}')
    with open(results_file, 'r') as f:
        results = json.load(f)
    print(f'[*] Loaded {len(results)} results')

    os.makedirs(output_dir, exist_ok=True)
    print(f'[*] Generating advanced visualizations to {output_dir}\n')

    # Architecture & Flow diagrams
    plot_attack_chain(output_dir)
    plot_framework_architecture(output_dir)
    plot_classification_flow(results, output_dir)

    # Advanced data visualizations
    plot_detection_heatmap(results, output_dir)
    plot_radar_comparison(results, output_dir)
    plot_threat_score_violin(results, output_dir)
    plot_network_bubble(results, output_dir)
    plot_obfuscation_breakdown(results, output_dir)
    plot_entropy_kde(results, output_dir)
    plot_size_distribution_advanced(results, output_dir)
    plot_scatter_matrix(results, output_dir)

    print(f'\n[+] All {11} advanced visualizations generated successfully!')


if __name__ == '__main__':
    main()
