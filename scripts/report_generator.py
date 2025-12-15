#!/usr/bin/env python3
#
# report_generator.py
# Processes benchmark results (summary.csv) and generates a Markdown report.
#

import csv
import os
import statistics
from collections import defaultdict

# Configuration
RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'results')
CSV_FILE = os.path.join(RESULTS_DIR, 'summary.csv')
REPORT_FILE = os.path.join(RESULTS_DIR, 'benchmark_report.md')

def load_data(csv_path):
    """Loads data from the CSV file."""
    data = []
    if not os.path.exists(csv_path):
        print(f"Error: CSV file not found at {csv_path}")
        return []
    
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            data.append(row)
    return data

def calculate_stats(data):
    """Calculates statistics from the raw data."""
    stats = defaultdict(lambda: {
        'total': 0,
        'success': 0,
        'times': [],
        'mems': [],
        'funcs': [],
        'blocks': [],
        'stmts': []
    })
    
    for row in data:
        tool = row['Tool']
        arch = row['Architecture']
        key = (tool, arch)
        
        stats[key]['total'] += 1
        
        if row['Success_Status'] == 'Success':
            stats[key]['success'] += 1
            try:
                stats[key]['times'].append(float(row['Time_s']))
                stats[key]['mems'].append(float(row['Mem_MB']))
                stats[key]['funcs'].append(int(row['Func_Count']))
                stats[key]['blocks'].append(int(row['Block_Count']))
                stats[key]['stmts'].append(int(row['IR_Stmt_Count']))
            except ValueError:
                pass # Skip malformed numbers

    return stats

def generate_markdown(stats):
    """Generates the Markdown report content."""
    lines = []
    lines.append("# IR Lifting Benchmark Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("This report summarizes the performance and reliability of IR lifting tools across different architectures.")
    lines.append("")
    
    lines.append("## Aggregate Performance by Tool & Architecture")
    lines.append("")
    lines.append("| Tool | Architecture | Success Rate | Avg Time (s) | Avg Mem (MB) | Avg Blocks | Avg IR Stmts |")
    lines.append("|---|---|---|---|---|---|---|")
    
    # Sort keys for consistent output
    sorted_keys = sorted(stats.keys())
    
    for tool, arch in sorted_keys:
        s = stats[(tool, arch)]
        total = s['total']
        success = s['success']
        success_rate = (success / total * 100) if total > 0 else 0
        
        avg_time = statistics.mean(s['times']) if s['times'] else 0
        avg_mem = statistics.mean(s['mems']) if s['mems'] else 0
        avg_blocks = statistics.mean(s['blocks']) if s['blocks'] else 0
        avg_stmts = statistics.mean(s['stmts']) if s['stmts'] else 0
        
        lines.append(f"| {tool} | {arch} | {success_rate:.1f}% ({success}/{total}) | {avg_time:.2f} | {avg_mem:.2f} | {avg_blocks:.1f} | {avg_stmts:.1f} |")
        
    lines.append("")
    lines.append("## Practicality Gap Analysis")
    lines.append("")
    lines.append("Comparison of operational readiness (Success Rate) between tools.")
    lines.append("")
    
    # Calculate overall success rate per tool
    tool_stats = defaultdict(lambda: {'total': 0, 'success': 0})
    for (tool, _), s in stats.items():
        tool_stats[tool]['total'] += s['total']
        tool_stats[tool]['success'] += s['success']
        
    lines.append("| Tool | Overall Success Rate |")
    lines.append("|---|---|")
    for tool in sorted(tool_stats.keys()):
        ts = tool_stats[tool]
        rate = (ts['success'] / ts['total'] * 100) if ts['total'] > 0 else 0
        lines.append(f"| {tool} | {rate:.1f}% ({ts['success']}/{ts['total']}) |")

    return "\n".join(lines)

def main():
    print(f"Reading data from: {CSV_FILE}")
    data = load_data(CSV_FILE)
    
    if not data:
        print("No data found.")
        return

    print(f"Processing {len(data)} records...")
    stats = calculate_stats(data)
    
    print("Generating report...")
    report_content = generate_markdown(stats)
    
    with open(REPORT_FILE, 'w') as f:
        f.write(report_content)
        
    print(f"Report saved to: {REPORT_FILE}")

if __name__ == "__main__":
    main()
