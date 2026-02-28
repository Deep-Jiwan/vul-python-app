"""
Security Scan Coverage Visualization
Generates 3 key plots from sast_stats_summary.json and dast_stats_summary.json
"""

import json
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from pathlib import Path

# ── Load data ────────────────────────────────────────────────────────────────
base = Path(__file__).parent
try:
    sast = json.loads((base / "results/sast_stats_summary.json").read_text(encoding="utf-8"))
except FileNotFoundError:
    raise FileNotFoundError(f"Missing SAST summary: {base / 'sast_stats_summary.json'}")
try:
    dast = json.loads((base / "results/dast_stats_summary.json").read_text(encoding="utf-8"))
except FileNotFoundError:
    raise FileNotFoundError(f"Missing DAST summary: {base / 'dast_stats_summary.json'}")

# ── Palette ──────────────────────────────────────────────────────────────────
C_DETECTED   = "#2ECC71"   # green
C_MISSED     = "#C53030"   # red (darker for light bg)
C_SAST       = "#1f77b4"   # blue
C_DAST       = "#e67e22"   # orange
C_BOTH       = "#6a4c93"   # purple
C_BG         = "#FFFFFF"   # page background (light)
C_PANEL      = "#FAFAFB"   # panel / axes background
C_TEXT       = "#111827"   # very dark gray for text
C_SUBTEXT    = "#6B7280"   # muted gray for ticks/annotations
C_GRID       = "#E5E7EB"   # light gray grid

plt.rcParams.update({
    "figure.facecolor":  C_BG,
    "axes.facecolor":    C_PANEL,
    "axes.edgecolor":    C_GRID,
    "axes.labelcolor":   C_TEXT,
    "axes.titlecolor":   C_TEXT,
    "xtick.color":       C_SUBTEXT,
    "ytick.color":       C_SUBTEXT,
    "text.color":        C_TEXT,
    "grid.color":        C_GRID,
    "grid.linewidth":    0.6,
    "font.family":       "sans-serif",
    "font.sans-serif":   ["DejaVu Sans", "Arial", "sans-serif"],
    "axes.spines.top":   False,
    "axes.spines.right": False,
    "legend.framealpha": 0.12,
})

# ------------------ PLOT 1: Combined SAST / DAST detection summary
fig1, ax1 = plt.subplots(figsize=(6.5, 5), facecolor=C_BG)
fig1.suptitle("SAST vs DAST Detection Summary", fontsize=12, fontweight="bold", color=C_TEXT)

# Compute combined denominators and numerators per your rule:
# SAST: (sast-only covered + sast-and-dast covered) / (sast-only total + sast-and-dast total)
# DAST: (dast-only covered + sast-and-dast covered) / (dast-only total + sast-and-dast total)
sast_num = sast["groups"]["sast_only"]["covered_count"] + sast["groups"]["sast_and_dast"]["covered_count"]
sast_den = sast["groups"]["sast_only"]["total"] + sast["groups"]["sast_and_dast"]["total"]
dast_num = dast["groups"]["dast_only"]["covered_count"] + dast["groups"]["sast_and_dast"]["covered_count"]
dast_den = dast["groups"]["dast_only"]["total"] + dast["groups"]["sast_and_dast"]["total"]

def safe_pct(n, d):
    return round((n / d) * 100, 2) if d else 0.0

sast_pct = safe_pct(sast_num, sast_den)
dast_pct = safe_pct(dast_num, dast_den)

labels = ["SAST Detection", "DAST Detection"]
values = [sast_pct, dast_pct]
counts = [f"{sast_num}/{sast_den}", f"{dast_num}/{dast_den}"]

bars = ax1.bar(labels, values, color=[C_SAST, C_DAST], zorder=3)
for i, bar in enumerate(bars):
    h = bar.get_height()
    ax1.text(bar.get_x() + bar.get_width() / 2, h + 1.2, f"{values[i]}%", ha="center", va="bottom", fontsize=10, fontweight="bold", color=C_TEXT)
    ax1.text(bar.get_x() + bar.get_width() / 2, h - 6.5, counts[i], ha="center", va="bottom", fontsize=9, color=C_SUBTEXT)

ax1.set_ylim(0, 110)
ax1.set_ylabel("Detection Rate (%)", fontsize=9)
ax1.grid(axis="y", zorder=0)

out1 = base / "results/detection_count_by_group.png"
fig1.tight_layout()
fig1.savefig(out1, dpi=150, bbox_inches="tight", facecolor=C_BG)
plt.close(fig1)
print(f"Saved -> {out1}")

# ------------------ PLOT 2: Pie - Overall coverage across all 26 SNs
fig2, ax2 = plt.subplots(figsize=(6.5, 5), facecolor=C_BG)

sast_detected = set(sast["detected_sn_total"])
dast_detected = set(dast["detected_sn_total"])
all_sns = {f"{i:02d}" for i in range(1, 27)}

both_detected = sast_detected & dast_detected
sast_only_det = sast_detected - dast_detected
dast_only_det = dast_detected - sast_detected
neither = all_sns - sast_detected - dast_detected

sizes = [len(both_detected), len(sast_only_det), len(dast_only_det), len(neither)]
labels = [
    f"Both\n({len(both_detected)} SNs)",
    f"SAST only\n({len(sast_only_det)} SNs)",
    f"DAST only\n({len(dast_only_det)} SNs)",
    f"Neither\n({len(neither)} SNs)",
]
colors = [C_BOTH, C_SAST, C_DAST, C_MISSED]
explode = [0.04] * 4

wedges, texts, autotexts = ax2.pie(sizes, labels=None, colors=colors, explode=explode, autopct="%1.0f%%", startangle=120, pctdistance=0.65, wedgeprops={"linewidth": 1.5, "edgecolor": C_BG})
for at in autotexts:
    at.set_fontsize(9)
    at.set_color(C_BG)

legend_patches = [mpatches.Patch(color=c, label=l) for c, l in zip(colors, labels)]
ax2.legend(handles=legend_patches, loc="lower center", bbox_to_anchor=(0.5, -0.18), ncol=2, fontsize=8, framealpha=0.1)

total_covered = len(sast_detected | dast_detected)
ax2.text(0, 0, f"{total_covered}/26\ncovered", ha="center", va="center", fontsize=10, fontweight="bold", color=C_TEXT, bbox=dict(boxstyle="round,pad=0.3", facecolor=C_BG, edgecolor="none", alpha=0.7))
ax2.set_title("Overall Coverage Across 26 SNs", fontsize=10, fontweight="bold", pad=10)

out2 = base / "results/overall_coverage_pie.png"
fig2.tight_layout()
fig2.savefig(out2, dpi=150, bbox_inches="tight", facecolor=C_BG)
plt.close(fig2)
print(f"Saved -> {out2}")

# ------------------ PLOT 3: Horizontal bar - Detection rate % per group for both tools
fig3, ax3 = plt.subplots(figsize=(6.5, 5), facecolor=C_BG)

categories = [
    "SAST · SAST-only group\n(CodeQL, 7 SNs)",
    "SAST · Both-capable group\n(CodeQL, 13 SNs)",
    "DAST · DAST-only group\n(ZAP, 6 SNs)",
    "DAST · Both-capable group\n(ZAP, 13 SNs)",
]
percentages = [
    sast["groups"]["sast_only"]["percentage"],
    sast["groups"]["sast_and_dast"]["percentage"],
    dast["groups"]["dast_only"]["percentage"],
    dast["groups"]["sast_and_dast"]["percentage"],
]
bar_colors = [C_SAST, C_SAST, C_DAST, C_DAST]
covered = [
    sast["groups"]["sast_only"]["covered_count"],
    sast["groups"]["sast_and_dast"]["covered_count"],
    dast["groups"]["dast_only"]["covered_count"],
    dast["groups"]["sast_and_dast"]["covered_count"],
]
totals2 = [7, 13, 6, 13]

y = np.arange(len(categories))

ax3.barh(y, [100]*4, 0.5, color=C_GRID, zorder=2)
bars3 = ax3.barh(y, percentages, 0.5, color=bar_colors, zorder=3, alpha=0.9)

for i, (bar, pct, cov, tot) in enumerate(zip(bars3, percentages, covered, totals2)):
    label = f"{cov}/{tot}  ({pct}%)"
    x_pos = pct + 1.5
    ax3.text(x_pos, bar.get_y() + bar.get_height()/2, label, va="center", ha="left", fontsize=8.5, color=C_TEXT)

ax3.set_yticks(y)
ax3.set_yticklabels(categories, fontsize=8)
ax3.set_xlim(0, 130)
ax3.set_xlabel("Detection Rate (%)", fontsize=9)
ax3.set_title("Detection Rate by Tool & Group", fontsize=10, fontweight="bold", pad=10)
ax3.axvline(50, color=C_SUBTEXT, linewidth=0.8, linestyle=":", zorder=4)
ax3.axvline(100, color=C_SUBTEXT, linewidth=0.8, linestyle=":", zorder=4)
ax3.grid(axis="x", zorder=0)

out3 = base / "results/detection_rate_by_tool_and_group.png"
fig3.tight_layout()
fig3.savefig(out3, dpi=150, bbox_inches="tight", facecolor=C_BG)
plt.close(fig3)
print(f"Saved -> {out3}")
