"""
Comparison plots for KZG, Bulletproofs, Dory, and Multilinear KZG
across BLS12-377, BLS12-381, and BN254 curves.

Outputs
-------
plots/<curve>_<metric>.png      – per-curve, all-protocol comparison (one metric)
plots/<curve>_combined.png      – per-curve 4-panel (setup/commit/prove/verify)
plots/<proto>_all_curves_<metric>.png – per-protocol, all-curve comparison
"""

import json
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

# ── paths ─────────────────────────────────────────────────────────────────────
HERE      = os.path.dirname(os.path.abspath(__file__))
PLOTS_DIR = os.path.join(HERE, "plots")
os.makedirs(PLOTS_DIR, exist_ok=True)

# ── load ──────────────────────────────────────────────────────────────────────
def load(name):
    with open(os.path.join(HERE, name)) as f:
        return json.load(f)

kzg_data  = load("single_point_results_Pip.json")
bp_data   = load("bulletproofs_results_Pip.json")
dory_data = load("dory_results.json")
mkzg_data = load("multilinear_kzg_results.json")

# ── normalise curve names (BN-254 → BN254) ────────────────────────────────────
def norm(c):
    return c.replace("BN-254", "BN254")

for dataset in (kzg_data, bp_data, dory_data, mkzg_data):
    for row in dataset:
        row["curve"] = norm(row["curve"])

CURVES = ["BLS12-377", "BLS12-381", "BN254"]

# ── per-protocol x-axis field ─────────────────────────────────────────────────
# all represent polynomial size n
X_KEY = {
    "KZG":             "degree",
    "Bulletproofs":    "n",
    "Dory":            "n",
    "Multilinear KZG": "poly_size",
}
DATASETS = {
    "KZG":             kzg_data,
    "Bulletproofs":    bp_data,
    "Dory":            dory_data,
    "Multilinear KZG": mkzg_data,
}

def rows_for(data, curve, x_key):
    out = [r for r in data if r["curve"] == curve and x_key in r]
    return sorted(out, key=lambda r: r[x_key])

# ── visual style ──────────────────────────────────────────────────────────────
PROTO_STYLE = {
    "KZG":             {"color": "#1565C0", "marker": "o",  "ls": "-"},
    "Bulletproofs":    {"color": "#2E7D32", "marker": "s",  "ls": "--"},
    "Dory":            {"color": "#BF360C", "marker": "^",  "ls": "-."},
    "Multilinear KZG": {"color": "#6A1B9A", "marker": "D",  "ls": ":"},
}
CURVE_STYLE = {
    "BLS12-377": {"color": "#C62828", "marker": "o",  "ls": "-"},
    "BLS12-381": {"color": "#E65100", "marker": "s",  "ls": "--"},
    "BN254":     {"color": "#00695C", "marker": "^",  "ls": "-."},
}

METRICS = [
    ("setup_ms",   "Setup Time (ms)"),
    ("commit_ms",  "Commit Time (ms)"),
    ("prove_ms",   "Prove Time (ms)"),
    ("verify_ms",  "Verify Time (ms)"),
    ("proof_bytes","Proof Size (bytes)"),
]

plt.rcParams.update({
    "font.family":   "DejaVu Serif",
    "font.size":     11,
    "axes.grid":     True,
    "grid.alpha":    0.3,
    "grid.linestyle":"--",
    "figure.dpi":    150,
})

_fmt = ticker.FuncFormatter(lambda x, _: f"{x:g}")

def _style_axes(ax, xlabel="Polynomial Size (n)", ylabel="", title=""):
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.xaxis.set_major_formatter(_fmt)
    ax.yaxis.set_major_formatter(_fmt)
    ax.set_xlabel(xlabel, fontsize=11)
    ax.set_ylabel(ylabel, fontsize=11)
    ax.set_title(title, fontsize=12, fontweight="bold")
    ax.legend(fontsize=9, framealpha=0.9, loc="upper left")

def save(fig, name):
    path = os.path.join(PLOTS_DIR, name)
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"  saved  {name}")

# ══════════════════════════════════════════════════════════════════════════════
# 1.  PER-CURVE, ALL-PROTOCOL individual plots
# ══════════════════════════════════════════════════════════════════════════════
print("── per-curve / per-metric ─────────────────────────────────────────────")
for curve in CURVES:
    ctag = curve.replace("-", "")  # BLS12381, BN254
    for mkey, mlabel in METRICS:
        fig, ax = plt.subplots(figsize=(8, 5))
        for proto, style in PROTO_STYLE.items():
            rs = rows_for(DATASETS[proto], curve, X_KEY[proto])
            xs = [r[X_KEY[proto]] for r in rs if mkey in r]
            ys = [r[mkey]         for r in rs if mkey in r]
            if xs:
                ax.plot(xs, ys, color=style["color"], marker=style["marker"],
                        linestyle=style["ls"], linewidth=1.8, markersize=6,
                        label=proto)
        _style_axes(ax, ylabel=mlabel,
                    title=f"{mlabel}  –  {curve}")
        save(fig, f"{ctag}_{mkey}.png")

# ══════════════════════════════════════════════════════════════════════════════
# 2.  PER-CURVE combined 4-panel (setup / commit / prove / verify)
# ══════════════════════════════════════════════════════════════════════════════
print("── per-curve combined ─────────────────────────────────────────────────")
PANEL_METRICS = [m for m in METRICS if m[0] != "proof_bytes"]

for curve in CURVES:
    ctag = curve.replace("-", "")
    fig, axes = plt.subplots(2, 2, figsize=(14, 9))
    fig.suptitle(f"Polynomial Commitment Schemes  –  {curve}",
                 fontsize=14, fontweight="bold", y=1.01)

    for ax, (mkey, mlabel) in zip(axes.flat, PANEL_METRICS):
        for proto, style in PROTO_STYLE.items():
            rs = rows_for(DATASETS[proto], curve, X_KEY[proto])
            xs = [r[X_KEY[proto]] for r in rs if mkey in r]
            ys = [r[mkey]         for r in rs if mkey in r]
            if xs:
                ax.plot(xs, ys, color=style["color"], marker=style["marker"],
                        linestyle=style["ls"], linewidth=1.8, markersize=5,
                        label=proto)
        _style_axes(ax, ylabel=mlabel, title=mlabel)

    fig.tight_layout()
    save(fig, f"{ctag}_combined.png")

# ══════════════════════════════════════════════════════════════════════════════
# 3.  PER-PROTOCOL, ALL-CURVE plots  (how curves compare within one scheme)
# ══════════════════════════════════════════════════════════════════════════════
print("── per-protocol / all-curves ──────────────────────────────────────────")
for proto, style in PROTO_STYLE.items():
    ptag = proto.replace(" ", "_")
    data = DATASETS[proto]
    xkey = X_KEY[proto]

    for mkey, mlabel in METRICS:
        fig, ax = plt.subplots(figsize=(8, 5))
        for curve, cstyle in CURVE_STYLE.items():
            rs = rows_for(data, curve, xkey)
            xs = [r[xkey] for r in rs if mkey in r]
            ys = [r[mkey] for r in rs if mkey in r]
            if xs:
                ax.plot(xs, ys, color=cstyle["color"], marker=cstyle["marker"],
                        linestyle=cstyle["ls"], linewidth=1.8, markersize=6,
                        label=curve)
        _style_axes(ax, ylabel=mlabel,
                    title=f"{proto}  –  {mlabel}  (all curves)")
        save(fig, f"{ptag}_allcurves_{mkey}.png")

print(f"\nAll plots saved to  {PLOTS_DIR}")
