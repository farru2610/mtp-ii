import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os

PLOT_DIR = "plots"
os.makedirs(PLOT_DIR, exist_ok=True)

# ---------------------------------------------------
# Load benchmark results
# ---------------------------------------------------
with open("single_point_results.json", "r") as f:
    data = json.load(f)

df = pd.DataFrame(data)

# All degree values
degrees = sorted(df["degree"].unique())

# ---------------------------------------------------
# Plot helper
# ---------------------------------------------------
def plot_metric(metric, ylabel, filename):
    plt.figure(figsize=(8, 5))

    for curve in df["curve"].unique():
        curve_df = df[df["curve"] == curve]

        plt.plot(
            curve_df["degree"],
            curve_df[metric],
            marker="o",
            linewidth=2,
            label=curve
        )

    plt.xscale("log", base=2)

    # Force all degree values on x-axis
    plt.xticks(degrees, degrees)

    plt.xlabel("Polynomial Degree")
    plt.ylabel(ylabel)
    plt.title(f"{ylabel} vs Polynomial Degree")

    plt.grid(True, which="both", linestyle="--", alpha=0.5)
    plt.legend()

    plt.tight_layout()
    plt.savefig(os.path.join(PLOT_DIR, filename), dpi=300)
    plt.close()


# ---------------------------------------------------
# Individual Graphs
# ---------------------------------------------------
plot_metric("setup_ms", "Setup Time (ms)", "setup_time.png")
plot_metric("commit_ms", "Commit Time (ms)", "commit_time.png")
plot_metric("prove_ms", "Proof Generation Time (ms)", "prove_time.png")
plot_metric("verify_ms", "Verification Time (ms)", "verify_time.png")


# ---------------------------------------------------
# Scalar Multiplication Comparison
# ---------------------------------------------------
scalar_df = (
    df.groupby("curve")["scalar_mul_ms"]
    .first()
    .reset_index()
)

plt.figure(figsize=(6, 4))
plt.bar(scalar_df["curve"], scalar_df["scalar_mul_ms"])

for i, v in enumerate(scalar_df["scalar_mul_ms"]):
    plt.text(i, v, f"{v:.3f}", ha="center", va="bottom")

plt.ylabel("Time (ms)")
plt.title("Scalar Multiplication Benchmark")
plt.tight_layout()
plt.savefig(os.path.join(PLOT_DIR, "scalar_mul.png"), dpi=300)
plt.close()


# ---------------------------------------------------
# Pairing Comparison
# ---------------------------------------------------
pair_df = (
    df.groupby("curve")["pairing_ms"]
    .first()
    .reset_index()
)

plt.figure(figsize=(6, 4))
plt.bar(pair_df["curve"], pair_df["pairing_ms"])

for i, v in enumerate(pair_df["pairing_ms"]):
    plt.text(i, v, f"{v:.3f}", ha="center", va="bottom")

plt.ylabel("Time (ms)")
plt.title("Pairing Benchmark")
plt.tight_layout()
plt.savefig(os.path.join(PLOT_DIR, "pairing.png"), dpi=300)
plt.close()


# ---------------------------------------------------
# Proof Size Comparison
# ---------------------------------------------------
proof_df = (
    df.groupby("curve")["proof_bytes"]
    .first()
    .reset_index()
)

plt.figure(figsize=(6, 4))
plt.bar(proof_df["curve"], proof_df["proof_bytes"])

for i, v in enumerate(proof_df["proof_bytes"]):
    plt.text(i, v, str(v), ha="center", va="bottom")

plt.ylabel("Proof Size (Bytes)")
plt.title("Proof Size Comparison")
plt.tight_layout()
plt.savefig(os.path.join(PLOT_DIR, "proof_size.png"), dpi=300)
plt.close()


# ---------------------------------------------------
# Combined Plot for Each Curve
# ---------------------------------------------------
metrics = [
    ("setup_ms", "Setup"),
    ("commit_ms", "Commit"),
    ("prove_ms", "Prove"),
    ("verify_ms", "Verify")
]

for curve in df["curve"].unique():

    curve_df = df[df["curve"] == curve]

    plt.figure(figsize=(10, 6))

    for metric, label in metrics:
        plt.plot(
            curve_df["degree"],
            curve_df[metric],
            marker="o",
            linewidth=2,
            label=label
        )

    plt.xscale("log", base=2)
    plt.xticks(degrees, degrees)

    plt.xlabel("Polynomial Degree")
    plt.ylabel("Time (ms)")
    plt.title(f"KZG Performance Breakdown ({curve})")

    plt.grid(True, which="both", linestyle="--", alpha=0.5)
    plt.legend()

    plt.tight_layout()

    # Safe filename
    filename = curve.lower().replace("-", "_")

    plt.savefig(
        os.path.join(PLOT_DIR, f"combined_{filename}.png"),
        dpi=300
    )

    plt.close()
print("All plots generated successfully!")