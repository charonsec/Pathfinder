# PATHFINDER: Path-Feasibility-Aware Cross-Contract Reentrancy Detection

A Slither plugin that adds SMT-based path feasibility checking (Z3) to reentrancy detection, with configurable protection suppressors and cross-contract analysis for ablation studies.

## Overview

This project implements a reentrancy detector that goes beyond syntactic pattern matching by using Z3 SMT solver to verify whether the path to a reentrancy vulnerability is actually feasible. It supports ablation of 5 protection suppressors to measure their individual contribution to false positive reduction.

### Key Features

- **Z3 Path Feasibility**: Checks if path constraints from external call to state write are SAT/UNSAT/UNKNOWN
- **5 Protection Suppressors** (all configurable via env vars):
  - **Mutex**: `nonReentrant` modifiers, manual lock patterns, inherited guards
  - **Authorization**: `onlyOwner`, `onlyRole`, inline `msg.sender` checks
  - **Initialization**: `initializer`, `onlyInitializing` modifiers
  - **CEI**: Checks-effects-interactions pattern (state zeroed/checked before call)
  - **Inherited**: Nested modifier guards
- **Cross-Contract Analysis**: Builds call graph across contracts in compilation unit, analyzes callbacks via `receive`/`fallback`
- **Solc Auto-Switching**: Automatically installs/uses correct solc version per contract
- **Ablation Infrastructure**: 8-config matrix dispatched via Celery for parallel evaluation

## Installation

```bash
# Clone
git clone https://github.com/charonsec/Pathfinder.git
cd Pathfinder

# Create venv and install
python3 -m venv .venv
source .venv/bin/activate
pip install -e . --break-system-packages

# Install solc versions (auto-handled at runtime, but can pre-install)
solc-select install 0.4.25 0.5.16 0.6.12 0.8.20  # etc.

# Start Redis (required for Celery)
redis-server --port 6379
```

## Quick Test

```bash
# Run detector on test contract (all protections OFF, Z3 ON)
PATHFINDER_Z3=1 PATHFINDER_PPT_MUTEX=0 PATHFINDER_PPT_AUTH=0 \
PATHFINDER_PPT_INIT=0 PATHFINDER_PPT_CEI=0 PATHFINDER_PPT_INHERIT=0 \
PATHFINDER_XCFG=0 slither test_contracts/reentrancy_test.sol --detect pathfinder
```

Expected: Flags `VulnerableBank.withdraw` and `Pool.withdraw` (cross-contract), suppresses protected variants.

## Ablation Study

### Configuration Matrix

| Config | Z3 | Mutex | Auth | Init | CEI | Inherit | XCFG | Purpose |
|--------|----|-------|------|------|-----|---------|------|---------|
| `z3_only` | 1 | 0 | 0 | 0 | 0 | 0 | 0 | Baseline Z3 only |
| `z3_ppt` | 1 | 1 | 1 | 1 | 1 | 1 | 0 | All protections (single-contract) |
| `full` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | All + cross-contract |
| `full_no_mutex` | 1 | 0 | 1 | 1 | 1 | 1 | 1 | Ablate mutex |
| `full_no_auth` | 1 | 1 | 0 | 1 | 1 | 1 | 1 | Ablate auth |
| `full_no_init` | 1 | 1 | 1 | 0 | 1 | 1 | 1 | Ablate init |
| `full_no_cei` | 1 | 1 | 1 | 1 | 0 | 1 | 1 | Ablate CEI |
| `full_no_inherit` | 1 | 1 | 1 | 1 | 1 | 0 | 1 | Ablate inherit |

### Run on ScBench Dataset

```bash
# Terminal 1: Start Celery worker
celery -A pathfinder.celery_app worker --loglevel=info --concurrency=2

# Terminal 2: Run ablation on vulnerable Reentrancy contracts (label=1)
python run_vuln_reentrancy.py 95   # 95 vuln contracts × 8 configs = 760 tasks

# Terminal 2 (after above completes): Run on non-vulnerable (label=0)
python run_nonvuln_reentrancy.py 30  # sample of 30 non-vuln × 8 configs = 240 tasks
```

### Evaluate Results

```bash
python evaluate_ablation.py
```

Outputs precision/recall/F1/specificity table for all 8 configs.

## Results (ScBench: 757 vuln + 238 non-vuln = 995 contracts)

| Config | TP | FP | TN | FN | Precision | Recall | F1 | Specificity |
|--------|----|----|----|----|-----------|--------|-----|-------------|
| **full_no_cei** | 89 | 10 | 19 | 5 | **0.899** | **0.947** | **0.922** | 0.655 |
| z3_only | 89 | 15 | 15 | 6 | 0.856 | 0.937 | 0.894 | 0.500 |
| z3_ppt / full | 70 | 10 | 20 | 25 | 0.875 | 0.737 | 0.800 | 0.667 |
| full_no_mutex | 70 | 10 | 20 | 25 | 0.875 | 0.737 | 0.800 | 0.667 |
| full_no_auth | 70 | 15 | 15 | 25 | 0.824 | 0.737 | 0.778 | 0.500 |
| full_no_init | 70 | 10 | 20 | 24 | 0.875 | 0.745 | 0.805 | 0.667 |
| full_no_inherit | 70 | 10 | 19 | 25 | 0.875 | 0.737 | 0.800 | 0.655 |

### Key Finding

**CEI suppressor is the single largest contributor to false negative rate** — removing it recovers 94.7% recall with only 10 false positives. All other suppressors have similar moderate impact (~73-74% recall each).

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Ablation   │────▶│   Celery     │────▶│   Slither   │
│  Producer   │     │   Workers    │     │  + PATH-    │
│  (8 configs)│     │  (parallel)  │     │  FINDER     │
└─────────────┘     └──────────────┘     └──────┬──────┘
                                                │
                        ┌───────────────────────┘
                        ▼
               ┌────────────────┐
               │   Z3 Solver    │
               │  (path cond.)  │
               └────────────────┘
```

### Detector Pipeline (`pathfinder/detector.py`)

1. **Build Cross-Contract Call Graph** — resolves `HighLevelCall`/`LowLevelCall` to known contracts
2. **For each entry-point function**:
   - Check 5 protection suppressors (guarded by env vars)
   - Collect path conditions (binary comparisons) from CFG
   - Query Z3 for SAT/UNSAT/UNKNOWN with timeout
   - If SAT + cross-contract enabled: analyze callback functions in target contract
3. **Return findings** with path feasibility status

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PATHFINDER_Z3` | 1 | Enable Z3 path feasibility |
| `PATHFINDER_PPT_MUTEX` | 1 | Enable mutex suppressor |
| `PATHFINDER_PPT_AUTH` | 1 | Enable authorization suppressor |
| `PATHFINDER_PPT_INIT` | 1 | Enable initialization suppressor |
| `PATHFINDER_PPT_CEI` | 1 | Enable CEI suppressor |
| `PATHFINDER_PPT_INHERIT` | 1 | Enable inherited guard suppressor |
| `PATHFINDER_XCFG` | 1 | Enable cross-contract analysis |
| `PATHFINDER_Z3_TIMEOUT_MS` | 5000 | Z3 solver timeout (ms) |
| `PATHFINDER_SLITHER_BIN` | auto | Override slither binary path |
| `PATHFINDER_SOLC_ARTIFACTS` | auto | Override solc artifacts dir |
| `PATHFINDER_DATASET_DIR` | `./Solidity` | Dataset directory for ablation |
| `PATHFINDER_REDIS_BROKER` | `redis://localhost:6379/0` | Celery broker |
| `PATHFINDER_REDIS_BACKEND` | `redis://localhost:6379/1` | Celery result backend |

## Dataset

Uses **ScBench** (from Khimchenko et al., NDSS 2025):
- 653 labeled Solidity contracts
- Ground truth: `Reentrancy.csv` (0/1 labels)
- Contracts organized as `Reentrancy*{0,1}*0xADDRESS.sol` where `0`=non-vuln, `1`=vuln

## Requirements

- Python 3.10+
- Slither 0.10+
- Z3 solver 4.12+
- solc-select (for multi-version compilation)
- Redis (for Celery)
- Celery 5.3+

## Research Context

This is Semester 1 of a 2-semester project:
- **Semester 1**: SMT-based path feasibility + ablation on ScBench (this repo)
- **Semester 2**: Generalize to other vulnerability classes (Integer Overflow, Suicide), add explainability, large-scale eval on Clairvoyance (17K contracts)

## Citation

If you use this work, please cite:
```bibtex
@inproceedings{pathfinder2025,
  title={Path-Feasibility-Aware Cross-Contract Reentrancy Detection with Low False Positives},
  author={...},
  booktitle={...},
  year={2025}
}
```

## License

MIT