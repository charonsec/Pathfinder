#!/usr/bin/env python3
"""
Shared configuration for PATHFINDER ablation runs.
All paths and settings configurable via environment variables.
"""

import os
from pathlib import Path


def get_dataset_dir() -> Path:
    """Get dataset directory from env var or default to ./Solidity"""
    return Path(os.getenv("PATHFINDER_DATASET_DIR", "./Solidity"))


def get_labels_path() -> Path:
    """Get labels CSV path from env var or default"""
    default = Path("/mnt/data/sc-developer-study-1/Empirical Evaluation of Security Analyzers/Tools_Labels/Reentrancy_labels.csv")
    return Path(os.getenv("PATHFINDER_LABELS_PATH", str(default)))


def get_solidity_dir() -> Path:
    """Get Solidity contracts directory"""
    dataset_dir = get_dataset_dir()
    # If dataset_dir already ends with Solidity, use it directly
    if dataset_dir.name == "Solidity":
        return dataset_dir
    return dataset_dir / "Solidity"


# Configurable parameters
CELERY_BROKER = os.getenv("PATHFINDER_REDIS_BROKER", "redis://localhost:6379/0")
CELERY_BACKEND = os.getenv("PATHFINDER_REDIS_BACKEND", "redis://localhost:6379/1")
TASK_TIMEOUT = int(os.getenv("PATHFINDER_TASK_TIMEOUT", "180"))

# Ablation configurations
CONFIGS = {
    "z3_only": {"Z3": "1", "PPT_MUTEX": "0", "PPT_AUTH": "0", "PPT_INIT": "0", "PPT_CEI": "0", "PPT_INHERIT": "0", "XCFG": "0"},
    "z3_ppt": {"Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "1", "PPT_INIT": "1", "PPT_CEI": "1", "PPT_INHERIT": "1", "XCFG": "0"},
    "full": {"Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "1", "PPT_INIT": "1", "PPT_CEI": "1", "PPT_INHERIT": "1", "XCFG": "1"},
    "full_no_mutex": {"Z3": "1", "PPT_MUTEX": "0", "PPT_AUTH": "1", "PPT_INIT": "1", "PPT_CEI": "1", "PPT_INHERIT": "1", "XCFG": "1"},
    "full_no_auth": {"Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "0", "PPT_INIT": "1", "PPT_CEI": "1", "PPT_INHERIT": "1", "XCFG": "1"},
    "full_no_init": {"Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "1", "PPT_INIT": "0", "PPT_CEI": "1", "PPT_INHERIT": "1", "XCFG": "1"},
    "full_no_cei": {"Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "1", "PPT_INIT": "1", "PPT_CEI": "0", "PPT_INHERIT": "1", "XCFG": "1"},
    "full_no_inherit": {"Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "1", "PPT_INIT": "1", "PPT_CEI": "1", "PPT_INHERIT": "0", "XCFG": "1"},
}


def extract_addr(fname: str) -> str | None:
    import re
    m = re.search(r'0x([a-fA-F0-9]{40})', fname)
    return m.group(0).lower() if m else None


def load_vuln_addrs() -> set[str]:
    """Load vulnerable contract addresses from labels CSV"""
    import pandas as pd
    labels_path = get_labels_path()
    if not labels_path.exists():
        raise FileNotFoundError(f"Labels file not found: {labels_path}. Set PATHFINDER_LABELS_PATH.")
    labels_df = pd.read_csv(labels_path)
    labels_df['addr'] = labels_df['contract_address'].apply(extract_addr)
    return set(labels_df[labels_df['label'] == 1]['addr'].tolist())


def load_nonvuln_addrs() -> set[str]:
    """Load non-vulnerable contract addresses from labels CSV"""
    import pandas as pd
    labels_path = get_labels_path()
    if not labels_path.exists():
        raise FileNotFoundError(f"Labels file not found: {labels_path}. Set PATHFINDER_LABELS_PATH.")
    labels_df = pd.read_csv(labels_path)
    labels_df['addr'] = labels_df['contract_address'].apply(extract_addr)
    return set(labels_df[labels_df['label'] == 0]['addr'].tolist())


def get_vuln_files(limit: int | None = None) -> list[Path]:
    """Get vulnerable Reentrancy contract files"""
    solidity_dir = get_solidity_dir()
    vuln_addrs = load_vuln_addrs()
    all_files = sorted(solidity_dir.glob('Reentrancy*1*.sol'))
    files = [f for f in all_files if extract_addr(f.name) in vuln_addrs]
    if limit:
        files = files[:limit]
    return files


def get_nonvuln_files(limit: int | None = None) -> list[Path]:
    """Get non-vulnerable Reentrancy contract files"""
    solidity_dir = get_solidity_dir()
    nonvuln_addrs = load_nonvuln_addrs()
    all_files = sorted(solidity_dir.glob('Reentrancy*0*.sol'))
    files = [f for f in all_files if extract_addr(f.name) in nonvuln_addrs]
    if limit:
        files = files[:limit]
    return files