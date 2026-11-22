#!/usr/bin/env python3
"""
Run suppressor unit tests with each PPT configuration.
Tests FALSE POSITIVE suppression on intra_suppressor_tests.sol
"""

import os
import subprocess
import sys
from pathlib import Path


CONFIGS = {
    "z3_only": {"Z3": "1", "PPT_MUTEX": "0", "PPT_AUTH": "0", "PPT_INIT": "0", "PPT_CEI": "0", "PPT_INHERIT": "0", "XCFG": "0"},
    "mutex_on": {"Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "0", "PPT_INIT": "0", "PPT_CEI": "0", "PPT_INHERIT": "0", "XCFG": "0"},
    "cei_on": {"Z3": "1", "PPT_MUTEX": "0", "PPT_AUTH": "0", "PPT_INIT": "0", "PPT_CEI": "1", "PPT_INHERIT": "0", "XCFG": "0"},
    "all_on": {"Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "1", "PPT_INIT": "1", "PPT_CEI": "1", "PPT_INHERIT": "1", "XCFG": "0"},
}


def run_slither(sol_file: str, env_vars: dict):
    env = os.environ.copy()
    for k, v in env_vars.items():
        env[f"PATHFINDER_{k}"] = v
    
    cmd = ["slither", sol_file, "--detect", "pathfinder"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def get_findings(stdout: str, stderr: str) -> list[str]:
    """Extract finding function names from slither output."""
    findings = []
    output = stdout + "\n" + stderr
    for line in output.splitlines():
        if "Reentrancy (single-contract" in line and "external call in" in line:
            # Extract function name: "external call in withdraw followed by"
            import re
            m = re.search(r"external call in (\w+) followed by", line)
            if m:
                findings.append(m.group(1))
    return findings


def main():
    test_file = Path("test_contracts/intra_suppressor_tests.sol")
    if not test_file.exists():
        print(f"ERROR: {test_file} not found")
        sys.exit(1)
    
    # Expected results for each config
    # Format: config_name -> set of function names that should be FOUND
    expectations = {
        "z3_only": {"withdraw"},  # FP_MutexManual, FP_CEIProper, TP_Vulnerable all flagged
        "mutex_on": {"withdraw"},  # FP_MutexManual suppressed, FP_CEIProper and TP_Vulnerable flagged
        "cei_on": {"withdraw"},    # FP_CEIProper and FP_MutexManual suppressed, TP_Vulnerable flagged
        "all_on": {"withdraw"},    # All FPs suppressed, only TP_Vulnerable flagged
    }
    
    print("=" * 80)
    print("INTRA-FUNCTION SUPPRESSOR UNIT TEST RESULTS")
    print("=" * 80)
    print(f"{'Config':<12} {'Expected':<25} {'Actual':<25} {'PASS'}")
    print("-" * 80)
    
    all_pass = True
    
    for config_name, env_vars in CONFIGS.items():
        returncode, stdout, stderr = run_slither(str(test_file), env_vars)
        found_funcs = set(get_findings(stdout, stderr))
        expected_funcs = expectations[config_name]
        
        passed = (found_funcs == expected_funcs)
        if not passed:
            all_pass = False
        
        expected_str = "{" + ", ".join(sorted(expected_funcs)) + "}"
        actual_str = "{" + ", ".join(sorted(found_funcs)) + "}"
        result = "✓" if passed else "✗ FAIL"
        
        print(f"{config_name:<12} {expected_str:<25} {actual_str:<25} {result}")
    
    print("-" * 80)
    if all_pass:
        print("ALL TESTS PASSED")
    else:
        print("SOME TESTS FAILED")
    print("=" * 80)
    
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()