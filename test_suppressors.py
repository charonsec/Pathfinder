#!/usr/bin/env python3
"""
Run suppressor unit tests with each PPT configuration.
Verifies each suppressor fires when it should.
"""

import os
import subprocess
import sys
from pathlib import Path


CONFIGS = {
    "z3_only": {"Z3": "1", "PPT_MUTEX": "0", "PPT_AUTH": "0", "PPT_INIT": "0", "PPT_CEI": "0", "PPT_INHERIT": "0", "XCFG": "0"},
    "mutex_on": {"Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "0", "PPT_INIT": "0", "PPT_CEI": "0", "PPT_INHERIT": "0", "XCFG": "0"},
    "auth_on": {"Z3": "1", "PPT_MUTEX": "0", "PPT_AUTH": "1", "PPT_INIT": "0", "PPT_CEI": "0", "PPT_INHERIT": "0", "XCFG": "0"},
    "init_on": {"Z3": "1", "PPT_MUTEX": "0", "PPT_AUTH": "0", "PPT_INIT": "1", "PPT_CEI": "0", "PPT_INHERIT": "0", "XCFG": "0"},
    "cei_on": {"Z3": "1", "PPT_MUTEX": "0", "PPT_AUTH": "0", "PPT_INIT": "0", "PPT_CEI": "1", "PPT_INHERIT": "0", "XCFG": "0"},
    "inherit_on": {"Z3": "1", "PPT_MUTEX": "0", "PPT_AUTH": "0", "PPT_INIT": "0", "PPT_CEI": "0", "PPT_INHERIT": "1", "XCFG": "0"},
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


def has_finding(stdout: str, stderr: str, contract_name: str, function_name: str) -> bool:
    """Check if slither found reentrancy in specific function."""
    output = stdout + "\n" + stderr
    # Look for the finding line containing the function name
    for line in output.splitlines():
        if "Reentrancy" in line and function_name in line:
            return True
    return False


def main():
    test_file = Path("test_contracts/suppressor_unit_tests.sol")
    if not test_file.exists():
        print(f"ERROR: {test_file} not found")
        sys.exit(1)
    
    # Expected results: which configs should SUPPRESS each contract
    expectations = {
        "MutexTest.guardedWithdraw": ["mutex_on", "all_on"],
        "AuthTest.guardedWithdraw": ["auth_on", "all_on"],
        "InitTest.initialize": ["init_on", "all_on"],
        "CEITest.withdrawCEI": ["cei_on", "all_on"],
        "InheritTest.guardedWithdraw": ["inherit_on", "all_on"],
        "VulnerableTest.vulnerableWithdraw": [],  # Never suppressed
    }
    
    print("=" * 80)
    print("SUPPRESSOR UNIT TEST RESULTS")
    print("=" * 80)
    print(f"{'Contract.Function':<35} {'Config':<12} {'Finding':<8} {'Expected':<8} {'PASS'}")
    print("-" * 80)
    
    all_pass = True
    
    for contract_func, should_suppress in expectations.items():
        for config_name, env_vars in CONFIGS.items():
            returncode, stdout, stderr = run_slither(str(test_file), env_vars)
            found = has_finding(stdout, stderr, contract_func.split(".")[0], contract_func.split(".")[1])
            
            expected_suppressed = config_name in should_suppress
            expected_finding = not expected_suppressed
            
            passed = (found == expected_finding)
            if not passed:
                all_pass = False
            
            status = "FOUND" if found else "SUPPRESSED"
            expected = "FOUND" if expected_finding else "SUPPRESSED"
            result = "✓" if passed else "✗ FAIL"
            
            print(f"{contract_func:<35} {config_name:<12} {status:<8} {expected:<8} {result}")
    
    print("-" * 80)
    if all_pass:
        print("ALL TESTS PASSED")
    else:
        print("SOME TESTS FAILED")
    print("=" * 80)


if __name__ == "__main__":
    main()