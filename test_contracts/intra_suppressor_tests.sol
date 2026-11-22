// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Synthetic unit tests for PATHFINDER suppressors (intra-function patterns)
// These test FALSE POSITIVE suppression: Slither flags them, PATHFINDER should suppress with PPTs

// ============================================================
// TEST 1: MUTEX suppressor - manual lock in SAME function
// Pattern: flag = true before call, flag = false after call
// ============================================================
contract FP_MutexManual {
    bool public locked;
    
    function withdraw() external {
        // Manual mutex: set lock before call
        locked = true;
        // External call
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        // Release lock after call
        locked = false;
        // State write AFTER call - looks like reentrancy to Slither
        // But mutex pattern is present
    }
}

// ============================================================
// TEST 2: CEI suppressor - same variable written before call
// Pattern: balances[msg.sender] = 0 BEFORE call, then written again after
// ============================================================
contract FP_CEIProper {
    mapping(address => uint256) public balances;
    
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        // CEI: write the SAME variable to 0 BEFORE external call
        balances[msg.sender] = 0;
        // External call
        (bool success, ) = msg.sender.call{value: amount}("");
        // State write AFTER call (redundant but pattern is there)
        balances[msg.sender] = 0;
    }
}

// ============================================================
// TEST 3: AUTH suppressor - msg.sender check in SAME function
// Pattern: require(msg.sender == owner) before call
// ============================================================
contract FP_AuthInline {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    function withdraw() external {
        // Inline auth check
        require(msg.sender == owner, "Not owner");
        // External call
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        // State write AFTER call
    }
}

// ============================================================
// TEST 4: INIT suppressor - initialized check in SAME function
// Pattern: require(initialized) before call
// ============================================================
contract FP_InitInline {
    bool public initialized;
    
    function initialize() external {
        initialized = true;
    }
    
    function withdraw() external {
        // Inline init check
        require(initialized, "Not initialized");
        // External call
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        // State write AFTER call
    }
}

// ============================================================
// TEST 5: INHERIT suppressor - nested modifier guard
// ============================================================
abstract contract BaseLock {
    bool private locked;
    
    modifier baseLock() {
        require(!locked, "Reentrant");
        locked = true;
        _;
        locked = false;
    }
}

contract FP_InheritLock is BaseLock {
    function withdraw() external baseLock {
        // External call
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        // State write AFTER call - protected by inherited modifier
    }
}

// ============================================================
// TEST 5: TRUE POSITIVE - no protection, should ALWAYS be flagged
// ============================================================
contract TP_Vulnerable {
    mapping(address => uint256) public vulnBalances;
    
    function withdraw() external {
        uint256 amount = vulnBalances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        vulnBalances[msg.sender] = 0;  // State write AFTER call - REAL reentrancy
    }
}