// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Synthetic unit tests for PATHFINDER suppressors
// These test FALSE POSITIVE suppression: Slither flags them, PATHFINDER should suppress with PPTs

// ============================================================
// TEST 1: FALSE POSITIVE with mutex-like pattern (not a real mutex)
// Slither flags this, but PATHFINDER with MUTEX PPT should suppress
// ============================================================
contract FP_MutexLike {
    bool public flag;
    
    function setFlag() external {
        flag = true;
    }
    
    function withdraw() external {
        // External call
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        // State write AFTER call - looks like reentrancy to Slither
        // But there's a flag check that acts like a weak mutex
        if (flag) {
            flag = false;  // This write confuses Slither
        }
    }
}

// ============================================================
// TEST 2: FALSE POSITIVE with auth-like pattern
// Slither flags, but PATHFINDER with AUTH PPT should suppress
// ============================================================
contract FP_AuthLike {
    address public admin;
    
    constructor() {
        admin = msg.sender;
    }
    
    function setAdmin(address _admin) external {
        admin = _admin;
    }
    
    function withdraw() external {
        // External call
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        // State write AFTER call
        // There's an admin check but it's not a proper modifier
        if (msg.sender == admin) {
            // This is a weak auth check
        }
    }
}

// ============================================================
// TEST 3: FALSE POSITIVE with init-like pattern
// Slither flags, but PATHFINDER with INIT PPT should suppress
// ============================================================
contract FP_InitLike {
    bool public initialized = false;
    
    function initialize() external {
        initialized = true;
    }
    
    function withdraw() external {
        // External call
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        // State write AFTER call
        // There's an initialized check but not a proper initializer modifier
        if (initialized) {
            // Weak init check
        }
    }
}

// ============================================================
// TEST 4: FALSE POSITIVE with CEI-like pattern (write before call but not the same variable)
// Slither flags, but PATHFINDER with CEI PPT should suppress
// ============================================================
contract FP_CEILike {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public otherState;
    
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        // Write to DIFFERENT state variable before call - looks like CEI but isn't
        otherState[msg.sender] = 1;
        // External call
        (bool success, ) = msg.sender.call{value: amount}("");
        // State write AFTER call
        balances[msg.sender] = 0;
    }
}

// ============================================================
// TEST 5: TRUE POSITIVE - should ALWAYS be flagged
// ============================================================
contract TP_Vulnerable {
    mapping(address => uint256) public balances;
    
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;  // State write AFTER call - REAL reentrancy
    }
}