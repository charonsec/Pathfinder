// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Synthetic unit tests for PATHFINDER suppressors
// Each contract should be SUPPRESSED (not flagged) when the corresponding PPT is enabled

// ============================================================
// TEST 1: MUTEX suppressor (nonReentrant modifier)
// Expected: NOT flagged when PATHFINDER_PPT_MUTEX=1
// ============================================================
contract MutexTest {
    bool private locked;
    
    modifier nonReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }
    
    function guardedWithdraw() external nonReentrant {
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        // State write AFTER external call - would be reentrancy without mutex
    }
}

// ============================================================
// TEST 2: AUTH suppressor (onlyOwner)
// Expected: NOT flagged when PATHFINDER_PPT_AUTH=1
// ============================================================
contract AuthTest {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    function guardedWithdraw() external onlyOwner {
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        // State write AFTER external call - would be reentrancy without auth
    }
}

// ============================================================
// TEST 3: INIT suppressor (initializer)
// Expected: NOT flagged when PATHFINDER_PPT_INIT=1
// ============================================================
contract InitTest {
    bool public initialized;
    
    modifier initializer() {
        require(!initialized, "Already initialized");
        _;
        initialized = true;
    }
    
    function initialize() external initializer {
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        // State write AFTER external call - would be reentrancy without init guard
    }
}

// ============================================================
// TEST 4: CEI suppressor (Checks-Effects-Interactions)
// Expected: NOT flagged when PATHFINDER_PPT_CEI=1
// ============================================================
contract CEITest {
    mapping(address => uint256) public balances;
    
    function withdrawCEI() external {
        uint256 amount = balances[msg.sender];
        // EFFECTS first: zero the balance BEFORE external call
        balances[msg.sender] = 0;
        // INTERACTIONS last
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}

// ============================================================
// TEST 5: INHERIT suppressor (nested modifier guard)
// Expected: NOT flagged when PATHFINDER_PPT_INHERIT=1
// ============================================================
abstract contract BaseGuard {
    bool private locked;
    
    modifier baseLock() {
        require(!locked, "Reentrant");
        locked = true;
        _;
        locked = false;
    }
}

contract InheritTest is BaseGuard {
    function guardedWithdraw() external baseLock {
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        // State write AFTER external call - protected by inherited modifier
    }
}

// ============================================================
// TEST 6: VULNERABLE (no protection)
// Expected: ALWAYS flagged regardless of PPT settings
// ============================================================
contract VulnerableTest {
    mapping(address => uint256) public balances;
    
    function vulnerableWithdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        // State write AFTER external call - REENTRANCY
        balances[msg.sender] = 0;
    }
}