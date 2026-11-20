// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint amount = balances[msg.sender];
        require(amount > 0, "No balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
    }
}

contract SafeBank {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint amount = balances[msg.sender];
        require(amount > 0, "No balance");
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}

contract UnsafeButImpossibleBank {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint amount = balances[msg.sender];
        require(amount > 0, "No balance");
        require(amount == 0, "Contradiction");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
    }
}

contract ProtectedBank {
    mapping(address => uint) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function withdraw() public nonReentrant {
        uint amount = balances[msg.sender];
        require(amount > 0);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}

contract OwnerProtectedBank {
    mapping(address => uint) public balances;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function withdraw() public onlyOwner {
        uint amount = balances[msg.sender];
        require(amount > 0);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}

contract InlineAuthBank {
    mapping(address => uint) public balances;
    address public owner;

    function withdraw() public {
        require(msg.sender == owner, "Not owner");
        uint amount = balances[msg.sender];
        require(amount > 0);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}

contract InitGuardedBank {
    mapping(address => uint) public balances;
    bool private initialized;

    function withdraw() public {
        require(!initialized, "Already initialized");
        initialized = true;
        uint amount = balances[msg.sender];
        require(amount > 0);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}

contract CEIGuardedBank {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint amount = balances[msg.sender];
        require(amount > 0);
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}

contract BaseGuard {
    bool internal locked;

    modifier baseNonReentrant() {
        require(!locked, "Reentrant");
        locked = true;
        _;
        locked = false;
    }
}

contract InheritedGuardBank is BaseGuard {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public baseNonReentrant {
        uint amount = balances[msg.sender];
        require(amount > 0);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}


contract Token {
    mapping(address => uint) public balances;
    function transfer(address to, uint amount) public {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}

contract Pool {
    Token public token;
    mapping(address => uint) public deposits;

    function withdraw() public {
        uint amount = deposits[msg.sender];
        require(amount > 0);
        // external call into Token
        token.transfer(msg.sender, amount);
        deposits[msg.sender] = 0;  // state write after external call
    }
}