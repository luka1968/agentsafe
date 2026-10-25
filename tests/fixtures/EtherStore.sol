// EtherStore-style vulnerable contract (classic reentrancy teaching example)
// plus a deliberately overflow-vulnerable token for corroboration regression.

contract EtherStore {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0);
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");
        balances[msg.sender] = 0;
    }
}

contract VulnerableToken {
    mapping(address => uint) public balanceOf;
    uint public totalSupply;

    function batchTransfer(address[] memory receivers, uint amount) external {
        for (uint i = 0; i < receivers.length; i++) {
            balanceOf[receivers[i]] += amount;
            totalSupply += amount;
        }
    }
}
