// Safe regression fixtures: each must NOT trigger the P0-4 rules.
// 1) SafeEtherStore: CEI-satisfied withdraw (state update before external call).
// 2) SafeOracle: TWAP-derived price, not manipulable spot.
// 3) SafeFlash: state settled before external borrower callback.

contract SafeEtherStore {
    mapping(address => uint) public balances;

    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0);
        balances[msg.sender] = 0;                    // state update first
        (bool sent, ) = msg.sender.call{value: bal}(""); // then external call
        require(sent, "send failed");
    }
}

contract SafeOracle {
    uint public price;

    // TWAP: time-weighted average over a window, not a manipulable spot read.
    function updatePrice(uint cumulative0, uint cumulative1, uint lastTs) external {
        require(block.timestamp - lastTs > 0, "window too short");
        price = (cumulative1 * 1e18) / cumulative0;
    }
}

contract SafeFlash {
    mapping(address => uint) public balanceOf;
    uint public fee;

    function flashLoan(address token, uint amount, address borrower) external {
        // settle internal accounting BEFORE the external borrower callback
        balanceOf[borrower] += amount;
        fee += amount / 100;
        token.call(abi.encodeWithSignature("transfer(address,uint256)", borrower, amount));
    }
}