// FlashLoan-style vulnerable contract: a flash-loan callback that makes a
// state write AFTER an external token call, letting the borrower re-enter and
// manipulate accounting before the state is settled (classic check-then-act /
// reentrancy-in-flashloan regression fixture).

contract VulnerableFlash {
    mapping(address => uint) public balanceOf;
    uint public fee;

    // Correctly: transfer token, then call borrower callback.
    function flashLoan(address token, uint amount, address borrower) external {
        require(token.call(abi.encodeWithSignature(
            "transfer(address,uint256)", borrower, amount)));
        // VULN: state write AFTER external callback lets borrower re-enter.
        balanceOf[borrower] += amount;
        fee += amount / 100;
    }
}