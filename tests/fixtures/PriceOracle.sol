// PriceOracle-style vulnerable contract: a lending protocol that prices
// collateral directly from an AMM spot reserve (manipulable with a single
// flash loan), with no TWAP, time-weighted average, or secondary oracle.

contract VulnerableOracle {
    mapping(address => uint) public collateralOf;
    mapping(address => uint) public debtOf     ;
    address public uniswapPair;

    // VULN: prices from the live AMM spot reserve, no TWAP/derivation.
    // An attacker flash-loans tokens to skew reserves, inflates the spot
    // price, borrows against overvalued collateral, then repays the flash.
    function getPrice(uint reserve0, uint reserve1) public pure returns (uint) {
        return (reserve1 * 1e18) / reserve0;
    }

    // VULN: health factor trusts the manipulable spot price with no oracle.
    function borrow(uint amount, uint collateral) external {
        uint reserve0 = pairReserve0();
        uint reserve1 = pairReserve1();
        uint price = getPrice(reserve0, reserve1);
        uint value = (collateral * price) / 1e18;
        require(value >= amount, "under-collateralized");
        debtOf[msg.sender] += amount;
        collateralOf[msg.sender] += collateral;
    }

    function pairReserve0() public view returns (uint) {
        return 1e18;
    }

    function pairReserve1() public view returns (uint) {
        return 1e18;
    }
}