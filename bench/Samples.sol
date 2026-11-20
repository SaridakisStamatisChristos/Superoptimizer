// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

contract Samples {
    function quote(uint112 reserveIn, uint112 reserveOut, uint112 amountIn)
        external pure returns (uint256)
    {
        uint256 weighted = uint256(amountIn) * 997;
        return weighted * reserveOut / (uint256(reserveIn) * 1000 + weighted);
    }

    function pack(uint96 a, uint96 b, uint64 tag) external pure returns (uint256) {
        return (uint256(a) << 160) | (uint256(b) << 64) | tag;
    }

    function unpack(uint256 word) external pure returns (uint96, uint96, uint64) {
        return (uint96(word >> 160), uint96(word >> 64), uint64(word));
    }
}
