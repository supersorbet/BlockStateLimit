// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IAntiMev {
  function onTransfer(address from, address to, uint256 amount, bool isTaxingInProgress) external;
}
