# Directional Block Limit Protection 🛡️

Directional Block Limit Protection is a smart contract system designed to prevent sandwich attacks by enforcing directional transaction limits per block. This ensures each address can perform only one incoming and one outgoing transaction within a single block, mitigating front-running and MEV exploits.

## Features

- **Directional Transaction Limits**: Restricts each address to one incoming and one outgoing transaction per block.
- **Exemption Mechanism**: Allows whitelisting of specific addresses and factory contracts.
- **Gas Optimized**: Efficient bit manipulation for minimal gas usage.
- **Owner Controlled**: Administrative functions for managing exemptions and whitelists.

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/your-repo/directional-block-limit.git
   cd directional-block-limit
   ```

2. **Install Dependencies**

   ```bash
   npm install
   ```

3. **Compile Contracts**

   ```bash
   npx hardhat compile
   ```


### Integrate with Your Token

Modify your ERC-20 token contract to call `onTransfer` during transfers.

```solidity
function transfer(address to, uint256 amount) public override returns (bool) {
directionalBlockLimit.onTransfer(msg.sender, to, amount, false);
return super.transfer(to, amount);
}```


### Configure Protection

Whitelist factories and exempt addresses as needed.
```javascript
await directionalBlockLimit.setFactoryWhitelist("FACTORY_ADDRESS", 2, true);
await directionalBlockLimit.setProteccExemption("EXEMPT_ADDRESS", true);```