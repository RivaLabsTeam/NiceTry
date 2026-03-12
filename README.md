# NiceTry
 
NiceTry is a smart wallet infrastructure project. The first key feature is our original quantum safe design achieved through ephemeral key pairs and account abstraction.
 
## Achieving Quantum Safety Through Ephemeral Key Pairs and Account Abstraction
 
We designed a quantum-safe wallet design that requires no changes to Ethereum's signature schemes or protocol rules. By leveraging account abstraction, we make each ECDSA key pair single-use: every transaction rotates the signer while the smart contract wallet address remains constant. This eliminates long-term public key exposure, the core vulnerability that Shor's algorithm would exploit, using only today's infrastructure. This aims to solve, at least in the short term, quantum security on the execution layer.
 
<img src="images/image.png" width="750"/>
 
The solution has been described in greater details in our [Ethresearch introduction post](#). This [repo](#) currently provides a simple implementation of the design on Base Sepolia.
 
A live demo of our quantum-safe design is available here: [https://nicetry.xyz/](https://nicetry.xyz/)

## Implementation

The rotation logic is implemented in two ways in this repo.

### SimpleAccount

The original implementation is a standalone ERC-4337 smart account with rotation baked directly into the account contract. Each user deploys their own `SimpleAccount` instance. The account handles validation, execution, and key rotation internally — no external dependencies beyond the EntryPoint.

### ERC-7579 Validator Module

As an extension of the core design, the rotation logic is also available as a standalone ERC-7579 validator module compatible with Biconomy Nexus and any other ERC-7579 compliant smart account.

Rather than deploying a custom `SimpleAccount`, users can install the rotating validator on an existing modular account. A single deployed module instance serves any number of accounts, each with its own independent key state.
