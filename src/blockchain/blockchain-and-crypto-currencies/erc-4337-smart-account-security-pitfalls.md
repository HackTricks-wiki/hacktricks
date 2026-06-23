# ERC-4337 Smart Account Security Pitfalls

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction wallets को programmable systems में बदल देता है। core flow पूरे bundle में **validate-then-execute** होता है: `EntryPoint` किसी भी `UserOperation` को execute करने से पहले हर एक को validate करता है। यह ordering validation permissive, stateful, या bundler simulation rules के साथ inconsistent होने पर non-obvious attack surface बनाती है।

## 1) privileged functions का direct-call bypass
कोई भी externally callable `execute` (या fund-moving) function जो `EntryPoint` (या एक vetted executor module) तक restricted नहीं है, उसे सीधे call करके account drain किया जा सकता है।
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
सुरक्षित pattern: `EntryPoint` तक restrict करें, और admin/self-management flows (module install, validator changes, upgrades) के लिए `msg.sender == address(this)` का use करें।
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Unsigned or unchecked gas fields -> fee drain
यदि signature validation केवल intent (`callData`) को cover करती है, लेकिन gas-related fields को नहीं, तो bundler या frontrunner fees बढ़ा सकता है और ETH drain कर सकता है। signed payload को कम से कम इनसे bind करना चाहिए:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: `EntryPoint`-provided `userOpHash` (जिसमें gas fields शामिल हैं) का उपयोग करें और/या हर field को strictly cap करें।
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Stateful validation clobbering (bundle semantics)
क्योंकि सभी validations किसी भी execution से पहले run होती हैं, contract state में validation results store करना unsafe है। उसी bundle में कोई दूसरा op इसे overwrite कर सकता है, जिससे आपकी execution attacker-influenced state use करेगी।

`validateUserOp` में storage में write करने से बचें। अगर unavoidable हो, तो temporary data को `userOpHash` से key करें और use के बाद उसे deterministically delete करें (stateless validation prefer करें)।

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` को signatures को **this contract** और **this chain** से bind करना must है। Raw hash पर recover करने से signatures accounts या chains across replay हो सकती हैं।

EIP-712 typed data use करें (domain में `verifyingContract` और `chainId` शामिल हों) और success पर exact ERC-1271 magic value `0x1626ba7e` return करें।

## 5) Reverts do not refund after validation
एक बार `validateUserOp` सफल हो जाए, fees commit हो जाती हैं, भले ही बाद में execution revert हो जाए। Attackers बार-बार ऐसे ops submit कर सकते हैं जो fail होंगे और फिर भी account से fees collect करेंगे।

Paymasters के लिए, `validateUserOp` में shared pool से pay करना और `postOp` में users से charge करना fragile है क्योंकि `postOp` payment undo किए बिना revert हो सकता है। Validation के दौरान funds secure करें (per-user escrow/deposit), `postOp` को minimal और non-reverting रखें, और worst-case reimbursement path के लिए `paymasterPostOpGasLimit` budget करें।

## 6) Counterfactual deployment / factory assumptions
पहला `UserOperation` अक्सर `initCode` carry करता है, जिससे account validation के दौरान एक **factory** के through deploy होता है। यह path under-audit होना आसान है क्योंकि यह सिर्फ first use पर run होता है।

Common failures:

- Factory/initializer `msg.sender == entryPoint` को trust करता है, लेकिन ERC-4337 deployment path `initCode` को सीधे `EntryPoint` से call नहीं करता।
- Salt, owner, validator, या module configuration signed intent से पूरी तरह bound नहीं है, इसलिए एक frontrunner पहली deployment race करके attacker-controlled settings के साथ counterfactual address burn कर सकता है।
- Factory non-idempotent है, इसलिए repeated first-use flow wallet को brick कर देता है, बजाय पहले से created address return करने के।

Safe pattern: signed deployment parameters से expected sender recompute करें, deployment को deterministic बनाएं (typically `CREATE2`), और initialization को one-shot बनाएं।
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) वह validation logic जिसे bundlers reject करते हैं
Validation code local tests में सही हो सकता है, लेकिन real bundlers में unusable हो सकता है। Public bundlers `validateUserOp()` / `validatePaymasterUserOp()` को off-chain simulate करते हैं और inclusion से पहले आमतौर पर full `debug_traceCall(handleOps)` run करते हैं।

इसलिए validation के अंदर ये patterns dangerous बन जाते हैं:

- Block-dependent opcodes जैसे `TIMESTAMP`, `NUMBER`, या `BLOCKHASH`
- State writes जैसे `SSTORE`
- Storage पर unbounded iteration
- Arbitrary external calls या oracle reads जो simulation और inclusion के बीच बदल सकते हैं

Bad example:
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // SSTORE in validation
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
वैलिडेशन को एक deterministic, bounded preflight function की तरह treat करें। अगर आपको सच में shared state या external lookups चाहिए, तो उस complexity को staked/reputation-tracked entities में push करें और exact bundler simulation path को test करें, सिर्फ unit tests को नहीं।

## 8) ERC-7702 initialization frontrun
ERC-7702 एक EOA को single tx के लिए smart-account code चलाने देता है। अगर initialization externally callable हो, तो एक frontrunner खुद को owner set कर सकता है।

Mitigation: initialization को केवल **self-call** पर और सिर्फ एक बार allow करें।
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## जल्दी pre-merge checks
- `EntryPoint` के `userOpHash` का उपयोग करके signatures validate करें (gas fields bind करता है)।
- Privileged functions को उपयुक्त रूप से केवल `EntryPoint` और/या `address(this)` तक सीमित रखें।
- `validateUserOp` को stateless, deterministic, और bundler simulation rules के compatible रखें।
- ERC-1271 के लिए EIP-712 domain separation enforce करें और success पर `0x1626ba7e` return करें।
- `postOp` को minimal, bounded, और non-reverting रखें; validation के दौरान fees secure करें।
- पहले `initCode` path को अलग से test करें: deterministic deployment, idempotent factory behavior, और one-shot initialization।
- shipping से पहले full bundler simulation (`simulateValidation` plus a traced `handleOps`) run करें।
- ERC-7702 के लिए, init केवल self-call पर और केवल once allow करें।



## References

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [https://eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
{{#include ../../banners/hacktricks-training.md}}
