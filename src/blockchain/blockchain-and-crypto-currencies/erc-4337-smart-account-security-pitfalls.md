# ERC-4337 Smart Account Security Pitfalls

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction wallets को programmable systems में बदलता है। इसका core flow पूरे bundle में **validate-then-execute** होता है: `EntryPoint` किसी भी `UserOperation` को execute करने से पहले हर `UserOperation` को validate करता है। यह ordering तब non-obvious attack surface उत्पन्न करती है, जब validation permissive, stateful, या bundler simulation rules के साथ inconsistent हो।

## 1) Privileged functions का Direct-call bypass
कोई भी externally callable `execute` (या funds transfer करने वाला) function, जो `EntryPoint` (या किसी vetted executor module) तक restricted नहीं है, account को drain करने के लिए सीधे call किया जा सकता है।<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
सुरक्षित pattern: इसे केवल `EntryPoint` तक सीमित रखें, और admin/self-management flows (module install, validator changes, upgrades) के लिए `msg.sender == address(this)` का उपयोग करें।
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Unsigned or unchecked gas fields -> fee drain
यदि signature validation केवल intent (`callData`) को कवर करता है, लेकिन gas-related fields को नहीं, तो bundler या frontrunner fees बढ़ाकर ETH drain कर सकता है। Signed payload को कम-से-कम इन fields से bind होना चाहिए:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: `EntryPoint` द्वारा प्रदान किए गए `userOpHash` का उपयोग करें (जिसमें gas fields शामिल होते हैं) और/या प्रत्येक field पर सख्त cap लगाएँ।<sup>[[1]](#references)</sup>
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
क्योंकि सभी validations किसी भी execution से पहले run होती हैं, contract state में validation results store करना unsafe है। उसी bundle में मौजूद कोई अन्य op इसे overwrite कर सकता है, जिससे आपका execution attacker-influenced state का उपयोग कर सकता है।<sup>[[1]](#references)</sup>

`validateUserOp` में storage लिखने से बचें। यदि यह unavoidable हो, तो temporary data को `userOpHash` के आधार पर key करें और उपयोग के बाद उसे deterministic तरीके से delete करें (stateless validation को प्राथमिकता दें)।<sup>[[1]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` को signatures को **इस contract** और **इस chain** से bind करना आवश्यक है। Raw hash पर recover करने से signatures अलग-अलग accounts या chains पर replay हो सकते हैं।<sup>[[1]](#references)</sup>

EIP-712 typed data का उपयोग करें (domain में `verifyingContract` और `chainId` शामिल हों) और success पर exact ERC-1271 magic value `0x1626ba7e` return करें।<sup>[[1]](#references)</sup>

## 5) Reverts do not refund after validation
एक बार `validateUserOp` सफल हो जाने पर fees commit हो जाती हैं, भले ही execution बाद में revert हो जाए। Attackers बार-बार ऐसी ops submit कर सकते हैं जो fail होंगी और फिर भी account से fees collect कर सकते हैं।<sup>[[1]](#references)</sup>

Paymasters के लिए, `validateUserOp` में shared pool से payment करना और `postOp` में users से charge करना fragile है, क्योंकि payment को undo किए बिना `postOp` revert हो सकता है। Validation के दौरान funds secure करें (per-user escrow/deposit), `postOp` को minimal और non-reverting रखें, और worst-case reimbursement path के लिए `paymasterPostOpGasLimit` का budget निर्धारित करें।<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
पहली `UserOperation` में अक्सर `initCode` शामिल होता है, जिससे validation के दौरान account को **factory** के माध्यम से deploy किया जाता है। इस path का under-audit रह जाना आसान है, क्योंकि यह केवल first use पर run होता है।<sup>[[2]](#references)</sup>

Common failures:

- Factory/initializer `msg.sender == entryPoint` पर भरोसा करता है, लेकिन ERC-4337 deployment path `initCode` को सीधे `EntryPoint` से call **नहीं** करता।
- Salt, owner, validator या module configuration signed intent से पूरी तरह bound नहीं होती, इसलिए frontrunner first deployment को race करके counterfactual address को attacker-controlled settings के साथ burn कर सकता है।
- Factory non-idempotent है, इसलिए repeated first-use flow पहले से बनाए गए address को return करने के बजाय wallet को brick कर देता है।

Safe pattern: signed deployment parameters से expected sender को recompute करें, deployment को deterministic बनाएं (आमतौर पर `CREATE2`), और initialization को one-shot बनाएं।<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validation logic जिसे bundlers reject करते हैं
Validation code local tests में सही हो सकता है और फिर भी वास्तविक bundlers में अनुपयोगी हो सकता है। Public bundlers off-chain `validateUserOp()` / `validatePaymasterUserOp()` को simulate करते हैं और inclusion से पहले सामान्यतः पूरा `debug_traceCall(handleOps)` चलाते हैं।<sup>[[3]](#references)</sup>

इस कारण validation के अंदर ये patterns खतरनाक हैं:

- Block-dependent opcodes जैसे `TIMESTAMP`, `NUMBER`, या `BLOCKHASH`
- State writes जैसे `SSTORE`
- Storage पर unbounded iteration
- Arbitrary external calls या oracle reads, जो simulation और inclusion के बीच बदल सकते हैं

खराब उदाहरण:
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
Validation को एक deterministic, bounded preflight function के रूप में मानें। यदि आपको वास्तव में shared state या external lookups की आवश्यकता है, तो उस complexity को staked/reputation-tracked entities में डालें और केवल unit tests पर निर्भर रहने के बजाय exact bundler simulation path का परीक्षण करें।

## 8) ERC-7702 initialization frontrun
ERC-7702 किसी EOA को single tx के लिए smart-account code चलाने देता है। यदि initialization externally callable है, तो एक frontrunner स्वयं को owner के रूप में set कर सकता है।<sup>[[1]](#references)</sup>

Mitigation: initialization की अनुमति केवल **self-call** पर दें और वह भी केवल एक बार।<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## त्वरित pre-merge जाँचें
- `EntryPoint` के `userOpHash` का उपयोग करके signatures validate करें (यह gas fields को bind करता है)।
- आवश्यकतानुसार privileged functions को केवल `EntryPoint` और/या `address(this)` तक सीमित करें।
- `validateUserOp` को stateless, deterministic और bundler simulation rules के साथ compatible रखें।
- ERC-1271 के लिए EIP-712 domain separation लागू करें और success पर `0x1626ba7e` return करें।
- `postOp` को minimal, bounded और non-reverting रखें; validation के दौरान fees को secure करें।
- पहले `initCode` path का अलग से परीक्षण करें: deterministic deployment, idempotent factory behavior और one-shot initialization।
- shipping से पहले full bundler simulation (`simulateValidation` और traced `handleOps`) चलाएँ।
- ERC-7702 के लिए init को केवल self-call पर और केवल एक बार allow करें।

## संदर्भ

- [1] [ERC-4337 smart accounts में छह गलतियाँ (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Alt Mempool का उपयोग करके Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)
- [3] [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)

{{#include ../../banners/hacktricks-training.md}}
