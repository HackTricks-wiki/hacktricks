# ERC-4337 Smart Account Security Pitfalls

ERC-4337 account abstraction wallets को programmable systems में बदलता है। इसका core flow पूरे bundle में **validate-then-execute** होता है: `EntryPoint` किसी भी `UserOperation` को execute करने से पहले हर `UserOperation` को validate करता है।<sup>[[5]](#references)</sup> यह क्रम तब non-obvious attack surface बनाता है, जब validation permissive, stateful या bundler simulation rules के साथ inconsistent हो।

## 1) Privileged functions का Direct-call bypass

कोई भी externally callable `execute` (या fund-moving) function, जो `EntryPoint` (या vetted executor module) तक restricted नहीं है, account को drain करने के लिए सीधे call किया जा सकता है।<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
सुरक्षित pattern: `EntryPoint` तक सीमित रखें, और admin/self-management flows (module install, validator changes, upgrades) के लिए `msg.sender == address(this)` का उपयोग करें।<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Unsigned या unchecked gas fields -> fee drain
यदि signature validation केवल intent (`callData`) को cover करता है, लेकिन gas-related fields को नहीं, तो bundler या frontrunner fees बढ़ाकर ETH drain कर सकता है। Signed payload को कम-से-कम निम्नलिखित से bind होना चाहिए:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: `EntryPoint` द्वारा प्रदान किए गए `userOpHash` का उपयोग करें (जिसमें gas fields शामिल होते हैं) और/या प्रत्येक field पर सख्त cap लगाएं।<sup>[[2]](#references)[[5]](#references)</sup>
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
क्योंकि सभी validations किसी भी execution से पहले run होते हैं, contract state में validation results store करना unsafe है। उसी bundle में कोई अन्य op इसे overwrite कर सकता है, जिससे आपका execution attacker-influenced state का उपयोग कर सकता है।<sup>[[2]](#references)</sup>

`validateUserOp` में storage लिखने से बचें। यदि यह unavoidable हो, तो temporary data को `userOpHash` के आधार पर key करें और उपयोग के बाद इसे deterministically delete करें (stateless validation को प्राथमिकता दें)।<sup>[[2]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` को signatures को **इस contract** और **इस chain** से bind करना चाहिए। Raw hash पर recover करने से signatures अलग-अलग accounts या chains पर replay किए जा सकते हैं।<sup>[[1]](#references)[[4]](#references)</sup>

EIP-712 typed data का उपयोग करें (domain में `verifyingContract` और `chainId` शामिल हों) और success पर exact ERC-1271 magic value `0x1626ba7e` return करें।<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Reverts do not refund after validation
जब `validateUserOp` सफल हो जाता है, तो बाद में execution revert होने पर भी fees committed रहती हैं। Attackers बार-बार ऐसी ops submit कर सकते हैं जो fail होंगी और फिर भी account से fees collect कर सकते हैं।<sup>[[2]](#references)</sup>

Paymasters के लिए, `validateUserOp` में shared pool से payment करना और `postOp` में users से charge करना fragile है, क्योंकि payment को undo किए बिना `postOp` revert हो सकता है। Validation के दौरान funds secure करें (per-user escrow/deposit), `postOp` को minimal और non-reverting रखें, और worst-case reimbursement path के लिए `paymasterPostOpGasLimit` का budget निर्धारित करें।<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
पहली `UserOperation` में अक्सर `initCode` होता है, जिसके कारण validation के दौरान account को **factory** के माध्यम से deploy किया जाता है। इस path का कम audit होना आसान है, क्योंकि यह केवल first use पर run होता है।<sup>[[5]](#references)</sup>

Common failures में शामिल हैं:<sup>[[5]](#references)</sup>

- Factory/initializer `msg.sender == entryPoint` पर trust करता है, लेकिन ERC-4337 deployment path `initCode` को सीधे `EntryPoint` से call **नहीं** करता।
- Salt, owner, validator या module configuration signed intent से पूरी तरह bound नहीं है, इसलिए कोई frontrunner first deployment को race करके counterfactual address को attacker-controlled settings के साथ burn कर सकता है।
- Factory non-idempotent है, इसलिए repeated first-use flow पहले से बनाए गए address को return करने के बजाय wallet को brick कर देता है।

Safe pattern: signed deployment parameters से expected sender को फिर से compute करें, deployment को deterministic बनाएं (आमतौर पर `CREATE2`), और initialization को one-shot बनाएं।<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validation logic जिसे bundlers reject करते हैं

Validation code local tests में सही हो सकता है, फिर भी real bundlers में unusable हो सकता है। Bundlers validation को कई बार run करते हैं और submission से पहले traced full-bundle validation करनी चाहिए।<sup>[[6]](#references)</sup>

इन validation-scope rules के तहत, ये patterns dangerous हैं:<sup>[[6]](#references)</sup>

- Block-dependent opcodes जैसे `TIMESTAMP`, `NUMBER`, या `BLOCKHASH`
- Allowed account/entity scope के बाहर storage access, या storage पर unbounded iteration
- External calls या oracle reads, जो allowed validation scope के बाहर mutable state पर depend करते हैं

खराब उदाहरण:
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // stateful validation can be clobbered by another op
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
Validation को एक deterministic, bounded preflight function मानें। यदि shared state या external lookups आवश्यक हों, तो staked-entity rules का पालन करें और केवल unit tests के बजाय उसी multi-pass bundler simulation path को test करें।<sup>[[6]](#references)</sup>

## 8) ERC-7702 initialization frontrun
ERC-7702 किसी EOA को smart-account code के लिए persistent delegation देता है; delegation initialization को atomically run नहीं करता। यदि initialization externally callable है, तो कोई observer इसे front-run करके स्वयं को owner के रूप में set कर सकता है।<sup>[[7]](#references)</sup>

Mitigation: initialization calldata को EOA द्वारा authorized होना आवश्यक करें और initialization को केवल एक बार allow करें। ERC-4337 EIP-7702 flow में caller को `EntryPoint.senderCreator()` तक भी restrict करें।<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## त्वरित pre-merge checks
- `EntryPoint` के `userOpHash` का उपयोग करके signatures validate करें (जो gas fields को bind करता है)।
- Privileged functions को उचित रूप से केवल `EntryPoint` और/या `address(this)` तक सीमित रखें।
- `validateUserOp` को stateless, deterministic और bundler simulation rules के साथ compatible रखें।
- ERC-1271 के लिए EIP-712 domain separation लागू करें और सफलता पर `0x1626ba7e` return करें।
- `postOp` को minimal, bounded और non-reverting रखें; validation के दौरान fees को secure करें।
- पहले `initCode` path का अलग से परीक्षण करें: deterministic deployment, idempotent factory behavior और one-shot initialization।
- Shipping से पहले bundler का multi-pass validation और traced full-bundle check चलाएँ।
- ERC-7702 के लिए init को EOA authorization से bind करें और इसे केवल एक बार allow करें; ERC-4337 flows में caller को `EntryPoint.senderCreator()` तक सीमित रखें।

## References

- [1] [ERC1271 Replay - 15+ Teams Affected (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [ERC-4337 smart accounts में छह गलतियाँ (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Contracts के लिए Standard Signature Validation Method](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Alt Mempool का उपयोग करके Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: EOAs के लिए Set Code](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
