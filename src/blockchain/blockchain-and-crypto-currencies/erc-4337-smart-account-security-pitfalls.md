# ERC-4337 Smart Account Security Pitfalls

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction वॉलेट्स को programmable systems में बदल देता है। मुख्य फ्लो पूरे बंडल पर **validate-then-execute** है: `EntryPoint` किसी भी `UserOperation` को execute करने से पहले हर एक को validate करता है। जब validation permissive या stateful होती है, तो यह ordering अस्पष्ट attack surface पैदा कर देती है।

## 1) Direct-call bypass of privileged functions
किसी भी externally callable `execute` (या fund-moving) फ़ंक्शन को, जो `EntryPoint` (या किसी vetted executor module) तक सीमित नहीं है, सीधे कॉल करके खाते को खाली किया जा सकता है।
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
सुरक्षित पैटर्न: इसे `EntryPoint` तक सीमित रखें, और admin/self-management flows के लिए `msg.sender == address(this)` का उपयोग करें (module install, validator changes, upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) बिना साइन किए गए या जाँचे नहीं गए गैस फ़ील्ड -> शुल्क निकासी
यदि सिग्नेचर सत्यापन केवल इरादा (`callData`) को कवर करता है लेकिन गैस-संबंधी फ़ील्ड्स को नहीं, तो एक bundler या frontrunner फ़ीस बढ़ाकर ETH निकाल सकता है। साइन किया गया payload कम से कम निम्न से बाइंड होना चाहिए:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

रक्षात्मक पैटर्न: `EntryPoint`-provided `userOpHash` (जो गैस फ़ील्ड्स को शामिल करता है) का उपयोग करें और/या प्रत्येक फ़ील्ड को कड़ाई से सीमित करें।
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
क्योंकि सभी validations किसी भी execution से पहले चलती हैं, contract state में validation परिणाम स्टोर करना unsafe है। उसी bundle में कोई दूसरा op इसे overwrite कर सकता है, जिससे आपकी execution attacker-influenced state का उपयोग करेगी।

`validateUserOp` में storage लिखने से बचें। अगर अनिवार्य हो, तो अस्थायी डेटा को `userOpHash` से key करें और उपयोग के बाद deterministic तरीके से delete करें (stateless validation को प्राथमिकता दें)।

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` को signatures को **इस कॉन्ट्रैक्ट** और **इस चेन** से बाँधना चाहिए। raw hash पर recover करने से signatures accounts या chains के बीच replay हो सकते हैं।

EIP-712 typed data का उपयोग करें (domain में `verifyingContract` और `chainId` शामिल हों) और सफलता पर ठीक वही ERC-1271 magic value `0x1626ba7e` return करें।

## 5) Reverts do not refund after validation
एक बार `validateUserOp` सफल हो जाने पर, execution बाद में revert होने पर भी fees committed रहती हैं। Attackers बार-बार ऐसे ops जमा कर सकते हैं जो fail होंगे और फिर भी account से fees ले लेंगे।

paymasters के लिए, अगर आप `validateUserOp` में shared pool से भुगतान करते हैं और users से `postOp` में charge करते हैं तो यह fragile है क्योंकि `postOp` revert कर सकता है बिना payment undo किए। validation के दौरान funds को secure करें (per-user escrow/deposit), और `postOp` को minimal और non-reverting रखें।

## 6) ERC-7702 initialization frontrun
ERC-7702 एक EOA को single tx के लिए smart-account code चलाने देता है। अगर initialization externally callable है, तो एक frontrunner खुद को owner बना सकता है।

Mitigation: initialization केवल **self-call** पर और केवल एक बार की अनुमति दें।
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## त्वरित प्री-मर्ज जांच
- हस्ताक्षर सत्यापित करें `EntryPoint` के `userOpHash` का उपयोग करके (binds gas fields).
- प्रिविलेज्ड फंक्शन्स को `EntryPoint` और/या `address(this)` तक सीमित रखें जैसा उपयुक्त हो.
- `validateUserOp` को stateless रखें.
- ERC-1271 के लिए EIP-712 domain separation लागू करें और सफलता पर `0x1626ba7e` लौटाएँ.
- `postOp` को minimal, bounded, और non-reverting रखें; validation के दौरान fees को secure करें.
- ERC-7702 के लिए, init केवल self-call पर और केवल एक बार अनुमति दें.

## संदर्भ

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)

{{#include ../../banners/hacktricks-training.md}}
