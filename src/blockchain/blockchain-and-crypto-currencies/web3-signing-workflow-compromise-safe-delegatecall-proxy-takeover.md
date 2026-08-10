# Web3 Signing Workflow Compromise और Safe Delegatecall Proxy Takeover

## Overview

एक cold-wallet theft chain में **Safe{Wallet} web UI का supply-chain compromise** और **एक on-chain delegatecall primitive, जिसने proxy के implementation pointer (slot 0) को overwrite कर दिया**, शामिल था। मुख्य निष्कर्ष:

- यदि कोई dApp signing path में code inject कर सकता है, तो वह signer से **attacker-chosen fields पर एक valid EIP-712 signature** बनवा सकता है और फिर original UI data restore कर सकता है, ताकि अन्य signers को इसकी जानकारी न हो।<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Safe proxies `masterCopy` (implementation) को **storage slot 0** में store करते हैं। ऐसे contract को delegatecall करना, जो slot 0 में लिखता है, प्रभावी रूप से Safe को attacker logic पर “upgrade” कर देता है और wallet पर full control प्रदान करता है।<sup>[[3]](#references)</sup>

## Off-chain: Safe{Wallet} में Targeted signing mutation

एक tampered Safe bundle (`_app-*.js`) ने चुनिंदा Safe + signer addresses को target किया। Injected logic signing call से ठीक पहले execute हुआ:<sup>[[1]](#references)[[3]](#references)</sup>
```javascript
// Pseudocode of the malicious flow
orig = structuredClone(tx.data);
if (isVictimSafe && isVictimSigner && tx.data.operation === 0) {
tx.data.to = attackerContract;
tx.data.data = "0xa9059cbb...";      // ERC-20 transfer selector
tx.data.operation = 1;                 // delegatecall
tx.data.value = 0;
tx.data.safeTxGas = 45746;
const sig = await sdk.signTransaction(tx, safeVersion);
sig.data = orig;                       // restore original before submission
tx.data = orig;
return sig;
}
```
### Attack properties
- **Context-gated**: victim Safes/signers के लिए hard-coded allowlists ने noise को रोका और detection को कम किया।<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: `signTransaction` से तुरंत पहले fields (`to`, `data`, `operation`, gas) को overwrite किया गया, फिर revert कर दिया गया, इसलिए UI में proposal payloads benign दिखे जबकि signatures attacker payload से match हुए।<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: wallets ने structured data दिखाया, लेकिन nested calldata को decode नहीं किया या `operation = delegatecall` को highlight नहीं किया, जिससे mutated message प्रभावी रूप से blind-signed था।<sup>[[3]](#references)[[4]](#references)</sup>

### Gateway validation relevance
Safe proposals **Safe Client Gateway** को submit किए जाते हैं।<sup>[[5]](#references)</sup> Hardened checks से पहले, यदि UI ने signing के बाद fields को rewrite किया हो, तो gateway ऐसा proposal स्वीकार कर सकता था जिसमें `safeTxHash`/signature JSON body के fields से अलग होते थे। Incident के बाद, gateway अब उन proposals को reject करता है जिनका hash/signature submitted transaction से match नहीं करता।<sup>[[3]](#references)</sup> ऐसी ही server-side hash verification किसी भी signing-orchestration API पर enforce की जानी चाहिए।

### 2025 Bybit/Safe incident highlights
- February 21, 2025 का Bybit cold-wallet drain (~401k ETH) इसी pattern का उपयोग करता था: compromised Safe S3 bundle केवल Bybit signers के लिए trigger हुआ और `operation=0` → `1` swap करके `to` को एक pre-deployed attacker contract पर point किया, जो slot 0 में write करता था।<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback-cached `_app-52c9031bfa03da47.js` में logic Bybit के Safe (`0x1db9…cf4`) और signer addresses पर keyed दिखाई देता है, फिर execution के दो मिनट बाद तुरंत clean bundle पर rollback हो गया, जो “mutate → sign → restore” trick को mirror करता है।<sup>[[1]](#references)[[2]](#references)</sup>
- Malicious contract (जैसे, `0x9622…c7242`) में simple functions `sweepETH/sweepERC20` और एक `transfer(address,uint256)` था, जो implementation slot में write करता था। `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` के execution ने proxy implementation को shift किया और full control प्रदान किया।<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxies **storage slot 0** में `masterCopy` रखते हैं और सभी logic को उसी पर delegate करते हैं। क्योंकि Safe **`operation = 1` (delegatecall)** को support करता है, कोई भी signed transaction arbitrary contract को point कर सकती है और proxy के storage context में उसका code execute कर सकती है।<sup>[[3]](#references)</sup>

एक attacker contract ने ERC-20 `transfer(address,uint256)` की नकल की, लेकिन इसके बजाय `_to` को slot 0 में write किया:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:<sup>[[1]](#references)[[3]](#references)</sup>
1. Victims `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)` के साथ `execTransaction` sign करते हैं।
2. Safe masterCopy इन parameters पर signatures validate करता है।
3. Proxy `attackerContract` में delegatecall करता है; `transfer` body slot 0 में write करती है।
4. Slot 0 (`masterCopy`) अब attacker-controlled logic की ओर point करता है → **पूर्ण wallet takeover और funds drain**।

### Guard & version notes (post-incident hardening)
- Transaction guards को Safe v1.3.0 में introduce किया गया था और वे execution से पहले सभी `execTransaction` parameters inspect कर सकते हैं; guard `delegatecall` को reject कर सकता है या destination और calldata पर policy लागू कर सकता है। Bybit v1.1.1 चला रहा था, जो इस hook से पहले का version है।<sup>[[2]](#references)[[6]](#references)</sup>

## Detection & hardening checklist

- **UI integrity**: JS assets / SRI को pin करें; bundle diffs monitor करें; signing UI को trust boundary का हिस्सा मानें।
- **Sign-time validation**: **EIP-712 clear-signing** वाले hardware wallets का उपयोग करें; `operation` को स्पष्ट रूप से render करें और nested calldata decode करें। `operation = 1` होने पर signing reject करें, जब तक policy इसकी अनुमति न दे।<sup>[[3]](#references)</sup>
- **Server-side hash checks**: proposals relay करने वाले gateways/services को `safeTxHash` फिर से compute करना चाहिए और validate करना चाहिए कि signatures submitted fields से match करते हैं।<sup>[[3]](#references)</sup>
- **Policy/allowlists**: `to`, selectors और asset types के लिए preflight rules लागू करें, तथा vetted flows को छोड़कर delegatecall को disallow करें। Fully signed transactions broadcast करने से पहले internal policy service आवश्यक करें।
- **Contract design**: multisig/treasury wallets में arbitrary delegatecall expose करने से बचें, जब तक यह strictly necessary न हो। किसी भी implementation pointer को upgrade primitive मानें: इसे explicit access control से protect करें और delegatecall targets/selectors पर guard लागू करें; pointer को केवल किसी अन्य slot में move करना complete defense नहीं है।<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoring**: treasury funds रखने वाले wallets से delegatecall executions पर alert करें, और उन proposals पर भी alert करें जो `operation` को typical `call` patterns से बदलते हैं।

## References

- [1] [Bybit Safe exploit का AnChain.AI forensic breakdown](https://www.anchain.ai/blog/bybit)
- [2] [Safe bundle compromise का Zero Hour Technology analysis](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Bybit hack का in-depth technical analysis (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Safe smart account v1.3.0 changelog (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
