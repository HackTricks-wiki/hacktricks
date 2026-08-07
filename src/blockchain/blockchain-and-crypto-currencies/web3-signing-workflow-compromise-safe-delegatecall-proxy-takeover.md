# Web3 Signing Workflow Compromise और Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Overview

एक cold-wallet theft chain में **Safe{Wallet} web UI का supply-chain compromise** और **on-chain delegatecall primitive, जिसने proxy के implementation pointer (slot 0) को overwrite कर दिया**, दोनों शामिल थे। मुख्य निष्कर्ष:

- यदि कोई dApp signing path में code inject कर सकता है, तो वह signer से attacker द्वारा चुने गए fields पर एक valid **EIP-712 signature** बनवा सकता है<sup>[[4]](#references)</sup>, और फिर original UI data को restore कर सकता है ताकि अन्य signers को इसकी जानकारी न हो।
- Safe proxies `masterCopy` (implementation) को **storage slot 0** पर store करते हैं। ऐसे contract पर delegatecall करना, जो slot 0 में write करता है, प्रभावी रूप से Safe को attacker logic पर “upgrade” कर देता है और wallet का full control प्रदान करता है।

## Off-chain: Safe{Wallet} में Targeted signing mutation

एक tampered Safe bundle (`_app-*.js`) ने विशिष्ट Safe + signer addresses को चुनिंदा रूप से target किया। Injected logic signing call से ठीक पहले execute हुआ:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: victim Safes/signers के लिए hard-coded allowlists ने noise को रोका और detection की संभावना कम की।<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: `signTransaction` से तुरंत पहले fields (`to`, `data`, `operation`, gas) को overwrite किया गया, फिर वापस revert कर दिया गया। इस कारण UI में proposal payloads benign दिखे, जबकि signatures attacker payload से match कर रहे थे।
- **EIP-712 opacity**: wallets ने structured data दिखाया, लेकिन nested calldata को decode नहीं किया या `operation = delegatecall` को highlight नहीं किया। इससे mutated message प्रभावी रूप से blind-signed हो गया।

### Gateway validation relevance
Safe proposals **Safe Client Gateway** को submit किए जाते हैं।<sup>[[5]](#references)</sup> Hardened checks से पहले, यदि UI signing के बाद fields को rewrite करता था, तो gateway ऐसा proposal स्वीकार कर सकता था जिसमें `safeTxHash`/signature JSON body के fields से अलग transaction के अनुरूप होते थे। Incident के बाद, gateway अब उन proposals को reject करता है जिनका hash/signature submitted transaction से match नहीं करता। इसी प्रकार का server-side hash verification किसी भी signing-orchestration API पर लागू किया जाना चाहिए।

### 2025 Bybit/Safe incident highlights
- 21 फरवरी, 2025 का Bybit cold-wallet drain (~401k ETH) इसी pattern का पुनः उपयोग करता था: एक compromised Safe S3 bundle केवल Bybit signers के लिए trigger हुआ और `operation=0` → `1` swap करके `to` को एक pre-deployed attacker contract पर point किया, जो slot 0 में write करता था।<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback-cached `_app-52c9031bfa03da47.js` में दिखता है कि logic Bybit के Safe (`0x1db9…cf4`) और signer addresses पर keyed था, और execution के दो मिनट बाद तुरंत एक clean bundle पर rollback कर दिया गया, जो “mutate → sign → restore” trick को mirror करता है।<sup>[[1]](#references)[[2]](#references)</sup>
- Malicious contract (जैसे, `0x9622…c7242`) में simple functions `sweepETH/sweepERC20` और एक `transfer(address,uint256)` था, जो implementation slot में write करता था। `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` के execution ने proxy implementation को shift किया और full control प्रदान कर दिया।<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxies **storage slot 0** में `masterCopy` रखते हैं और सभी logic को उसी पर delegate करते हैं। क्योंकि Safe **`operation = 1` (delegatecall)** को support करता है, कोई भी signed transaction arbitrary contract को point कर सकता है और proxy के storage context में उसका code execute कर सकता है।<sup>[[3]](#references)</sup>

एक attacker contract ने ERC-20 `transfer(address,uint256)` की नकल की, लेकिन इसके बजाय `_to` को slot 0 में write किया:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
निष्पादन पथ:<sup>[[1]](#references)[[3]](#references)</sup>
1. Victims `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)` के साथ `execTransaction` sign करते हैं।
2. Safe masterCopy इन parameters पर signatures validate करता है।
3. Proxy `attackerContract` में delegatecall करता है; `transfer` body slot 0 में लिखती है।
4. Slot 0 (`masterCopy`) अब attacker-controlled logic पर point करता है → **पूर्ण wallet takeover और fund drain**।

### Guard और version notes (post-incident hardening)
- Safes >= v1.3.0 `delegatecall` को veto करने या `to`/selectors पर ACLs लागू करने के लिए **Guard** install कर सकते हैं; Bybit v1.1.1 चला रहा था, इसलिए कोई Guard hook मौजूद नहीं था। इस control plane का लाभ लेने के लिए contracts को upgrade करना (और owners को फिर से add करना) आवश्यक है।

## Detection और hardening checklist

- **UI integrity**: JS assets / SRI को pin करें; bundle diffs monitor करें; signing UI को trust boundary का हिस्सा मानें।
- **Sign-time validation**: **EIP-712 clear-signing** वाले hardware wallets इस्तेमाल करें; `operation` को स्पष्ट रूप से render करें और nested calldata को decode करें। जब तक policy अनुमति न दे, `operation = 1` होने पर signing reject करें।
- **Server-side hash checks**: proposals relay करने वाले gateways/services को `safeTxHash` फिर से compute करना चाहिए और validate करना चाहिए कि signatures submitted fields से match करती हैं।
- **Policy/allowlists**: `to`, selectors, asset types के लिए preflight rules लागू करें और vetted flows को छोड़कर delegatecall को disallow करें। Fully signed transactions broadcast करने से पहले internal policy service आवश्यक करें।
- **Contract design**: multisig/treasury wallets में arbitrary delegatecall expose करने से बचें, जब तक यह strictly necessary न हो। Upgrade pointers को slot 0 से दूर रखें या explicit upgrade logic और access control से guard करें।
- **Monitoring**: treasury funds रखने वाले wallets से delegatecall executions और उन proposals पर alert करें जो typical `call` patterns से `operation` बदलते हैं।

## References

- [1] [Bybit Safe exploit का AnChain.AI forensic breakdown](https://www.anchain.ai/blog/bybit)
- [2] [Safe bundle compromise का Zero Hour Technology analysis](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Bybit hack का in-depth technical analysis (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
