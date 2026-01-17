# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Overview

एक cold-wallet theft chain ने **supply-chain compromise of the Safe{Wallet} web UI** को और एक **on-chain delegatecall primitive that overwrote a proxy’s implementation pointer (slot 0)** को मिलाकर काम किया। मुख्य निष्कर्ष हैं:

- यदि कोई dApp signing path में code inject कर सकता है, तो यह एक signer को वैध **EIP-712 signature over attacker-chosen fields** बनाने पर मजबूर कर सकता है, जबकि original UI data को restore कर देता है ताकि अन्य signers को पता न चले।
- Safe proxies `masterCopy` (implementation) को **storage slot 0** पर store करते हैं। एक delegatecall जो किसी contract को slot 0 में लिखने देता है प्रभावी तौर पर Safe को attacker logic में “upgrade” कर देता है, जिससे wallet का पूर्ण नियंत्रण मिल जाता है।

## Off-chain: Targeted signing mutation in Safe{Wallet}

एक छेड़छाड़ किया गया Safe bundle (`_app-*.js`) ने चुनिंदा Safe और signer addresses को निशाना बनाया। Injected logic signing call से ठीक पहले execute होता था:
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
### हमले की विशेषताएँ
- **Context-gated**: पीड़ित Safes/signers के लिए हार्ड-कोडेड allowlists ने शोर कम किया और पता लगने की संभावना घटाई।
- **Last-moment mutation**: fields (`to`, `data`, `operation`, gas) को `signTransaction` से ठीक पहले overwrite किया गया और बाद में वापस कर दिया गया, इसलिए UI में proposal payloads सामान्य दिखते थे जबकि signatures हमलावर के payload से मेल खा रहे थे।
- **EIP-712 opacity**: wallets structured डेटा दिखाते थे पर nested calldata को decode नहीं करते थे और `operation = delegatecall` को हाइलाइट नहीं करते थे, जिससे mutated message प्रभावी रूप से blind-signed हो गया।

### Gateway सत्यापन का महत्व
Safe proposals को **Safe Client Gateway** में सबमिट किया जाता है। कड़े checks से पहले, gateway ऐसी proposal स्वीकार कर सकता था जहाँ `safeTxHash`/signature JSON बॉडी में दिए गए फील्ड्स से अलग होते थे अगर UI ने उन्हें sign करने के बाद फिर से लिख दिया। घटना के बाद, gateway अब उन proposals को reject करता है जिनका hash/signature सबमिट किए गए transaction से मेल नहीं खाता। इसी तरह का server-side hash verification किसी भी signing-orchestration API पर लागू किया जाना चाहिए।

## ऑन-चेन: slot collision के माध्यम से Delegatecall proxy takeover

Safe proxies `masterCopy` को **storage slot 0** में रखते हैं और सारी logic उसे delegate करते हैं। क्योंकि Safe सपोर्ट करता है **`operation = 1` (delegatecall)**, कोई भी signed transaction किसी भी arbitrary contract की ओर इशारा कर सकता है और उसके कोड को proxy के storage context में execute कर सकता है।

एक attacker contract ने ERC-20 `transfer(address,uint256)` की नकल की पर इसके बजाय slot 0 में `_to` लिख दिया:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
निष्पादन पथ:
1. पीड़ित `execTransaction` पर हस्ताक्षर करते हैं, जिसमें `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`।
2. Safe masterCopy इन पैरामीटरों पर किए गए हस्ताक्षरों को सत्यापित करता है।
3. Proxy `attackerContract` में delegatecall करता है; `transfer` बॉडी slot 0 में लिखती है।
4. Slot 0 (`masterCopy`) अब attacker-controlled logic की ओर इशारा करता है → **पूर्ण वॉलेट कब्ज़ा और धन निकासी**।

## पता लगाना और हार्डनिंग चेकलिस्ट

- **UI integrity**: JS assets को pin करें / SRI लागू करें; bundle diffs की निगरानी रखें; signing UI को ट्रस्ट सीमा (trust boundary) का हिस्सा मानें।
- **Sign-time validation**: हार्डवेयर wallets के साथ **EIP-712 clear-signing**; स्पष्ट रूप से `operation` को रेंडर करें और nested calldata को decode करें। जब `operation = 1` हो तो साइनिंग अस्वीकार करें जब तक कि policy इसकी अनुमति न दे।
- **Server-side hash checks**: proposals relay करने वाले gateways/services को `safeTxHash` पुन: compute करना चाहिए और सत्यापित करना चाहिए कि सिग्नेचर सबमिट किए गए फील्ड्स से मेल खाते हैं।
- **Policy/allowlists**: `to`, selectors, asset प्रकारों के लिए preflight नियम बनाएं, और vetted flows को छोड़कर delegatecall को नकारें। पूर्ण रूप से साइन किए गए लेनदेन ब्रॉडकास्ट करने से पहले एक internal policy service आवश्यक करें।
- **Contract design**: जब तक आवश्यक न हो multisig/treasury wallets में arbitrary delegatecall एक्सपोज़ न करें। upgrade pointers को slot 0 से दूर रखें या explicit upgrade logic और access control के साथ सुरक्षित रखें।
- **Monitoring**: treasury funds रखने वाले wallets से होने वाली delegatecall executions पर अलर्ट करें, और उन proposals पर भी अलर्ट करें जो सामान्य `call` पैटर्न से `operation` बदलते हैं।

## References

- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
