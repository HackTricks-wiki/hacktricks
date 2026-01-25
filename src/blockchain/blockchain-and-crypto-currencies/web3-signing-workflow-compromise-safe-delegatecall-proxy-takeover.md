# Web3 साइनिंग वर्कफ़्लो समझौता & Safe delegatecall Proxy कब्ज़ा

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन

एक cold-wallet चोरी श्रृंखला ने **Safe{Wallet} वेब UI की आपूर्ति-श्रृंखला का समझौता** को एक **on-chain delegatecall primitive के साथ जो proxy के implementation pointer (slot 0) को ओवरराइट कर देता है** जोड़ दिया। मुख्य निष्कर्ष हैं:

- यदि कोई dApp साइनिंग पाथ में कोड इंजेक्ट कर सकता है, तो यह एक साइनर को attacker-चुने हुए फील्ड्स पर वैध **EIP-712 signature** उत्पन्न करा सकता है जबकि मूल UI डेटा को बहाल करके अन्य साइनर्स को अनजान रखता है।
- Safe proxies `masterCopy` (implementation) को **storage slot 0** पर स्टोर करते हैं। किसी ऐसे कॉन्ट्रैक्ट को delegatecall जो slot 0 में लिखता है, प्रभावी रूप से Safe को attacker लॉजिक में "upgrade" कर देता है, जिससे वॉलेट का पूरा नियंत्रण मिल जाता है।

## ऑफ-चेन: Safe{Wallet} में लक्षित साइनिंग परिवर्तन

एक छेड़छाड़ की गई Safe बंडल (`_app-*.js`) ने चुनिंदा Safe + signer पतों पर हमला किया। इंजेक्ट किया गया लॉजिक साइनिंग कॉल से ठीक पहले निष्पादित हुआ:
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
- **Context-gated**: पीड़ित Safes/signers के लिए हार्ड-कोडेड allowlists ने शोर रोका और डिटेक्शन घटा दिया।
- **Last-moment mutation**: fields (`to`, `data`, `operation`, gas) को `signTransaction` से ठीक पहले ओवरराइट किया गया, फिर वापस कर दिया गया, जिससे UI में proposal payloads benign दिखते थे जबकि signatures attacker payload से मेल खाते थे।
- **EIP-712 opacity**: wallets structured data दिखाते थे पर nested calldata को decode नहीं करते या `operation = delegatecall` को हाइलाइट नहीं करते थे, जिससे mutated message प्रभावी रूप से blind-signed हो गया।

### Gateway validation relevance
Safe प्रस्ताव **Safe Client Gateway** को सबमिट किए जाते हैं। हर्डन्डेड चेक्स से पहले, gateway एक ऐसा proposal स्वीकार कर सकता था जहाँ `safeTxHash`/signature JSON बॉडी से अलग fields से मेल खाते थे अगर UI ने उन्हें post-signing rewrite किया था। इंसिडेंट के बाद, gateway अब उन proposals को reject करता है जिनका hash/signature सबमिट किए गए transaction से मेल नहीं खाता। किसी भी signing-orchestration API पर इसी तरह का server-side hash verification लागू किया जाना चाहिए।

### 2025 Bybit/Safe घटना की मुख्य बातें
- 21 फ़रवरी 2025 Bybit cold-wallet ड्रेन (~401k ETH) ने वही पैटर्न दोहराया: एक compromised Safe S3 bundle केवल Bybit signers के लिए ट्रिगर हुआ और `operation=0` → `1` swap कर दिया, `to` को एक pre-deployed attacker contract की ओर पॉइंट किया जो slot 0 लिखता है।
- Wayback-cached `_app-52c9031bfa03da47.js` दिखाता है कि लॉजिक Bybit के Safe (`0x1db9…cf4`) और signer addresses पर की-आधारित था, फिर execution के दो मिनट बाद तुरंत एक clean bundle में rollback कर दिया गया, जो “mutate → sign → restore” trick को mirror करता है।
- malicious contract (e.g., `0x9622…c7242`) में simple functions `sweepETH/sweepERC20` और एक `transfer(address,uint256)` था जो implementation slot लिखता था। `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` के execution ने proxy implementation को शिफ्ट कर दिया और पूर्ण नियंत्रण दे दिया।

## ऑन-चेन: Delegatecall proxy takeover via slot collision

Safe proxies `masterCopy` को **storage slot 0** पर रखते हैं और सारा logic उसे delegate करते हैं। क्योंकि Safe सपोर्ट करता है **`operation = 1` (delegatecall)**, कोई भी signed transaction किसी arbitrary contract की ओर पॉइंट कर सकता है और उसके code को proxy के storage context में execute करवा सकता है।

एक attacker contract ने ERC-20 `transfer(address,uint256)` की नकल की लेकिन इसके बजाय `_to` को slot 0 में लिख दिया:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
कार्यान्वयन पथ:
1. पीड़ित `execTransaction` पर हस्ताक्षर करते हैं जिसमें `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy इन पैरामीटरों पर हस्ताक्षरों को मान्य करता है।
3. Proxy `attackerContract` में delegatecall करता है; `transfer` बॉडी slot 0 में लिखती है।
4. Slot 0 (`masterCopy`) अब attacker-नियंत्रित लॉजिक की ओर इशारा करता है → **full wallet takeover and fund drain**।

### Guard & version notes (post-incident hardening)
- Safes >= v1.3.0 इंस्टॉल कर सकते हैं एक **Guard** ताकि `delegatecall` को veto किया जा सके या `to`/selectors पर ACL लागू किए जा सकें; Bybit v1.1.1 चला रहा था, इसलिए कोई Guard hook मौजूद नहीं था। इस नियंत्रण प्लेन को हासिल करने के लिए contracts को अपग्रेड करना (और owners को फिर से जोड़ना) आवश्यक है।

## पहचान और कड़ेकरण चेकलिस्ट

- **UI integrity**: JS assets / SRI को pin करें; bundle diffs की निगरानी करें; signing UI को ट्रस्ट बाउंड्री का हिस्सा मानें।
- **Sign-time validation**: hardware wallets जो **EIP-712 clear-signing** सपोर्ट करते हैं; स्पष्ट रूप से `operation` को रेंडर करें और nested calldata को decode करें। जब `operation = 1` हो तो साइनिंग अस्वीकार करें, जब तक कि नीति इसे अनुमति न दे।
- **Server-side hash checks**: gateways/services जो proposals relay करते हैं उन्हें `safeTxHash` फिर से recompute करना चाहिए और सत्यापित करना चाहिए कि signatures प्रस्तुत किए गए fields से मेल खाते हैं।
- **Policy/allowlists**: `to`, selectors, asset types के लिए preflight नियम; vetted flows के अलावा delegatecall को नकारें। पूर्ण रूप से साइन किए गए लेनदेन प्रसारित करने से पहले एक internal policy service आवश्यक करें।
- **Contract design**: arbitrary delegatecall को multisig/treasury wallets में एक्सपोज़ करने से बचें जब तक कि बिल्कुल आवश्यक न हो। upgrade pointers को slot 0 से दूर रखें या explicit upgrade logic और access control के साथ guard करें।
- **Monitoring**: treasury funds रखने वाले wallets से आने वाले delegatecall executions पर alert जारी करें, और उन proposals पर भी जिनमें `operation` सामान्य `call` पैटर्न से बदलता है।

## References

- [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
