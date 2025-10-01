# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" व्यवस्थित रूप से आपके Solidity कोड में छोटे परिवर्तन (mutants) डालकर और आपके test suite को पुनः चलाकर काम करता है। यदि कोई टेस्ट असफल होता है, तो mutant नष्ट माना जाता है। यदि टेस्ट अभी भी पास होते हैं, तो mutant जीवित रह जाता है, जो आपके test suite में एक ऐसा अंधा स्थान उजागर करता है जिसे line/branch coverage नहीं पकड़ पाती।

Key idea: कवरेज दिखाती है कि कोड निष्पादित हुआ; mutation testing दिखाती है कि व्यवहार वास्तव में सत्यापित किया गया है या नहीं।

## क्यों कवरेज भ्रामक हो सकती है

Consider this simple threshold check:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Unit tests that only check a value below and a value above the threshold can reach 100% line/branch coverage while failing to assert the equality boundary (==). A refactor to `deposit >= 2 ether` would still pass such tests, silently breaking protocol logic.

Mutation testing exposes this gap by mutating the condition and verifying your tests fail.

## सामान्य Solidity mutation ऑपरेटर

Slither’s mutation engine कई छोटे, semantics-changing edits लागू करता है, जैसे:
- ऑपरेटर प्रतिस्थापन: `+` ↔ `-`, `*` ↔ `/`, आदि।
- Assignment replacement: `+=` → `=`, `-=` → `=`
- Constant replacement: non-zero → `0`, `true` ↔ `false`
- Condition negation/replacement `if`/loops के अंदर
- पूरी लाइनों को टिप्पणी में बदलना (CR: Comment Replacement)
- एक लाइन को `revert()` से बदलना
- डेटा टाइप स्वैप: उदाहरण के लिए, `int128` → `int64`

लक्ष्य: उत्पन्न हुए 100% mutants को kill करना, या जिन survivors हैं उनके लिए स्पष्ट तर्क पेश करना।

## Running mutation testing with slither-mutate

Requirements: Slither v0.10.2+.

- List options and mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry उदाहरण (परिणाम कैप्चर करें और पूरा लॉग रखें):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- यदि आप Foundry का उपयोग नहीं करते हैं, तो `--test-cmd` को उस कमांड से बदलें जिससे आप टेस्ट चलाते हैं (जैसे, `npx hardhat test`, `npm test`).

`./mutation_campaign` में डिफ़ॉल्ट रूप से आर्टिफैक्ट्स और रिपोर्ट्स स्टोर किए जाते हैं। पकड़े न गए (बचे हुए) म्यूटेंट्स निरीक्षण के लिए वहाँ कॉपी किए जाते हैं।

### Understanding the output

रिपोर्ट लाइनें इस तरह दिखती हैं:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- ब्रैकेट में दिया टैग mutator alias है (उदा., `CR` = Comment Replacement).
- `UNCAUGHT` का मतलब है कि mutated व्यवहार के तहत tests पास हो गए → missing assertion.

## रनटाइम कम करना: प्रभावशाली म्यूटेंट्स को प्राथमिकता दें

Mutation campaigns कई घंटे या दिनों तक चल सकती हैं। लागत कम करने के सुझाव:
- Scope: पहले केवल महत्वपूर्ण contracts/directories पर शुरू करें, फिर विस्तार करें।
- Prioritize mutators: यदि किसी लाइन पर high-priority mutant बचता है (उदा., पूरी लाइन commented), तो आप उस लाइन के lower-priority variants को स्किप कर सकते हैं।
- अगर आपका runner अनुमति देता है तो tests को parallelize करें; dependencies/builds को cache करें।
- Fail-fast: जब कोई बदलाव स्पष्ट रूप से assertion gap दिखाए तो जल्दी रोक दें।

## बचे हुए म्यूटेंट्स के लिए ट्राइएज वर्कफ़्लो

1) बदली हुई लाइन और व्यवहार का निरीक्षण करें।
- बदली हुई लाइन लागू करके और एक focused test चला कर लोकली पुनरुत्पादन करें।

2) tests को मजबूत बनाएं ताकि वे केवल return values न बल्कि state को assert करें।
- equality-boundary checks जोड़ें (उदा., test threshold `==`)।
- post-conditions को assert करें: balances, total supply, authorization effects, और emitted events।

3) बहुत permissive mocks को realistic व्यवहार वाले mocks से बदलें।
- सुनिश्चित करें कि mocks transfers, failure paths, और on-chain होने वाले event emissions को enforce करें।

4) fuzz tests के लिए invariants जोड़ें।
- जैसे: conservation of value, non-negative balances, authorization invariants, जहाँ लागू हो monotonic supply।

5) Re-run slither-mutate करें जब तक कि survivors को killed न किया जाए या स्पष्ट रूप से justified न किया जाए।

## केस स्टडी: state assertions की कमी का खुलासा (Arkis protocol)

Arkis DeFi protocol के audit के दौरान एक mutation campaign ने निम्नलिखित तरह के survivors उभारे:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commenting out the assignment ने tests को टूटने से रोक दिया, जिससे post-state assertions की कमी स्पष्ट हुई। मूल कारण: कोड ने वास्तविक token transfers को validate करने के बजाय user-controlled `_cmd.value` पर भरोसा किया। एक attacker अपेक्षित और वास्तविक transfers को desynchronize कर के funds निकाल सकता है। परिणाम: protocol की solvency के लिए उच्च गंभीरता का जोखिम।

दिशानिर्देश: जो बचे हुए मामले (survivors) value transfers, accounting, या access control को प्रभावित करते हैं, उन्हें तब तक उच्च-जोखिम मानें जब तक उन्हें समाप्त (killed) न किया जाए।

## व्यावहारिक चेकलिस्ट

- एक लक्षित अभियान चलाएँ:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- बचे हुए मामलों (survivors) की triage करें और ऐसे tests/invariants लिखें जो परिवर्तित व्यवहार (mutated behavior) के अंतर्गत fail हों।
- balances, supply, authorizations, and events की assertions जोड़ें।
- boundary tests जोड़ें (`==`, overflows/underflows, zero-address, zero-amount, empty arrays)।
- अवास्तविक mocks को बदलें; failure modes का अनुकरण करें।
- तब तक 반복 करें जब तक सभी mutants नष्ट (killed) न हो जाएँ या comments और rationale के साथ justified न किए जाएँ।

## संदर्भ

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
