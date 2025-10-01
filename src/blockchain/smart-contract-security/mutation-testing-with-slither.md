# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" आपके Solidity कोड में व्यवस्थित रूप से छोटे बदलाव (mutants) करके और आपकी टेस्ट सूट को फिर से चलाकर किया जाता है। यदि कोई टेस्ट फेल होता है तो mutant मर जाता है (killed)। अगर टेस्ट फिर भी पास हो जाते हैं, तो mutant बच जाता है (survives), जिससे आपकी टेस्ट सूट में एक ऐसी कमी उजागर होती है जिसे line/branch coverage पकड़ नहीं पाती।

मुख्य विचार: कवरेज दिखाता है कि कोड execute हुआ था; mutation testing दिखाता है कि व्यवहार वास्तव में assert किया गया है या नहीं।

## क्यों कवरेज धोखा दे सकती है

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

Mutation testing इस अंतर को उजागर करता है, शर्त को बदलकर और यह सत्यापित करके कि आपके परीक्षण fail हों।

## सामान्य Solidity mutation operators

Slither’s mutation engine कई छोटे, semantics-changing edits लागू करता है, जैसे:
- ऑपरेटर बदलना: `+` ↔ `-`, `*` ↔ `/`, आदि।
- Assignment replacement: `+=` → `=`, `-=` → `=`
- Constant replacement: non-zero → `0`, `true` ↔ `false`
- Condition negation/replacement `if`/loops के अंदर
- पूरे लाइनों को comment out करना (CR: Comment Replacement)
- किसी लाइन को `revert()` से बदलना
- Data type swaps: उदाहरण के लिए, `int128` → `int64`

Goal: generated mutants में से 100% को kill करें, या जिनका बचना आवश्यक है उन्हें स्पष्ट तर्क के साथ justify करें।

## Running mutation testing with slither-mutate

Requirements: Slither v0.10.2+.

- List options and mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry उदाहरण (परिणाम कैप्चर करें और एक पूर्ण लॉग रखें):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- यदि आप Foundry का उपयोग नहीं करते हैं, तो `--test-cmd` को अपने परीक्षण चलाने के तरीके से बदलें (उदा., `npx hardhat test`, `npm test`)।

Artifacts और रिपोर्ट्स डिफ़ॉल्ट रूप से `./mutation_campaign` में संग्रहीत होते हैं। कैच न हुए (बचे हुए) mutants निरीक्षण के लिए वहाँ कॉपी किए जाते हैं।

### आउटपुट को समझना

रिपोर्ट लाइनें इस तरह दिखती हैं:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- कोष्ठक में टैग mutator उपनाम है (उदा., `CR` = Comment Replacement).
- `UNCAUGHT` का मतलब है कि mutated व्यवहार के तहत tests पास हुए → assertion गायब है।

## रनटाइम घटाना: प्रभावशाली mutants को प्राथमिकता दें

Mutation अभियानों में घंटे या दिन लग सकते हैं। लागत घटाने के सुझाव:
- Scope: पहले केवल critical contracts/directories से शुरुआत करें, फिर विस्तार करें।
- Prioritize mutators: अगर किसी लाइन पर high-priority mutant बच जाता है (उदा., पूरी लाइन comment कर दी गई), तो आप उस लाइन के लिए lower-priority variants को छोड़ सकते हैं।
- Parallelize tests अगर आपका runner अनुमति देता है; dependencies/builds को cache करें।
- Fail-fast: जब कोई परिवर्तन स्पष्ट रूप से assertion gap दिखाता है तो जल्दी बंद कर दें।

## Triage workflow for surviving mutants

1) mutated line और व्यवहार का निरीक्षण करें।
- mutated line लागू करके स्थानीय रूप से reproduce करें और एक focused test चलाएँ।

2) केवल return values पर नहीं बल्कि state को assert करने के लिए tests को मजबूत करें।
- equality-boundary checks जोड़ें (उदा., test threshold `==`)।
- post-conditions को assert करें: balances, total supply, authorization प्रभाव, और emitted events।

3) अत्यधिक permissive mocks को realistic व्यवहार से बदलें।
- सुनिश्चित करें कि mocks transfers, failure paths, और on-chain होने वाली event emissions को enforce करें।

4) fuzz tests के लिए invariants जोड़ें।
- उदा., conservation of value, non-negative balances, authorization invariants, जहाँ लागू हो वहां monotonic supply।

5) survivors मरने तक या स्पष्ट रूप से justified होने तक slither-mutate फिर से चलाएँ।

## Case study: revealing missing state assertions (Arkis protocol)

Arkis DeFi protocol के एक audit के दौरान एक mutation अभियान ने निम्नलिखित जैसे surviving cases surface किए:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commenting out the assignment didn’t break the tests, proving missing post-state assertions. Root cause: code trusted a user-controlled `_cmd.value` instead of validating actual token transfers. An attacker could desynchronize expected vs. actual transfers to drain funds. Result: high severity risk to protocol solvency.

मार्गदर्शन: वैल्यू ट्रांसफर, अकाउंटिंग, या एक्सेस कंट्रोल को प्रभावित करने वाले survivors को killed किए जाने तक high-risk मानें।

## व्यावहारिक चेकलिस्ट

- लक्षित अभियान चलाएँ:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- बचे हुए survivors की triage करें और ऐसे tests/invariants लिखें जो mutated व्यवहार में fail हों।
- balances, supply, authorizations, और events को assert करें।
- बाउंडरी tests जोड़ें (`==`, overflows/underflows, zero-address, zero-amount, empty arrays)।
- अवास्तविक mocks को बदलें; failure modes का simulate करें।
- इटरेट करें जब तक सभी mutants killed न हों या comments और rationale के साथ justified न हों।

## संदर्भ

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
