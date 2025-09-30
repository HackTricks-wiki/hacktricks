# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" का मतलब है कि यह व्यवस्थित रूप से आपकी Solidity कोड में छोटे परिवर्तन (mutants) डालता है और आपका test suite फिर से चलाता है। यदि कोई टेस्ट फेल होता है, तो mutant को किल माना जाता है। अगर टेस्ट फिर भी पास हो जाते हैं, तो mutant जीवित रह जाता है — यह आपके test suite में एक छिपी हुई कमी उजागर करता है जिसे line/branch coverage पकड़ नहीं पाती।

मुख्य विचार: Coverage दिखाती है कि कोड executed हुआ था; mutation testing दिखाता है कि व्यवहार वास्तव में assert किया गया है या नहीं।

## क्यों कवरेज भ्रामक हो सकती है

इस सरल threshold चेक पर विचार करें:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
यूनिट टेस्ट जो केवल थ्रेशोल्ड से नीचे और थ्रेशोल्ड से ऊपर के वैल्यू को चेक करते हैं, वे 100% line/branch coverage तक पहुँच सकते हैं जबकि equality boundary (==) की assertion को चेक करने में असफल हो सकते हैं। कोड को `deposit >= 2 ether` में refactor करने पर ऐसे tests फिर भी पास हो जाएंगे और protocol लॉजिक चुपचाप टूट जाएगा।

Mutation testing इस कमी को उजागर करता है — यह condition में बदलाव करके यह सत्यापित करता है कि आपके tests फेल होते हैं।

## Common Solidity mutation operators

Slither’s mutation engine कई छोटे, semantics बदलने वाले edits लागू करता है, जैसे:
- Operator replacement: `+` ↔ `-`, `*` ↔ `/`, आदि।
- Assignment replacement: `+=` → `=`, `-=` → `=`
- Constant replacement: non-zero → `0`, `true` ↔ `false`
- Condition negation/replacement inside `if`/loops
- Comment out whole lines (CR: Comment Replacement)
- Replace a line with `revert()`
- Data type swaps: e.g., `int128` → `int64`

लक्ष्य: 100% generated mutants को kill करना, या बचे हुए के लिए स्पष्ट तर्क देना।

## Running mutation testing with slither-mutate

आवश्यकताएँ: Slither v0.10.2+.

- List options and mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry उदाहरण (परिणाम कैप्चर करें और पूरा लॉग रखें):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- यदि आप Foundry का उपयोग नहीं करते हैं, तो `--test-cmd` को उस तरीके से बदलें जिससे आप टेस्ट चलाते हैं (उदाहरण के लिए, `npx hardhat test`, `npm test`)।

आर्टिफैक्ट्स और रिपोर्टें डिफ़ॉल्ट रूप से `./mutation_campaign` में संग्रहीत होती हैं। जो पकड़े नहीं गए (बचे हुए) mutants निरीक्षण के लिए वहाँ कॉपी किए जाते हैं।

### Understanding the output

रिपोर्ट की पंक्तियाँ इस तरह दिखती हैं:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- ब्रैकेट में टैग mutator alias है (उदाहरण: `CR` = Comment Replacement).
- `UNCAUGHT` का मतलब है कि mutated behavior के तहत tests पास हो गए → missing assertion.

## रनटाइम घटाना: प्रभावशाली mutants को प्राथमिकता दें

Mutation campaigns कई घंटे या दिनों तक चल सकती हैं। लागत घटाने के टिप्स:
- Scope: केवल critical contracts/directories से शुरुआत करें, फिर आवश्यकतानुसार बढ़ाएँ।
- Prioritize mutators: अगर किसी लाइन पर high-priority mutant बच जाता है (उदा., पूरी लाइन commented), तो आप उस लाइन के lower-priority variants को स्किप कर सकते हैं।
- Parallelize tests अगर आपका runner अनुमति देता है; dependencies/builds को cache करें।
- Fail-fast: जल्दी रोक दें जब कोई परिवर्तन स्पष्ट रूप से assertion gap दिखाए।

## बची हुई mutants के लिए ट्रायेज workflow

1) mutated लाइन और व्यवहार का निरीक्षण करें।
- स्थानीय रूप से reproduce करें: mutated लाइन लागू करके और एक focused test चलाकर।

2) tests को मजबूत करें ताकि वे केवल return values नहीं बल्कि state को assert करें।
- समानता-बाउंडरी चेक जोड़ें (उदा., test threshold `==`)।
- post-conditions assert करें: balances, total supply, authorization effects, और emitted events।

3) अत्यधिक permissive mocks को realistic behavior से बदलें।
- सुनिश्चित करें कि mocks उन transfers, failure paths, और event emissions को enforce करें जो on-chain होते हैं।

4) fuzz tests के लिए invariants जोड़ें।
- उदाहरण: conservation of value, non-negative balances, authorization invariants, और जहाँ लागू हो monotonic supply।

5) Re-run slither-mutate तब तक चलाएँ जब तक survivors मारे न जाएँ या स्पष्ट रूप से justified न हों।

## केस स्टडी: missing state assertions का खुलासा (Arkis protocol)

Arkis DeFi protocol के audit के दौरान एक mutation campaign ने कुछ survivors उभरे जैसे:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commenting out the assignment didn’t break the tests, proving missing post-state assertions. Root cause: code trusted a user-controlled `_cmd.value` instead of validating actual token transfers. An attacker could desynchronize expected vs. actual transfers to drain funds. Result: high severity risk to protocol solvency.

Guidance: ऐसे survivors जिन्हें मूल्य-स्थानांतरण, लेखांकन, या पहुँच नियंत्रण प्रभावित करते हैं, उन्हें नष्ट किए जाने तक उच्च-जोखिम मानें।

## Practical checklist

- लक्ष्यित अभियान चलाएँ:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- बचे हुए म्यूटेंट्स का ट्रायज करें और ऐसे tests/invariants लिखें जो म्यूटेड व्यवहार के तहत फेल हों।
- बैलेंस, सप्लाई, प्राधिकरण, और इवेंट्स की पुष्टि करें।
- बाउंडरी टेस्ट जोड़ें: (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- अवास्तविक mocks बदलें; विफलता-परिस्थितियों का अनुकरण करें।
- तब तक पुनरावृत्ति करें जब तक सभी mutants नष्ट न हों या टिप्पणियों और तर्क के साथ औचित्य न दिया गया हो।

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../../banners/hacktricks-training.md}}
