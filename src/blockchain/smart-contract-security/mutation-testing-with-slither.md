# Smart Contracts के लिए Mutation Testing (slither-mutate, mewt, MuTON)

Mutation testing आपके tests को "test" करता है: यह contract code में व्यवस्थित रूप से छोटे बदलाव (mutants) करता है और test suite को फिर से चलाता है। यदि कोई test fail होता है, तो mutant kill हो जाता है। यदि tests फिर भी pass होते हैं, तो mutant survive करता है, जिससे वह blind spot सामने आता है जिसे line/branch coverage detect नहीं कर सकती।

मुख्य विचार: Coverage दिखाता है कि code execute किया गया था; mutation testing दिखाता है कि क्या behavior को वास्तव में assert किया गया है।<sup>[[2]](#references)</sup>

## Coverage क्यों गुमराह कर सकती है

इस सरल threshold check पर विचार करें:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
वे unit tests जो केवल threshold से नीचे और threshold से ऊपर की value जाँचते हैं, equality boundary (==) को assert किए बिना 100% line/branch coverage प्राप्त कर सकते हैं। `deposit >= 2 ether` में refactor करने पर भी ऐसे tests pass होते रहेंगे और protocol logic चुपचाप टूट जाएगा।<sup>[[2]](#references)</sup>

Mutation testing condition में बदलाव करके और यह verify करके इस gap को उजागर करता है कि tests fail हों।

Smart contracts के लिए, surviving mutants अक्सर इन checks की कमी से जुड़े होते हैं:
- Authorization और role boundaries
- Accounting/value-transfer invariants
- Revert conditions और failure paths
- Boundary conditions (`==`, zero values, empty arrays, max/min values)

## सबसे अधिक security signal वाले mutation operators

Contract auditing के लिए उपयोगी mutation classes:<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**: unexecuted paths उजागर करने के लिए statements को `revert()` से replace करना
- **Medium severity**: unverified side effects प्रकट करने के लिए lines को comment out करना / logic हटाना
- **Low severity**: सूक्ष्म operator या constant swaps, जैसे `>=` -> `>` या `+` -> `-`
- अन्य सामान्य edits: assignment replacement, boolean flips, condition negation और type changes

Practical goal: सभी meaningful mutants को kill करना और उन survivors को स्पष्ट रूप से justify करना जो irrelevant या semantically equivalent हैं।

## Regex की तुलना में syntax-aware mutation बेहतर क्यों है

पुराने mutation engines regex या line-oriented rewrites पर निर्भर करते थे। यह काम करता है, लेकिन इसकी महत्वपूर्ण limitations हैं:<sup>[[1]](#references)</sup>
- Multi-line statements को सुरक्षित रूप से mutate करना कठिन होता है
- Language structure समझ में नहीं आती, इसलिए comments/tokens को गलत तरीके से target किया जा सकता है
- कमजोर line पर हर possible variant generate करने से runtime का बड़ा हिस्सा व्यर्थ होता है

AST- या Tree-sitter-based tooling raw lines के बजाय structured nodes को target करके इसे बेहतर बनाती है:<sup>[[1]](#references)</sup>
- **slither-mutate** Slither के Solidity AST का उपयोग करता है।<sup>[[4]](#references)</sup>
- **mewt** language-agnostic core के रूप में Tree-sitter का उपयोग करता है।<sup>[[6]](#references)</sup>
- **MuTON** `mewt` पर आधारित है और FunC, Tolk और Tact जैसी TON languages के लिए first-class support जोड़ता है।<sup>[[7]](#references)</sup>

इससे multi-line constructs और expression-level mutations regex-only approaches की तुलना में काफी अधिक reliable हो जाते हैं।

## slither-mutate के साथ mutation testing चलाना

Requirements: Slither v0.10.2+.

- Options और mutators की list बनाएं:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry उदाहरण (परिणाम कैप्चर करें और पूरा लॉग रखें):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- यदि आप Foundry का उपयोग नहीं करते हैं, तो `--test-cmd` को उस कमांड से बदलें जिससे आप tests चलाते हैं (जैसे, `npx hardhat test`, `npm test`)।

Artifacts डिफ़ॉल्ट रूप से `./mutation_campaign` में संग्रहीत किए जाते हैं। Uncaught (surviving) mutants को निरीक्षण के लिए वहां कॉपी किया जाता है।<sup>[[5]](#references)</sup>

### आउटपुट को समझना

Report lines इस तरह दिखती हैं:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- कोष्ठक में दिया गया tag mutator alias है (जैसे, `CR` = Comment Replacement)।
- `UNCAUGHT` का अर्थ है कि mutated behavior के तहत tests पास हो गए → assertion missing है।

## Runtime कम करना: प्रभावशाली mutants को प्राथमिकता दें

Mutation campaigns में कई घंटे या दिन लग सकते हैं। Cost कम करने के लिए सुझाव:<sup>[[1]](#references)[[2]](#references)</sup>
- Scope: केवल critical contracts/directories से शुरू करें, फिर विस्तार करें।
- Mutators को प्राथमिकता दें: यदि किसी line पर high-priority mutant survive करता है (उदाहरण के लिए `revert()` या comment-out), तो उस line के लिए lower-priority variants को skip करें।
- Two-phase campaigns का उपयोग करें: पहले focused/fast tests चलाएं, फिर केवल uncaught mutants को full suite के साथ दोबारा test करें।
- जब संभव हो, mutation targets को specific test commands से map करें (उदाहरण के लिए auth code -> auth tests)।
- समय कम होने पर campaigns को केवल high/medium severity mutants तक सीमित करें।
- यदि आपका runner इसकी अनुमति देता है तो tests को parallelize करें; dependencies/builds को cache करें।
- Fail-fast: जब कोई change assertion gap को स्पष्ट रूप से प्रदर्शित करे, तो जल्दी रुक जाएं।

Runtime math बहुत कठोर है: `1000 mutants x 5-minute tests ~= 83 hours`, इसलिए campaign design mutator जितना ही महत्वपूर्ण है।<sup>[[1]](#references)</sup>

## Persistent campaigns और scale पर triage

पुराने workflows की एक कमजोरी यह है कि results को केवल `stdout` में dump किया जाता है। लंबे campaigns के लिए इससे pause/resume, filtering और review कठिन हो जाते हैं।<sup>[[1]](#references)</sup>

`mewt`/`MuTON` SQLite-backed campaigns में mutants और outcomes store करके इसे बेहतर बनाते हैं। फायदे:<sup>[[1]](#references)</sup>
- Progress खोए बिना लंबे runs को pause और resume करें
- किसी specific file या mutation class में केवल uncaught mutants को filter करें
- Review tooling के लिए results को SARIF में export/translate करें
- Raw terminal logs के बजाय AI-assisted triage को छोटे, filtered result sets दें

Persistent results विशेष रूप से उपयोगी होते हैं जब mutation testing एक one-off manual review के बजाय audit pipeline का हिस्सा बन जाता है।

## Surviving mutants के लिए triage workflow

1) Mutated line और behavior की जांच करें।
- Mutated line लागू करके और focused test चलाकर local रूप से reproduce करें।

2) Tests को केवल return values के बजाय state assert करने के लिए मजबूत करें।
- Equality-boundary checks जोड़ें (जैसे, threshold `==` को test करें)।
- Post-conditions assert करें: balances, total supply, authorization effects और emitted events।

3) अत्यधिक permissive mocks को realistic behavior से बदलें।
- सुनिश्चित करें कि mocks on-chain होने वाले transfers, failure paths और event emissions को enforce करें।

4) Fuzz tests के लिए invariants जोड़ें।
- जैसे, conservation of value, non-negative balances, authorization invariants, और जहां लागू हो वहां monotonic supply।

5) True positives को semantic no-ops से अलग करें।
- उदाहरण: `x > 0` -> `x != 0` तब meaningless है जब `x` unsigned हो।

6) Campaign को तब तक दोबारा run करें जब तक survivors kill न हो जाएं या उन्हें स्पष्ट रूप से justify न किया जाए।

## Case study: missing state assertions को उजागर करना (Arkis protocol)

Arkis DeFi protocol के audit के दौरान एक mutation campaign ने ऐसे survivors सामने लाए:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Assignment को comment out करने से tests break नहीं हुए, जिससे missing post-state assertions साबित होते हैं। मूल कारण: code ने actual token transfers को validate करने के बजाय user-controlled `_cmd.value` पर भरोसा किया। Attacker expected और actual transfers को desynchronize करके funds drain कर सकता था। परिणाम: protocol solvency के लिए high severity risk।<sup>[[2]](#references)[[3]](#references)</sup>

Guidance: ऐसे surviving mutants जो value transfers, accounting या access control को प्रभावित करते हैं, उन्हें kill होने तक high-risk मानें।

## हर mutant को kill करने के लिए tests blindly generate न करें

Mutation-driven test generation तब उलटा असर डाल सकता है जब वर्तमान implementation गलत हो। उदाहरण: `priority >= 2` को `priority > 2` में mutate करने से behavior बदलता है, लेकिन सही fix हमेशा "`priority == 2` के लिए test लिखना" नहीं होता। वह behavior स्वयं bug हो सकता है।<sup>[[1]](#references)</sup>

अधिक सुरक्षित workflow:
- Ambiguous requirements की पहचान करने के लिए surviving mutants का उपयोग करें
- Specs, protocol docs या reviewers से expected behavior validate करें
- इसके बाद ही behavior को test/invariant के रूप में encode करें

अन्यथा, आप implementation accidents को test suite में hard-code करने और false confidence प्राप्त करने का जोखिम उठाते हैं।

## Practical checklist

- एक targeted campaign चलाएँ:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- जब उपलब्ध हों, तो regex-only mutation के बजाय syntax-aware mutators (AST/Tree-sitter) को प्राथमिकता दें।
- Survivors को triage करें और ऐसे tests/invariants लिखें जो mutated behavior के तहत fail हों।
- Balances, supply, authorizations और events assert करें।
- Boundary tests जोड़ें (`==`, overflows/underflows, zero-address, zero-amount, empty arrays)।
- Unrealistic mocks को बदलें; failure modes simulate करें।
- जब tooling इसे support करे, तो results persist करें और triage से पहले uncaught mutants को filter करें।
- Runtime को manageable रखने के लिए two-phase या per-target campaigns का उपयोग करें।
- तब तक iterate करें जब तक सभी mutants kill न हो जाएँ या comments और rationale के साथ justified न हों।

## References

- [1] [Agentic era के लिए Mutation testing](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [अपने tests द्वारा न पकड़े जाने वाले bugs खोजने के लिए mutation testing का उपयोग करें (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
