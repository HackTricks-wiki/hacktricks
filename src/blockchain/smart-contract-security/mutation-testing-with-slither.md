# Smart Contracts के लिए Mutation Testing (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" by systematically contract code में छोटे changes (mutants) introduce करके और फिर test suite को दोबारा चलाकर काम करता है। अगर कोई test fail होता है, तो mutant killed हो जाता है। अगर tests फिर भी pass करते हैं, तो mutant survives करता है, जिससे एक blind spot सामने आता है जिसे line/branch coverage detect नहीं कर सकती।

Key idea: Coverage दिखाती है कि code execute हुआ; mutation testing दिखाती है कि behavior सच में asserted है या नहीं।

## Why coverage can deceive

इस simple threshold check पर विचार करें:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
एकमात्र ऐसे unit tests जो threshold के नीचे और threshold के ऊपर का value check करते हैं, 100% line/branch coverage तक पहुंच सकते हैं, जबकि equality boundary (==) को assert करने में fail हो सकते हैं। `deposit >= 2 ether` में refactor करने पर भी ऐसे tests pass हो जाएंगे, और protocol logic silently टूट जाएगी।

Mutation testing condition को mutate करके और यह verify करके कि tests fail होते हैं, इस gap को expose करता है।

smart contracts के लिए, surviving mutants अक्सर इन missing checks की ओर इशारा करते हैं:
- Authorization और role boundaries
- Accounting/value-transfer invariants
- Revert conditions और failure paths
- Boundary conditions (`==`, zero values, empty arrays, max/min values)

## सबसे ज्यादा security signal वाले Mutation operators

contract auditing के लिए उपयोगी mutation classes:
- **High severity**: unexecuted paths को expose करने के लिए statements को `revert()` से replace करना
- **Medium severity**: unverified side effects को उजागर करने के लिए lines को comment out / logic remove करना
- **Low severity**: subtle operator या constant swaps जैसे `>=` -> `>` या `+` -> `-`
- अन्य common edits: assignment replacement, boolean flips, condition negation, और type changes

Practical goal: सभी meaningful mutants को kill करना, और जो survivors irrelevant या semantically equivalent हैं, उन्हें explicitly justify करना।

## regex से syntax-aware mutation बेहतर क्यों है

पुराने mutation engines regex या line-oriented rewrites पर निर्भर थे। यह काम करता है, लेकिन इसकी महत्वपूर्ण limitations हैं:
- Multi-line statements को safely mutate करना कठिन है
- Language structure समझी नहीं जाती, इसलिए comments/tokens को गलत तरीके से target किया जा सकता है
- कमजोर line पर हर possible variant generate करने से runtime का बहुत बड़ा हिस्सा waste होता है

AST- या Tree-sitter-based tooling raw lines के बजाय structured nodes को target करके इसे बेहतर बनाता है:
- **slither-mutate** Slither के Solidity AST का उपयोग करता है
- **mewt** language-agnostic core के रूप में Tree-sitter का उपयोग करता है
- **MuTON** `mewt` पर build होता है और TON languages जैसे FunC, Tolk, और Tact के लिए first-class support जोड़ता है

इससे multi-line constructs और expression-level mutations regex-only approaches की तुलना में बहुत अधिक reliable हो जाते हैं।

## slither-mutate के साथ mutation testing चलाना

Requirements: Slither v0.10.2+.

- Options और mutators list करें:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry उदाहरण (results को capture करें और एक full log रखें):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- यदि आप Foundry का उपयोग नहीं करते हैं, तो `--test-cmd` को अपने tests चलाने के तरीके से बदलें (उदा., `npx hardhat test`, `npm test`)।

Artifacts डिफ़ॉल्ट रूप से `./mutation_campaign` में संग्रहीत होते हैं। Uncaught (surviving) mutants जांच के लिए वहाँ कॉपी किए जाते हैं।

### आउटपुट को समझना

Report lines इस तरह दिखती हैं:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- ब्रैकेट्स में दिया गया tag mutator alias है (जैसे, `CR` = Comment Replacement).
- `UNCAUGHT` का मतलब है tests mutated behavior के तहत pass हो गए → missing assertion.

## runtime कम करना: प्रभावशाली mutants को प्राथमिकता दें

Mutation campaigns में hours या days लग सकते हैं। cost कम करने के tips:
- Scope: पहले सिर्फ critical contracts/directories से शुरू करें, फिर expand करें।
- Prioritize mutators: अगर किसी line पर high-priority mutant survive कर जाता है (उदाहरण `revert()` या comment-out), तो उसी line के lower-priority variants को skip करें।
- दो-phase campaigns इस्तेमाल करें: पहले focused/fast tests चलाएँ, फिर सिर्फ uncaught mutants को full suite के साथ re-test करें।
- जब संभव हो, mutation targets को specific test commands से map करें (उदाहरण auth code -> auth tests)।
- Time कम हो तो high/medium severity mutants तक सीमित रखें।
- अगर आपका runner allow करता है, tests को parallelize करें; dependencies/builds cache करें।
- Fail-fast: जब कोई change साफ तौर पर assertion gap दिखाए, तो early stop करें।

runtime math बहुत brutal है: `1000 mutants x 5-minute tests ~= 83 hours`, इसलिए campaign design उतना ही महत्वपूर्ण है जितना mutator खुद।

## Persistent campaigns और scale पर triage

पुराने workflows की एक कमजोरी यह है कि results सिर्फ `stdout` पर dump होते हैं। लंबे campaigns के लिए इससे pause/resume, filtering, और review मुश्किल हो जाता है।

`mewt`/`MuTON` mutants और outcomes को SQLite-backed campaigns में store करके इसे बेहतर बनाते हैं। Benefits:
- लंबी runs को progress खोए बिना pause और resume करें
- किसी specific file या mutation class में सिर्फ uncaught mutants filter करें
- Review tooling के लिए results को SARIF में export/translate करें
- AI-assisted triage को raw terminal logs के बजाय छोटे, filtered result sets दें

Persistent results खासकर तब useful होते हैं जब mutation testing एक one-off manual review के बजाय audit pipeline का हिस्सा बन जाता है।

## surviving mutants के लिए triage workflow

1) mutated line और behavior को inspect करें।
- mutated line apply करके और focused test चलाकर locally reproduce करें।

2) tests को मजबूत करें ताकि वे सिर्फ return values नहीं, state भी assert करें।
- equality-boundary checks जोड़ें (उदाहरण, threshold `==` test करें)।
- post-conditions assert करें: balances, total supply, authorization effects, और emitted events।

3) overly permissive mocks को realistic behavior से replace करें।
- सुनिश्चित करें कि mocks transfers, failure paths, और event emissions enforce करें जो on-chain होती हैं।

4) fuzz tests के लिए invariants जोड़ें।
- उदाहरण: value conservation, non-negative balances, authorization invariants, जहाँ लागू हो वहाँ monotonic supply।

5) true positives को semantic no-ops से अलग करें।
- उदाहरण: `x > 0` -> `x != 0` meaningless है जब `x` unsigned हो।

6) campaign को तब तक re-run करें जब तक survivors kill न हो जाएँ या explicitly justify न कर दिए जाएँ।

## Case study: missing state assertions को उजागर करना (Arkis protocol)

Arkis DeFi protocol के audit के दौरान एक mutation campaign में ऐसे survivors सामने आए जैसे:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Assignment को comment out करने से tests नहीं टूटे, जिससे missing post-state assertions साबित हुईं। Root cause: code ने actual token transfers को validate करने के बजाय user-controlled `_cmd.value` पर भरोसा किया। एक attacker expected vs. actual transfers को desynchronize करके funds drain कर सकता था। Result: protocol solvency के लिए high severity risk।

Guidance: value transfers, accounting, या access control को affect करने वाले survivors को killed होने तक high-risk मानें।

## Do not blindly generate tests to kill every mutant

Mutation-driven test generation backfire कर सकती है अगर current implementation गलत हो। Example: `priority >= 2` को `priority > 2` में mutate करने से behavior बदलता है, लेकिन सही fix हमेशा "write a test for `priority == 2`" नहीं होता। वह behavior खुद bug हो सकता है।

Safer workflow:
- Surviving mutants का उपयोग ambiguous requirements identify करने के लिए करें
- Expected behavior को specs, protocol docs, या reviewers से validate करें
- केवल तब behavior को test/invariant के रूप में encode करें

वरना, आप implementation accidents को test suite में hard-code कर सकते हैं और false confidence पा सकते हैं।

## Practical checklist

- Run a targeted campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- उपलब्ध होने पर regex-only mutation की जगह syntax-aware mutators (AST/Tree-sitter) को prefer करें।
- Survivors को triage करें और ऐसे tests/invariants लिखें जो mutated behavior के under fail हों।
- Balances, supply, authorizations, और events assert करें।
- Boundary tests जोड़ें (`==`, overflows/underflows, zero-address, zero-amount, empty arrays)।
- Unrealistic mocks replace करें; failure modes simulate करें।
- Tooling support करे तो results persist करें, और triage से पहले uncaught mutants filter करें।
- Runtime manageable रखने के लिए two-phase या per-target campaigns use करें।
- Iterate करें जब तक सभी mutants killed न हों या comments और rationale के साथ justified न हों।

## References

- [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)
- [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [mewt](https://github.com/trailofbits/mewt)
- [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
