# Smart Contracts के लिए Mutation Testing (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "आपके tests को जाँचता है"। इसमें contract code में व्यवस्थित रूप से छोटे बदलाव (mutants) किए जाते हैं और test suite को दोबारा चलाया जाता है। अगर कोई test fail होता है, तो mutant मारा जाता है। अगर tests फिर भी pass होते हैं, तो mutant बच जाता है और एक ऐसा blind spot सामने आता है जिसे line/branch coverage नहीं पकड़ सकती।

मुख्य विचार: Coverage दिखाता है कि code चलाया गया; mutation testing दिखाता है कि क्या behavior को वास्तव में assert किया गया है।<sup>[[2]](#references)</sup>

## Coverage भ्रामक क्यों हो सकता है

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

यूनिट टेस्ट जो केवल threshold से कम और threshold से अधिक value जांचते हैं, 100% line/branch coverage हासिल कर सकते हैं, लेकिन equality boundary (==) को assert करने में विफल हो सकते हैं। `deposit >= 2 ether` में refactor करने पर भी ऐसे टेस्ट पास हो जाएंगे और protocol logic चुपचाप टूट जाएगा।<sup>[[2]](#references)</sup>

Mutation testing condition में बदलाव करके और यह जांचकर इस कमी को उजागर करता है कि टेस्ट विफल होते हैं या नहीं।

Smart contracts में, surviving mutants अक्सर इन जगहों पर छूटे हुए checks की ओर संकेत करते हैं:
- Authorization और role boundaries
- Accounting/value-transfer invariants
- Revert conditions और failure paths
- Boundary conditions (`==`, zero values, empty arrays, max/min values)

## सबसे अधिक security signal देने वाले mutation operators

Contract auditing के लिए उपयोगी mutation classes:<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**: निष्पादित न हुए paths उजागर करने के लिए statements को `revert()` से बदलना
- **Medium severity**: अप्रमाणित side effects उजागर करने के लिए lines पर comment करना / logic हटाना
- **Low severity**: operators या constants में सूक्ष्म बदलाव, जैसे `>=` -> `>` या `+` -> `-`
- अन्य आम बदलाव: assignment replacement, boolean flips, condition negation, और type changes

व्यावहारिक लक्ष्य: सभी अर्थपूर्ण mutants को kill करना और उन survivors का स्पष्ट औचित्य देना जो अप्रासंगिक या semantically equivalent हों।

## Regex की तुलना में syntax-aware mutation बेहतर क्यों है

पुराने mutation engines regex या line-oriented rewrites पर निर्भर थे। यह काम करता है, लेकिन इसकी कुछ अहम सीमाएं हैं:<sup>[[1]](#references)</sup>
- Multi-line statements को सुरक्षित रूप से mutate करना कठिन है
- Language structure समझ में नहीं आती, इसलिए comments/tokens को गलत तरीके से target किया जा सकता है
- कमजोर line पर हर संभव variant बनाना runtime का बड़ा हिस्सा व्यर्थ करता है

AST- या Tree-sitter-आधारित tooling raw lines के बजाय structured nodes को target करके इसे बेहतर बनाती है:<sup>[[1]](#references)</sup>
- **slither-mutate** Slither के Solidity AST का उपयोग करता है।<sup>[[4]](#references)</sup>
- **mewt** language-agnostic core के रूप में Tree-sitter का उपयोग करता है।<sup>[[6]](#references)</sup>
- **MuTON**, `mewt` पर आधारित है और TON languages जैसे FunC, Tolk, और Tact के लिए first-class support जोड़ता है।<sup>[[7]](#references)</sup>

इससे multi-line constructs और expression-level mutations, केवल regex वाले तरीकों की तुलना में कहीं अधिक विश्वसनीय हो जाते हैं।

## slither-mutate के साथ mutation testing चलाना

आवश्यकताएं: Slither v0.10.2+।

- Options और mutators की सूची देखें:

```bash
slither-mutate --help
slither-mutate --list-mutators
```

- Foundry उदाहरण (परिणाम कैप्चर करें और पूरा लॉग रखें):<sup>[[2]](#references)</sup>

```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```

- यदि आप Foundry का उपयोग नहीं करते हैं, तो `--test-cmd` को अपने tests चलाने के तरीके से बदलें (जैसे, `npx hardhat test`, `npm test`)।

डिफ़ॉल्ट रूप से artifacts `./mutation_campaign` में संग्रहीत होते हैं। Uncaught (surviving) mutants को निरीक्षण के लिए वहाँ कॉपी किया जाता है।<sup>[[5]](#references)</sup>

### आउटपुट को समझना

Report की पंक्तियाँ इस तरह दिखती हैं:

```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```

- ब्रैकेट में दिया गया tag mutator alias है (उदाहरण के लिए, `CR` = Comment Replacement)।
- `UNCAUGHT` का अर्थ है कि mutated behavior के तहत tests पास हुए → assertion मौजूद नहीं है।

## रनटाइम कम करना: प्रभावशाली mutants को प्राथमिकता दें

Mutation campaigns में घंटों या दिन लग सकते हैं। लागत कम करने के लिए सुझाव:<sup>[[1]](#references)[[2]](#references)</sup>
- Scope: पहले केवल critical contracts/directories से शुरू करें, फिर विस्तार करें।
- Mutators को प्राथमिकता दें: अगर किसी line पर high-priority mutant बच जाता है (उदाहरण के लिए, `revert()` या comment-out), तो उस line के लिए lower-priority variants छोड़ दें।
- Two-phase campaigns चलाएँ: पहले focused/fast tests चलाएँ, फिर केवल uncaught mutants को पूरे suite के साथ दोबारा test करें।
- जहाँ संभव हो, mutation targets को specific test commands से जोड़ें (उदाहरण के लिए, auth code -> auth tests)।
- समय कम हो तो campaigns को high/medium severity mutants तक सीमित रखें।
- अगर आपका runner अनुमति देता है, तो tests parallelize करें; dependencies/builds को cache करें।
- Fail-fast: जब कोई बदलाव स्पष्ट रूप से assertion gap दिखाए, तो जल्दी रोक दें।

रनटाइम का हिसाब बहुत भारी है: `1000 mutants x 5-minute tests ~= 83 hours`, इसलिए campaign design, mutator जितना ही मायने रखता है।<sup>[[1]](#references)</sup>

## Persistent campaigns और बड़े पैमाने पर triage

पुराने workflows की एक कमजोरी यह है कि वे results को केवल `stdout` में डालते हैं। लंबी campaigns के लिए इससे pause/resume, filtering और review करना मुश्किल हो जाता है।<sup>[[1]](#references)</sup>

`mewt`/`MuTON` mutants और outcomes को SQLite-backed campaigns में store करके इसे बेहतर बनाते हैं। फ़ायदे:<sup>[[1]](#references)</sup>
- Progress खोए बिना लंबे runs को pause और resume करें
- किसी specific file या mutation class में केवल uncaught mutants filter करें
- Review tooling के लिए results को SARIF में export/translate करें
- Raw terminal logs के बजाय AI-assisted triage को छोटे, filtered result sets दें

जब mutation testing किसी one-off manual review के बजाय audit pipeline का हिस्सा बन जाता है, तब persistent results विशेष रूप से उपयोगी होते हैं।

## बच जाने वाले mutants के लिए triage workflow

1) Mutated line और behavior की जाँच करें।
   - Mutated line लागू करके और focused test चलाकर इसे locally reproduce करें।

2) Tests को केवल return values नहीं, बल्कि state assert करने के लिए मजबूत करें।
   - Equality-boundary checks जोड़ें (उदाहरण के लिए, threshold `==` को test करें)।
   - Post-conditions assert करें: balances, total supply, authorization effects और emitted events।

3) बहुत permissive mocks को realistic behavior से बदलें।
   - सुनिश्चित करें कि mocks, on-chain होने वाले transfers, failure paths और event emissions को enforce करें।

4) Fuzz tests के लिए invariants जोड़ें।
   - उदाहरण के लिए, value का conservation, non-negative balances, authorization invariants और जहाँ लागू हो वहाँ monotonic supply।

5) True positives को semantic no-ops से अलग करें।
   - उदाहरण: `x > 0` -> `x != 0` तब अर्थहीन है जब `x` unsigned हो।

6) Campaign को तब तक दोबारा चलाएँ, जब तक survivors मारे न जाएँ या उन्हें स्पष्ट रूप से उचित न ठहराया जाए।

## Case study: missing state assertions उजागर करना (Arkis protocol)

Arkis DeFi protocol के audit के दौरान एक mutation campaign में ऐसे survivors सामने आए:<sup>[[2]](#references)[[3]](#references)</sup>

```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```

Commenting out assignment से tests नहीं टूटे, जिससे missing post-state assertions साबित हुए। Root cause: code ने actual token transfers को validate करने के बजाय user-controlled `_cmd.value` पर भरोसा किया। Attacker expected और actual transfers के बीच तालमेल बिगाड़कर funds निकाल सकता था। नतीजा: protocol की solvency के लिए high severity risk।<sup>[[2]](#references)[[3]](#references)</sup>

Guidance: Value transfers, accounting या access control को प्रभावित करने वाले survivors को तब तक high-risk मानें, जब तक वे kill न हो जाएँ।

## Do not blindly generate tests to kill every mutant

Mutation-driven test generation उलटा असर डाल सकता है, अगर मौजूदा implementation गलत हो। उदाहरण: `priority >= 2` को `priority > 2` में mutate करने से behavior बदलता है, लेकिन सही fix हमेशा " `priority == 2` के लिए test लिखना" नहीं होता। वह behavior खुद bug हो सकता है।<sup>[[1]](#references)</sup>

ज़्यादा सुरक्षित workflow:
- अस्पष्ट requirements पहचानने के लिए surviving mutants का उपयोग करें
- Specs, protocol docs या reviewers से expected behavior validate करें
- उसके बाद ही उस behavior को test/invariant के रूप में encode करें

अन्यथा, आप implementation की आकस्मिकताओं को test suite में hard-code करने और false confidence पाने का जोखिम उठाते हैं।

## Practical checklist

- एक targeted campaign चलाएँ:
  - `slither-mutate ./src/contracts --test-cmd="forge test"`
- उपलब्ध होने पर regex-only mutation के बजाय syntax-aware mutators (AST/Tree-sitter) को प्राथमिकता दें।
- Survivors की triage करें और ऐसे tests/invariants लिखें जो mutated behavior के तहत fail हों।
- Balances, supply, authorizations और events assert करें।
- Boundary tests जोड़ें (`==`, overflows/underflows, zero-address, zero-amount, empty arrays)।
- Unrealistic mocks बदलें; failure modes simulate करें।
- Tooling सपोर्ट करे तो results persist करें, और triage से पहले uncaught mutants को filter करें।
- Runtime को manageable रखने के लिए two-phase या per-target campaigns का उपयोग करें।
- तब तक iterate करें, जब तक सभी mutants kill न हो जाएँ या comments और rationale के साथ justify न किए जाएँ।

## References

- [1] [Agentic era के लिए mutation testing](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [अपने tests से छूट जाने वाले bugs खोजने के लिए mutation testing का उपयोग करें (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
