# Mutation Testing kwa Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "hujaribu tests zako" kwa kuingiza kwa utaratibu mabadiliko madogo (mutants) kwenye code ya contract na kuendesha tena test suite. Test ikishindwa, mutant huondolewa. Ikiwa tests bado zinapita, mutant husalia, na kufichua blind spot ambayo line/branch coverage haiwezi kugundua.

Wazo kuu: Coverage huonyesha kuwa code ilitekelezwa; mutation testing huonyesha ikiwa tabia yake imethibitishwa kwa assertions.<sup>[[2]](#references)</sup>

## Kwa nini coverage inaweza kupotosha

Fikiria ukaguzi huu rahisi wa threshold:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Unit tests zinazokagua tu value iliyo chini na value iliyo juu ya threshold zinaweza kufikia 100% line/branch coverage huku zikishindwa kuassert equality boundary (==). Refactor ya kuwa `deposit >= 2 ether` bado ingepita tests hizo, na kuvunja logic ya protocol kimya kimya.<sup>[[2]](#references)</sup>

Mutation testing hufichua pengo hili kwa kubadilisha condition na kuthibitisha kuwa tests zinashindwa.

Kwa smart contracts, mutants wanaosalia mara nyingi huonyesha ukosefu wa checks zinazohusu:
- Authorization na role boundaries
- Accounting/value-transfer invariants
- Revert conditions na failure paths
- Boundary conditions (`==`, zero values, empty arrays, max/min values)

## Mutation operators zenye security signal ya juu

Mutation classes muhimu kwa contract auditing:<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**: badilisha statements ziwe `revert()` ili kufichua paths ambazo hazijatekelezwa
- **Medium severity**: comment out lines / ondoa logic ili kufichua side effects ambazo hazijathibitishwa
- **Low severity**: subtle operator au constant swaps kama `>=` -> `>` au `+` -> `-`
- Mabadiliko mengine ya kawaida: assignment replacement, boolean flips, condition negation, na type changes

Lengo la vitendo: kill mutants wote wenye maana, na ueleze wazi survivors ambao hawana umuhimu au wana semantic equivalence.

## Kwa nini syntax-aware mutation ni bora kuliko regex

Mutation engines za zamani zilitumia regex au line-oriented rewrites. Hii hufanya kazi, lakini ina limitations muhimu:<sup>[[1]](#references)</sup>
- Multi-line statements ni vigumu kuzim vitu kwa usalama
- Muundo wa language haueleweki, hivyo comments/tokens zinaweza kulengwa vibaya
- Kuzalisha kila possible variant kwenye line dhaifu hupoteza kiasi kikubwa cha runtime

Tooling ya AST- au Tree-sitter-based huboresha hili kwa kulenga structured nodes badala ya raw lines:<sup>[[1]](#references)</sup>
- **slither-mutate** hutumia Slither's Solidity AST.<sup>[[4]](#references)</sup>
- **mewt** hutumia Tree-sitter kama language-agnostic core.<sup>[[6]](#references)</sup>
- **MuTON** hujengwa juu ya `mewt` na huongeza first-class support kwa TON languages kama FunC, Tolk, na Tact.<sup>[[7]](#references)</sup>

Hii hufanya multi-line constructs na expression-level mutations ziwe reliable zaidi kuliko approaches zinazotumia regex pekee.

## Kuendesha mutation testing na slither-mutate

Requirements: Slither v0.10.2+.

- Orodhesha options na mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Mfano wa Foundry (nasa matokeo na uhifadhi logi kamili):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Ikiwa hutumii Foundry, badilisha `--test-cmd` na jinsi unavyoendesha tests (kwa mfano, `npx hardhat test`, `npm test`).

Artifacts huhifadhiwa katika `./mutation_campaign` kwa chaguo-msingi. Mutants ambao hawajakamatwa (walionusurika) hunakiliwa humo kwa ajili ya ukaguzi.<sup>[[5]](#references)</sup>

### Kuelewa matokeo

Mistari ya ripoti huonekana hivi:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Tag iliyo kwenye mabano ni alias ya mutator (kwa mfano, `CR` = Comment Replacement).
- `UNCAUGHT` inamaanisha tests zilifaulu chini ya tabia iliyobadilishwa → assertion haipo.

## Kupunguza muda wa utekelezaji: prioritiza mutants wenye athari

Mutation campaigns zinaweza kuchukua saa au siku. Vidokezo vya kupunguza gharama:<sup>[[1]](#references)[[2]](#references)</sup>
- Scope: Anza na contracts/directories muhimu pekee, kisha panua.
- Prioritize mutators: Ikiwa mutant yenye priority ya juu kwenye mstari fulani inanusurika (kwa mfano `revert()` au comment-out), ruka variants zenye priority ya chini za mstari huo.
- Tumia campaigns za awamu mbili: endesha tests zilizolenga na za haraka kwanza, kisha fanya re-test ya mutants ambao hawakukamatwa pekee kwa kutumia full suite.
- Panga mutation targets na test commands mahususi inapowezekana (kwa mfano auth code -> auth tests).
- Punguza campaigns hadi mutants wa severity ya juu/kati wakati muda ni mdogo.
- Endesha tests kwa parallel ikiwa runner yako inaruhusu; weka dependencies/builds kwenye cache.
- Fail-fast: simamisha mapema wakati mabadiliko yanaonyesha wazi pengo la assertion.

Hesabu ya runtime ni kali: `1000 mutants x 5-minute tests ~= 83 hours`, kwa hiyo muundo wa campaign ni muhimu sawa na mutator yenyewe.<sup>[[1]](#references)</sup>

## Campaigns zinazoendelea na triage kwa kiwango kikubwa

Udhaifu mmoja wa workflows za zamani ni kutupa matokeo kwenye `stdout` pekee. Kwa campaigns ndefu, hii hufanya pause/resume, filtering na review kuwa ngumu zaidi.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` huboresha hili kwa kuhifadhi mutants na outcomes katika campaigns zinazotumia SQLite. Faida:<sup>[[1]](#references)</sup>
- Pause na resume runs ndefu bila kupoteza progress
- Filter mutants ambao hawakukamatwa pekee katika file au mutation class mahususi
- Export/translate results kuwa SARIF kwa review tooling
- Ipe AI-assisted triage result sets ndogo zilizochujwa badala ya raw terminal logs

Matokeo yanayohifadhiwa ni muhimu hasa wakati mutation testing inakuwa sehemu ya audit pipeline badala ya manual review ya mara moja.

## Workflow ya triage kwa mutants wanaonusurika

1) Kagua mstari na tabia iliyobadilishwa.
- I-reproduce locally kwa kutumia mstari uliobadilishwa na kuendesha focused test.

2) Imarisha tests ili kuthibitisha state, si return values pekee.
- Ongeza equality-boundary checks (kwa mfano, test threshold `==`).
- Thibitisha post-conditions: balances, total supply, authorization effects na emitted events.

3) Badilisha mocks zinazoruhusu kupita kiasi na tabia halisi.
- Hakikisha mocks zinatekeleza transfers, failure paths na event emissions zinazotokea on-chain.

4) Ongeza invariants kwa fuzz tests.
- Kwa mfano, conservation of value, non-negative balances, authorization invariants na monotonic supply inapohusika.

5) Tenganisha true positives na semantic no-ops.
- Mfano: `x > 0` -> `x != 0` haina maana wakati `x` ni unsigned.

6) Endesha tena campaign hadi survivors wauawa au waelezwe waziwazi.

## Case study: kufichua state assertions zinazokosekana (Arkis protocol)

Mutation campaign wakati wa audit ya Arkis DeFi protocol ilifichua survivors kama:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Kuweka comment kwenye assignment hakukuvunja tests, jambo linalothibitisha ukosefu wa post-state assertions. Chanzo kikuu: code iliamini `_cmd.value` inayodhibitiwa na user badala ya kuthibitisha token transfers halisi. Attacker angeweza kutenganisha transfers zilizotarajiwa na halisi ili kuiba funds. Matokeo: risk ya kiwango cha juu kwa solvency ya protocol.<sup>[[2]](#references)[[3]](#references)</sup>

Mwongozo: Chukulia mutants survivors wanaoathiri value transfers, accounting, au access control kuwa high-risk hadi waangamizwe.

## Usizalishe tests bila kufikiri ili kuangamiza kila mutant

Mutation-driven test generation inaweza kuleta madhara ikiwa implementation ya sasa ina makosa. Mfano: kubadilisha `priority >= 2` kuwa `priority > 2` hubadilisha tabia, lakini fix sahihi si lazima iwe "andika test ya `priority == 2`". Tabia hiyo yenyewe inaweza kuwa bug.<sup>[[1]](#references)</sup>

Workflow salama:
- Tumia mutants survivors kutambua requirements zenye utata
- Thibitisha tabia inayotarajiwa kwa kutumia specs, protocol docs, au reviewers
- Ni baada ya hapo ndipo uweke tabia hiyo kama test/invariant

Vinginevyo, unaweza kuweka kwa lazima ajali za implementation ndani ya test suite na kupata confidence ya uongo.

## Practical checklist

- Endesha campaign inayolenga:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Pendelea mutators wanaotambua syntax (AST/Tree-sitter) badala ya mutation inayotegemea regex pekee inapowezekana.
- Changanua survivors na uandike tests/invariants ambazo zingeshindwa chini ya tabia iliyobadilishwa.
- Kagua balances, supply, authorizations, na events.
- Ongeza boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Badilisha mocks zisizo halisi; simulate failure modes.
- Hifadhi matokeo tooling inaposaidia, na chuja mutants ambao hawakukamatwa kabla ya triage.
- Tumia campaigns za awamu mbili au kwa kila target ili kudhibiti runtime.
- Rudia hadi mutants wote waangamizwe au waelezwe kwa comments na rationale.

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Tumia mutation testing kutafuta bugs ambazo tests zako hazigundui (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Mapitio ya Usalama ya Arkis DeFi Prime Brokerage (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Nyaraka za Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
