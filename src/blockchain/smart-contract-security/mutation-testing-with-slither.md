# Mutation Testing kwa Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "hupima tests zako" kwa kuingiza kimfumo mabadiliko madogo (mutants) kwenye code ya contract na kuendesha tena test suite. Ikiwa test itashindwa, mutant inauawa. Ikiwa tests bado zitapita, mutant itaendelea kuishi, ikifichua blind spot ambayo line/branch coverage haiwezi kugundua.

Wazo kuu: Coverage huonyesha kuwa code ilitekelezwa; mutation testing huonyesha ikiwa behavior imethibitishwa kwa assertions.<sup>[[2]](#references)</sup>

## Kwa nini coverage inaweza kupotosha

Fikiria threshold check hii rahisi:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Unit tests zinazoangalia tu thamani iliyo chini na thamani iliyo juu ya threshold zinaweza kufikia 100% ya line/branch coverage bila kuthibitisha mpaka wa usawa (==). Refactor ya `deposit >= 2 ether` bado ingepita kwenye tests hizo, na hivyo kuvunja logic ya protocol kimya kimya.<sup>[[2]](#references)</sup>

Mutation testing hufichua pengo hili kwa kubadilisha condition na kuthibitisha kuwa tests zinashindwa.

Kwa smart contracts, mutants wanaosalia mara nyingi huonyesha checks zilizokosekana kuhusu:
- Authorization na mipaka ya roles
- Invariants za accounting/value-transfer
- Revert conditions na failure paths
- Boundary conditions (`==`, zero values, empty arrays, max/min values)

## Mutation operators zenye security signal ya juu zaidi

Mutation classes zenye manufaa kwa contract auditing:<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**: badilisha statements ziwe `revert()` ili kufichua paths ambazo hazijatekelezwa
- **Medium severity**: comment out lines / ondoa logic ili kufichua side effects ambazo hazijathibitishwa
- **Low severity**: mabadiliko madogo ya operators au constants kama `>=` -> `>` au `+` -> `-`
- Mabadiliko mengine ya kawaida: assignment replacement, boolean flips, condition negation, na type changes

Lengo la kiutendaji: kill mutants wote wenye maana, na utoe justification wazi kwa survivors ambao hawana umuhimu au wana maana sawa.

## Kwa nini syntax-aware mutation ni bora kuliko regex

Mutation engines za zamani zilitegemea regex au line-oriented rewrites. Hii inafanya kazi, lakini ina limitations muhimu:<sup>[[1]](#references)</sup>
- Statements za mistari mingi ni vigumu kuzibadilisha kwa usalama
- Muundo wa language haueleweki, hivyo comments/tokens zinaweza kulengwa vibaya
- Kutengeneza kila variant inayowezekana kwenye line dhaifu hupoteza runtime nyingi

Tooling inayotumia AST au Tree-sitter huboresha hili kwa kulenga structured nodes badala ya raw lines:<sup>[[1]](#references)</sup>
- **slither-mutate** hutumia Solidity AST ya Slither<sup>[[4]](#references)</sup>
- **mewt** hutumia Tree-sitter kama core isiyofungamana na language<sup>[[6]](#references)</sup>
- **MuTON** hujengwa juu ya `mewt` na kuongeza first-class support kwa languages za TON kama FunC, Tolk, na Tact<sup>[[7]](#references)</sup>

Hii hufanya constructs za mistari mingi na mutations za kiwango cha expression ziwe za kuaminika zaidi kuliko approaches zinazotumia regex pekee.

## Kuendesha mutation testing kwa slither-mutate

Mahitaji: Slither v0.10.2+.

- Orodhesha options na mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Mfano wa Foundry (kusanya matokeo na uhifadhi log kamili):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Ikiwa hutumii Foundry, badilisha `--test-cmd` kwa jinsi unavyoendesha tests (kwa mfano, `npx hardhat test`, `npm test`).

Artifacts huhifadhiwa katika `./mutation_campaign` kwa chaguo-msingi. Mutants ambao hawajakamatwa (walionusurika) hunakiliwa humo kwa ajili ya ukaguzi.<sup>[[5]](#references)</sup>

### Kuelewa matokeo

Mistari ya ripoti huonekana kama:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Tag iliyo kwenye mabano ni alias ya mutator (kwa mfano, `CR` = Comment Replacement).
- `UNCAUGHT` inamaanisha tests zilifaulu chini ya tabia iliyobadilishwa → assertion haipo.

## Kupunguza muda wa utekelezaji: panga mutants wenye athari kubwa

Mutation campaigns zinaweza kuchukua saa au siku. Vidokezo vya kupunguza gharama:<sup>[[1]](#references)[[2]](#references)</sup>
- Scope: Anza na contracts/directories muhimu pekee, kisha panua.
- Panga mutators kwa kipaumbele: Ikiwa mutant yenye kipaumbele cha juu kwenye mstari fulani itasalia (kwa mfano `revert()` au comment-out), ruka variants zenye kipaumbele cha chini za mstari huo.
- Tumia campaigns za awamu mbili: endesha tests zinazolenga maeneo fulani na zilizo fast kwanza, kisha fanya re-test ya mutants ambazo hazikukamatwa pekee kwa kutumia full suite.
- Husisha mutation targets na test commands maalum inapowezekana (kwa mfano auth code -> auth tests).
- Zuilia campaigns kwenye mutants za severity ya juu/ya kati wakati muda ni mdogo.
- Endesha tests kwa parallel ikiwa runner yako inaruhusu; weka dependencies/builds kwenye cache.
- Fail-fast: simamisha mapema wakati mabadiliko yanaonyesha wazi pengo la assertion.

Hesabu ya muda ni kali: `1000 mutants x 5-minute tests ~= 83 hours`, kwa hiyo muundo wa campaign ni muhimu sawa na mutator yenyewe.<sup>[[1]](#references)</sup>

## Campaigns zinazoendelea na triage kwa kiwango kikubwa

Udhaifu mmoja wa workflows za zamani ni kutupa matokeo kwenye `stdout` pekee. Kwa campaigns ndefu, hii hufanya pause/resume, filtering, na review kuwa ngumu zaidi.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` huboresha hili kwa kuhifadhi mutants na outcomes kwenye campaigns zinazotumia SQLite. Faida:<sup>[[1]](#references)</sup>
- Sitisha na endeleza runs ndefu bila kupoteza progress
- Filter mutants ambazo hazikukamatwa pekee katika file au mutation class maalum
- Export/translate matokeo hadi SARIF kwa review tooling
- Ipe AI-assisted triage result sets ndogo zilizochujwa badala ya raw terminal logs

Matokeo yanayodumu ni muhimu hasa mutation testing inapokuwa sehemu ya audit pipeline badala ya manual review ya mara moja.

## Workflow ya triage kwa mutants wanaosalia

1) Kagua mstari na tabia iliyobadilishwa.
- Reproduce locally kwa kutumia mstari uliobadilishwa na kuendesha test inayolenga eneo husika.

2) Imarisha tests ili kuassert state, si return values pekee.
- Ongeza equality-boundary checks (kwa mfano, test threshold `==`).
- Assert post-conditions: balances, total supply, authorization effects, na emitted events.

3) Badilisha mocks zinazoruhusu mambo kupita kiasi kwa tabia halisi.
- Hakikisha mocks zinatekeleza transfers, failure paths, na event emissions zinazotokea on-chain.

4) Ongeza invariants kwa fuzz tests.
- Kwa mfano, conservation of value, non-negative balances, authorization invariants, na monotonic supply inapohusika.

5) Tenganisha true positives na semantic no-ops.
- Mfano: `x > 0` -> `x != 0` haina maana wakati `x` ni unsigned.

6) Endesha tena campaign hadi survivors wauawe au waelezwe kwa uwazi.

## Case study: kufichua state assertions zinazokosekana (Arkis protocol)

Mutation campaign wakati wa audit ya Arkis DeFi protocol ilifichua survivors kama:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Ku-comment out assignment hakukuvunja tests, ikithibitisha ukosefu wa post-state assertions. Chanzo kikuu: code iliweka imani kwenye `_cmd.value` inayodhibitiwa na user badala ya kuthibitisha token transfers halisi. Attacker angeweza kutenganisha transfers zilizotarajiwa na halisi ili kuchota funds. Matokeo: hatari ya severity ya juu kwa solvency ya protocol.<sup>[[2]](#references)[[3]](#references)</sup>

Mwongozo: Chukulia survivors zinazoathiri value transfers, accounting, au access control kuwa high-risk hadi ziangamizwe.

## Usizalishe tests bila kufikiri ili kuangamiza kila mutant

Mutation-driven test generation inaweza kuleta madhara ikiwa implementation ya sasa si sahihi. Mfano: kubadilisha `priority >= 2` kuwa `priority > 2` hubadilisha tabia, lakini suluhisho sahihi si kila mara "andika test ya `priority == 2`". Tabia hiyo yenyewe inaweza kuwa bug.<sup>[[1]](#references)</sup>

Workflow salama:
- Tumia surviving mutants kutambua requirements zisizoeleweka
- Thibitisha tabia inayotarajiwa kutoka kwenye specs, protocol docs, au reviewers
- Ndipo uweke tabia hiyo kama test/invariant

Vinginevyo, unaweza ku-hard-code ajali za implementation kwenye test suite na kupata false confidence.

## Orodha ya ukaguzi ya vitendo

- Endesha campaign iliyolengwa:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Pendelea mutators wanaotambua syntax (AST/Tree-sitter) kuliko mutation ya regex pekee inapowezekana.
- Fanya triage ya survivors na uandike tests/invariants ambazo zingefeli chini ya tabia iliyomutatiwa.
- Thibitisha balances, supply, authorizations, na events.
- Ongeza boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Badilisha mocks zisizo halisi; simulate failure modes.
- Hifadhi matokeo tooling inapowezesha, na uchuje mutants ambao hawakunaswa kabla ya triage.
- Tumia campaigns za awamu mbili au kwa kila target ili kuweka runtime katika kiwango kinachoweza kudhibitiwa.
- Endelea kurudia hadi mutants wote waangamizwe au wa justified kwa comments na rationale.

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
