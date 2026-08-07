# Mutation Testing for Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "hujaribu tests zako" kwa kuanzisha kimfumo mabadiliko madogo (mutants) kwenye code ya contract na kuendesha tena test suite. Ikiwa test itafeli, mutant inauawa. Ikiwa tests bado zitapita, mutant inasalia, ikifichua blind spot ambayo line/branch coverage haiwezi kugundua.

Wazo kuu: Coverage inaonyesha kuwa code ilitekelezwa; mutation testing inaonyesha ikiwa behavior imethibitishwa na assertions.<sup>[[2]](#references)</sup>

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
Unit tests zinazokagua tu thamani iliyo chini na thamani iliyo juu ya threshold zinaweza kufikia 100% ya line/branch coverage huku zikishindwa kuthibitisha boundary ya usawa (==). Refactor ya kuwa `deposit >= 2 ether` bado ingepita kwenye tests hizo, na hivyo kuvunja logic ya protocol bila kuonekana.<sup>[[2]](#references)</sup>

Mutation testing hufichua pengo hili kwa kubadilisha condition na kuthibitisha kuwa tests zinashindwa.

Kwa smart contracts, mutants wanaosalia mara nyingi huonyesha checks zinazokosekana kuhusu:
- Authorization na mipaka ya roles
- Invariants za accounting/value-transfer
- Conditions za revert na failure paths
- Boundary conditions (`==`, zero values, empty arrays, max/min values)

## Mutation operators zenye security signal ya juu zaidi

Aina muhimu za mutations kwa contract auditing:<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**: badilisha statements ziwe `revert()` ili kufichua paths ambazo hazijatekelezwa
- **Medium severity**: comment out lines / ondoa logic ili kufichua side effects ambazo hazijathibitishwa
- **Low severity**: mabadiliko madogo ya operators au constants kama `>=` -> `>` au `+` -> `-`
- Mabadiliko mengine ya kawaida: assignment replacement, boolean flips, condition negation, na type changes

Lengo la kiutendaji: kill mutants wote wenye maana, na utoe justification wazi kwa survivors ambao hawahusiki au wana semantic equivalence.

## Kwa nini syntax-aware mutation ni bora kuliko regex

Mutation engines za zamani zilitumia regex au line-oriented rewrites. Hilo hufanya kazi, lakini lina limitations muhimu:<sup>[[1]](#references)</sup>
- Statements zenye mistari mingi ni vigumu kuzibadilisha kwa usalama
- Muundo wa language haueleweki, hivyo comments/tokens zinaweza kulengwa vibaya
- Kuzalisha kila variant inayowezekana kwenye line dhaifu hupoteza runtime nyingi

Tooling inayotumia AST au Tree-sitter huboresha hili kwa kulenga structured nodes badala ya lines ghafi:<sup>[[1]](#references)</sup>
- **slither-mutate** hutumia Solidity AST ya Slither
- **mewt** hutumia Tree-sitter kama core isiyofungamana na language maalum
- **MuTON** hujengwa juu ya `mewt` na huongeza support ya kwanza kwa languages za TON kama FunC, Tolk, na Tact

Hii hufanya constructs zenye mistari mingi na mutations za kiwango cha expression ziwe zenye reliability kubwa zaidi kuliko approaches zinazotumia regex pekee.

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
- Ikiwa hutumii Foundry, badilisha `--test-cmd` na jinsi unavyoendesha tests (kwa mfano, `npx hardhat test`, `npm test`).

Artifacts huhifadhiwa katika `./mutation_campaign` kwa chaguo-msingi. Mutants ambao hawakunaswa (walionusurika) hunakiliwa humo kwa ajili ya ukaguzi.<sup>[[5]](#references)</sup>

### Kuelewa output

Mistari ya ripoti huonekana kama:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Tag iliyo kwenye mabano ni alias ya mutator (kwa mfano, `CR` = Comment Replacement).
- `UNCAUGHT` inamaanisha tests zilifaulu chini ya tabia iliyobadilishwa → assertion haipo.

## Kupunguza runtime: weka kipaumbele kwa mutants wenye athari

Mutation campaigns zinaweza kuchukua saa au siku. Vidokezo vya kupunguza gharama:<sup>[[1]](#references)[[2]](#references)</sup>
- Scope: Anza na contracts/directories muhimu pekee, kisha panua.
- Weka kipaumbele kwa mutators: Ikiwa mutant yenye kipaumbele cha juu kwenye mstari fulani inaendelea kuwepo (kwa mfano `revert()` au comment-out), ruka variants zenye kipaumbele cha chini za mstari huo.
- Tumia campaigns za awamu mbili: endesha tests zinazolenga eneo fulani na zenye kasi kwanza, kisha fanya re-test kwa mutants ambazo hazikukamatwa pekee ukitumia full suite.
- Linganisha mutation targets na test commands mahususi inapowezekana (kwa mfano auth code -> auth tests).
- Zuia campaigns kwenye mutants zenye severity ya juu/ya kati wakati muda ni mdogo.
- Endesha tests kwa parallel ikiwa runner yako inaruhusu; cache dependencies/builds.
- Fail-fast: simamisha mapema wakati mabadiliko yanaonyesha wazi kuwepo kwa assertion gap.

Hesabu ya runtime ni kali: `1000 mutants x 5-minute tests ~= 83 hours`, kwa hiyo muundo wa campaign ni muhimu sawa na mutator yenyewe.

## Campaigns zinazoendelea na triage kwa kiwango kikubwa

Udhaifu mmoja wa workflows za zamani ni kutupa matokeo kwenye `stdout` pekee. Kwa campaigns ndefu, hili hufanya pause/resume, filtering, na review kuwa ngumu zaidi.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` huboresha hili kwa kuhifadhi mutants na outcomes kwenye campaigns zinazotumia SQLite. Faida:<sup>[[1]](#references)</sup>
- Pause na resume runs ndefu bila kupoteza maendeleo
- Filter mutants ambazo hazikukamatwa pekee kwenye file au mutation class mahususi
- Export/translate results kwenda SARIF kwa review tooling
- Ipe AI-assisted triage result sets ndogo zilizochujwa badala ya raw terminal logs

Matokeo yanayohifadhiwa huwa muhimu hasa mutation testing inapokuwa sehemu ya audit pipeline badala ya manual review ya mara moja.

## Workflow ya triage kwa mutants zinazoendelea kuwepo

1) Kagua mstari uliobadilishwa na tabia yake.
- Reproduce locally kwa kutumia mstari uliobadilishwa na kuendesha focused test.

2) Imarisha tests ili ku-assert state, si return values pekee.
- Ongeza equality-boundary checks (kwa mfano, test threshold `==`).
- Assert post-conditions: balances, total supply, authorization effects, na emitted events.

3) Badilisha mocks zinazoruhusu mambo kupita kiasi na uweke realistic behavior.
- Hakikisha mocks zinatekeleza transfers, failure paths, na event emissions zinazotokea on-chain.

4) Ongeza invariants kwa fuzz tests.
- Kwa mfano, conservation of value, non-negative balances, authorization invariants, na monotonic supply inapohusika.

5) Tenganisha true positives na semantic no-ops.
- Mfano: `x > 0` -> `x != 0` haina maana wakati `x` ni unsigned.

6) Endesha tena campaign hadi survivors wauawe au waelezwe wazi kuwa wameachwa kwa sababu maalum.

## Case study: kufichua state assertions zinazokosekana (Arkis protocol)

Mutation campaign wakati wa audit ya Arkis DeFi protocol ilifichua survivors kama:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Kuweka assignment kama comment hakukuvunja tests, hivyo kuthibitisha kuwa kulikuwa na post-state assertions zinazokosekana. Chanzo kikuu: code iliutumainia `_cmd.value` inayodhibitiwa na user badala ya kuthibitisha token transfers halisi. Attacker angeweza kutenganisha transfers zilizotarajiwa na halisi ili kuchota funds. Matokeo: risk ya high severity kwa solvency ya protocol.<sup>[[2]](#references)[[3]](#references)</sup>

Mwongozo: Wachukulie mutants walionusurika wanaoathiri value transfers, accounting, au access control kuwa high-risk hadi waangamizwe.

## Usigenerate tests bila kufikiri ili kuangamiza kila mutant

Mutation-driven test generation inaweza kuwa na madhara ikiwa implementation ya sasa si sahihi. Mfano: kubadilisha `priority >= 2` kuwa `priority > 2` hubadilisha tabia, lakini fix sahihi si kila mara ni "andika test ya `priority == 2`". Tabia hiyo yenyewe inaweza kuwa bug.<sup>[[1]](#references)</sup>

Workflow salama:
- Tumia mutants walionusurika kutambua requirements zenye utata
- Thibitisha tabia inayotarajiwa kupitia specs, protocol docs, au reviewers
- Baada ya hapo, encode tabia hiyo kama test/invariant

La sivyo, una risk ya kuhard-code ajali za implementation ndani ya test suite na kupata false confidence.

## Checklist ya vitendo

- Endesha campaign inayolenga:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Pendelea mutators wanaotambua syntax (AST/Tree-sitter) kuliko mutation ya regex-only inapowezekana.
- Fanya triage ya mutants walionusurika na uandike tests/invariants ambazo zingefeli chini ya tabia iliyomutatiwa.
- Assert balances, supply, authorizations, na events.
- Ongeza boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Badilisha mocks zisizo realistic; simulate failure modes.
- Hifadhi matokeo tooling inapowezesha, na filter mutants ambao hawajakamatwa kabla ya triage.
- Tumia campaigns za two-phase au per-target ili runtime ibaki manageable.
- Rudia hadi mutants wote waangamizwe au wa justified kwa comments na rationale.

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
