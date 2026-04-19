# Mutation Testing for Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "hujaribu majaribio yako" kwa kuingiza mabadiliko madogo kwa utaratibu (mutants) ndani ya code ya contract na kuendesha tena test suite. Ikiwa test inashindwa, mutant imeuliwa. Ikiwa tests bado zinapita, mutant inanusurika, ikifichua blind spot ambayo line/branch coverage haiwezi kugundua.

Wazo kuu: Coverage inaonyesha code ilitekelezwa; mutation testing inaonyesha kama behavior kweli imeassertiwa.

## Why coverage can deceive

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
Vipimo vya unit ambavyo vinaangalia tu thamani iliyo chini na thamani iliyo juu ya threshold vinaweza kufikia 100% line/branch coverage huku vikishindwa kuthibitisha boundary ya usawa (==). Refactor kwenda `deposit >= 2 ether` bado inaweza kupita vipimo hivyo, na hivyo kuvunja logic ya protocol kimya kimya.

Mutation testing hufichua pengo hili kwa kubadilisha condition na kuthibitisha kuwa tests zinashindwa.

Kwa smart contracts, surviving mutants mara nyingi huonyesha checks zinazokosekana kuhusu:
- Authorization na role boundaries
- Accounting/value-transfer invariants
- Revert conditions na failure paths
- Boundary conditions (`==`, zero values, empty arrays, max/min values)

## Mutation operators with the highest security signal

Vikundi muhimu vya mutation kwa contract auditing:
- **High severity**: badilisha statements kuwa `revert()` ili kufichua paths ambazo hazitekelezwi
- **Medium severity**: comment out lines / ondoa logic ili kufichua side effects ambazo hazijathibitishwa
- **Low severity**: subtle operator au constant swaps kama `>=` -> `>` au `+` -> `-`
- Mabadiliko mengine ya kawaida: assignment replacement, boolean flips, condition negation, na type changes

Lengo la vitendo: kill mutants wote wenye maana, na toa sababu wazi kwa survivors ambao hawana umuhimu au ni semantically equivalent.

## Why syntax-aware mutation is better than regex

Mikakati ya zamani ya mutation ilitegemea regex au rewrites za line-oriented. Hiyo inafanya kazi, lakini ina mapungufu muhimu:
- Multi-line statements ni vigumu kuzibadilisha kwa usalama
- Muundo wa language haufahamiki, hivyo comments/tokens zinaweza kulengwa vibaya
- Kuzalisha kila variant inayowezekana kwenye line dhaifu hupoteza muda mwingi wa runtime

Zana zinazotumia AST au Tree-sitter huboresha hili kwa kulenga structured nodes badala ya raw lines:
- **slither-mutate** hutumia Solidity AST ya Slither
- **mewt** hutumia Tree-sitter kama core ya language-agnostic
- **MuTON** hujengwa juu ya `mewt` na huongeza support ya kwanza kwa TON languages kama FunC, Tolk, na Tact

Hii hufanya multi-line constructs na expression-level mutations ziwe za kuaminika zaidi kuliko approaches za regex pekee.

## Running mutation testing with slither-mutate

Mahitaji: Slither v0.10.2+.

- Orodha ya options na mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Mfano wa Foundry (nasa matokeo na weka logi kamili):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Ikiwa hutumii Foundry, badilisha `--test-cmd` na jinsi unavyoendesha tests zako (k.m., `npx hardhat test`, `npm test`).

Artifacts huhifadhiwa kwenye `./mutation_campaign` kwa chaguo msingi. Mutants ambao hawakukamatwa (waliosalimika) hunakiliwa hapo kwa ukaguzi.

### Kuelewa output

Mistari ya report huonekana kama:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Tagi katika mabano ni mutator alias (mfano, `CR` = Comment Replacement).
- `UNCAUGHT` inamaanisha tests zilipita chini ya mutated behavior → assertion haipo.

## Kupunguza runtime: weka kipaumbele kwenye mutants zenye athari kubwa

Mutation campaigns zinaweza kuchukua saa au siku. Vidokezo vya kupunguza cost:
- Scope: Anza na critical contracts/directories pekee, kisha panua.
- Prioritize mutators: Ikiwa high-priority mutant kwenye line survives (kwa mfano `revert()` au comment-out), ruka lower-priority variants kwa line hiyo.
- Tumia two-phase campaigns: endesha focused/fast tests kwanza, kisha retest mutants zisizokamatwa pekee na full suite.
- Ramani mutation targets kwa specific test commands inapowezekana (kwa mfano auth code -> auth tests).
- Punguza campaigns kwa high/medium severity mutants wakati muda ni mdogo.
- Parallelize tests ikiwa runner yako inaruhusu; cache dependencies/builds.
- Fail-fast: simama mapema ikiwa change inaonyesha wazi assertion gap.

Runtime math ni kali: `1000 mutants x 5-minute tests ~= 83 hours`, kwa hiyo campaign design ni muhimu kama mutator yenyewe.

## Persistent campaigns na triage kwa scale

Udhaifu mmoja wa older workflows ni kutupa results tu kwenye `stdout`. Kwa long campaigns, hili hufanya pause/resume, filtering, na review kuwa ngumu zaidi.

`mewt`/`MuTON` huboresha hili kwa kuhifadhi mutants na outcomes kwenye SQLite-backed campaigns. Faida:
- Pause na resume long runs bila kupoteza progress
- Filter only uncaught mutants kwenye specific file au mutation class
- Export/translate results to SARIF kwa review tooling
- Toa AI-assisted triage smaller, filtered result sets badala ya raw terminal logs

Persistent results ni muhimu hasa mutation testing inapoanza kuwa sehemu ya audit pipeline badala ya one-off manual review.

## Triage workflow kwa surviving mutants

1) Kagua mutated line na behavior.
- Reproduce locally kwa kutumia mutated line na running focused test.

2) Imarisha tests ili zihakikishe state, si return values pekee.
- Ongeza equality-boundary checks (mfano, test threshold `==`).
- Assert post-conditions: balances, total supply, authorization effects, na emitted events.

3) Badilisha mocks zilizo permissive kupita kiasi na realistic behavior.
- Hakikisha mocks zinatekeleza transfers, failure paths, na event emissions zinazotokea on-chain.

4) Ongeza invariants kwa fuzz tests.
- Mfano, conservation of value, non-negative balances, authorization invariants, monotonic supply pale panapofaa.

5) Tenganisha true positives kutoka semantic no-ops.
- Mfano: `x > 0` -> `x != 0` haina maana wakati `x` ni unsigned.

6) Endesha campaign tena hadi survivors wauliwe au wathibitishwe wazi.

## Case study: kufichua missing state assertions (Arkis protocol)

Mutation campaign wakati wa audit ya Arkis DeFi protocol ilifichua survivors kama:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commenting out the assignment didn’t break the tests, proving missing post-state assertions. Root cause: code trusted a user-controlled `_cmd.value` instead of validating actual token transfers. An attacker could desynchronize expected vs. actual transfers to drain funds. Result: high severity risk to protocol solvency.

Mwongozo: Chukulia survivors zinazohusu value transfers, accounting, au access control kama high-risk hadi ziwe killed.

## Do not blindly generate tests to kill every mutant

Uzalishaji wa tests unaoongozwa na Mutation unaweza kurudi nyuma ikiwa implementation ya sasa ni wrong. Mfano: kubadilisha `priority >= 2` kuwa `priority > 2` hubadilisha behavior, lakini fix sahihi si mara zote "andika test kwa `priority == 2`". Hiyo behavior yenyewe inaweza kuwa bug.

Workflow salama:
- Tumia surviving mutants kutambua requirements zenye utata
- Validate behavior inayotarajiwa kutoka kwenye specs, protocol docs, au reviewers
- Kisha tu encode hiyo behavior kama test/invariant

Vinginevyo, una hatari ya hard-coding ajali za implementation ndani ya test suite na kupata false confidence.

## Practical checklist

- Endesha targeted campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Pendelea syntax-aware mutators (AST/Tree-sitter) kuliko regex-only mutation inapowezekana.
- Panga survivors na andika tests/invariants ambazo zingeshindwa chini ya mutated behavior.
- Assert balances, supply, authorizations, na events.
- Ongeza boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Badilisha unrealistic mocks; simulate failure modes.
- Hifadhi results tooling inapounga mkono hilo, na filter uncaught mutants kabla ya triage.
- Tumia two-phase au per-target campaigns ili runtime ibaki manageable.
- Rudia hadi mutants zote ziwe killed au ziwe justified kwa comments na rationale.

## References

- [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)
- [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [mewt](https://github.com/trailofbits/mewt)
- [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
