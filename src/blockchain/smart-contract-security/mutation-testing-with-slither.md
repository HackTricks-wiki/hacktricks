# Mutation Testing kwa Smart Contracts (slither-mutate, mewt, MuTON)

Mutation testing "hujaribu tests zako" kwa kuanzisha kwa utaratibu mabadiliko madogo (mutants) kwenye contract code na kuendesha tena test suite. Ikiwa test itashindwa, mutant inauawa. Ikiwa tests bado zitapita, mutant inasalia, ikifichua blind spot ambayo line/branch coverage haiwezi kugundua.

Wazo kuu: Coverage huonyesha kuwa code ilitekelezwa; mutation testing huonyesha ikiwa behavior imethibitishwa kweli.<sup>[[2]](#references)</sup>

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
Unit tests zinazokagua tu thamani iliyo chini na thamani iliyo juu ya threshold zinaweza kufikia 100% ya line/branch coverage huku zikishindwa kuthibitisha equality boundary (==). Refactor ya `deposit >= 2 ether` bado ingepita kwenye tests hizo, na kuvunja kimya kimya mantiki ya protocol.<sup>[[2]](#references)</sup>

Mutation testing hufichua pengo hili kwa kubadilisha condition na kuthibitisha kuwa tests zinashindwa.

Kwa smart contracts, mutants wanaosalia mara nyingi huhusishwa na checks zinazokosekana kuhusu:
- Authorization na mipaka ya roles
- Invariants za accounting/value-transfer
- Masharti ya revert na failure paths
- Boundary conditions (`==`, zero values, empty arrays, max/min values)

## Mutation operators zilizo na security signal ya juu zaidi

Mutation classes zenye manufaa kwa contract auditing:<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**: badilisha statements kwa `revert()` ili kufichua paths ambazo hazijatekelezwa
- **Medium severity**: comment out lines / ondoa logic ili kufichua side effects ambazo hazijathibitishwa
- **Low severity**: mabadiliko madogo ya operators au constants kama `>=` -> `>` au `+` -> `-`
- Mabadiliko mengine ya kawaida: assignment replacement, boolean flips, condition negation, na type changes

Lengo la vitendo: kill mutants wote wenye maana, na utoe justification wazi kwa mutants wanaosalia ambao hawahusiki au wana semantic equivalence.

## Kwa nini syntax-aware mutation ni bora kuliko regex

Mutation engines za zamani zilitumia regex au line-oriented rewrites. Hilo linafanya kazi, lakini lina limitations muhimu:<sup>[[1]](#references)</sup>
- Statements za mistari mingi ni vigumu kuzibadilisha kwa usalama
- Muundo wa language haueleweki, hivyo comments/tokens zinaweza kulengwa vibaya
- Kutengeneza kila variant inayowezekana kwenye line dhaifu hupoteza kiasi kikubwa cha runtime

Tooling inayotegemea AST au Tree-sitter huboresha hili kwa kulenga structured nodes badala ya raw lines:<sup>[[1]](#references)</sup>
- **slither-mutate** hutumia Solidity AST ya Slither.<sup>[[4]](#references)</sup>
- **mewt** hutumia Tree-sitter kama core isiyofungamana na language.<sup>[[6]](#references)</sup>
- **MuTON** imejengwa juu ya `mewt` na inaongeza first-class support kwa TON languages kama FunC, Tolk, na Tact.<sup>[[7]](#references)</sup>

Hii hufanya constructs za mistari mingi na mutations za kiwango cha expression ziwe za kuaminika zaidi kuliko approaches zinazotumia regex pekee.

## Kuendesha mutation testing kwa slither-mutate

Requirements: Slither v0.10.2+.

- Orodhesha options na mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Mfano wa Foundry (nasa matokeo na uhifadhi log kamili):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Ikiwa hutumii Foundry, badilisha `--test-cmd` na jinsi unavyoendesha tests (kwa mfano, `npx hardhat test`, `npm test`).

Artifacts huhifadhiwa katika `./mutation_campaign` kwa chaguomsingi. Mutants ambao hawakugunduliwa (surviving) hunakiliwa humo kwa ajili ya ukaguzi.<sup>[[5]](#references)</sup>

### Kuelewa matokeo

Mistari ya ripoti huonekana hivi:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Tag iliyo kwenye mabano ni alias ya mutator (kwa mfano, `CR` = Comment Replacement).
- `UNCAUGHT` inamaanisha tests zilifaulu chini ya tabia iliyobadilishwa → assertion haipo.

## Kupunguza runtime: panga mutants zenye athari kubwa

Mutation campaigns zinaweza kuchukua saa au siku. Vidokezo vya kupunguza gharama:<sup>[[1]](#references)[[2]](#references)</sup>
- Scope: Anza na contracts/directories muhimu pekee, kisha panua.
- Panga mutators kwa kipaumbele: Ikiwa mutant yenye kipaumbele cha juu kwenye line fulani ita-survive (kwa mfano `revert()` au comment-out), ruka variants zenye kipaumbele cha chini za line hiyo.
- Tumia campaigns za awamu mbili: endesha tests zilizolenga na za haraka kwanza, kisha fanya re-test ya mutants ambazo hazikupatikana pekee kwa kutumia full suite.
- Oanisha mutation targets na test commands maalum inapowezekana (kwa mfano auth code -> auth tests).
- Zuia campaigns kwenye mutants zenye severity ya juu/kati wakati muda ni mdogo.
- Endesha tests kwa parallel ikiwa runner yako inaruhusu; weka dependencies/builds kwenye cache.
- Fail-fast: simamisha mapema wakati mabadiliko yanaonyesha wazi pengo la assertion.

Hesabu ya runtime ni ngumu: `1000 mutants x 5-minute tests ~= 83 hours`, kwa hiyo muundo wa campaign ni muhimu sawa na mutator yenyewe.<sup>[[1]](#references)</sup>

## Campaigns zinazoendelea na triage kwa kiwango kikubwa

Udhaifu mmoja wa workflows za zamani ni kutupa matokeo kwenye `stdout` pekee. Kwa campaigns ndefu, hii hufanya pause/resume, filtering, na review kuwa ngumu zaidi.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` huboresha hili kwa kuhifadhi mutants na outcomes kwenye campaigns zinazotumia SQLite. Faida:<sup>[[1]](#references)</sup>
- Pause na resume runs ndefu bila kupoteza progress
- Filter mutants ambazo hazikupatikana pekee kwenye file au mutation class maalum
- Export/translate results kuwa SARIF kwa ajili ya review tooling
- Ipe AI-assisted triage result sets ndogo zilizofilteriwa badala ya raw terminal logs

Matokeo yanayohifadhiwa yanafaa hasa wakati mutation testing inakuwa sehemu ya audit pipeline badala ya review ya manual ya mara moja.

## Workflow ya triage kwa mutants zinazo-survive

1) Kagua line na behavior iliyobadilishwa.
- I-reproduce locally kwa kutumia line iliyobadilishwa na kuendesha test iliyolenga.

2) Imarisha tests ili ku-assert state, si return values pekee.
- Ongeza equality-boundary checks (kwa mfano, test threshold `==`).
- Assert post-conditions: balances, total supply, authorization effects, na emitted events.

3) Badilisha mocks zinazoruhusu mambo kupita kupita kiasi kwa behavior halisi.
- Hakikisha mocks zinatekeleza transfers, failure paths, na event emissions zinazotokea on-chain.

4) Ongeza invariants kwa fuzz tests.
- Kwa mfano, conservation of value, non-negative balances, authorization invariants, na monotonic supply inapohusika.

5) Tenganisha true positives na semantic no-ops.
- Mfano: `x > 0` -> `x != 0` haina maana wakati `x` ni unsigned.

6) Endesha tena campaign hadi survivors ziangamizwe au zielezwe wazi kuwa zimeachwa kwa sababu maalum.

## Case study: kufichua state assertions zilizokosekana (Arkis protocol)

Mutation campaign wakati wa audit ya Arkis DeFi protocol ilifichua survivors kama:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Kutoa maelekezo ya assignment hakukuvuruga tests, jambo linalothibitisha ukosefu wa post-state assertions. Chanzo kikuu: code iliweka imani kwenye `_cmd.value` inayodhibitiwa na user badala ya kuthibitisha token transfers halisi. Attacker angeweza kutenganisha transfers zilizotarajiwa na halisi ili kutoa funds. Matokeo: risk ya kiwango cha juu kwa solvency ya protocol.<sup>[[2]](#references)[[3]](#references)</sup>

Mwongozo: Chukulia survivors zinazoathiri value transfers, accounting, au access control kuwa high-risk hadi ziwe killed.

## Usitengeneze tests bila kufikiri ili kuua kila mutant

Mutation-driven test generation inaweza kuleta madhara ikiwa implementation ya sasa si sahihi. Mfano: kubadilisha `priority >= 2` kuwa `priority > 2` hubadilisha tabia, lakini fix sahihi si lazima iwe "andika test ya `priority == 2`". Tabia hiyo yenyewe inaweza kuwa bug.<sup>[[1]](#references)</sup>

Workflow salama:
- Tumia surviving mutants kutambua requirements zenye utata
- Thibitisha tabia inayotarajiwa kutoka kwenye specs, protocol docs, au reviewers
- Ni baada ya hapo ndipo uweke tabia hiyo kama test/invariant

La sivyo, una risk ya kuweka kwa kudumu makosa ya implementation ndani ya test suite na kupata false confidence.

## Practical checklist

- Endesha campaign inayolenga:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Pendelea mutators zinazotambua syntax (AST/Tree-sitter) badala ya mutation ya regex pekee zinapopatikana.
- Fanya triage ya survivors na uandike tests/invariants ambazo zingefeli chini ya tabia iliyomutated.
- Assert balances, supply, authorizations, na events.
- Ongeza boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Badilisha mocks zisizo realistic; simulate failure modes.
- Hifadhi results pale tooling inapounga mkono hilo, na filter mutants ambazo hazijakamatwa kabla ya triage.
- Tumia campaigns za awamu mbili au zinazolenga kila target ili kuweka runtime katika kiwango kinachoweza kudhibitika.
- Rudia hadi mutants wote wawe killed au waelezwe kwa comments na rationale.

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Tumia mutation testing kupata bugs ambazo tests zako hazikamatili (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Ukaguzi wa Usalama wa Arkis DeFi Prime Brokerage (Kiambatisho C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Nyaraka za Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
