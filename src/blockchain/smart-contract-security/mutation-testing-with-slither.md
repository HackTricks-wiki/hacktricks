# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" kwa kuingiza mabadiliko madogo (mutants) kwa njia ya kimfumo katika msimbo wako wa Solidity na kuendesha tena test suite yako. Ikiwa test itashindwa, mutant anaangamizwa. Ikiwa tests bado zinafaulu, mutant ataishi, ikifunua doa la giza kwenye test suite yako ambalo line/branch coverage haiwezi kugundua.

Wazo kuu: Coverage inaonyesha msimbo uliendeshwa; mutation testing inaonyesha kama tabia imethibitishwa kwa kweli.

## Kwa nini coverage inaweza kudanganya

Fikiria ukaguzi huu rahisi wa kizingiti:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Majaribio ya kitengo yanayochunguza tu thamani chini ya na thamani juu ya kikomo yanaweza kufikia 100% ya coverage ya mistari/matawi wakati yakishindwa kuthibitisha ukomo wa usawa (==). Urekebishaji kuwa `deposit >= 2 ether` bado ungefanya majaribio hayo yapite, ukivunja kimya kimya mantiki ya protocol.

Mutation testing inaonyesha pengo hili kwa kubadilisha sharti na kuthibitisha majaribio yako yanashindwa.

## Vigezo vya mutation vya kawaida katika Solidity

Slither’s mutation engine inatekeleza mabadiliko madogo mengi yanayobadilisha semantiki, kama vile:
- Ubadilishaji wa operator: `+` ↔ `-`, `*` ↔ `/`, etc.
- Ubadilishaji wa assignment: `+=` → `=`, `-=` → `=`
- Ubadilishaji wa constant: non-zero → `0`, `true` ↔ `false`
- Kukatizwa/kubadilishwa kwa masharti ndani ya `if`/loops
- Kufanya mistari yote kuwa maoni (CR: Comment Replacement)
- Badilisha mstari kwa `revert()`
- Ubadilishaji wa aina za data: mfano, `int128` → `int64`

Lengo: Uangamize 100% ya mutants waliotengenezwa, au fafanua wale wanaoishi kwa sababu zilizo wazi.

## Kutumia mutation testing na slither-mutate

Mahitaji: Slither v0.10.2+.

- Orodhesha chaguzi na mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Mfano wa Foundry (rekodi matokeo na uhifadhi log kamili):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Ikiwa hautumii Foundry, badilisha `--test-cmd` na amri unayotumia kuendesha majaribio (mfano, `npx hardhat test`, `npm test`).

Mafaili ya matokeo (artifacts) na ripoti zinahifadhiwa katika `./mutation_campaign` kwa chaguo-msingi. Mutants wasiokamatwa (waliobaki) wanakiliwa huko kwa uchunguzi.

### Understanding the output

Mistari ya ripoti yanaonekana kama:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- The tag in brackets is the mutator alias (e.g., `CR` = Comment Replacement).
- `UNCAUGHT` means tests passed under the mutated behavior → missing assertion.

## Kupunguza wakati wa utekelezaji: ipa kipaumbele mutants zenye athari kubwa

Mutation campaigns can take hours or days. Tips to reduce cost:
- Scope: Start with critical contracts/directories only, then expand.
- Prioritize mutators: If a high-priority mutant on a line survives (e.g., entire line commented), you can skip lower-priority variants for that line.
- Parallelize tests if your runner allows it; cache dependencies/builds.
- Fail-fast: stop early when a change clearly demonstrates an assertion gap.

## Triage workflow for surviving mutants

1) Inspect the mutated line and behavior.
- Reproduce locally by applying the mutated line and running a focused test.

2) Strengthen tests to assert state, not only return values.
- Add equality-boundary checks (e.g., test threshold `==`).
- Assert post-conditions: balances, total supply, authorization effects, and emitted events.

3) Replace overly permissive mocks with realistic behavior.
- Ensure mocks enforce transfers, failure paths, and event emissions that occur on-chain.

4) Add invariants for fuzz tests.
- E.g., conservation of value, non-negative balances, authorization invariants, monotonic supply where applicable.

5) Re-run slither-mutate until survivors are killed or explicitly justified.

## Case study: revealing missing state assertions (Arkis protocol)

A mutation campaign during an audit of the Arkis DeFi protocol surfaced survivors like:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Kuongeza maoni (commenting out the assignment) hakukuangusha tests, ikithibitisha ukosefu wa post-state assertions. Sababu ya mzizi: code iliamini `_cmd.value` iliyo chini ya udhibiti wa mtumiaji badala ya kuthibitisha uhamisho halisi wa tokeni. Mshambulizi angeweza kusababisha uhamisho uliotarajiwa kutofautiana na uhamisho halisi ili kumwaga fedha. Matokeo: hatari ya kiwango cha juu kwa uthabiti wa kifedha wa protocol.

Mwongozo: Tibu survivors zinazogusa uhamisho wa thamani, uhasibu, au udhibiti wa upatikanaji kama hatari ya juu hadi zitakaposuluhishwa (killed).

## Orodha ya vitendo

- Endesha kampeni iliyolengwa:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Fanya triage ya survivors na andika tests/invariants ambazo zingeanguka chini ya tabia iliyobadilishwa.
- Thibitisha salio, usambazaji, idhini, na matukio.
- Ongeza tests za mipaka (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Badilisha mocks zisizo za kweli; simulate failure modes.
- Rudia hadi mutants zote ziwe killed au zifafanuliwe kwa maoni na mantiki.

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../../banners/hacktricks-training.md}}
