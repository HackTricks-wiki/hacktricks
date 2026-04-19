# Mutation Testing for Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "toets jou toetse" deur sistematies klein veranderinge (mutants) in contract code in te voer en die test suite weer uit te voer. As 'n test faal, is die mutant doodgemaak. As die tests steeds slaag, oorleef die mutant, wat 'n blindekol openbaar wat line/branch coverage nie kan opspoor nie.

Key idea: Coverage wys code is uitgevoer; mutation testing wys of gedrag werklik geasserteer is.

## Why coverage can deceive

Oorweeg hierdie eenvoudige threshold check:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Eenheidstoetse wat net ’n waarde onder en ’n waarde bo die drempel toets, kan 100% line/branch coverage bereik terwyl hulle nalaat om die gelykheidsgrens (`==`) te bevestig. ’n Refactor na `deposit >= 2 ether` sou steeds sulke toetse slaag, en die protokol-logika stilweg breek.

Mutation testing ontbloot hierdie gaping deur die voorwaarde te muteer en te verifieer dat toetse faal.

Vir smart contracts korreleer oorlewende mutants dikwels met ontbrekende kontroles rondom:
- Authorization and role boundaries
- Rekeningkunde/waarde-oordrag invariants
- Revert conditions and failure paths
- Grensvoorwaardes (`==`, nulwaardes, leë arrays, max/min values)

## Mutation operators with the highest security signal

Nuttige mutation classes vir contract auditing:
- **High severity**: vervang statements met `revert()` om ongekonsulteerde paaie bloot te stel
- **Medium severity**: kommentaar uit lyne / verwyder logika om onbevestigde newe-effekte te onthul
- **Low severity**: subtiele operator- of konstante-ruilings soos `>=` -> `>` of `+` -> `-`
- Ander algemene edits: assignment replacement, boolean flips, condition negation, en type changes

Praktiese doel: doodmaak alle betekenisvolle mutants, en motiveer oorlewendes eksplisiet wat irrelevant of semanties ekwivalent is.

## Why syntax-aware mutation is better than regex

Ouer mutation engines het op regex of line-oriented rewrites gesteun. Dit werk, maar het belangrike beperkings:
- Multi-line statements is moeilik om veilig te muteer
- Language structure word nie verstaan nie, so comments/tokens kan swak geteiken word
- Om elke moontlike variant op ’n swak line te genereer, mors groot hoeveelhede runtime

AST- of Tree-sitter-gebaseerde tooling verbeter dit deur gestruktureerde nodes te teiken in plaas van rou lyne:
- **slither-mutate** uses Slither's Solidity AST
- **mewt** uses Tree-sitter as a language-agnostic core
- **MuTON** builds on `mewt` and adds first-class support for TON languages such as FunC, Tolk, and Tact

Dit maak multi-line constructs en expression-level mutations baie meer betroubaar as regex-only approaches.

## Running mutation testing with slither-mutate

Requirements: Slither v0.10.2+.

- List options and mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry-voorbeeld (vang resultate vas en hou ’n volledige log):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- As jy nie Foundry gebruik nie, vervang `--test-cmd` met hoe jy toetse uitvoer (bv. `npx hardhat test`, `npm test`).

Artifacts word by verstek in `./mutation_campaign` gestoor. Ongevange (oorlewende) mutants word daarheen gekopieer vir inspeksie.

### Verstaan die uitset

Verslaglyne lyk soos:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- The tag in brackets is the mutator alias (e.g., `CR` = Comment Replacement).
- `UNCAUGHT` means tests passed under the mutated behavior → missing assertion.

## Vermindering van looptyd: prioritiseer impakvolle mutants

Mutation campaigns kan ure of dae neem. Wenke om koste te verminder:
- Scope: Begin eers met slegs kritieke contracts/directories, en brei dan uit.
- Prioritiseer mutators: As ’n hoë-prioriteit mutant op ’n reël oorleef (byvoorbeeld `revert()` of comment-out), slaan laer-prioriteit variante vir daardie reël oor.
- Gebruik twee-fase campaigns: voer eers gefokusde/vinnige tests uit, en toets daarna net uncaught mutants weer met die volle suite.
- Map mutation targets na spesifieke test commands waar moontlik (byvoorbeeld auth code -> auth tests).
- Beperk campaigns tot high/medium severity mutants wanneer tyd min is.
- Parallelize tests as jou runner dit toelaat; cache dependencies/builds.
- Fail-fast: stop vroeg as ’n verandering duidelik ’n assertion gap toon.

Die runtime wiskunde is brutaal: `1000 mutants x 5-minute tests ~= 83 hours`, so campaign design matters as much as the mutator itself.

## Persisterende campaigns en triage op skaal

Een swakpunt van ouer workflows is om resultate net na `stdout` te dump. Vir lang campaigns maak dit pause/resume, filtering, en review moeiliker.

`mewt`/`MuTON` verbeter dit deur mutants en uitkomste in SQLite-backed campaigns te stoor. Voordele:
- Pause en resume lang runs sonder om vordering te verloor
- Filter net uncaught mutants in ’n spesifieke file of mutation class
- Export/translate results to SARIF vir review tooling
- Gee AI-assisted triage kleiner, gefiltreerde result sets in plaas van rou terminal logs

Persisterende resultate is veral nuttig wanneer mutation testing deel word van ’n audit pipeline in plaas van ’n eenmalige handmatige review.

## Triage workflow for surviving mutants

1) Inspekteer die gemuteerde reël en gedrag.
- Reproduce locally deur die gemuteerde reël toe te pas en ’n gefokusde test uit te voer.

2) Versterk tests om state te assert, nie net return values nie.
- Voeg equality-boundary checks by (bv. toets threshold `==`).
- Assert post-conditions: balances, total supply, authorization effects, and emitted events.

3) Vervang te permissive mocks met realistic behavior.
- Maak seker mocks enforce transfers, failure paths, en event emissions wat on-chain plaasvind.

4) Voeg invariants by vir fuzz tests.
- Bv. conservation of value, non-negative balances, authorization invariants, monotonic supply where applicable.

5) Skei true positives van semantic no-ops.
- Example: `x > 0` -> `x != 0` is meaningless when `x` is unsigned.

6) Voer die campaign weer uit totdat survivors gekill is of eksplisiet geregverdig word.

## Case study: revealing missing state assertions (Arkis protocol)

A mutation campaign during an audit of the Arkis DeFi protocol surfaced survivors like:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Die uitkommentering van die toewysing het nie die toetse gebreek nie, wat ontbrekende post-state-asserties bewys. Grondoorsaak: die kode het ’n gebruiker-beheerde `_cmd.value` vertrou in plaas daarvan om die werklike token-oordragte te valideer. ’n Aanvaller kon verwagte vs. werklike oordragte desinkroniseer om fondse te dreineer. Gevolg: hoë-severiteit risiko vir protokol-solvensie.

Riglyn: Behandel survivors wat waarde-oordragte, rekeningkunde, of access control beïnvloed as hoë-risiko totdat hulle killed is.

## Moenie tests blindelings genereer om elke mutant te kill nie

Mutation-driven test generation kan terugskiet as die huidige implementering verkeerd is. Voorbeeld: die mutering van `priority >= 2` na `priority > 2` verander gedrag, maar die regte fix is nie altyd “skryf ’n test vir `priority == 2`” nie. Daardie gedrag kan self die bug wees.

Veiliger werkvloei:
- Gebruik surviving mutants om dubbelsinnige vereistes te identifiseer
- Valideer verwagte gedrag uit specs, protocol docs, of reviewers
- Eers dan enkodeer jy die gedrag as ’n test/invariant

Anders loop jy die risiko om implementasie-ongelukke in die testsuite vas te hardkodeer en vals selfvertroue te kry.

## Praktiese checklist

- Run ’n geteikende kampanje:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Verkies syntax-aware mutators (AST/Tree-sitter) bo regex-only mutation wanneer beskikbaar.
- Triage survivors en skryf tests/invariants wat sou faal onder die gemuteerde gedrag.
- Assert balances, supply, authorizations, en events.
- Voeg boundary tests by (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Vervang onrealistiese mocks; simuleer failure modes.
- Bewaar resultate wanneer die tooling dit ondersteun, en filter uncaught mutants uit voor triage.
- Gebruik twee-fase of per-target kampanjes om runtime hanteerbaar te hou.
- Itereer totdat al die mutants gekill is of met kommentaar en rasionaal geregverdig is.

## Verwysings

- [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)
- [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [mewt](https://github.com/trailofbits/mewt)
- [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
