# Mutation Testing vir Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "toets jou toetse" deur stelselmatig klein veranderinge (mutants) aan contract-kode aan te bring en die test suite weer uit te voer. As ’n toets misluk, word die mutant gekill. As die toetse steeds slaag, oorleef die mutant, wat ’n blindekol onthul wat line/branch coverage nie kan opspoor nie.

Sleutelidee: Coverage wys dat kode uitgevoer is; mutation testing wys of gedrag werklik geassert word.<sup>[[2]](#references)</sup>

## Waarom coverage kan mislei

Beskou hierdie eenvoudige threshold-kontrole:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Eenheidstoetse wat slegs 'n waarde onder en 'n waarde bo die drempel nagaan, kan 100% lyn-/takdekking bereik sonder om die gelykheidsgrens (`==`) te bevestig. 'n Refaktorering na `deposit >= 2 ether` sou steeds sulke toetse laat slaag en protokollogika stilweg breek.<sup>[[2]](#references)</sup>

Mutation testing onthul hierdie gaping deur die voorwaarde te muteer en te verifieer dat toetse misluk.

Vir smart contracts hou surviving mutants dikwels verband met ontbrekende kontroles rondom:
- Magtiging en rolgrense
- Rekeningkunde-/waarde-oordrag-invariante
- Revert-voorwaardes en mislukkingspaaie
- Grensvoorwaardes (`==`, nulwaardes, leë arrays, maksimum-/minimumwaardes)

## Mutation operators met die hoogste sekuriteitssein

Nuttige mutation-klasse vir contract-ouditering:<sup>[[1]](#references)[[2]](#references)</sup>
- **Hoë erns**: vervang stellings met `revert()` om onuitgevoerde paaie bloot te lê
- **Medium erns**: kommentarieer lyne uit / verwyder logika om ongeverifieerde newe-effekte bloot te lê
- **Lae erns**: subtiele operator- of konstantewisselings soos `>=` -> `>` of `+` -> `-`
- Ander algemene wysigings: vervanging van toewysings, boolean-omkerings, negasie van voorwaardes en tipeveranderings

Praktiese doel: kill alle betekenisvolle mutants, en motiveer uitdruklik survivors wat irrelevant of semanties ekwivalent is.

## Waarom syntax-aware mutation beter as regex is

Ouer mutation engines het op regex- of lyngeoriënteerde herskrywings staatgemaak. Dit werk, maar het belangrike beperkings:<sup>[[1]](#references)</sup>
- Multilyn-stellings is moeilik om veilig te muteer
- Die taalstruktuur word nie verstaan nie, sodat kommentare/tokens verkeerd geteiken kan word
- Die generering van elke moontlike variant op 'n swak lyn mors groot hoeveelhede runtime

AST- of Tree-sitter-gebaseerde tooling verbeter dit deur gestruktureerde nodes eerder as rou lyne te teiken:<sup>[[1]](#references)</sup>
- **slither-mutate** gebruik Slither se Solidity AST<sup>[[4]](#references)</sup>
- **mewt** gebruik Tree-sitter as 'n taalagnostiese kern<sup>[[6]](#references)</sup>
- **MuTON** bou op `mewt` en voeg eersteklas-ondersteuning by vir TON-tale soos FunC, Tolk en Tact<sup>[[7]](#references)</sup>

Dit maak multilyn-konstrukte en uitdrukkingvlak-mutasies baie meer betroubaar as slegs-regex-benaderings.

## Mutation testing met slither-mutate uitvoer

Vereistes: Slither v0.10.2+.

- Lys opsies en mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry-voorbeeld (vang resultate vas en hou ’n volledige log):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- As jy nie Foundry gebruik nie, vervang `--test-cmd` met hoe jy toetse uitvoer (byvoorbeeld `npx hardhat test`, `npm test`).

Artefakte word by verstek in `./mutation_campaign` gestoor. Ongevange (oorlewende) mutants word daarheen gekopieer vir inspeksie.<sup>[[5]](#references)</sup>

### Verstaan die uitvoer

Verslagreëls lyk soos:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Die tag tussen hakies is die mutator-alias (bv. `CR` = Comment Replacement).
- `UNCAUGHT` beteken toetse het onder die gemuteerde gedrag geslaag → ontbrekende assertion.

## Vermindering van runtime: prioritiseer impakvolle mutants

Mutation campaigns kan ure of dae neem. Wenke om koste te verminder:<sup>[[1]](#references)[[2]](#references)</sup>
- Omvang: Begin slegs met kritieke contracts/directories en brei daarna uit.
- Prioritiseer mutators: Indien ’n hoë-prioriteit-mutant op ’n lyn oorleef (byvoorbeeld `revert()` of comment-out), slaan laer-prioriteit-variante vir daardie lyn oor.
- Gebruik twee-fase campaigns: Laat eers gefokusde/vinnige toetse loop, en toets daarna slegs uncaught mutants weer met die volledige suite.
- Koppel mutation targets waar moontlik aan spesifieke test commands (byvoorbeeld auth code -> auth tests).
- Beperk campaigns tot mutants met hoë/medium severity wanneer tyd beperk is.
- Paralleliseer toetse indien jou runner dit toelaat; cache dependencies/builds.
- Fail-fast: stop vroeg wanneer ’n verandering duidelik ’n assertion gap toon.

Die runtime-wiskunde is brutaal: `1000 mutants x 5-minute tests ~= 83 hours`, dus is campaign-ontwerp net so belangrik soos die mutator self.<sup>[[1]](#references)</sup>

## Volgehoue campaigns en triage op skaal

Een swakheid van ouer workflows is dat resultate slegs na `stdout` geskryf word. Vir lang campaigns maak dit pause/resume, filtering en review moeiliker.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` verbeter dit deur mutants en uitkomste in SQLite-backed campaigns te stoor. Voordele:<sup>[[1]](#references)</sup>
- Pause en resume lang runs sonder om vordering te verloor
- Filter slegs uncaught mutants in ’n spesifieke file of mutation class
- Export/translate resultate na SARIF vir review tooling
- Gee AI-assisted triage kleiner, gefiltreerde resultaatstelle in plaas van rou terminal logs

Volgehoue resultate is veral nuttig wanneer mutation testing deel van ’n audit pipeline word in plaas van ’n eenmalige handmatige review.

## Triage-workflow vir mutants wat oorleef

1) Inspekteer die gemuteerde lyn en gedrag.
- Reproduceer plaaslik deur die gemuteerde lyn toe te pas en ’n gefokusde toets te laat loop.

2) Versterk toetse om state te assert, nie slegs return values nie.
- Voeg equality-boundary checks by (bv. toets threshold `==`).
- Assert post-conditions: balances, total supply, authorization effects en emitted events.

3) Vervang té permissiewe mocks met realistiese gedrag.
- Verseker dat mocks transfers, failure paths en event emissions afdwing wat on-chain plaasvind.

4) Voeg invariants vir fuzz tests by.
- Bv. conservation of value, non-negative balances, authorization invariants en monotonic supply waar toepaslik.

5) Skei true positives van semantic no-ops.
- Voorbeeld: `x > 0` -> `x != 0` is betekenisloos wanneer `x` unsigned is.

6) Laat die campaign weer loop totdat survivors killed is of uitdruklik geregverdig is.

## Case study: onthulling van ontbrekende state assertions (Arkis protocol)

’n Mutation campaign tydens ’n audit van die Arkis DeFi protocol het survivors soos die volgende aan die lig gebring:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Om die toewysing uit te kommentarieer het nie die toetse laat misluk nie, wat ontbrekende post-state assertions bewys. Die hoofoorsaak: die code het op ’n user-controlled `_cmd.value` vertrou in plaas daarvan om werklike token transfers te valideer. ’n Aanvaller kon verwagte en werklike transfers uit sinkronisasie bring om funds te dreineer. Resultaat: ’n hoë-severiteitrisiko vir die protocol se solvency.<sup>[[2]](#references)[[3]](#references)</sup>

Guidance: Behandel survivors wat value transfers, accounting of access control beïnvloed as hoërisiko totdat hulle gekill is.

## Moenie blindelings tests genereer om elke mutant te kill nie

Mutation-driven test generation kan terugvuur as die huidige implementasie verkeerd is. Voorbeeld: om `priority >= 2` na `priority > 2` te muteer verander gedrag, maar die korrekte fix is nie altyd om “’n test vir `priority == 2` te skryf” nie. Daardie gedrag kan self die bug wees.<sup>[[1]](#references)</sup>

Veiliger workflow:
- Gebruik surviving mutants om ambigue requirements te identifiseer
- Valideer die verwagte gedrag vanuit specs, protocol docs of reviewers
- Kodeer eers daarna die gedrag as ’n test/invariant

Anders loop jy die risiko om implementasie-ongelukke in die test suite vas te hardkodeer en vals vertroue te verkry.

## Praktiese checklist

- Run ’n targeted campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Verkies syntax-aware mutators (AST/Tree-sitter) bo regex-only mutation waar beskikbaar.
- Triage survivors en skryf tests/invariants wat onder die gemuteerde gedrag sou misluk.
- Assert balances, supply, authorizations en events.
- Voeg boundary tests by (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Vervang onrealistiese mocks; simuleer failure modes.
- Persist results wanneer die tooling dit ondersteun, en filter uncaught mutants voor triage.
- Gebruik two-phase of per-target campaigns om runtime hanteerbaar te hou.
- Iterateer totdat alle mutants gekill of met comments en rationale geregverdig is.

## Verwysings

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
