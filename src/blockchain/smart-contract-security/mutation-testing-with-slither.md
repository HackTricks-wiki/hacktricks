# Mutation Testing vir Smart Contracts (slither-mutate, mewt, MuTON)

Mutation testing "toets jou toetse" deur stelselmatig klein veranderinge (mutante) aan contract-kode bekend te stel en die test suite weer uit te voer. As 'n toets misluk, word die mutant doodgemaak. As die toetse steeds slaag, oorleef die mutant, wat 'n blindekol onthul wat line/branch coverage nie kan opspoor nie.

Sleutelidee: Coverage wys dat kode uitgevoer is; mutation testing wys of gedrag werklik geassert word.<sup>[[2]](#references)</sup>

## Waarom coverage kan mislei

Beskou hierdie eenvoudige drempelkontrole:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Eenheidstoetse wat slegs ’n waarde onder en ’n waarde bo die drempel nagaan, kan 100% lyn-/takdekking bereik terwyl hulle nie die gelykheidsgrens (`==`) bevestig nie. ’n Refaktorering na `deposit >= 2 ether` sal steeds sulke toetse laat slaag en protokollogika stilweg breek.<sup>[[2]](#references)</sup>

Mutation testing stel hierdie gaping bloot deur die voorwaarde te muteer en te verifieer dat toetse misluk.

Vir smart contracts stem mutants wat oorleef gereeld ooreen met ontbrekende kontroles rondom:
- Magtiging en rolgrense
- Rekeningkundige-/waardeoordrag-invariante
- Revert-voorwaardes en foutpaaie
- Grensvoorwaardes (`==`, nulwaardes, leë skikkings, maksimum-/minimumwaardes)

## Mutation operators with the highest security signal

Nuttige mutation-klasse vir contract auditing:<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**: vervang stellings met `revert()` om onuitgevoerde paaie bloot te lê
- **Medium severity**: kommentarieer lyne uit / verwyder logika om ongeverifieerde newe-effekte te onthul
- **Low severity**: subtiele operator- of konstante-ruilings soos `>=` -> `>` of `+` -> `-`
- Ander algemene wysigings: vervanging van toewysings, boolean-wisselings, ontkenning van voorwaardes en tipeveranderings

Praktiese doel: maak alle betekenisvolle mutants dood, en motiveer uitdruklik oorlewendes wat irrelevant of semanties ekwivalent is.

## Why syntax-aware mutation is better than regex

Ouer mutation-enjins het op regex- of lyngeoriënteerde herskrywings staatgemaak. Dit werk, maar het belangrike beperkings:<sup>[[1]](#references)</sup>
- Multi-lyn-stellings is moeilik om veilig te muteer
- Die taalstruktuur word nie verstaan nie, dus kan kommentare/tokens verkeerd geteiken word
- Die generering van elke moontlike variant op ’n swak lyn mors groot hoeveelhede runtime

AST- of Tree-sitter-gebaseerde tooling verbeter dit deur gestruktureerde nodusse eerder as rou lyne te teiken:<sup>[[1]](#references)</sup>
- **slither-mutate** gebruik Slither se Solidity AST.<sup>[[4]](#references)</sup>
- **mewt** gebruik Tree-sitter as ’n taalagnostiese kern.<sup>[[6]](#references)</sup>
- **MuTON** bou op `mewt` en voeg eersteklas-ondersteuning by vir TON-tale soos FunC, Tolk en Tact.<sup>[[7]](#references)</sup>

Dit maak multi-lyn-konstrukte en uitdrukkingsvlak-mutasies baie meer betroubaar as benaderings wat slegs regex gebruik.

## Running mutation testing with slither-mutate

Vereistes: Slither v0.10.2+.

- Lys opsies en mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry-voorbeeld (vang resultate vas en hou ’n volledige logboek):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- As jy nie Foundry gebruik nie, vervang `--test-cmd` met die manier waarop jy toetse uitvoer (byvoorbeeld `npx hardhat test`, `npm test`).

Artefakte word by verstek in `./mutation_campaign` gestoor. Ongevange (oorlewende) mutants word daarheen gekopieer vir inspeksie.<sup>[[5]](#references)</sup>

### Verstaan die uitvoer

Verslagreëls lyk soos:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Die tag tussen hakies is die mutator-alias (byvoorbeeld, `CR` = Comment Replacement).
- `UNCAUGHT` beteken dat toetse onder die gemuteerde gedrag geslaag het → ontbrekende assertion.

## Vermindering van runtime: prioritiseer impakvolle mutante

Mutation campaigns kan ure of dae duur. Wenke om koste te verminder:<sup>[[1]](#references)[[2]](#references)</sup>
- Omvang: Begin slegs met kritieke kontrakte/gidse en brei dit daarna uit.
- Prioritiseer mutators: As ’n hoëprioriteit-mutant op ’n reël oorleef (byvoorbeeld `revert()` of comment-out), slaan laerprioriteit-variante vir daardie reël oor.
- Gebruik tweefase-campaigns: Voer eers gefokusde/vinnige toetse uit, en toets daarna slegs ongekaugde mutante weer met die volledige suite.
- Koppel mutation targets waar moontlik aan spesifieke toetsopdragte (byvoorbeeld auth-kode -> auth-toetse).
- Beperk campaigns tot mutante met hoë/medium severity wanneer tyd beperk is.
- Paralleliseer toetse indien jou runner dit toelaat; cache dependencies/builds.
- Fail-fast: stop vroeg wanneer ’n verandering duidelik ’n assertion gap aantoon.

Die runtime-wiskunde is genadeloos: `1000 mutants x 5-minute tests ~= 83 hours`, dus is campaign-ontwerp net so belangrik soos die mutator self.<sup>[[1]](#references)</sup>

## Volgehoue campaigns en triage op skaal

Een swakheid van ouer workflows is dat resultate slegs na `stdout` geskryf word. Vir lang campaigns maak dit pause/resume, filtering en review moeiliker.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` verbeter dit deur mutante en uitkomste in SQLite-backed campaigns te stoor. Voordele:<sup>[[1]](#references)</sup>
- Pause en resume lang lopies sonder om vordering te verloor
- Filter slegs ongekaugde mutante in ’n spesifieke lêer of mutation class
- Export/translate resultate na SARIF vir review tooling
- Gee AI-assisted triage kleiner, gefiltreerde resultaatstelle in plaas van rou terminal logs

Volgehoue resultate is veral nuttig wanneer mutation testing deel van ’n audit pipeline word, eerder as ’n eenmalige manual review.

## Triage-workflow vir mutante wat oorleef

1) Inspekteer die gemuteerde reël en gedrag.
- Reproduseer dit plaaslik deur die gemuteerde reël toe te pas en ’n gefokusde toets uit te voer.

2) Versterk toetse om toestand, nie slegs return values nie, te assert.
- Voeg equality-boundary checks by (byvoorbeeld, toets threshold `==`).
- Assert post-conditions: balances, total supply, authorization effects en emitted events.

3) Vervang té permissiewe mocks met realistiese gedrag.
- Verseker dat mocks transfers, failure paths en event emissions wat on-chain plaasvind, afdwing.

4) Voeg invariants vir fuzz tests by.
- Byvoorbeeld, conservation of value, non-negative balances, authorization invariants en monotonic supply waar van toepassing.

5) Skei true positives van semantic no-ops.
- Voorbeeld: `x > 0` -> `x != 0` is betekenisloos wanneer `x` unsigned is.

6) Voer die campaign weer uit totdat survivors gekill is of uitdruklik geregverdig is.

## Case study: onthulling van ontbrekende state assertions (Arkis protocol)

’n Mutation campaign tydens ’n audit van die Arkis DeFi protocol het survivors soos die volgende blootgelê:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Deur die toewysing uit te kommentarieer, het die toetse nie misluk nie, wat bewys dat post-state-assertions ontbreek. Oorsaak: die kode het ’n gebruikerbeheerde `_cmd.value` vertrou in plaas daarvan om werklike token transfers te valideer. ’n Aanvaller kon verwagte en werklike transfers uit sinchronisasie bring om fondse te dreineer. Resultaat: hoë-severiteitsrisiko vir protokol-solvensie.<sup>[[2]](#references)[[3]](#references)</sup>

Riglyn: Behandel survivors wat waarde-oordragte, rekeningkunde of toegangsbeheer beïnvloed as hoë risiko totdat hulle gekill word.

## Moenie blindelings tests genereer om elke mutant te kill nie

Mutation-driven test generation kan terugvuur as die huidige implementering verkeerd is. Voorbeeld: Deur `priority >= 2` na `priority > 2` te muteer, verander gedrag, maar die korrekte oplossing is nie altyd om "’n test vir `priority == 2` te skryf" nie. Daardie gedrag kan self die bug wees.<sup>[[1]](#references)</sup>

Veiliger workflow:
- Gebruik surviving mutants om dubbelsinnige vereistes te identifiseer
- Valideer verwagte gedrag vanuit specs, protokol-dokumentasie of reviewers
- Kodeer eers daarna die gedrag as ’n test/invariant

Anders loop jy die risiko om toevallige implementeringsbesluite in die test suite vas te lê en vals vertroue te verkry.

## Praktiese kontrolelys

- Voer ’n geteikende campaign uit:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Verkies syntax-aware mutators (AST/Tree-sitter) bo regex-only mutation waar beskikbaar.
- Triage survivors en skryf tests/invariants wat onder die gemuteerde gedrag sou misluk.
- Assert balances, supply, authorizations en events.
- Voeg boundary tests by (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Vervang onrealistiese mocks; simuleer failure modes.
- Behou resultate wanneer die tooling dit ondersteun, en filter uncaught mutants voor triage.
- Gebruik two-phase- of per-target-campaigns om runtime hanteerbaar te hou.
- Itereer totdat alle mutants gekill of met comments en rationale geregverdig is.

## References

- [1] [Mutation testing vir die agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Gebruik mutation testing om die bugs te vind wat jou tests nie opvang nie (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage-sekuriteitsoorsig (Bylae C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator-dokumentasie](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
