# Mutation Testing vir Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "toets jou toetse" deur stelselmatig klein veranderinge (mutants) aan contract-kode bekend te stel en die testsuite weer uit te voer. As 'n toets misluk, word die mutant gekill. As die toetse steeds slaag, oorleef die mutant, wat 'n blinde kol onthul wat line/branch coverage nie kan opspoor nie.

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
Unit tests wat slegs ’n waarde onder en ’n waarde bo die drempel nagaan, kan 100% reël-/takdekking bereik sonder om die gelykheidsgrens (`==`) te bevestig. ’n Herfaktorering na `deposit >= 2 ether` sou steeds sulke toetse slaag en protokollogika stilweg breek.<sup>[[2]](#references)</sup>

Mutation testing onthul hierdie gaping deur die voorwaarde te muteer en te verifieer dat toetse misluk.

Vir smart contracts stem mutante wat oorleef dikwels ooreen met ontbrekende kontroles rondom:
- Magtiging en rolgrense
- Rekeningkundige-/waardoordrag-invariante
- Revert-voorwaardes en mislukkingpaaie
- Grensvoorwaardes (`==`, nulwaardes, leë skikkings, maksimum-/minimumwaardes)

## Mutation operators met die hoogste sekuriteitssein

Nuttige mutation-klasse vir contract auditing:<sup>[[1]](#references)[[2]](#references)</sup>
- **Hoë erns**: vervang statements met `revert()` om paaie wat nie uitgevoer word nie, bloot te lê
- **Medium erns**: kommenteer reëls uit / verwyder logika om ongeverifieerde newe-effekte te onthul
- **Lae erns**: subtiele operator- of konstantevervangings soos `>=` -> `>` of `+` -> `-`
- Ander algemene wysigings: vervanging van assignments, boolean-omkerings, negasie van voorwaardes en tipeveranderings

Praktiese doel: maak alle betekenisvolle mutante dood en regverdig oorlewendes wat irrelevant of semanties ekwivalent is, uitdruklik.

## Waarom syntax-aware mutation beter as regex is

Ouer mutation engines het op regex- of lyngebaseerde herskrywings staatgemaak. Dit werk, maar het belangrike beperkings:<sup>[[1]](#references)</sup>
- Multi-line statements is moeilik om veilig te muteer
- Die taalstruktuur word nie verstaan nie, dus kan comments/tokens verkeerd geteiken word
- Die generering van elke moontlike variant op ’n swak lyn mors groot hoeveelhede runtime

AST- of Tree-sitter-gebaseerde tooling verbeter dit deur gestruktureerde nodes pleks van rou lyne te teiken:<sup>[[1]](#references)</sup>
- **slither-mutate** gebruik Slither se Solidity AST.<sup>[[4]](#references)</sup>
- **mewt** gebruik Tree-sitter as ’n language-agnostic kern.<sup>[[6]](#references)</sup>
- **MuTON** bou op `mewt` en voeg first-class support by vir TON-tale soos FunC, Tolk en Tact.<sup>[[7]](#references)</sup>

Dit maak multi-line constructs en expression-level mutations baie meer betroubaar as regex-only benaderings.

## Mutation testing met slither-mutate uitvoer

Vereistes: Slither v0.10.2+.

- Lys opsies en mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry-voorbeeld (vang resultate vas en hou 'n volledige log):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- As jy nie Foundry gebruik nie, vervang `--test-cmd` met die manier waarop jy toetse uitvoer (bv. `npx hardhat test`, `npm test`).

Artifacts word by verstek in `./mutation_campaign` gestoor. Ongevange (oorlewende) mutante word daarheen gekopieer vir inspeksie.<sup>[[5]](#references)</sup>

### Verstaan die uitvoer

Verslagreëls lyk soos:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Die tag tussen hakies is die mutator-alias (byvoorbeeld, `CR` = Comment Replacement).
- `UNCAUGHT` beteken dat toetse onder die gemuteerde gedrag geslaag het → ontbrekende assertion.

## Vermindering van runtime: prioritiseer impakvolle mutants

Mutation campaigns kan ure of dae neem. Wenke om koste te verminder:<sup>[[1]](#references)[[2]](#references)</sup>
- Omvang: Begin slegs met kritieke contracts/directories en brei dit daarna uit.
- Prioritiseer mutators: As ’n hoëprioriteit-mutant op ’n reël oorleef (byvoorbeeld `revert()` of comment-out), slaan laerprioriteit-variante vir daardie reël oor.
- Gebruik tweefase-campaigns: Voer eers gefokusde/vinnige toetse uit, en toets daarna slegs uncaught mutants weer met die volledige suite.
- Koppel mutation targets waar moontlik aan spesifieke test commands (byvoorbeeld auth-kode -> auth-toetse).
- Beperk campaigns tot mutants met hoë/medium severity wanneer tyd beperk is.
- Paralleliseer toetse indien jou runner dit toelaat; cache dependencies/builds.
- Fail-fast: stop vroeg wanneer ’n verandering duidelik ’n assertion gap demonstreer.

Die runtime-wiskunde is brutaal: `1000 mutants x 5-minute tests ~= 83 hours`, dus is campaign-ontwerp net so belangrik soos die mutator self.<sup>[[1]](#references)</sup>

## Persistente campaigns en triage op skaal

Een swakheid van ouer workflows is dat resultate slegs na `stdout` geskryf word. Vir lang campaigns maak dit pause/resume, filtering en review moeiliker.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` verbeter dit deur mutants en uitkomste in SQLite-backed campaigns te stoor. Voordele:<sup>[[1]](#references)</sup>
- Pause en resume lang runs sonder om vordering te verloor
- Filter slegs uncaught mutants in ’n spesifieke lêer of mutation class
- Export/translate resultate na SARIF vir review tooling
- Gee AI-assisted triage kleiner, gefiltreerde resultaatstelle in plaas van rou terminal logs

Persistente resultate is veral nuttig wanneer mutation testing deel van ’n audit pipeline word in plaas van ’n eenmalige handmatige review.

## Triage-workflow vir mutants wat oorleef

1) Inspekteer die gemuteerde reël en gedrag.
- Reproduceer plaaslik deur die gemuteerde reël toe te pas en ’n gefokusde toets uit te voer.

2) Versterk toetse om state te assert, nie slegs return values nie.
- Voeg equality-boundary checks by (byvoorbeeld, toets threshold `==`).
- Assert post-conditions: balances, total supply, authorization effects en emitted events.

3) Vervang té permissive mocks met realistiese gedrag.
- Verseker dat mocks transfers, failure paths en event emissions afdwing wat on-chain plaasvind.

4) Voeg invariants vir fuzz tests by.
- Byvoorbeeld, conservation of value, non-negative balances, authorization invariants en monotonic supply waar van toepassing.

5) Skei true positives van semantic no-ops.
- Voorbeeld: `x > 0` -> `x != 0` is betekenisloos wanneer `x` unsigned is.

6) Voer die campaign weer uit totdat survivors vernietig of uitdruklik geregverdig is.

## Gevallestudie: onthulling van ontbrekende state assertions (Arkis-protokol)

’n Mutation campaign tydens ’n audit van die Arkis DeFi-protokol het survivors soos die volgende blootgelê:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Deur die assignment uit te kommentarieer, het die tests steeds geslaag, wat bewys dat post-state assertions ontbreek. Die hoofoorsaak: die code het ’n user-controlled `_cmd.value` vertrou in plaas daarvan om werklike token transfers te valideer. ’n Attacker kon verwagte en werklike transfers desinchroniseer om fondse te dreineer. Gevolg: hoë-severity risiko vir protocol-solvensie.<sup>[[2]](#references)[[3]](#references)</sup>

Guidance: Behandel survivors wat value transfers, accounting of access control beïnvloed as hoë risiko totdat hulle gekill word.

## Moenie blindelings tests genereer om elke mutant te kill nie

Mutation-driven test generation kan terugvuur as die huidige implementasie verkeerd is. Voorbeeld: om `priority >= 2` na `priority > 2` te mutateer, verander gedrag, maar die korrekte fix is nie altyd om "’n test vir `priority == 2` te skryf nie". Daardie gedrag kan self die bug wees.<sup>[[1]](#references)</sup>

Veiliger workflow:
- Gebruik surviving mutants om onduidelike requirements te identifiseer
- Valideer verwagte gedrag vanuit specs, protocol docs of reviewers
- Encodeer eers daarna die gedrag as ’n test/invariant

Anders loop jy die risiko om implementasie-ongelukke in die test suite vas te kodeer en valse selfvertroue te verkry.

## Praktiese checklist

- Run ’n targeted campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Verkies syntax-aware mutators (AST/Tree-sitter) bo regex-only mutation waar beskikbaar.
- Triage survivors en skryf tests/invariants wat onder die gemuteerde gedrag sou fail.
- Assert balances, supply, authorizations en events.
- Voeg boundary tests by (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Vervang onrealistiese mocks; simuleer failure modes.
- Persist results wanneer die tooling dit ondersteun, en filter uncaught mutants voor triage.
- Gebruik two-phase of per-target campaigns om runtime hanteerbaar te hou.
- Iterateer totdat alle mutants gekill of met comments en rationale geregverdig is.

## References

- [1] [Mutation testing vir die agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Gebruik mutation testing om die bugs te vind wat jou tests nie opvang nie (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
