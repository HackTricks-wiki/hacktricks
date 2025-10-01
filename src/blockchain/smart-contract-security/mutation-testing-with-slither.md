# Mutasietoetsing vir Solidity met Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutasietoetsing "toets jou toetse" deur sistematies klein veranderinge (mutante) in jou Solidity-kode in te bring en jou toetsuite weer uit te voer. As 'n toets misluk, word die mutant gedood. As die toetse steeds slaag, oorleef die mutant, wat 'n blinde kol in jou toetsuite openbaar wat lyn-/takdekking nie kan opspoor nie.

Hoofgedagte: Dekking toon dat kode uitgevoer is; mutasietoetsing wys of gedrag werklik deur toetse geasserseer word.

## Waarom dekking kan mislei

Oorweeg hierdie eenvoudige drempelkontrole:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Eenheidstoetse wat slegs 'n waarde onder en 'n waarde bo die drempel kontroleer, kan 100% lyn-/takbedekking bereik terwyl hulle versuim om die gelykheidsgrens (==) te bevestig. 'n Refaktorering na `deposit >= 2 ether` sou steeds sulke toetse deurstaan en terselfdertyd die protokol-logika stilweg breek.

Mutation testing openbaar hierdie gaping deur die voorwaarde te muteer en te verifieer dat jou toetse misluk.

## Algemene Solidity mutation operators

Slither se mutation engine pas baie klein, semantiek-veranderende wysigings toe, soos:
- Operatorvervanging: `+` ↔ `-`, `*` ↔ `/`, etc.
- Toewysingsvervanging: `+=` → `=`, `-=` → `=`
- Konstantevervanging: non-zero → `0`, `true` ↔ `false`
- Voorwaardelike negasie/vervanging binne `if`/lusse
- Maak hele lyne kommentaar (CR: Comment Replacement)
- Vervang 'n lyn met `revert()`
- Datatipe-ruilings: bv. `int128` → `int64`

Doel: Vernietig 100% van die gegenereerde mutante, of regverdig oorlewendes met duidelike redenasie.

## Uitvoer van mutation testing met slither-mutate

Vereistes: Slither v0.10.2+.

- Lys opsies en mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry-voorbeeld (vang resultate en hou 'n volledige logboek):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- As jy nie Foundry gebruik nie, vervang `--test-cmd` met hoe jy toetse uitvoer (bv., `npx hardhat test`, `npm test`).

Artefakte en verslae word standaard gestoor in `./mutation_campaign`. Ongevatte (oorlewende) mutants word daarheen gekopieer vir inspeksie.

### Begrip van die uitvoer

Verslagreëls lyk soos:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Die etiket in hakies is die mutator-alias (bv., `CR` = Comment Replacement).
- `UNCAUGHT` beteken dat toetse geslaag het onder die gemuteerde gedrag → ontbrekende assertie.

## Verminder uitvoeringstyd: prioritiseer impakvolle mutante

Mutasieveldtogte kan ure of dae neem. Wenke om koste te verminder:
- Scope: Begin slegs met kritieke kontrakte/direktorieë, en brei dan uit.
- Prioritiseer mutators: As 'n hoëprioriteits-mutant op 'n lyn oorleef (bv., die hele lyn gekommenteer), kan jy laerprioriteitsweergawes vir daardie lyn oorslaan.
- Paralleliseer toetse as jou runner dit toelaat; kas afhanklikhede en builds.
- Fail-fast: stop vroeg wanneer 'n verandering duidelik 'n assertiegaping aantoon.

## Triage-werkvloei vir oorblywende mutante

1) Inspekteer die gemuteerde lyn en gedrag.
- Reproduseer lokaal deur die gemuteerde lyn toe te pas en 'n gefokusde toets te laat loop.

2) Versterk toetse om staat te bevestig, nie net return-waardes nie.
- Voeg gelykheids-grenskontroles by (bv., toets drempel `==`).
- Bekragtig post-voorwaardes: saldo's, totale aanbod, magtigingseffekte, en uitgee gebeure.

3) Vervang te permissiewe mocks met realistiese gedrag.
- Verseker dat mocks transfers, faalpaaie en event-emissies afdwing wat on-chain voorkom.

4) Voeg invarianties by vir fuzz tests.
- Byvoorbeeld: bewaring van waarde, nie-negatiewe saldo's, magtiging-invarianties, monotoniese aanbod waar toepaslik.

5) Herhaal slither-mutate totdat oorblywende mutante gedood is of uitdruklik geregverdig.

## Gevalstudie: ontbloot ontbrekende staatasserties (Arkis protocol)

'n mutasieveldtog tydens 'n oudit van die Arkis DeFi protocol het oorblywende mutante na vore gebring soos:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Om die toekenning uit te kommentarieer het nie die tests gebreek nie, wat bewys dat post-state assertions ontbreek. Wortel oorsaak: die kode het 'n user-controlled `_cmd.value` vertrou in plaas daarvan om werklike token transfers te valideer. 'n aanvaller kon verwagte vs. werklike transfers desinchroniseer om fondse leeg te trek. Resultaat: hoë risiko wat die protokol se betaalvermoë bedreig.

Riglyne: Behandel survivors wat value transfers, accounting, of access control beïnvloed as hoë-risiko totdat hulle killed is.

## Praktiese kontrolelys

- Voer 'n geteikende veldtog uit:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Triage survivors en skryf tests/invariants wat sou misluk onder die gemuteerde gedrag.
- Asserteer balances, supply, authorizations, en events.
- Voeg boundary tests by (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Vervang onrealistiese mocks; simuleer failure modes.
- Itereer totdat alle mutants killed is, of totdat hulle met kommentaar en rationale geregverdig is.

## Verwysings

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
