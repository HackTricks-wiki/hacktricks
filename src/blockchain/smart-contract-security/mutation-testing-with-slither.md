# Mutasietoetsing vir Solidity met Slither (slither-mutate)

{{#include ../../../banners/hacktricks-training.md}}

Mutasietoetsing "toets jou toetse" deur stelselmatig klein veranderinge (mutants) in jou Solidity-kode in te bring en jou toetsuite weer te laat loop. As 'n toets faal, word die mutant gedood. As die toetse steeds slaag, oorleef die mutant, wat 'n blinde kol in jou toetsuite aan die lig bring wat lyn-/vertakkingsdekking nie kan opspoor nie.

Sleutelgedagte: Dekking toon dat kode uitgevoer is; mutasietoetsing toon of gedrag werklik deur toetse bekragtig word.

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
Eenheidstoetse wat slegs `n` waarde onder en `n` waarde bo die drempel nagaan kan 100% lyn-/takdekking bereik terwyl hulle versuim om die gelykheidsgrens (==) te bekragtig. 'n Refaktorering na `deposit >= 2 ether` sou steeds sulke toetse deurstaan en stilweg protokollogika breek.

Mutasietoetsing openbaar hierdie gaping deur die voorwaarde te muteer en te verifieer dat jou toetse faal.

## Algemene Solidity mutasie-operateurs

Die mutasie-enjin van Slither pas baie klein, semantiekveranderende wysigings toe, soos:
- Operatorvervanging: `+` ↔ `-`, `*` ↔ `/`, etc.
- Toewysingsvervanging: `+=` → `=`, `-=` → `=`
- Konstantevervanging: nie-nul → `0`, `true` ↔ `false`
- Voorwaardelike negasie/vervanging binne `if`/lusse
- Kommentaar uitkommentarieer hele reëls (CR: Comment Replacement)
- Vervang 'n reël deur `revert()`
- Datatipe-wissel: bv. `int128` → `int64`

Doel: Vernietig 100% van die gegenereerde mutants, of regverdig oorlewendes met duidelike redes.

## Uitvoering van mutasietoetsing met slither-mutate

Vereistes: Slither v0.10.2+.

- Lys opsies en mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry voorbeeld (vang resultate en hou 'n volledige log):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- As jy nie Foundry gebruik nie, vervang `--test-cmd` met hoe jy toetse hardloop (bv., `npx hardhat test`, `npm test`).

Artefakte en verslae word standaard in `./mutation_campaign` gestoor. Ongevang (oorleefde) mutante word daarheen gekopieer vir inspeksie.

### Verstaan die uitset

Verslagreëls lyk soos:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Die etiket in hakies is die mutator-alias (bv., `CR` = Comment Replacement).
- `UNCAUGHT` beteken dat toetse geslaag het onder die gemuteerde gedrag → ontbrekende assertie.

## Verminder uitvoeringstyd: prioritiseer invloedryke mutante

Mutasieveldtogte kan ure of dae neem. Wenke om koste te verminder:
- Scope: Begin slegs met kritieke contracts/direktore, en brei dan uit.
- Prioritiseer mutators: As 'n hoë-prioriteits mutant op 'n reël oorleef (bv., hele reël uitgekommenteer), kan jy laer-prioriteits variante vir daardie reël oorslaan.
- Paralleliseer toetse as jou runner dit toelaat; cache dependencies/builds.
- Fail-fast: stop vroeg wanneer 'n verandering duidelik 'n assertie-gaping toon.

## Triage-werkstroom vir oorblywende mutante

1) Inspekteer die gemuteerde reël en gedrag.
- Reproduceer plaaslik deur die gemuteerde reël toe te pas en 'n gefokusde toets te hardloop.

2) Verskerp toetse om die toestand te assereer, nie net returnwaardes nie.
- Voeg gelykheids-grenskontroles by (bv., toets drempel `==`).
- Asserteer post-voorwaardes: balanse, totale aanbod, magtigings-effekte, en uitgesaai gebeurtenisse.

3) Vervang te permissiewe mocks met realistiese gedrag.
- Verseker dat mocks transfers afdwing, foutpaaie en gebeurtenisuitstoot hanteer wat op-chain voorkom.

4) Voeg invariantes by vir fuzz-toetse.
- Byv., behoud van waarde, nie-negatiewe balanse, magtigings-invariantes, monotone voorraad waar toepaslik.

5) Herhardloop slither-mutate totdat die oorblywende mutante gedood is of eksplisiet geregverdig.

## Gevallestudie: onthul ontbrekende toestand-asserties (Arkis protocol)

'n Mutasieveldtog tydens 'n oudit van die Arkis DeFi-protokol het oorblywende mutante soos die volgende na vore gebring:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Kommentering van die toekenning het die toetse nie gebreek nie, wat ontbrekende post-state-asserties bewys. Oorsaak: die kode het vertrou op 'n gebruiker-beheerde `_cmd.value` in plaas daarvan om werklike token-oordragte te valideer. 'n Aanvaller kon verwagte en werklike oordragte desinchroniseer om fondse uit te tap. Resultaat: hoë risiko vir die protokol se solvabiliteit.

Riglyne: Beskou oorlewende mutante wat waarde-oordragte, rekeningkunde of toegangbeheer raak as hoë-risiko totdat hulle uitgeskakel is.

## Praktiese kontrolelys

- Voer 'n geteikende veldtog uit:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Prioritiseer oorlewende mutante en skryf toetse/invariante wat sou misluk onder die gemuteerde gedrag.
- Kontroleer balanse, totale supply, magtigings en events.
- Voeg grensgeval-toetse by (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Vervang onrealistiese mocks; simuleer faalmodusse.
- Herhaal totdat alle mutante uitgeskakel is of met kommentaar en motivering geregverdig is.

## Verwysings

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../../banners/hacktricks-training.md}}
