# Mutasietoetsing vir Solidity met Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutasietoetsing "toets jou toetse" deur sistematies klein veranderinge (mutante) in jou Solidity-kode in te voer en jou toets-suite weer te laat loop. As 'n toets faal, word die mutant gedood. As die toetse steeds slaag, oorleef die mutant en openbaar dit 'n blinde kol in jou toets-suite wat lyn-/tak-dekking nie kan opspoor nie.

Hoofgedagte: Dekking toon dat kode uitgevoer is; mutasietoetsing toon of gedrag werklik bevestig word.

## Hoekom dekking kan mislei

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
Unit tests wat slegs 'n waarde onder en 'n waarde bo die drempel nagaan, kan 100% lyn-/tak-dekking bereik terwyl hulle versuim om die gelykheidsgrens (==) te bevestig. 'n Refaktor na `deposit >= 2 ether` sou steeds sulke toetse deurgaan en stilweg die protokollogika breek.

Mutasietoetsing openbaar hierdie gaping deur die voorwaarde te muteer en te verifieer dat jou toetse misluk.

## Algemene Solidity mutasie-operateurs

Slither se mutasie-enjin pas baie klein, semantiekveranderende wysigings toe, soos:
- Operateurvervanging: `+` ↔ `-`, `*` ↔ `/`, etc.
- Toekenningvervanging: `+=` → `=`, `-=` → `=`
- Konstante vervanging: nie-nul → `0`, `true` ↔ `false`
- Voorwaardelike negasie/vervanging binne `if`/loops
- Comment out whole lines (CR: Comment Replacement)
- Vervang 'n lyn met `revert()`
- Datatipruilings: e.g., `int128` → `int64`

Doel: Vernietig 100% van die gegenereerde mutante, of regverdig oorblywende mutante met duidelike motivering.

## Uitvoering van mutasietoetsing met slither-mutate

Vereistes: Slither v0.10.2+.

- Lys opsies en mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry voorbeeld (vang resultate en hou 'n volledige logboek):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- As jy nie Foundry gebruik nie, vervang `--test-cmd` met hoe jy toetse uitvoer (bv., `npx hardhat test`, `npm test`).

Artefakte en verslae word standaard in `./mutation_campaign` gestoor. Ongevang (oorlewende) mutants word daarheen gekopieer vir inspeksie.

### Verstaan die uitset

Verslagreëls lyk soos:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Die etiket in hakies is die mutator-alias (bv. `CR` = Comment Replacement).
- `UNCAUGHT` beteken dat toetse deurgegaan het onder die gemuteerde gedrag → ontbrekende assertie.

## Verminder uitvoeringstyd: prioritiseer invloedryke mutants

Mutasie-veldtogte kan ure of dae neem. Wenke om koste te verminder:
- Omvang: Begin slegs met kritiese contracts/direktore, brei daarna uit.
- Prioritiseer mutators: As 'n hoë-prioriteits mutant op 'n reël oorleef (bv. hele reël uitgekommenteer), kan jy laer-prioriteits variante vir daardie reël oorslaan.
- Paralleliseer toetse as jou runner dit toelaat; cache afhanklikhede en builds.
- Fail-fast: hou op vroeg wanneer 'n verandering duidelik 'n assertie-gaping aandui.

## Triëringswerkvloei vir oorlewende mutants

1) Inspekteer die gemuteerde reël en gedrag.
- Reproduceer plaaslik deur die gemuteerde reël toe te pas en 'n gefokusde toets te hardloop.

2) Versterk toetse om toestand te bevestig, nie net teruggegewe waardes nie.
- Voeg gelykheid-grenskontroles by (bv. toets drempel `==`).
- Bevestig post-voorwaardes: balanse, totale toevoer, magtigingseffekte en uitgesaai gebeurtenisse.

3) Vervang oormatige permissiewe mocks met realistiese gedrag.
- Verseker dat mocks transfers, foutpade en gebeurtenisuitsendings afdwing wat on-chain plaasvind.

4) Voeg invariantes by vir fuzz-toetse.
- Bv.: behoud van waarde, nie-negatiewe balanse, magtiging-invariantes, monotoonse voorraad waar toepaslik.

5) Herhardloop slither-mutate totdat oorlewendes gedood is of uitdruklik geregverdig word.

## Gevallestudie: blootlegging van ontbrekende toestand-asserties (Arkis protocol)

'n Mutasie-veldtog tydens 'n oudit van die Arkis DeFi protocol het oorlewendes soos die onderstaande na vore gebring:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Om die toewysing uit te kommentarieer het die toetse nie gebreek nie, wat bewys dat post-state-asserties ontbreek. Ware oorsaak: die kode het ` _cmd.value` deur die gebruiker beheer vertrou in plaas daarvan om werklike token-oordragte te valideer. ’n aanvaller kon verwagte en werklike oordragte desinkroniseer om fondse leeg te maak. Resultaat: risiko van hoë erns vir die protokol se solvensie.

Riglyn: Behandel oorlewendes wat waarde-oordragte, rekeninghouding of toegangsbeheer beïnvloed as hoë-risiko totdat hulle vernietig is.

## Praktiese kontrolelys

- Voer 'n geteikende veldtog uit:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Sorteer oorlewendes en skryf toetse/invariante wat sou misluk onder die gemuteerde gedrag.
- Bevestig balans, totale aanbod, magtigings en gebeure.
- Voeg grens-toetse by (`==`, oorvloei/ondervloei, nul-adres, nul-bedrag, leë arrays).
- Vervang onrealistiese mocks; simuleer foutmodusse.
- Herhaal totdat alle mutants vernietig is of met kommentaar en motivering geregverdig is.

## Verwysings

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
