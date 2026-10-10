# Mutasietoetsing vir Slimkontrakte (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutasietoetsing “toets jou toetse” deur sistematies klein veranderinge (mutante) aan kontrakkode aan te bring en die toetssuite weer uit te voer. As ’n toets misluk, word die mutant doodgemaak. As die toetse steeds slaag, oorleef die mutant en onthul dit ’n blinde kol wat lyn-/vertakkingsdekking nie kan opspoor nie.

Sleutelidee: Dekking wys dat kode uitgevoer is; mutasietoetsing wys of gedrag werklik bevestig word.<sup>[[2]](#references)</sup>

## Waarom dekking misleidend kan wees

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

Eenheidstoetse wat net ’n waarde onder en ’n waarde bo die drempel nagaan, kan 100% lyn-/vertakkingsdekking bereik sonder om die gelykheidsgrens (`==`) te toets. ’n Herfaktorering na `deposit >= 2 ether` sou steeds hierdie toetse slaag en protokollogika ongemerk breek.<sup>[[2]](#references)</sup>

Mutasietoetsing lê hierdie leemte bloot deur die voorwaarde te muteer en te verifieer dat toetse misluk.

Vir smart contracts dui mutante wat oorleef dikwels op ontbrekende kontroles rondom:
- Magtigings- en rolgrense
- Rekeningkundige-/waardeoordrag-invariante
- Terugrolvoorwaardes en foutpaaie
- Grensvoorwaardes (`==`, nulwaardes, leë skikkings, maksimum-/minimumwaardes)

## Mutasie-operateurs met die sterkste sekuriteitsaanwyser

Nuttige mutasieklasse vir kontrakouditering:<sup>[[1]](#references)[[2]](#references)</sup>
- **Hoë erns**: vervang stellings met `revert()` om paaie bloot te lê wat nie uitgevoer word nie
- **Medium erns**: maak reëls kommentaar of verwyder logika om ongeverifieerde newe-effekte te onthul
- **Lae erns**: subtiele operateur- of konstanteveranderings soos `>=` -> `>` of `+` -> `-`
- Ander algemene wysigings: vervanging van toekenning, omkeer van booleans, ontkenning van voorwaardes en verandering van tipes

Praktiese doel: skakel alle betekenisvolle mutante uit en gee ’n uitdruklike rede vir oorlewendes wat irrelevant of semanties ekwivalent is.

## Waarom sintaksisbewuste mutasie beter is as regex

Ouer mutasie-enjins het op regex- of reëlgebaseerde herskrywings staatgemaak. Dit werk, maar het belangrike beperkings:<sup>[[1]](#references)</sup>
- Stellings oor verskeie reëls is moeilik om veilig te muteer
- Die taalstruktuur word nie verstaan nie, dus kan opmerkings/tekens verkeerd geteiken word
- Die generering van elke moontlike variant op ’n swak reël mors baie looptyd

Gereedskap gebaseer op AST of Tree-sitter verbeter dit deur gestruktureerde nodusse eerder as rou reëls te teiken:<sup>[[1]](#references)</sup>
- **slither-mutate** gebruik Slither se Solidity AST.<sup>[[4]](#references)</sup>
- **mewt** gebruik Tree-sitter as ’n taal-onafhanklike kern.<sup>[[6]](#references)</sup>
- **MuTON** bou voort op `mewt` en voeg eersteklas-ondersteuning by vir TON-tale soos FunC, Tolk en Tact.<sup>[[7]](#references)</sup>

Dit maak mutasies van konstruksies oor verskeie reëls en op uitdrukkingsvlak baie betroubaarder as benaderings wat slegs regex gebruik.

## Voer mutasietoetsing met slither-mutate uit

Vereistes: Slither v0.10.2+.

- Lys opsies en mutators:

```bash
slither-mutate --help
slither-mutate --list-mutators
```

- Foundry-voorbeeld (vang resultate vas en hou ’n volledige log by):<sup>[[2]](#references)</sup>

```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```

- As jy nie Foundry gebruik nie, vervang `--test-cmd` met die manier waarop jy toetse uitvoer (bv. `npx hardhat test`, `npm test`).

Artefakte word by verstek in `./mutation_campaign` gestoor. Ongevangde (oorlewende) mutants word daarheen gekopieer vir inspeksie.<sup>[[5]](#references)</sup>

### Verstaan die uitvoer

Verslagreëls lyk soos:

```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```

- Die merker tussen hakies is die mutator-alias (bv. `CR` = Comment Replacement).
- `UNCAUGHT` beteken dat toetse met die gemuteerde gedrag geslaag het → ontbrekende assertion.

## Looptyd verkort: prioritiseer impakvolle mutante

Mutasieveldtogte kan ure of dae duur. Wenke om koste te verminder:<sup>[[1]](#references)[[2]](#references)</sup>
- Omvang: Begin slegs met kritieke kontrakte/gidse en brei dan uit.
- Prioritiseer mutators: As ’n hoëprioriteit-mutant op ’n reël oorleef (byvoorbeeld `revert()` of kommentaar-uitsetting), slaan laerprioriteit-variante vir daardie reël oor.
- Gebruik tweefase-veldtogte: voer eers gefokusde/vinnige toetse uit, en toets dan slegs die mutante wat nie gevang is nie, weer met die volledige toetssuite.
- Koppel mutasieteikens waar moontlik aan spesifieke toetsopdragte (byvoorbeeld auth-kode -> auth-toetse).
- Beperk veldtogte tot mutante met hoë/matige erns wanneer tyd beperk is.
- Voer toetse parallel uit as jou runner dit toelaat; kas afhanklikhede/bouwerk.
- Stop vroeg: staak wanneer ’n verandering duidelik ’n leemte in assertions blootlê.

Die berekening van looptyd is straf: `1000 mutants x 5-minute tests ~= 83 hours`, dus is die ontwerp van die veldtog net so belangrik soos die mutator self.<sup>[[1]](#references)</sup>

## Aanhoudende veldtogte en triage op skaal

Een swakpunt van ouer werkvloeie is dat resultate net na `stdout` uitgevoer word. Vir lang veldtogte maak dit onderbreking/hervatting, filtering en hersiening moeiliker.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` verbeter dit deur mutante en uitkomste in SQLite-gesteunde veldtogte te stoor. Voordele:<sup>[[1]](#references)</sup>
- Onderbreek en hervat lang lopies sonder om vordering te verloor
- Filtreer slegs mutante wat nie gevang is nie, in ’n spesifieke lêer of mutasieklas
- Voer resultate uit/vertaal dit na SARIF vir hersieningshulpmiddels
- Gee AI-ondersteunde triage kleiner, gefiltreerde resultaatstelle in plaas van rou terminaallogboeke

Aanhoudende resultate is veral nuttig wanneer mutasietoetsing deel word van ’n ouditpyplyn eerder as ’n eenmalige handmatige hersiening.

## Triage-werkvloei vir mutante wat oorleef

1) Inspekteer die gemuteerde reël en gedrag.
   - Reproduseer dit plaaslik deur die gemuteerde reël toe te pas en ’n gefokusde toets uit te voer.

2) Versterk toetse om toestand te toets, nie net terugkeerwaardes nie.
   - Voeg kontroles vir gelykheidsgrense by (bv. toets drempel `==`).
   - Toets na-voorwaardes: saldo’s, totale aanbod, magtigingseffekte en gegenereerde gebeurtenisse.

3) Vervang te permissiewe mocks met realistiese gedrag.
   - Verseker dat mocks oordragte, mislukkingspaaie en gebeurtenisgenerering afdwing wat on-chain plaasvind.

4) Voeg invariants vir fuzz-toetse by.
   - Bv. waardebehoud, nie-negatiewe saldo’s, magtigingsinvariants, aanbod wat toeneem waar van toepassing.

5) Onderskei ware positiewe bevindings van semantiese geen-veranderinge.
   - Voorbeeld: `x > 0` -> `x != 0` is betekenisloos wanneer `x` unsigned is.

6) Voer die veldtog weer uit totdat oorlewendes gevang of uitdruklik geregverdig is.

## Gevallestudie: ontbrekende toestandstoetse blootlê (Arkis-protokol)

’n Mutasieveldtog tydens ’n oudit van die Arkis DeFi-protokol het oorlewendes soos die volgende blootgelê:<sup>[[2]](#references)[[3]](#references)</sup>

```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```

Om die toewysing uit te kommentarieer, het die toetse nie laat misluk nie, wat bewys dat post-state assertions ontbreek. Grondoorsaak: die kode het ’n gebruikerbeheerde `_cmd.value` vertrou in plaas daarvan om werklike tokentransaksies te valideer. ’n Aanvaller kon die verwagte en werklike transaksies uit pas bring om fondse te dreineer. Gevolg: ’n hoë erns-risiko vir die protokol se solvensie.<sup>[[2]](#references)[[3]](#references)</sup>

Riglyn: Behandel oorlewende mutante wat waarde-oordragte, rekeningkunde of toegangsbeheer beïnvloed as hoërisiko totdat hulle uitgeskakel is.

## Moenie blindelings toetse genereer om elke mutant uit te skakel nie

Mutasiegedrewe toetsgenerering kan teenproduktief wees as die huidige implementering verkeerd is. Voorbeeld: om `priority >= 2` na `priority > 2` te muteer, verander gedrag, maar die regte oplossing is nie altyd om “’n toets vir `priority == 2` te skryf” nie. Daardie gedrag kan self die fout wees.<sup>[[1]](#references)</sup>

Veiliger werkvloei:
- Gebruik oorlewende mutante om onduidelike vereistes te identifiseer
- Bevestig die verwagte gedrag aan die hand van spesifikasies, protokol-dokumentasie of beoordelaars
- Kodeer eers daarna die gedrag as ’n toets/invariant

Anders loop jy die risiko om implementeringsongelukke in die toetsstel vas te lê en vals sekerheid te verkry.

## Praktiese kontrolelys

- Voer ’n geteikende veldtog uit:
  - `slither-mutate ./src/contracts --test-cmd="forge test"`
- Verkies sintaksisbewuste mutators (AST/Tree-sitter) bo mutasie wat slegs regex gebruik, waar beskikbaar.
- Evalueer oorlewende mutante en skryf toetse/invariante wat met die gemuteerde gedrag sou misluk.
- Kontroleer saldo’s, aanbod, magtigings en gebeurtenisse.
- Voeg grenstoetse by (`==`, oorlope/onderlope, nuladres, nulbedrag, leë skikkings).
- Vervang onrealistiese mocks; simuleer mislukkingsmodusse.
- Stoor resultate wanneer die gereedskap dit ondersteun, en filter mutante wat nie onderskep is nie uit voordat jy hulle evalueer.
- Gebruik tweefase- of per-teikenv­­eldtogte om die looptyd hanteerbaar te hou.
- Herhaal totdat alle mutante uitgeskakel of met kommentaar en redes geregverdig is.

## References

- [1] [Mutasietoetsing vir die agentiese era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Gebruik mutasietoetsing om die foute te vind wat jou toetse nie opvang nie (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage-sekuriteitsoorsig (Bylae C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator-dokumentasie](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
