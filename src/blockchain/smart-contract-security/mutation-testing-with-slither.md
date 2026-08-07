# Mutation Testing za Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing „testira vaše testove“ tako što sistematski uvodi male izmene (mutante) u code ugovora i ponovo pokreće test suite. Ako test ne uspe, mutant je ubijen. Ako testovi i dalje prolaze, mutant preživljava, otkrivajući slepu tačku koju line/branch coverage ne može da detektuje.

Ključna ideja: Coverage pokazuje da je code izvršen; mutation testing pokazuje da li je ponašanje zaista provereno.<sup>[[2]](#references)</sup>

## Zašto coverage može da zavara

Razmotrite ovu jednostavnu proveru praga:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Unit testovi koji proveravaju samo vrednost ispod i vrednost iznad praga mogu dostići 100% pokrivenosti linija/grana, a da pritom ne provere granicu jednakosti (==). Refaktorisanje na `deposit >= 2 ether` i dalje bi prošlo takve testove, neprimetno narušavajući logiku protokola.<sup>[[2]](#references)</sup>

Mutation testing otkriva ovaj nedostatak mutiranjem uslova i proverom da li testovi padaju.

Kod smart contracta, preživeli mutanti često ukazuju na nedostajuće provere u vezi sa:
- Autorizacijom i granicama uloga
- Invarijantama obračuna/vrednosti transfera
- Revert uslovima i putanjama grešaka
- Graničnim uslovima (`==`, nulte vrednosti, prazni nizovi, maksimalne/minimalne vrednosti)

## Mutation operatori sa najjačim bezbednosnim signalom

Korisne klase mutacija za auditing contracta:<sup>[[1]](#references)[[2]](#references)</sup>
- **Visok severity**: zamena iskaza sa `revert()` radi otkrivanja neizvršenih putanja
- **Srednji severity**: komentarisanje linija / uklanjanje logike radi otkrivanja neproverenih sporednih efekata
- **Nizak severity**: suptilne zamene operatora ili konstanti, kao što su `>=` -> `>` ili `+` -> `-`
- Druge uobičajene izmene: zamena dodela, promene boolean vrednosti, negacija uslova i promene tipova

Praktični cilj: eliminisati sve smislene mutante i eksplicitno obrazložiti one koji su irelevantni ili semantički ekvivalentni.

## Zašto je syntax-aware mutation bolji od regex-a

Stariji mutation engine-i oslanjali su se na regex ili izmene orijentisane na linije. To funkcioniše, ali ima važna ograničenja:<sup>[[1]](#references)</sup>
- Višelinijske iskaze je teško bezbedno mutirati
- Struktura jezika se ne razume, pa komentari/tokeni mogu biti pogrešno ciljani
- Generisanje svake moguće varijante na slaboj liniji troši velike količine runtime-a

Alati zasnovani na AST-u ili Tree-sitter-u ovo poboljšavaju ciljanjem strukturiranih čvorova umesto sirovih linija:<sup>[[1]](#references)</sup>
- **slither-mutate** koristi Slither-ov Solidity AST<sup>[[4]](#references)</sup>
- **mewt** koristi Tree-sitter kao language-agnostic jezgro<sup>[[6]](#references)</sup>
- **MuTON** je izgrađen na `mewt`-u i dodaje first-class podršku za TON jezike kao što su FunC, Tolk i Tact<sup>[[7]](#references)</sup>

To višelinijske konstrukcije i mutacije na nivou izraza čini mnogo pouzdanijim od pristupa koji se oslanjaju isključivo na regex.

## Pokretanje mutation testing-a sa slither-mutate

Zahtevi: Slither v0.10.2+.

- Izlistaj opcije i mutatore:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry primer (zabeležite rezultate i sačuvajte kompletan log):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Ako ne koristite Foundry, zamenite `--test-cmd` načinom na koji pokrećete testove (npr. `npx hardhat test`, `npm test`).

Artefakti se podrazumevano čuvaju u `./mutation_campaign`. Neuhvaćeni (preživeli) mutanti se kopiraju tamo radi provere.<sup>[[5]](#references)</sup>

### Razumevanje izlaza

Linije izveštaja izgledaju ovako:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Tag u uglastim zagradama je alias mutatora (npr. `CR` = Comment Replacement).
- `UNCAUGHT` znači da su testovi prošli pod mutiranim ponašanjem → nedostaje assertion.

## Smanjenje vremena izvršavanja: prioritet dati uticajnim mutantima

Mutation kampanje mogu trajati satima ili danima. Saveti za smanjenje troškova:<sup>[[1]](#references)[[2]](#references)</sup>
- Opseg: Počnite samo sa kritičnim contractima/direktorijumima, pa zatim proširite opseg.
- Dajte prioritet mutatorima: Ako mutant visokog prioriteta na nekoj liniji preživi (na primer `revert()` ili comment-out), preskočite varijante nižeg prioriteta za tu liniju.
- Koristite kampanje u dve faze: prvo pokrenite fokusirane/brze testove, a zatim ponovo testirajte samo neuhvaćene mutante kompletnim test suite-om.
- Kad god je moguće, mapirajte mutation targete na konkretne test komande (na primer auth kod -> auth testovi).
- Kada je vreme ograničeno, ograničite kampanje na mutante visokog/srednjeg severity-ja.
- Paralelizujte testove ako vaš runner to dozvoljava; keširajte dependencies/buildove.
- Fail-fast: rano prekinite kada izmena jasno pokaže assertion gap.

Matematika vremena izvršavanja je brutalna: `1000 mutants x 5-minute tests ~= 83 hours`, zato je dizajn kampanje jednako važan kao i sam mutator.<sup>[[1]](#references)</sup>

## Persistent kampanje i triage u velikom obimu

Jedna slabost starijih workflow-a jeste ispisivanje rezultata samo na `stdout`. Kod dugih kampanja to otežava pauziranje/nastavak, filtriranje i pregled.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` ovo poboljšavaju čuvanjem mutanata i ishoda u kampanjama zasnovanim na SQLite-u. Prednosti:<sup>[[1]](#references)</sup>
- Pauziranje i nastavak dugih pokretanja bez gubitka napretka
- Filtriranje samo neuhvaćenih mutanata u određenom fajlu ili mutation klasi
- Export/translation rezultata u SARIF za alate za pregled
- Prosleđivanje manjih, filtriranih skupova rezultata za AI-assisted triage umesto sirovih logova terminala

Persistent rezultati su naročito korisni kada mutation testing postane deo audit pipeline-a, umesto jednokratnog manuelnog pregleda.

## Triage workflow za mutante koji prežive

1) Pregledajte izmenjenu liniju i ponašanje.
- Lokalno reprodukujte problem primenom izmenjene linije i pokretanjem fokusiranog testa.

2) Ojačajte testove tako da proveravaju stanje, a ne samo povratne vrednosti.
- Dodajte provere granica jednakosti (npr. testirajte prag `==`).
- Proverite post-uslove: balanse, ukupnu ponudu, efekte autorizacije i emitovane događaje.

3) Previše permisivne mockove zamenite realističnim ponašanjem.
- Uverite se da mockovi sprovode transfere, failure paths i emitovanje događaja do kojih dolazi on-chain.

4) Dodajte invariants za fuzz testove.
- Npr. očuvanje vrednosti, nenegativne balanse, authorization invariants i monotonic supply gde je primenljivo.

5) Razdvojite true positives od semantic no-op-ova.
- Primer: `x > 0` -> `x != 0` nema značenje kada je `x` unsigned.

6) Ponovo pokrenite kampanju dok mutanti koji su preživeli ne budu ubijeni ili eksplicitno opravdani.

## Studija slučaja: otkrivanje nedostajućih provera stanja (Arkis protocol)

Mutation kampanja tokom audita DeFi protokola Arkis otkrila je mutante koji su preživeli, kao što su:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Komentarisanje dodele nije pokvarilo testove, čime je dokazano da nedostaju post-state provere. Osnovni uzrok: kod je verovao korisnički kontrolisanom `_cmd.value` umesto da proverava stvarne transfere tokena. Napadač je mogao da desinhronizuje očekivane i stvarne transfere i isprazni sredstva. Rezultat: rizik visoke ozbiljnosti po solventnost protokola.<sup>[[2]](#references)[[3]](#references)</sup>

Smernice: Mutante koji prežive, a utiču na prenose vrednosti, računovodstvo ili kontrolu pristupa, tretirajte kao visokorizične dok ne budu uklonjeni.

## Nemojte slepo generisati testove za uklanjanje svakog mutanta

Generisanje testova zasnovano na mutacijama može imati suprotan efekat ako je trenutna implementacija pogrešna. Primer: mutiranje `priority >= 2` u `priority > 2` menja ponašanje, ali ispravka nije uvek „napisati test za `priority == 2`“. To ponašanje samo po sebi može biti greška.<sup>[[1]](#references)</sup>

Bezbedniji tok rada:
- Koristite mutante koji su preživeli da biste identifikovali nejasne zahteve
- Proverite očekivano ponašanje u specifikacijama, dokumentaciji protokola ili sa reviewerima
- Tek tada zapišite ponašanje kao test/invarijantu

U suprotnom, rizikujete da nehotične detalje implementacije ugradite u test suite i steknete lažnu sigurnost.

## Praktična kontrolna lista

- Pokrenite ciljanu kampanju:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Kada je dostupno, prednost dajte mutatorima koji uzimaju u obzir sintaksu (AST/Tree-sitter), umesto mutacija zasnovanih samo na regex-u.
- Razvrstajte preživele mutante i napišite testove/invarijante koji bi pali pri izmenjenom ponašanju.
- Proveravajte stanje sredstava, ukupnu ponudu, autorizacije i događaje.
- Dodajte testove graničnih slučajeva (`==`, prelivanja/podlivanja, nulta adresa, nulti iznos, prazni nizovi).
- Zamenite nerealistične mock-ove; simulirajte scenarije otkaza.
- Sačuvajte rezultate kada tooling to podržava i filtrirajte mutante koje alat nije uhvatio pre trijaže.
- Koristite kampanje u dve faze ili po cilju kako biste održali prihvatljivo vreme izvršavanja.
- Ponavljajte postupak dok svi mutanti ne budu uklonjeni ili opravdani komentarima i obrazloženjem.

## Reference

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
