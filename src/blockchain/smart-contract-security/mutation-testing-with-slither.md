# Mutation Testing za Smart Contracts (slither-mutate, mewt, MuTON)

Mutation testing „testira vaše testove“ tako što sistematski uvodi male izmene (mutante) u kod contracta i ponovo pokreće test suite. Ako test ne uspe, mutant je uništen. Ako testovi i dalje prolaze, mutant preživljava, otkrivajući slepu tačku koju line/branch coverage ne može da detektuje.

Ključna ideja: Coverage pokazuje da je kod izvršen; mutation testing pokazuje da li je ponašanje zaista provereno.<sup>[[2]](#references)</sup>

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
Unit testovi koji proveravaju samo vrednost ispod i vrednost iznad praga mogu dostići 100% line/branch coverage, a da ne proveravaju granicu jednakosti (==). Refaktorisanje na `deposit >= 2 ether` i dalje bi prolazilo takve testove, neprimetno narušavajući logiku protokola.<sup>[[2]](#references)</sup>

Mutation testing otkriva ovaj nedostatak tako što mutira uslov i proverava da li testovi padaju.

Kod smart contracta, preživeli mutanti često ukazuju na nedostajuće provere u vezi sa:
- Autorizacijom i granicama uloga
- Invarijantama obračuna i prenosa vrednosti
- Uslovima za revert i putanjama greške
- Graničnim uslovima (`==`, nulte vrednosti, prazni nizovi, maksimalne/minimalne vrednosti)

## Mutation operators sa najjačim bezbednosnim signalom

Korisne klase mutacija za audit contracta:<sup>[[1]](#references)[[2]](#references)</sup>
- **Visoka ozbiljnost**: zamena iskaza sa `revert()` radi otkrivanja neizvršenih putanja
- **Srednja ozbiljnost**: komentarisanje linija / uklanjanje logike radi otkrivanja neproverenih sporednih efekata
- **Niska ozbiljnost**: suptilne zamene operatora ili konstanti, kao što su `>=` -> `>` ili `+` -> `-`
- Druge uobičajene izmene: zamena dodela, obrtanje boolean vrednosti, negacija uslova i promene tipova

Praktični cilj: eliminisati sve značajne mutante i eksplicitno obrazložiti preživele mutante koji su irelevantni ili semantički ekvivalentni.

## Zašto je mutation koja razume sintaksu bolja od regex-a

Stariji mutation engine-i oslanjali su se na regex ili izmene orijentisane na linije. To funkcioniše, ali ima važna ograničenja:<sup>[[1]](#references)</sup>
- Višelinijske iskaze je teško bezbedno mutirati
- Struktura jezika se ne razume, pa komentari/tokeni mogu biti pogrešno ciljani
- Generisanje svake moguće varijante na slaboj liniji troši velike količine runtime-a

Alati zasnovani na AST-u ili Tree-sitter-u ovo poboljšavaju ciljanjem strukturiranih čvorova umesto sirovih linija:<sup>[[1]](#references)</sup>
- **slither-mutate** koristi Slither-ov Solidity AST.<sup>[[4]](#references)</sup>
- **mewt** koristi Tree-sitter kao jezički agnostičko jezgro.<sup>[[6]](#references)</sup>
- **MuTON** se zasniva na `mewt`-u i dodaje first-class podršku za TON jezike kao što su FunC, Tolk i Tact.<sup>[[7]](#references)</sup>

Zbog toga su višelinijske konstrukcije i mutation na nivou izraza mnogo pouzdaniji nego pristupi koji koriste samo regex.

## Pokretanje mutation testing-a sa slither-mutate

Zahtevi: Slither v0.10.2+.

- Prikaz opcija i mutatora:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry primer (snimite rezultate i zadržite potpun log):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Ako ne koristite Foundry, zamenite `--test-cmd` načinom na koji pokrećete testove (npr. `npx hardhat test`, `npm test`).

Artefakti se podrazumevano čuvaju u `./mutation_campaign`. Neuhvaćeni (preživeli) mutanti kopiraju se tamo radi provere.<sup>[[5]](#references)</sup>

### Razumevanje izlaza

Linije izveštaja izgledaju ovako:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Oznaka u zagradama je alias mutatora (npr. `CR` = Comment Replacement).
- `UNCAUGHT` znači da su testovi prošli pod mutiranim ponašanjem → nedostaje assertion.

## Smanjenje vremena izvršavanja: davanje prioriteta uticajnim mutantima

Mutation kampanje mogu trajati satima ili danima. Saveti za smanjenje troškova:<sup>[[1]](#references)[[2]](#references)</sup>
- Opseg: Počnite samo sa kritičnim contractima/direktorijumima, pa zatim proširite opseg.
- Dajte prioritet mutatorima: Ako mutant visokog prioriteta na nekoj liniji preživi (na primer `revert()` ili comment-out), preskočite varijante nižeg prioriteta za tu liniju.
- Koristite kampanje u dve faze: prvo pokrenite fokusirane/brze testove, a zatim ponovo testirajte samo neuhvaćene mutante kompletnim test suite-om.
- Kad god je moguće, mapirajte mutation targete na konkretne test komande (na primer auth code -> auth tests).
- Kada je vreme ograničeno, ograničite kampanje na mutante visoke/srednje ozbiljnosti.
- Paralelizujte testove ako vaš runner to dozvoljava; keširajte dependencies/builds.
- Fail-fast: rano prekinite kada promena jasno pokaže nedostatak assertion-a.

Matematika vremena izvršavanja je brutalna: `1000 mutants x 5-minute tests ~= 83 hours`, zato je dizajn kampanje podjednako važan kao i sam mutator.<sup>[[1]](#references)</sup>

## Persistent kampanje i triage u velikom obimu

Jedna slabost starijih workflow-a je upisivanje rezultata samo u `stdout`. Kod dugih kampanja to otežava pauziranje/nastavljanje, filtriranje i pregled.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` ovo poboljšavaju čuvanjem mutanata i ishoda u SQLite-backed kampanjama. Prednosti:<sup>[[1]](#references)</sup>
- Pauziranje i nastavljanje dugih izvršavanja bez gubitka napretka
- Filtriranje samo neuhvaćenih mutanata u konkretnoj datoteci ili mutation klasi
- Izvoz/prevođenje rezultata u SARIF za alate za pregled
- Pružanje manjih, filtriranih skupova rezultata za AI-assisted triage umesto sirovih logova terminala

Persistent rezultati su naročito korisni kada mutation testing postane deo audit pipeline-a, a ne jednokratni manualni pregled.

## Triage workflow za preživele mutante

1) Pregledajte izmenjenu liniju i ponašanje.
- Lokalno reprodukujte problem primenom izmenjene linije i pokretanjem fokusiranog testa.

2) Ojačajte testove tako da proveravaju stanje, a ne samo povratne vrednosti.
- Dodajte provere granica jednakosti (npr. testirajte prag `==`).
- Proverite post-conditions: balances, total supply, authorization effects i emitted events.

3) Zamenite previše permisivne mockove realističnim ponašanjem.
- Obezbedite da mockovi sprovode transfers, failure paths i event emissions koji se dešavaju on-chain.

4) Dodajte invariants za fuzz testove.
- Npr. conservation of value, non-negative balances, authorization invariants i monotonic supply gde je primenljivo.

5) Razdvojite true positives od semantic no-ops.
- Primer: `x > 0` -> `x != 0` nema značenje kada je `x` unsigned.

6) Ponovo pokrenite kampanju dok preživeli mutanti ne budu uklonjeni ili izričito opravdani.

## Studija slučaja: otkrivanje nedostajućih provera stanja (Arkis protocol)

Mutation kampanja tokom audita Arkis DeFi protokola otkrila je preživele mutante poput:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Komentarisanje dodele nije pokvarilo testove, što dokazuje nedostatak post-state assertions. Osnovni uzrok: kod je verovao vrednosti `_cmd.value` koju kontroliše korisnik, umesto da proverava stvarne transfers tokena. Napadač je mogao da desinhronizuje očekivane i stvarne transfers kako bi ispraznio sredstva. Rezultat: visokorizična pretnja po solventnost protokola.<sup>[[2]](#references)[[3]](#references)</sup>

Smernice: Survivors koji utiču na transfere vrednosti, accounting ili access control tretirajte kao visokorizične dok ne budu killed.

## Do not blindly generate tests to kill every mutant

Generisanje testova zasnovano na mutation pristupu može imati suprotan efekat ako je trenutna implementacija pogrešna. Primer: mutiranje `priority >= 2` u `priority > 2` menja ponašanje, ali ispravka nije uvek „napisati test za `priority == 2`“. To ponašanje samo po sebi može biti bug.<sup>[[1]](#references)</sup>

Bezbedniji workflow:
- Koristite surviving mutants da biste identifikovali nejasne zahteve
- Validirajte očekivano ponašanje na osnovu specifikacija, dokumentacije protokola ili mišljenja reviewera
- Tek tada kodirajte ponašanje kao test/invariant

U suprotnom rizikujete da u test suite hard-code-ujete slučajnosti implementacije i steknete lažno samopouzdanje.

## Practical checklist

- Pokrenite ciljanu kampanju:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Kada je dostupno, dajte prednost syntax-aware mutatorima (AST/Tree-sitter) u odnosu na mutation koji koristi samo regex.
- Triage-ujte survivors i napišite tests/invariants koji bi pali pri izmenjenom ponašanju.
- Proveravajte balances, supply, authorizations i events.
- Dodajte boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Zamenite nerealistične mocks; simulirajte failure modes.
- Sačuvajte rezultate kada tooling to podržava i filtrirajte uncaught mutants pre triage-a.
- Koristite two-phase ili per-target campaigns kako biste održali prihvatljivo vreme izvršavanja.
- Ponavljajte postupak dok svi mutants ne budu killed ili obrazloženi komentarima i razlozima.

## References

- [1] [Mutation testing za agentic eru](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Koristite mutation testing da pronađete bugove koje vaši testovi ne otkrivaju (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Bezbednosni review Arkis DeFi Prime Brokerage (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Dokumentacija za Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
