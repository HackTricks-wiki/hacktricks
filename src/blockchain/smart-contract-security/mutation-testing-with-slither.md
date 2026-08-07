# Mutation Testing za Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing „testira vaše testove“ tako što sistematski uvodi male izmene (mutante) u code contracta i ponovo pokreće test suite. Ako test padne, mutant je ubijen. Ako testovi i dalje prolaze, mutant preživljava, otkrivajući slepu tačku koju line/branch coverage ne može da detektuje.

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
Jedinični testovi koji proveravaju samo vrednost ispod i vrednost iznad praga mogu dostići 100% pokrivenosti linija/grana, a da ne provere granicu jednakosti (==). Refaktorisanje u `deposit >= 2 ether` i dalje bi prolazilo takve testove, neprimetno narušavajući logiku protokola.<sup>[[2]](#references)</sup>

Mutation testing otkriva ovaj nedostatak tako što menja uslov i proverava da li testovi padaju.

Kod pametnih ugovora, mutanti koji prežive često ukazuju na nedostajuće provere u vezi sa:
- Autorizacijom i granicama uloga
- Invarijantama obračuna i prenosa vrednosti
- Uslovima za vraćanje greške i putanjama neuspeha
- Graničnim uslovima (`==`, nulte vrednosti, prazni nizovi, maksimalne/minimalne vrednosti)

## Mutation operatori sa najjačim bezbednosnim signalom

Korisne klase mutacija za auditing ugovora:<sup>[[1]](#references)[[2]](#references)</sup>
- **Visoka ozbiljnost**: zamena naredbi sa `revert()` radi otkrivanja neizvršenih putanja
- **Srednja ozbiljnost**: komentarisanje linija / uklanjanje logike radi otkrivanja neproverenih sporednih efekata
- **Niska ozbiljnost**: suptilne zamene operatora ili konstanti, kao što su `>=` -> `>` ili `+` -> `-`
- Ostale uobičajene izmene: zamena dodele, obrtanje boolean vrednosti, negacija uslova i promene tipova

Praktični cilj: ukloniti sve značajne mutante i izričito obrazložiti one koji prežive, a koji su irelevantni ili semantički ekvivalentni.

## Zašto je mutation testing koji uzima u obzir sintaksu bolji od regex-a

Stariji mutation engine-i oslanjali su se na regex ili izmene zasnovane na linijama. To funkcioniše, ali ima važna ograničenja:<sup>[[1]](#references)</sup>
- Višelinijske naredbe teško je bezbedno menjati
- Struktura jezika se ne razume, pa komentari/tokeni mogu biti pogrešno ciljani
- Generisanje svake moguće varijante na slaboj liniji troši velike količine vremena izvršavanja

Alati zasnovani na AST-u ili Tree-sitter-u ovo poboljšavaju ciljanjem strukturiranih čvorova umesto sirovih linija:<sup>[[1]](#references)</sup>
- **slither-mutate** koristi Slither-ov Solidity AST
- **mewt** koristi Tree-sitter kao jezički agnostičko jezgro
- **MuTON** se nadovezuje na `mewt` i dodaje prvoklasnu podršku za TON jezike kao što su FunC, Tolk i Tact

Zbog toga su višelinijske konstrukcije i mutacije na nivou izraza mnogo pouzdanije nego pristupi koji koriste samo regex.

## Pokretanje mutation testing-a pomoću slither-mutate

Zahtevi: Slither v0.10.2+.

- Izlistajte opcije i mutatore:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry primer (zabeležite rezultate i sačuvajte kompletan log):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Ako ne koristite Foundry, zamenite `--test-cmd` načinom na koji pokrećete testove (npr. `npx hardhat test`, `npm test`).

Artefakti se podrazumevano čuvaju u `./mutation_campaign`. Neuhvaćeni (preživeli) mutanti se kopiraju tamo radi inspekcije.<sup>[[5]](#references)</sup>

### Razumevanje izlaza

Redovi izveštaja izgledaju ovako:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Tag u zagradama je alias mutatora (npr. `CR` = Comment Replacement).
- `UNCAUGHT` znači da su testovi prošli pod mutiranim ponašanjem → nedostaje assertion.

## Smanjenje vremena izvršavanja: prioritizujte uticajne mutante

Mutation campaigns mogu trajati satima ili danima. Saveti za smanjenje troškova:<sup>[[1]](#references)[[2]](#references)</sup>
- Scope: Počnite samo sa kritičnim contracts/directories, a zatim proširite scope.
- Prioritizujte mutatore: Ako mutant visokog prioriteta na nekoj liniji preživi (na primer `revert()` ili comment-out), preskočite varijante nižeg prioriteta za tu liniju.
- Koristite campaigns u dve faze: prvo pokrenite fokusirane/brze testove, a zatim ponovo testirajte samo uncaught mutants pomoću kompletne test suite.
- Kad god je moguće, mapirajte mutation targets na konkretne test commands (na primer auth code -> auth tests).
- Kada je vreme ograničeno, ograničite campaigns na mutante visoke/srednje severity.
- Paralelizujte testove ako vaš runner to dozvoljava; keširajte dependencies/builds.
- Fail-fast: rano prekinite kada izmena jasno pokaže assertion gap.

Matematika vremena izvršavanja je brutalna: `1000 mutants x 5-minute tests ~= 83 hours`, zato je dizajn campaign-a podjednako važan kao i sam mutator.

## Persistent campaigns i triage u velikom obimu

Jedna slabost starijih workflows-a je izbacivanje rezultata samo na `stdout`. Kod dugih campaigns, to otežava pause/resume, filtering i review.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` ovo poboljšavaju čuvanjem mutanata i ishoda u SQLite-backed campaigns. Prednosti:<sup>[[1]](#references)</sup>
- Pauzirajte i nastavite duga pokretanja bez gubitka napretka
- Filtrirajte samo uncaught mutants u konkretnoj datoteci ili mutation class
- Exportujte/prevodite rezultate u SARIF za review tooling
- AI-assisted triage-u prosledite manje, filtrirane skupove rezultata umesto sirovih terminal logs

Persistent results su naročito korisni kada mutation testing postane deo audit pipeline-a, a ne jednokratni manual review.

## Triage workflow za preživele mutante

1) Pregledajte izmenjenu liniju i ponašanje.
- Lokalno reprodukujte problem primenom izmenjene linije i pokretanjem fokusiranog testa.

2) Ojačajte testove tako da proveravaju state, a ne samo return values.
- Dodajte provere equality granica (npr. testirajte threshold `==`).
- Proverite post-conditions: balances, total supply, authorization effects i emitted events.

3) Previše permissive mocks zamenite realističnim ponašanjem.
- Obezbedite da mocks sprovode transfers, failure paths i event emissions koji se dešavaju on-chain.

4) Dodajte invariants za fuzz tests.
- Npr. conservation of value, non-negative balances, authorization invariants i monotonic supply gde je primenljivo.

5) Razdvojite true positives od semantic no-ops.
- Primer: `x > 0` -> `x != 0` nema značenje kada je `x` unsigned.

6) Ponovo pokrećite campaign dok survivors ne budu killed ili eksplicitno justified.

## Case study: otkrivanje nedostajućih state assertions (Arkis protocol)

Mutation campaign tokom audita Arkis DeFi protocol-a otkrio je survivors poput:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Komentarisanje dodele nije pokvarilo testove, čime je potvrđeno odsustvo provera stanja nakon izvršavanja. Osnovni uzrok: kod je verovao korisnički kontrolisanom `_cmd.value` umesto da proverava stvarne transfere tokena. Napadač je mogao da desinhronizuje očekivane i stvarne transfere i tako isprazni sredstva. Rezultat: rizik visoke ozbiljnosti po solventnost protokola.<sup>[[2]](#references)[[3]](#references)</sup>

Smernice: Mutante koji utiču na transfere vrednosti, računovodstvo ili kontrolu pristupa tretirajte kao visokorizične dok ne budu uklonjeni.

## Nemojte slepo generisati testove za uklanjanje svakog mutanta

Generisanje testova zasnovano na mutation testing-u može imati suprotan efekat ako je trenutna implementacija pogrešna. Primer: promena `priority >= 2` u `priority > 2` menja ponašanje, ali ispravno rešenje nije uvek „napisati test za `priority == 2`“. Samo ponašanje može biti greška.<sup>[[1]](#references)</sup>

Bezbedniji workflow:
- Koristite preživele mutante za identifikovanje nejasnih zahteva
- Proverite očekivano ponašanje na osnovu specifikacija, dokumentacije protokola ili mišljenja reviewera
- Tek potom kodirajte ponašanje kao test/invarijantu

U suprotnom rizikujete da u test suite trajno ugradite slučajna ponašanja implementacije i steknete lažno samopouzdanje.

## Praktična kontrolna lista

- Pokrenite ciljanu kampanju:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Kada je dostupno, dajte prednost syntax-aware mutatorima (AST/Tree-sitter) u odnosu na mutation zasnovan na samim regex-ima.
- Analizirajte preživele mutante i napišite testove/invarijante koji bi pali pri izmenjenom ponašanju.
- Proveravajte salda, ukupnu količinu, autorizacije i događaje.
- Dodajte boundary testove (`==`, prelivanja/podlivanja, zero-address, zero-amount, prazni nizovi).
- Zamenite nerealistične mock-ove; simulirajte scenarije otkaza.
- Sačuvajte rezultate kada tooling to podržava i filtrirajte neuhvaćene mutante pre analize.
- Koristite kampanje u dve faze ili po cilju da biste održali prihvatljivo vreme izvršavanja.
- Ponavljajte postupak dok svi mutanti ne budu uklonjeni ili opravdani komentarima i obrazloženjem.

## Reference

- [1] [Mutation testing za agentic eru](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Koristite mutation testing da pronađete greške koje vaši testovi ne otkrivaju (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Bezbednosni review Arkis DeFi Prime Brokerage-a (Dodatak C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Dokumentacija za Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
