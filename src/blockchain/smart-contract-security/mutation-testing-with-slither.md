# Mutation Testing za Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing „testira vaše testove“ tako što sistematski uvodi male izmene (mutante) u kod contracta i ponovo pokreće test suite. Ako test ne uspe, mutant je ubijen. Ako testovi i dalje prolaze, mutant preživljava, otkrivajući slepu tačku koju line/branch coverage ne može da detektuje.

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
Unit testovi koji proveravaju samo vrednost ispod i vrednost iznad praga mogu dostići 100% line/branch coverage, a da ne provere granicu jednakosti (==). Refaktorisanjem u `deposit >= 2 ether` takvi testovi bi i dalje prolazili, čime bi se neprimetno narušila logika protokola.<sup>[[2]](#references)</sup>

Mutation testing otkriva ovaj nedostatak tako što mutira uslov i proverava da li testovi padaju.

Kod pametnih ugovora, preživeli mutanti često ukazuju na nedostajuće provere u vezi sa:
- Autorizacijom i granicama uloga
- Invarijantama obračuna i prenosa vrednosti
- Uslovima za revert i putanjama greške
- Graničnim uslovima (`==`, nulte vrednosti, prazni nizovi, maksimalne/minimalne vrednosti)

## Mutation operators with the highest security signal

Korisne klase mutation-a za auditing ugovora:<sup>[[1]](#references)[[2]](#references)</sup>
- **High severity**: zamena naredbi sa `revert()` radi otkrivanja neizvršenih putanja
- **Medium severity**: komentarisanje linija / uklanjanje logike radi otkrivanja neproverenih sporednih efekata
- **Low severity**: suptilne zamene operatora ili konstanti, kao što su `>=` -> `>` ili `+` -> `-`
- Druge uobičajene izmene: zamena dodela, obrtanje boolean vrednosti, negacija uslova i promene tipova

Praktični cilj: ukloniti sve značajne mutante i izričito obrazložiti preživele mutante koji su nebitni ili semantički ekvivalentni.

## Why syntax-aware mutation is better than regex

Stariji mutation engine-i oslanjali su se na regex ili izmene zasnovane na linijama. To funkcioniše, ali ima važna ograničenja:<sup>[[1]](#references)</sup>
- Naredbe koje se prostiru kroz više linija teško je bezbedno mutirati
- Struktura jezika se ne razume, pa komentari/tokeni mogu biti neadekvatno ciljani
- Generisanje svake moguće varijante na osnovu slabe linije nepotrebno troši velike količine runtime-a

AST- ili Tree-sitter-based alati ovo poboljšavaju ciljanjem strukturiranih čvorova umesto sirovih linija:<sup>[[1]](#references)</sup>
- **slither-mutate** koristi Slither-ov Solidity AST.<sup>[[4]](#references)</sup>
- **mewt** koristi Tree-sitter kao language-agnostic jezgro.<sup>[[6]](#references)</sup>
- **MuTON** je izgrađen na `mewt`-u i dodaje first-class podršku za TON jezike kao što su FunC, Tolk i Tact.<sup>[[7]](#references)</sup>

Zbog toga su konstrukcije koje se prostiru kroz više linija i mutacije na nivou izraza mnogo pouzdanije nego pristupi koji se oslanjaju samo na regex.

## Running mutation testing with slither-mutate

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

Artefakti se podrazumevano čuvaju u `./mutation_campaign`. Neuhvaćeni (preživeli) mutanti kopiraju se tamo radi provere.<sup>[[5]](#references)</sup>

### Razumevanje izlaza

Linije izveštaja izgledaju ovako:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Tag u uglastim zagradama je alias mutatora (npr. `CR` = Comment Replacement).
- `UNCAUGHT` znači da su testovi prošli sa mutiranim ponašanjem → nedostaje assertion.

## Smanjenje vremena izvršavanja: davanje prioriteta uticajnim mutantima

Mutation kampanje mogu trajati satima ili danima. Saveti za smanjenje troškova:<sup>[[1]](#references)[[2]](#references)</sup>
- Opseg: Počnite samo sa kritičnim contracts/directories, a zatim proširite opseg.
- Dajte prioritet mutatorima: Ako mutant visokog prioriteta u nekoj liniji preživi (na primer `revert()` ili comment-out), preskočite varijante nižeg prioriteta za tu liniju.
- Koristite kampanje u dve faze: prvo pokrenite fokusirane/brze testove, a zatim ponovo testirajte samo mutants koje testovi nisu uhvatili, koristeći kompletan test suite.
- Kada je moguće, mapirajte mutation targets na određene test komande (na primer auth code -> auth tests).
- Kada je vreme ograničeno, ograničite kampanje na mutants srednje i visoke ozbiljnosti.
- Paralelizujte testove ako vaš runner to podržava; keširajte dependencies/builds.
- Fail-fast: rano prekinite kada promena jasno pokaže nedostatak assertion-a.

Matematika vremena izvršavanja je brutalna: `1000 mutants x 5-minute tests ~= 83 hours`, zato je dizajn kampanje podjednako važan kao i sam mutator.<sup>[[1]](#references)</sup>

## Persistent kampanje i trijaža na velikoj skali

Jedna slabost starijih workflow-a jeste ispisivanje rezultata samo na `stdout`. Kod dugih kampanja to otežava pauziranje/nastavljanje, filtriranje i pregled.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` ovo poboljšavaju čuvanjem mutants i ishoda u kampanjama zasnovanim na SQLite-u. Prednosti:<sup>[[1]](#references)</sup>
- Pauzirajte i nastavite duge runs bez gubitka napretka
- Filtrirajte samo mutants koje testovi nisu uhvatili u određenom fajlu ili mutation class-u
- Exportujte/prevodite rezultate u SARIF za review tooling
- AI-assisted trijaži prosledite manje, filtrirane skupove rezultata umesto sirovih terminal logova

Persistent rezultati su naročito korisni kada mutation testing postane deo audit pipeline-a, umesto jednokratnog manual review-a.

## Workflow trijaže za mutante koji prežive

1) Pregledajte mutiranu liniju i ponašanje.
- Lokalno reprodukujte problem primenom mutirane linije i pokretanjem fokusiranog testa.

2) Ojačajte testove tako da proveravaju stanje, a ne samo return values.
- Dodajte provere granica jednakosti (npr. testirajte threshold `==`).
- Proverite post-conditions: balances, total supply, authorization effects i emitted events.

3) Zamenite previše permisivne mocks realističnim ponašanjem.
- Obezbedite da mocks primenjuju transfers, failure paths i event emissions koji se dešavaju on-chain.

4) Dodajte invariants za fuzz tests.
- Npr. conservation of value, non-negative balances, authorization invariants i monotonic supply gde je primenljivo.

5) Razdvojite true positives od semantic no-ops.
- Primer: `x > 0` -> `x != 0` nema značenje kada je `x` unsigned.

6) Ponovo pokrenite kampanju dok svi mutants koji prežive ne budu uklonjeni ili eksplicitno opravdani.

## Studija slučaja: otkrivanje nedostajućih provera stanja (Arkis protocol)

Mutation kampanja tokom audit-a Arkis DeFi protocol-a otkrila je mutante koji su preživeli, kao što su:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Komentarisanje dodele nije pokvarilo testove, što dokazuje da nedostaju post-state assertions. Osnovni uzrok: kod se oslanjao na `_cmd.value` kojim upravlja korisnik, umesto da validira stvarne prenose tokena. Napadač je mogao da desinhronizuje očekivane i stvarne transfere i isprazni sredstva. Rezultat: rizik visoke ozbiljnosti po solventnost protokola.<sup>[[2]](#references)[[3]](#references)</sup>

Smernica: Tretirajte preživele mutante koji utiču na prenose vrednosti, računovodstvo ili kontrolu pristupa kao visokorizične dok ne budu uklonjeni.

## Nemojte slepo generisati testove za uklanjanje svakog mutanta

Generisanje testova zasnovano na mutacijama može imati suprotan efekat ako je trenutna implementacija pogrešna. Primer: mutiranje `priority >= 2` u `priority > 2` menja ponašanje, ali ispravka nije uvek „napisati test za `priority == 2`“. I samo to ponašanje može biti greška.<sup>[[1]](#references)</sup>

Bezbedniji tok rada:
- Koristite preživele mutante za identifikovanje nejasnih zahteva
- Potvrdite očekivano ponašanje na osnovu specifikacija, dokumentacije protokola ili recenzenata
- Tek tada kodirajte ponašanje kao test/invarijantu

U suprotnom rizikujete da greške u implementaciji ugradite u test suite i steknete lažno samopouzdanje.

## Praktična kontrolna lista

- Pokrenite ciljanu kampanju:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Kada je dostupno, dajte prednost mutatorima koji prepoznaju sintaksu (AST/Tree-sitter) u odnosu na mutacije zasnovane samo na regex-u.
- Analizirajte preživele mutante i napišite testove/invarijante koji bi pali pri izmenjenom ponašanju.
- Proveravajte stanja, ukupnu ponudu, autorizacije i događaje.
- Dodajte testove graničnih slučajeva (`==`, overflow/underflow, zero-address, zero-amount, empty arrays).
- Zamenite nerealistične mock-ove; simulirajte scenarije otkaza.
- Sačuvajte rezultate kada tooling to podržava i filtrirajte nezapažene mutante pre analize.
- Koristite kampanje u dve faze ili po cilju kako bi vreme izvršavanja ostalo prihvatljivo.
- Ponavljajte postupak dok svi mutanti ne budu uklonjeni ili opravdani komentarima i obrazloženjem.

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Koristite mutation testing da pronađete greške koje vaši testovi ne otkrivaju (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Bezbednosni pregled Arkis DeFi Prime Brokerage (Dodatak C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Dokumentacija za Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
