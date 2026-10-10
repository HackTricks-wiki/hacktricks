# Mutation Testing za Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing „testira vaše testove“ tako što sistematski unosi male izmene (mutante) u kod ugovora i ponovo pokreće testni skup. Ako test ne uspe, mutant je ubijen. Ako testovi i dalje prolaze, mutant preživljava, otkrivajući slepu tačku koju pokrivenost linija/grana ne može da otkrije.

Ključna ideja: Pokrivenost pokazuje da je kod izvršen; mutation testing pokazuje da li su ponašanja zaista proverena.<sup>[[2]](#references)</sup>

## Zašto pokrivenost može da zavara

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

Unit testovi koji proveravaju samo vrednost ispod i vrednost iznad praga mogu da dostignu 100% pokrivenosti linija/grana, a da ne proveravaju graničnu vrednost jednakosti (==). Refaktorisanje uslova u `deposit >= 2 ether` i dalje bi prošlo ove testove, čime bi se neprimetno narušila logika protokola.<sup>[[2]](#references)</sup>

Mutation testing otkriva ovaj nedostatak tako što menja uslov i proverava da li testovi padaju.

Kod smart contracts, preživeli mutanti često ukazuju na nedostajuće provere za:
- Granice autorizacije i uloga
- Invarijante računovodstva/prenosa vrednosti
- Uslove za revert i putanje grešaka
- Granične uslove (`==`, nulte vrednosti, prazni nizovi, maksimalne/minimalne vrednosti)

## Mutation operators sa najvećom bezbednosnom vrednošću

Korisne klase mutacija za reviziju contracts:<sup>[[1]](#references)[[2]](#references)</sup>
- **Visok nivo ozbiljnosti**: zamena naredbi sa `revert()` radi otkrivanja neizvršenih putanja
- **Srednji nivo ozbiljnosti**: komentarisanje linija / uklanjanje logike radi otkrivanja neproverenih sporednih efekata
- **Nizak nivo ozbiljnosti**: suptilna zamena operatora ili konstanti, poput `>=` -> `>` ili `+` -> `-`
- Druge česte izmene: zamena dodele, obrtanje boolean vrednosti, negiranje uslova i promene tipova

Praktični cilj: eliminisati sve smislene mutante i izričito obrazložiti one koji su nebitni ili semantički ekvivalentni.

## Zašto je mutacija koja poznaje sintaksu bolja od regex-a

Stariji mutation engines oslanjali su se na regex ili izmene zasnovane na linijama. To funkcioniše, ali ima značajna ograničenja:<sup>[[1]](#references)</sup>
- Višelinijske naredbe teško je bezbedno mutirati
- Struktura jezika se ne razume, pa komentari/tokeni mogu biti pogrešno odabrani
- Generisanje svih mogućih varijanti na liniji sa slabom pokrivenošću troši mnogo vremena izvršavanja

Alati zasnovani na AST-u ili Tree-sitter-u unapređuju ovaj pristup tako što ciljaju strukturirane čvorove umesto sirovih linija:<sup>[[1]](#references)</sup>
- **slither-mutate** koristi Slither-ov Solidity AST.<sup>[[4]](#references)</sup>
- **mewt** koristi Tree-sitter kao jezički nezavisno jezgro.<sup>[[6]](#references)</sup>
- **MuTON** se nadovezuje na `mewt` i dodaje izvornu podršku za TON jezike kao što su FunC, Tolk i Tact.<sup>[[7]](#references)</sup>

Zbog toga su višelinijske konstrukcije i mutacije na nivou izraza mnogo pouzdanije nego pristupi koji koriste samo regex.

## Pokretanje mutation testing-a pomoću slither-mutate

Zahtevi: Slither v0.10.2+.

- Prikaži opcije i mutatore:

```bash
slither-mutate --help
slither-mutate --list-mutators
```

- Foundry primer (zabeležite rezultate i sačuvajte kompletan log):<sup>[[2]](#references)</sup>

```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```

- Ako ne koristite Foundry, zamenite `--test-cmd` načinom na koji pokrećete testove (npr. `npx hardhat test`, `npm test`).

Artefakti se podrazumevano čuvaju u `./mutation_campaign`. Neuhvaćeni (preživeli) mutanti se kopiraju tamo radi pregleda.<sup>[[5]](#references)</sup>

### Razumevanje izlaza

Redovi izveštaja izgledaju ovako:

```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```

- Oznaka u uglastim zagradama je alias mutatora (npr. `CR` = zamena komentara).
- `UNCAUGHT` znači da su testovi prošli uz izmenjeno ponašanje → nedostaje assertion.

## Smanjenje vremena izvršavanja: dajte prednost mutantima sa najvećim uticajem

Kampanje mutacija mogu trajati satima ili danima. Saveti za smanjenje troškova:<sup>[[1]](#references)[[2]](#references)</sup>
- Opseg: Počnite samo sa kritičnim ugovorima/direktorijumima, pa zatim proširite opseg.
- Dajte prednost mutatorima: Ako mutant visokog prioriteta u nekoj liniji preživi (na primer `revert()` ili komentarisanje koda), preskočite varijante nižeg prioriteta za tu liniju.
- Koristite kampanje u dve faze: prvo pokrenite fokusirane/brze testove, a zatim ponovo testirajte samo neuhvaćene mutante kompletnim skupom testova.
- Kad god je moguće, povežite ciljeve mutacija sa konkretnim komandama za testiranje (na primer, auth kod -> auth testovi).
- Kada je vreme ograničeno, ograničite kampanje na mutante srednje i visoke ozbiljnosti.
- Paralelizujte testove ako vaš runner to podržava; keširajte zavisnosti/izgradnje.
- Prekinite čim promena jasno pokaže nedostatak u assertion-ima.

Proračun vremena je surov: `1000 mutants x 5-minute tests ~= 83 hours`, zato je osmišljavanje kampanje podjednako važno kao i sam mutator.<sup>[[1]](#references)</sup>

## Trajne kampanje i trijaža u velikom obimu

Jedna od slabosti starijih tokova rada jeste beleženje rezultata isključivo u `stdout`. Kod dugih kampanja to otežava pauziranje/nastavljanje, filtriranje i pregled.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` rešavaju ovaj problem tako što čuvaju mutante i ishode u kampanjama zasnovanim na SQLite-u. Prednosti:<sup>[[1]](#references)</sup>
- Pauzirajte i nastavite duge kampanje bez gubitka napretka
- Filtrirajte samo neuhvaćene mutante u određenoj datoteci ili klasi mutacija
- Izvezite/konvertujte rezultate u SARIF radi pregleda pomoću alata
- Omogućite AI-potpomognutoj trijaži da obrađuje manje, filtrirane skupove rezultata umesto sirovih terminalskih logova

Trajni rezultati su naročito korisni kada testiranje mutacijama postane deo revizijskog procesa, a ne jednokratni ručni pregled.

## Tok rada za trijažu preživelih mutanata

1) Pregledajte izmenjenu liniju i ponašanje.
   - Reprodukujte lokalno tako što ćete primeniti izmenjenu liniju i pokrenuti fokusirani test.

2) Ojačajte testove tako da proveravaju stanje, a ne samo povratne vrednosti.
   - Dodajte provere granica jednakosti (npr. testirajte prag `==`).
   - Proveravajte post-uslove: stanja računa, ukupnu ponudu, efekte autorizacije i emitovane događaje.

3) Zamenite previše permisivne mock-ove realističnim ponašanjem.
   - Obezbedite da mock-ovi sprovode transfere, putanje grešaka i emitovanje događaja koji se dešavaju on-chain.

4) Dodajte invarijante za fuzz testove.
   - Npr. očuvanje vrednosti, nenegativna stanja računa, invarijante autorizacije i monotona ponuda kada je primenljivo.

5) Razlikujte istinski pozitivne rezultate od semantičkih no-op izmena.
   - Primer: `x > 0` -> `x != 0` nema značaja kada je `x` bez predznaka.

6) Ponovo pokrećite kampanju dok se preživeli mutanti ne uklone ili dok se njihovo preživljavanje izričito ne opravda.

## Studija slučaja: otkrivanje nedostajućih provera stanja (Arkis protokol)

Kampanja mutacija tokom revizije DeFi protokola Arkis otkrila je preživele mutante kao što su:<sup>[[2]](#references)[[3]](#references)</sup>

```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```

Komentarisanje dodele vrednosti nije pokvarilo testove, što dokazuje da nedostaju provere stanja nakon izvršavanja. Osnovni uzrok: kod se oslanjao na korisnički kontrolisani `_cmd.value` umesto da proverava stvarne prenose tokena. Napadač je mogao da razdvoji očekivane od stvarnih prenosa i isprazni sredstva. Rezultat: visok rizik po solventnost protokola.<sup>[[2]](#references)[[3]](#references)</sup>

Smernice: Mutante koji prežive i utiču na prenose vrednosti, računovodstvo ili kontrolu pristupa tretirajte kao visokorizične dok ih ne uklonite.

## Nemojte slepo generisati testove da biste uklonili svakog mutanta

Generisanje testova vođeno mutacijama može imati neželjene posledice ako je trenutna implementacija pogrešna. Primer: mutacija `priority >= 2` u `priority > 2` menja ponašanje, ali ispravno rešenje nije uvek „napisati test za `priority == 2`“. I samo to ponašanje može biti greška.<sup>[[1]](#references)</sup>

Bezbedniji postupak:
- Koristite preživele mutante da biste identifikovali nejasne zahteve
- Proverite očekivano ponašanje na osnovu specifikacija, dokumentacije protokola ili mišljenja recenzenata
- Tek tada kodirajte to ponašanje kao test/invarijantu

U suprotnom, rizikujete da u testni skup ugradite slučajnosti implementacije i steknete lažno samopouzdanje.

## Praktična kontrolna lista

- Pokrenite ciljanu kampanju:
  - `slither-mutate ./src/contracts --test-cmd="forge test"`
- Kada su dostupni, dajte prednost mutatorima koji razumeju sintaksu (AST/Tree-sitter) u odnosu na mutacije zasnovane isključivo na regex-u.
- Analizirajte preživele mutante i napišite testove/invarijante koji bi pali pri izmenjenom ponašanju.
- Proveravajte stanje sredstava, ponudu tokena, ovlašćenja i događaje.
- Dodajte testove graničnih slučajeva (`==`, prekoračenja/podkoračenja, nulta adresa, nulti iznos, prazni nizovi).
- Zamenite nerealistične mock-ove; simulirajte režime otkaza.
- Sačuvajte rezultate kada alat to podržava i filtrirajte mutante koji nisu uhvaćeni pre analize.
- Koristite kampanje u dve faze ili po ciljnoj meti da biste održali prihvatljivo vreme izvršavanja.
- Ponavljajte postupak dok se svi mutanti ne uklone ili ne obrazlože komentarima i razlozima.

## References

- [1] [Testiranje mutacijama za agentičku eru](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Koristite testiranje mutacijama da pronađete greške koje vaši testovi ne otkrivaju (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Bezbednosni pregled Arkis DeFi Prime Brokerage (Dodatak C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Dokumentacija za Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
