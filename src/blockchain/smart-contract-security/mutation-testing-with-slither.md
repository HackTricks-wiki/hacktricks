# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../../banners/hacktricks-training.md}}

Mutation testing "testira vaše testove" tako što sistematski uvodi male izmene (mutante) u vaš Solidity kod i ponovo pokreće vaš skup testova. Ako test zakaže, mutant je eliminisan. Ako testovi i dalje prolaze, mutant preživi, otkrivajući slepu tačku u vašem skupu testova koju linijska/grananja pokrivenost ne može detektovati.

Ključna ideja: Pokrivenost pokazuje da je kod izvršen; mutation testing pokazuje da li je ponašanje zaista provereno.

## Zašto pokrivenost može zavarati

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
Unit testovi koji proveravaju samo vrednost ispod i iznad praga mogu dostići 100% pokriće linija/grana dok ne uspevaju da asertuju granicu jednakosti (==). Refaktorisanje u `deposit >= 2 ether` bi i dalje prošlo takve testove, tiho prekidajući logiku protokola.

Mutaciono testiranje otkriva ovu rupu mutiranjem uslova i verifikovanjem da vaši testovi zakažu.

## Uobičajeni mutacioni operatori za Solidity

Slither’s mutation engine primenjuje mnoge male izmene koje menjaju semantiku, kao što su:
- Operator replacement: `+` ↔ `-`, `*` ↔ `/`, etc.
- Assignment replacement: `+=` → `=`, `-=` → `=`
- Constant replacement: non-zero → `0`, `true` ↔ `false`
- Condition negation/replacement inside `if`/loops
- Comment out whole lines (CR: Comment Replacement)
- Replace a line with `revert()`
- Data type swaps: e.g., `int128` → `int64`

Cilj: eliminisati 100% generisanih mutanata, ili opravdati preživele jasnim obrazloženjem.

## Pokretanje mutacionog testiranja sa slither-mutate

Zahtevi: Slither v0.10.2+.

- List options and mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry primer (zabeleži rezultate i sačuvaj kompletan log):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Ako ne koristite Foundry, zamenite `--test-cmd` sa načinom na koji pokrećete testove (npr. `npx hardhat test`, `npm test`).

Artefakti i izveštaji se podrazumevano čuvaju u `./mutation_campaign`. Neuhvaćeni (preživeli) mutanti se kopiraju tamo radi inspekcije.

### Razumevanje izlaza

Linije izveštaja izgledaju ovako:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Oznaka u uglastim zagradama je alias mutatora (npr., `CR` = Comment Replacement).
- `UNCAUGHT` znači da su testovi prošli pod mutiranim ponašanjem → nedostajuća asercija.

## Smanjenje vremena izvršavanja: prioritizujte uticajne mutante

Kampanje mutacije mogu trajati satima ili danima. Saveti za smanjenje troškova:
- Obim: Počnite samo sa kritičnim kontraktima/direktorijumima, zatim proširite.
- Prioritetizujte mutatore: Ako mutant visokog prioriteta na liniji preživi (npr., cela linija je komentarisana), možete preskočiti varijante nižeg prioriteta za tu liniju.
- Paralelizujte testove ako vaš runner to dozvoljava; keširajte zavisnosti/buildove.
- Fail-fast: zaustavite rano kada izmena jasno pokaže nedostatak asercije.

## Radni tok trijaže za preživele mutante

1) Pregledajte mutiranu liniju i ponašanje.
- Reproducirajte lokalno tako što ćete primeniti mutiranu liniju i pokrenuti fokusirani test.

2) Ojačajte testove tako da asertuju stanje, ne samo povratne vrednosti.
- Dodajte provere granica jednakosti (npr., testirajte threshold `==`).
- Asertujte postuslove: stanja salda, ukupna ponuda, efekti autorizacije i emitovani događaji.

3) Zamenite previše permisivne mock-ove realističnim ponašanjem.
- Osigurajte da mock-ovi forsiraju transfere, puteve grešaka i emisione događaje koji se dešavaju on-chain.

4) Dodajte invarijante za fuzz testove.
- Npr., očuvanje vrednosti, nenegativni balansi, invarijante autorizacije, monotoni rast ponude gde je primenljivo.

5) Ponovo pokrenite slither-mutate dok preživele varijante ne budu uklonjene ili eksplicitno opravdane.

## Case study: revealing missing state assertions (Arkis protocol)

Kampanja mutacije tokom audita Arkis DeFi protocol-a iznela je preživele slučajeve poput:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Komentarisanje dodele nije pokvarilo testove, što dokazuje nedostatak post-state asercija. Korenski uzrok: kod je verovao user-controlled `_cmd.value` umesto da validira stvarne token transfere. Napadač bi mogao desinhronizovati očekivane i stvarne transfere da isisava sredstva. Rezultat: rizik visoke težine po solventnost protokola.

Smernice: Smatrati preživele mutante koji utiču na prenos vrednosti, računovodstvo ili kontrolu pristupa visokorizičnim dok ne budu ubijeni.

## Praktična lista provere

- Pokrenite ciljanu kampanju:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Razvrstajte preživele mutante i napišite testove/invarijante koji bi pali pod mutiranim ponašanjem.
- Potvrdite balanse, ukupnu ponudu, autorizacije i događaje.
- Dodajte granične testove (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Zamenite nerealne mocks; simulirajte scenarije grešaka.
- Iterirajte dok svi mutanti ne budu ubijeni ili opravdani komentarima i obrazloženjem.

## Reference

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../../banners/hacktricks-training.md}}
