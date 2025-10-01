# Mutation Testing za Solidity sa Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" tako što sistematski uvodi male promene (mutants) u vaš Solidity код и поново покреће ваш test suite. Ако тест не успе, mutant је killed. Ако тестови и даље пролазе, mutant преживи, откривајући слепу тачку у вашем test suite коју line/branch coverage не може да детектује.

Key idea: Coverage показује да је код извршен; mutation testing показује да ли је понашање заиста потврђено.

## Zašto coverage може зaварaти

Размотрите ову једноставну проверу прага:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Jedinični testovi koji proveravaju samo vrednost ispod i vrednost iznad praga mogu dostići 100% pokrivenost linija/grana, a ipak ne potvrditi granicu jednakosti (==). Refaktorisanje u `deposit >= 2 ether` i dalje bi prošlo takve testove, neprimetno narušivši logiku protokola.

Mutaciono testiranje otkriva ovaj nedostatak mutiranjem uslova i proverom da li testovi zakažu.

## Uobičajeni mutacioni operatori za Solidity

Slither-ov mehanizam za mutacije primenjuje mnoge male izmene koje menjaju semantiku, kao što su:
- Zamena operatora: `+` ↔ `-`, `*` ↔ `/`, etc.
- Zamena dodele: `+=` → `=`, `-=` → `=`
- Zamena konstanti: nenulta → `0`, `true` ↔ `false`
- Negacija/zamena uslova unutar `if`/petlji
- Zakomentarisati cele linije (CR: Comment Replacement)
- Zameniti liniju sa `revert()`
- Zamena tipova podataka: npr. `int128` → `int64`

Cilj: eliminisati 100% generisanih mutanata, ili opravdati preživele jasnim obrazloženjem.

## Pokretanje mutacionog testiranja sa slither-mutate

Zahtevi: Slither v0.10.2+.

- Prikaži opcije i mutatore:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry primer (zabeleži rezultate i vodi kompletan log):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Ako ne koristite Foundry, zamenite `--test-cmd` načinom na koji pokrećete testove (npr. `npx hardhat test`, `npm test`).

Artefakti i izveštaji se podrazumevano čuvaju u `./mutation_campaign`. Neotkriveni (preživeli) mutanti se tamo kopiraju radi inspekcije.

### Razumevanje izlaza

Linije izveštaja izgledaju ovako:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Oznaka u uglastim zagradama je alias mutatora (npr., `CR` = Comment Replacement).
- `UNCAUGHT` znači da su testovi prošli pod mutiranim ponašanjem → nedostaje asercija.

## Smanjivanje vremena izvršavanja: prioritizujte mutante sa najvećim uticajem

Kampanje mutacije mogu trajati satima ili danima. Saveti za smanjenje troškova:
- Opseg: Počnite samo sa kritičnim ugovorima/direktorijumima, pa zatim proširite.
- Prioritetizujte mutatore: Ako mutant visokog prioriteta na liniji preživi (npr., cela linija je zakomentarisana), možete preskočiti varijante nižeg prioriteta za tu liniju.
- Paralelizujte testove ako vaš runner to omogućava; keširajte zavisnosti i build-ove.
- Fail-fast: zaustavite se rano kada promena jasno demonstrira prazninu u asercijama.

## Radni tok trijaže za mutante koji prežive

1) Pregledajte mutiranu liniju i ponašanje.
- Reproducirajte lokalno primenom mutirane linije i pokretanjem fokusiranog testa.

2) Ojačajte testove tako da proveravaju stanje, a ne samo povratne vrednosti.
- Dodajte provere granica jednakosti (npr., test threshold `==`).
- Proverite post-uslove: bilansi, total supply, efekti autorizacije i emitovani događaji.

3) Zamenite previše permisivne mock-ove realističnim ponašanjem.
- Osigurajte da mock-ovi nameću transfere, puteve greške i emitovanje događaja koji se dešavaju on-chain.

4) Dodajte invarijante za fuzz testove.
- Npr., očuvanje vrednosti, nenegativni saldi, invarijante autorizacije, monotonost supply-a gde je primenljivo.

5) Ponovo pokrenite slither-mutate dok preživeli ne budu uklonjeni ili dok se eksplicitno ne opravdaju.

## Studija slučaja: otkrivanje nedostajućih asercija stanja (Arkis protocol)

Kampanja mutacije tokom audita Arkis DeFi protocola je identifikovala preživele, kao što su:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Komentarisanje dodele nije pokvarilo testove, što ukazuje na nedostatak post-state assertions. Osnovni uzrok: kod je verovao korisnički kontrolisanom `_cmd.value` umesto da verifikuje stvarne transfere tokena. Napadač bi mogao desinhronizovati očekivane i stvarne transfere kako bi isisao sredstva. Posledica: visok rizik po solventnost protokola.

Smernice: Smatrajte survivors koji utiču na value transfers, accounting, ili access control visokorizičnim dok nisu killed.

## Praktična kontrolna lista

- Pokrenite ciljanu kampanju:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Razvrstajte survivors i napišite testove/invarijante koje bi pale pri mutiranom ponašanju.
- Proverite balances, supply, authorizations i events.
- Dodajte boundary testove (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Zamenite nerealne mocks; simulirajte failure modes.
- Iterirajte dok svi mutants ne budu killed ili opravdani komentarima i objašnjenjem.

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
