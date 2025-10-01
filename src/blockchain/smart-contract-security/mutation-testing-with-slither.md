# Mutation Testing za Solidity sa Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" tako što sistematski uvodi male promene (mutante) u vaš Solidity kod i ponovo pokreće vaš skup testova. Ako test padne, mutant se smatra ubijenim. Ako testovi i dalje prolaze, mutant preživi, otkrivajući slepu tačku u vašem skupu testova koju linijsko/gransko pokriće ne može detektovati.

Ključna ideja: pokriće pokazuje da je kod izvršen; mutation testing pokazuje da li je ponašanje zaista provereno.

## Zašto pokriće može zavarati

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
Jedinični testovi koji proveravaju samo vrednost ispod i vrednost iznad praga mogu dostići 100% line/branch coverage, a da ne asertuju granicu jednakosti (==). Refaktor u `deposit >= 2 ether` bi i dalje prošao takve testove, tiho kvareći logiku protokola.

Mutation testing otkriva ovaj prazninu mutiranjem uslova i proverom da li vaši testovi zakažu.

## Common Solidity mutation operators

Slither’s mutation engine primenjuje mnogo malih izmena koje menjaju semantiku, kao što su:
- Zamena operatora: `+` ↔ `-`, `*` ↔ `/`, itd.
- Zamena dodele: `+=` → `=`, `-=` → `=`
- Zamena konstanti: non-zero → `0`, `true` ↔ `false`
- Negacija/izmena uslova unutar `if`/petlji
- Zakomentarisati cele linije (CR: Comment Replacement)
- Zameniti liniju sa `revert()`
- Zamene tipova podataka: npr. `int128` → `int64`

Cilj: Ugasiti 100% generisanih mutanata, ili opravdati preživele jasnim obrazloženjem.

## Running mutation testing with slither-mutate

Zahtevi: Slither v0.10.2+.

- List options and mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry example (uhvati rezultate i sačuvaj kompletan log):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Ako ne koristite Foundry, zamenite `--test-cmd` načinom na koji pokrećete testove (npr. `npx hardhat test`, `npm test`).

Artefakti i izveštaji se podrazumevano čuvaju u `./mutation_campaign`. Neotkriveni (preživeli) mutanti se kopiraju tamo radi inspekcije.

### Understanding the output

Redovi izveštaja izgledaju ovako:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Oznaka u uglastim zagradama je alias mutatora (npr. `CR` = Comment Replacement).
- `UNCAUGHT` znači da su testovi prošli pod mutiranim ponašanjem → nedostaje asercija.

## Reducing runtime: prioritize impactful mutants

Mutation kampanje mogu trajati satima ili danima. Saveti za smanjenje troškova:
- Scope: Počnite sa kritičnim contracts/directories samo, pa proširite.
- Prioritize mutators: Ako mutant visokog prioriteta na liniji preživi (npr. cela linija zakomentarisana), možete preskočiti varijante nižeg prioriteta za tu liniju.
- Paralelizujte testove ako vaš runner to dozvoljava; cache-ujte dependencies/builds.
- Fail-fast: zaustavite rano kada promena jasno demonstrira prazninu u asercijama.

## Triage workflow for surviving mutants

1) Inspect the mutated line and behavior.
- Reproducirajte lokalno primenom mutirane linije i pokretanjem fokusiranog testa.

2) Strengthen tests to assert state, not only return values.
- Dodajte provere granica jednakosti (npr. test threshold `==`).
- Asertujte post-uslove: balances, total supply, efekte autorizacije i emitovane događaje.

3) Replace overly permissive mocks with realistic behavior.
- Osigurajte da mocks forsiraju transfers, failure paths i event emissions koji se dešavaju on-chain.

4) Add invariants for fuzz tests.
- Npr. očuvanje vrednosti, nenegativni balances, invarianti autorizacije, monotonic supply gde je primenjivo.

5) Re-run slither-mutate until survivors are killed or explicitly justified.

## Case study: revealing missing state assertions (Arkis protocol)

A mutation campaign during an audit of the Arkis DeFi protocol surfaced survivors like:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Komentarisanje dodele nije prekinulo testove, što ukazuje na nedostatak asercija stanja nakon izvršenja. Osnovni uzrok: kod je verovao korisnički kontrolisanom `_cmd.value` umesto da proveri stvarne transfere tokena. Napadač bi mogao desinhronizovati očekivane i stvarne transfere da isprazni sredstva. Rezultat: visok stepen rizika po solventnost protokola.

Smernica: tretirajte preostale mutante koji utiču na transfere vrednosti, računovodstvo ili kontrolu pristupa kao visokorizične dok se ne uklone.

## Praktična kontrolna lista

- Pokrenite ciljanu kampanju:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Razvrstajte preostale mutante i napišite testove/invarijante koji bi pali pod izmenjenim ponašanjem.
- Potvrdite bilanse, ukupnu ponudu, autorizacije i događaje.
- Dodajte granične testove (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Zamenite nerealne mock-ove; simulirajte režime otkaza.
- Iterirajte dok svi mutanti nisu uklonjeni ili opravdani komentarima i obrazloženjem.

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
