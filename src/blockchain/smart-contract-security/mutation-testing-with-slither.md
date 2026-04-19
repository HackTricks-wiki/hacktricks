# Mutation Testing for Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "testira tvoje testove" tako što sistematski uvodi male promene (mutants) u kod ugovora i ponovo pokreće test suite. Ako test padne, mutant je ubijen. Ako testovi i dalje prolaze, mutant preživljava, otkrivajući slepu tačku koju line/branch coverage ne može da detektuje.

Ključna ideja: Coverage pokazuje da je kod izvršen; mutation testing pokazuje da li je ponašanje zaista provereno.

## Zašto coverage može da zavara

Razmotri ovu jednostavnu proveru praga:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Jedinični testovi koji proveravaju samo vrednost ispod i vrednost iznad praga mogu postići 100% line/branch coverage, a da pritom ne proveravaju granicu jednakosti (==). Refaktor na `deposit >= 2 ether` bi i dalje prošao takve testove, tiho narušavajući logiku protokola.

Mutation testing otkriva ovu prazninu tako što mutira uslov i proverava da testovi padnu.

Za smart contracts, preživeli mutanti često ukazuju na nedostajuće provere oko:
- Authorization i granica uloga
- Računovodstvenih/value-transfer invariants
- Revert uslova i failure pathova
- Graničnih uslova (`==`, nulte vrednosti, prazni nizovi, max/min vrednosti)

## Mutation operators sa najjačim security signalom

Korisne mutation klase za audit contracta:
- **High severity**: zamena iskaza sa `revert()` da bi se otkrili neizvršeni pathovi
- **Medium severity**: komentarisanje linija / uklanjanje logike da bi se otkrili neprovereni side effects
- **Low severity**: suptilne zamene operatora ili konstanti kao `>=` -> `>` ili `+` -> `-`
- Ostale česte izmene: zamena dodele, boolean flipovi, negacija uslova i promene tipova

Praktični cilj: ubiti sve značajne mutante i eksplicitno opravdati preživele koji su nebitni ili semantički ekvivalentni.

## Zašto je syntax-aware mutation bolji od regex-a

Stariji mutation engine-i su se oslanjali na regex ili line-oriented rewrites. To radi, ali ima važne ograničenja:
- Višelinijski iskazi su teški za bezbedno mutiranje
- Struktura jezika nije shvaćena, pa komentari/tokeni mogu biti loše targetirani
- Generisanje svake moguće varijante na slaboj liniji troši ogromnu količinu runtime-a

AST- ili Tree-sitter-based tooling poboljšava ovo targetiranjem strukturisanih nodova umesto sirovih linija:
- **slither-mutate** koristi Slither-ov Solidity AST
- **mewt** koristi Tree-sitter kao language-agnostic core
- **MuTON** se zasniva na `mewt` i dodaje prvoklasnu podršku za TON jezike kao što su FunC, Tolk i Tact

Ovo čini višelinijske konstrukte i mutation na nivou izraza mnogo pouzdanijim od pristupa zasnovanih samo na regex-u.

## Pokretanje mutation testing-a sa slither-mutate

Zahtjevi: Slither v0.10.2+.

- Prikaži opcije i mutatore:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry primer (snimi rezultate i čuvaj kompletan log):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Ako ne koristiš Foundry, zameni `--test-cmd` sa komandom kojom pokrećeš testove (npr. `npx hardhat test`, `npm test`).

Artifacts se podrazumevano čuvaju u `./mutation_campaign`. Neuhvaćeni (preživeli) mutanti se kopiraju tamo radi pregleda.

### Razumevanje izlaza

Redovi izveštaja izgledaju ovako:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- The tag in brackets is the mutator alias (e.g., `CR` = Comment Replacement).
- `UNCAUGHT` znači da su testovi prošli pod mutiranim ponašanjem → nedostaje assertion.

## Smanjenje runtime-a: prioritet daj uticajnim mutantima

Mutation kampanje mogu trajati satima ili danima. Saveti za smanjenje troška:
- Scope: Prvo kreni samo sa kritičnim contracts/direktorijumima, pa tek onda širi.
- Prioritizuj mutators: Ako visoko-prioritetni mutant na liniji preživi (na primer `revert()` ili comment-out), preskoči niže-prioritetne varijante za tu liniju.
- Koristi dvofazne kampanje: prvo pokreni fokusirane/brze testove, pa onda ponovo testiraj samo uncaught mutante sa kompletnim suite-om.
- Mapiraj mutation targets na konkretne test komande kada je moguće (na primer auth code -> auth tests).
- Ograniči kampanje na high/medium severity mutante kada je vreme tesno.
- Paralelizuj testove ako tvoj runner to dozvoljava; keširaj dependencies/builds.
- Fail-fast: stani rano kada promena jasno pokaže assertion gap.

Runtime matematika je brutalna: `1000 mutants x 5-minute tests ~= 83 hours`, tako da dizajn kampanje znači isto koliko i sam mutator.

## Trajne kampanje i triage u velikom obimu

Jedna slabost starijih workflow-a je bacanje rezultata samo na `stdout`. Za duge kampanje, ovo otežava pause/resume, filtriranje i review.

`mewt`/`MuTON` ovo poboljšavaju tako što čuvaju mutante i ishode u SQLite-backed campaigns. Prednosti:
- Pauziraj i nastavi duge run-ove bez gubitka progresa
- Filtriraj samo uncaught mutante u konkretnom fajlu ili mutation class
- Export/translate rezultate u SARIF za review tooling
- Daj AI-assisted triage-u manji, filtrirani skup rezultata umesto sirovih terminal logova

Trajni rezultati su posebno korisni kada mutation testing postane deo audit pipeline-a umesto jednokratnog manual review-a.

## Triage workflow za surviving mutantе

1) Pregledaj mutiranu liniju i ponašanje.
- Reprodukuj lokalno primenom mutirane linije i pokretanjem fokusiranog testa.

2) Ojačaj testove da assertuju state, ne samo return vrednosti.
- Dodaj equality-boundary provere (npr. testiraj threshold `==`).
- Assertuj post-conditions: balances, total supply, authorization effects i emitted events.

3) Zameni previše permisive mocks realističnim ponašanjem.
- Pobrinite se da mocks enforce-uju transfers, failure paths i event emissions koji se dešavaju on-chain.

4) Dodaj invariants za fuzz tests.
- Npr. conservation of value, non-negative balances, authorization invariants, monotonic supply tamo gde je primenljivo.

5) Odvoji true positives od semantic no-ops.
- Primer: `x > 0` -> `x != 0` je besmisleno kada je `x` unsigned.

6) Ponovo pokreni kampanju dok survivors ne budu killed ili eksplicitno opravdani.

## Case study: otkrivanje nedostajućih state assertions (Arkis protocol)

Mutation kampanja tokom audit-a Arkis DeFi protokola otkrila je survivors kao:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Komentarisanje dodele nije prekinulo testove, što dokazuje da nedostaju post-state assertions. Root cause: code je verovao korisnički kontrolisanom `_cmd.value` umesto da validira stvarne token transfere. Napadač je mogao da desinhronizuje očekivane i stvarne transfere i da povuče sredstva. Rezultat: high severity rizik po solventnost protokola.

Guidance: Tretirajte survivore koji utiču na value transfers, accounting ili access control kao high-risk dok ne budu ubijeni.

## Do not blindly generate tests to kill every mutant

Mutation-driven test generation can backfire if the current implementation is wrong. Example: mutating `priority >= 2` to `priority > 2` changes behavior, but the right fix is not always "write a test for `priority == 2`". That behavior may itself be the bug.

Safer workflow:
- Use surviving mutants to identify ambiguous requirements
- Validate expected behavior from specs, protocol docs, or reviewers
- Only then encode the behavior as a test/invariant

Otherwise, you risk hard-coding implementation accidents into the test suite and gaining false confidence.

## Practical checklist

- Run a targeted campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Prefer syntax-aware mutators (AST/Tree-sitter) over regex-only mutation when available.
- Triage survivors and write tests/invariants that would fail under the mutated behavior.
- Assert balances, supply, authorizations, and events.
- Add boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Replace unrealistic mocks; simulate failure modes.
- Persist results when the tooling supports it, and filter uncaught mutants before triage.
- Use two-phase or per-target campaigns to keep runtime manageable.
- Iterate until all mutants are killed or justified with comments and rationale.

## References

- [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)
- [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [mewt](https://github.com/trailofbits/mewt)
- [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
