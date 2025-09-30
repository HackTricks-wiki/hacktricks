# Mutation Testing dla Solidity z Slither (slither-mutate)

{{#include ../../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" poprzez systematyczne wprowadzanie drobnych zmian (mutantów) w twoim kodzie Solidity i ponowne uruchamianie zestawu testów. Jeśli test się nie powiedzie, mutant zostaje zabity. Jeśli testy nadal przechodzą, mutant przeżywa, ujawniając ślepy punkt w twoim zestawie testów, którego pokrycie linii/gałęzi nie wykryje.

Kluczowa myśl: Pokrycie pokazuje, że kod został wykonany; mutation testing pokazuje, czy zachowanie jest faktycznie sprawdzone.

## Dlaczego pokrycie może wprowadzać w błąd

Rozważ ten prosty warunek progowy:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Testy jednostkowe, które sprawdzają tylko wartość poniżej oraz wartość powyżej progu, mogą osiągnąć 100% pokrycia linii/gałęzi, jednocześnie nie asercjonując granicy równości (==). Refaktoring do `deposit >= 2 ether` nadal przejdzie takie testy, cicho łamiąc logikę protokołu.

Mutation testing ujawnia tę lukę, mutując warunek i weryfikując, że testy nie przejdą.

## Najczęstsze operatory mutacji w Solidity

Slither’s mutation engine stosuje wiele drobnych modyfikacji zmieniających semantykę, takich jak:
- Zamiana operatorów: `+` ↔ `-`, `*` ↔ `/`, itp.
- Zamiana przypisania: `+=` → `=`, `-=` → `=`
- Zamiana stałych: niezerowe → `0`, `true` ↔ `false`
- Negacja/zamiana warunku w `if`/pętlach
- Komentowanie całych linii (CR: Comment Replacement)
- Zamiana linii na `revert()`
- Zamiany typów danych: np. `int128` → `int64`

Cel: Zabić 100% wygenerowanych mutantów lub uzasadnić ocalałe przypadki jasnym wyjaśnieniem.

## Uruchamianie Mutation testing za pomocą slither-mutate

Wymagania: Slither v0.10.2+.

- Wypisz opcje i mutatory:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Przykład Foundry (przechwyć wyniki i zachowaj pełny log):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Jeśli nie używasz Foundry, zamień `--test-cmd` na komendę uruchamiającą testy (np. `npx hardhat test`, `npm test`).

Artefakty i raporty są domyślnie przechowywane w `./mutation_campaign`. Niewykryte (przetrwałe) mutanty są tam kopiowane do wglądu.

### Zrozumienie wyników

Wiersze raportu wyglądają tak:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- The tag in brackets is the mutator alias (e.g., `CR` = Comment Replacement).
- `UNCAUGHT` means tests passed under the mutated behavior → missing assertion.

## Reducing runtime: prioritize impactful mutants

Mutation campaigns can take hours or days. Tips to reduce cost:
- Scope: Start with critical contracts/directories only, then expand.
- Prioritize mutators: If a high-priority mutant on a line survives (e.g., entire line commented), you can skip lower-priority variants for that line.
- Parallelize tests if your runner allows it; cache dependencies/builds.
- Fail-fast: stop early when a change clearly demonstrates an assertion gap.

## Triage workflow for surviving mutants

1) Inspect the mutated line and behavior.
- Reproduce locally by applying the mutated line and running a focused test.

2) Strengthen tests to assert state, not only return values.
- Add equality-boundary checks (e.g., test threshold `==`).
- Assert post-conditions: balances, total supply, authorization effects, and emitted events.

3) Replace overly permissive mocks with realistic behavior.
- Ensure mocks enforce transfers, failure paths, and event emissions that occur on-chain.

4) Add invariants for fuzz tests.
- E.g., conservation of value, non-negative balances, authorization invariants, monotonic supply where applicable.

5) Re-run slither-mutate until survivors are killed or explicitly justified.

## Case study: revealing missing state assertions (Arkis protocol)

A mutation campaign during an audit of the Arkis DeFi protocol surfaced survivors like:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Zakomentowanie przypisania nie złamało testów, co dowodzi brakujących asercji stanu po wykonaniu. Przyczyna: kod zaufał kontrolowanej przez użytkownika zmiennej `_cmd.value` zamiast walidować rzeczywiste transfery tokenów. Atakujący mógłby rozdesynchronizować oczekiwane i rzeczywiste transfery, aby opróżnić środki. Skutek: ryzyko wysokiej wagi dla wypłacalności protokołu.

Wytyczne: Traktuj mutanty, które przetrwały i wpływają na transfery wartości, księgowość lub kontrolę dostępu, jako wysokiego ryzyka, dopóki nie zostaną wyeliminowane.

## Praktyczna lista kontrolna

- Uruchom ukierunkowaną kampanię:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Przejrzyj mutanty, które przetrwały, i napisz testy/inwarianty, które zawiodłyby przy zmienionym zachowaniu.
- Zweryfikuj salda, podaż, uprawnienia i zdarzenia.
- Dodaj testy brzegowe (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Zastąp nierealistyczne mocki; zasymuluj tryby awarii.
- Powtarzaj, aż wszystkie mutanty zostaną wyeliminowane lub uzasadnione komentarzami i wyjaśnieniem.

## Źródła

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../../banners/hacktricks-training.md}}
