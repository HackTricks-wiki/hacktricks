# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" poprzez systematyczne wprowadzanie małych zmian (mutantów) w Twoim kodzie Solidity i ponowne uruchamianie zestawu testów. Jeśli test zawiedzie, mutant zostaje zabity. Jeśli testy nadal przejdą, mutant przetrwa, ujawniając ślepą plamę w Twoim zestawie testów, której pokrycie linii/gałęzi nie wykryje.

Key idea: Pokrycie pokazuje, że kod został wykonany; testowanie mutacyjne pokazuje, czy zachowanie zostało faktycznie zweryfikowane.

## Dlaczego pokrycie może wprowadzać w błąd

Rozważ to proste sprawdzenie progu:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Testy jednostkowe, które sprawdzają tylko wartość poniżej i wartość powyżej progu, mogą osiągnąć 100% pokrycia linii/gałęzi, jednocześnie nie asercjonując granicy równości (==). Refaktoryzacja do `deposit >= 2 ether` nadal przejdzie takie testy, cicho łamiąc logikę protokołu.

Mutation testing ujawnia tę lukę przez mutowanie warunku i weryfikowanie, że testy nie przechodzą.

## Typowe operatory mutacji w Solidity

Silnik mutacji Slither stosuje wiele drobnych edycji zmieniających semantykę, takich jak:
- Zamiana operatorów: `+` ↔ `-`, `*` ↔ `/`, itd.
- Zamiana przypisania: `+=` → `=`, `-=` → `=`
- Zamiana stałych: wartość niezerowa → `0`, `true` ↔ `false`
- Negacja/zamiana warunku wewnątrz `if`/pętli
- Zakomentowanie całych linii (CR: Comment Replacement)
- Zastąpienie linii wywołaniem `revert()`
- Zamiana typów danych: np. `int128` → `int64`

Cel: Wyeliminować 100% wygenerowanych mutantów lub uzasadnić przeżycie poszczególnych mutantów jasnym wyjaśnieniem.

## Uruchamianie mutation testing za pomocą slither-mutate

Wymagania: Slither v0.10.2+.

- Wyświetl opcje i mutatory:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Przykład Foundry (zapisz wyniki i zachowaj pełny log):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Jeśli nie używasz Foundry, zastąp `--test-cmd` sposobem uruchamiania testów (np. `npx hardhat test`, `npm test`).

Artyfakty i raporty są domyślnie zapisywane w `./mutation_campaign`. Mutanty, które nie zostały wykryte (przetrwałe), są tam kopiowane do inspekcji.

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
Zakomentowanie przypisania nie zepsuło testów, co dowodzi braku asercji stanu końcowego. Przyczyna: kod ufał kontrolowanej przez użytkownika wartości `_cmd.value` zamiast weryfikować rzeczywiste transfery tokenów. Atakujący mógłby wprowadzić niespójność między oczekiwanymi a faktycznymi transferami i wyprowadzić środki. Skutek: ryzyko wysokiej wagi dla wypłacalności protokołu.

Wskazówka: Traktuj przetrwałe mutanty, które wpływają na transfery wartości, księgowość lub kontrolę dostępu, jako wysokie ryzyko, dopóki nie zostaną wyeliminowane.

## Practical checklist

- Przeprowadź ukierunkowaną kampanię:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Przeprowadź triage przetrwałych mutantów i napisz testy/inwarianty, które zawiodłyby przy zmienionym zachowaniu.
- Asercje sald, podaży, autoryzacji i zdarzeń.
- Dodaj testy graniczne (`==`, przepełnienia/underflow, adres zero, ilość zero, puste tablice).
- Zastąp nierealistyczne mocki; symuluj tryby awarii.
- Iteruj, aż wszystkie mutanty zostaną wyeliminowane lub udokumentowane komentarzami i uzasadnieniem.

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
