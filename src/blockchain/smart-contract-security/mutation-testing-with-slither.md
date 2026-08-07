# Mutation Testing dla Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing „testuje twoje testy” poprzez systematyczne wprowadzanie małych zmian (mutantów) do kodu kontraktu i ponowne uruchamianie zestawu testów. Jeśli test zakończy się niepowodzeniem, mutant zostaje zabity. Jeśli testy nadal przechodzą, mutant przetrwa, ujawniając martwy punkt, którego nie można wykryć za pomocą pokrycia linii/gałęzi.

Kluczowa idea: pokrycie pokazuje, że kod został wykonany; mutation testing pokazuje, czy zachowanie jest faktycznie asertywane.<sup>[[2]](#references)</sup>

## Dlaczego pokrycie może wprowadzać w błąd

Rozważmy to proste sprawdzenie progu:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Testy jednostkowe, które sprawdzają jedynie wartość poniżej i wartość powyżej progu, mogą osiągnąć 100% pokrycia linii/gałęzi, nie sprawdzając granicy równości (`==`). Refaktoryzacja do `deposit >= 2 ether` nadal przejdzie takie testy, po cichu łamiąc logikę protokołu.<sup>[[2]](#references)</sup>

Mutation testing ujawnia tę lukę, mutując warunek i sprawdzając, czy testy zakończą się niepowodzeniem.

W przypadku smart contracts przetrwałe mutanty często wskazują na brakujące kontrole dotyczące:
- Autoryzacji i granic ról
- Niezmienników księgowania/przekazywania wartości
- Warunków revert i ścieżek błędów
- Warunków brzegowych (`==`, wartości zerowe, puste tablice, wartości maksymalne/minimalne)

## Mutation operators o najwyższym sygnale bezpieczeństwa

Przydatne klasy mutacji podczas audytu kontraktów:<sup>[[1]](#references)[[2]](#references)</sup>
- **Wysoka ważność**: zastępowanie instrukcji przez `revert()` w celu ujawnienia niewykonywanych ścieżek
- **Średnia ważność**: komentowanie linii / usuwanie logiki w celu wykrycia niezweryfikowanych efektów ubocznych
- **Niska ważność**: subtelne zamiany operatorów lub stałych, takie jak `>=` -> `>` albo `+` -> `-`
- Inne typowe modyfikacje: zastępowanie przypisań, odwracanie wartości logicznych, negowanie warunków i zmiany typów

Praktyczny cel: zabić wszystkie istotne mutanty oraz wyraźnie uzasadnić mutanty, które przetrwały, a są nieistotne lub semantycznie równoważne.

## Dlaczego mutation uwzględniające składnię jest lepsze niż regex

Starsze silniki mutation testing opierały się na regex lub przekształceniach zorientowanych na linie. Działa to, ale ma istotne ograniczenia:<sup>[[1]](#references)</sup>
- Instrukcje wieloliniowe trudno bezpiecznie mutować
- Struktura języka nie jest rozumiana, więc komentarze/tokeny mogą być błędnie wybierane
- Generowanie każdego możliwego wariantu dla słabej linii marnuje duże ilości czasu działania

Narzędzia oparte na AST lub Tree-sitter poprawiają tę sytuację, wybierając ustrukturyzowane węzły zamiast surowych linii:<sup>[[1]](#references)</sup>
- **slither-mutate** używa AST języka Solidity w Slither<sup>[[4]](#references)</sup>
- **mewt** używa Tree-sitter jako niezależnego od języka rdzenia<sup>[[6]](#references)</sup>
- **MuTON** bazuje na `mewt` i dodaje natywne wsparcie dla języków TON, takich jak FunC, Tolk i Tact<sup>[[7]](#references)</sup>

Dzięki temu konstrukcje wieloliniowe i mutacje na poziomie wyrażeń są znacznie bardziej niezawodne niż podejścia oparte wyłącznie na regex.

## Uruchamianie mutation testing za pomocą slither-mutate

Wymagania: Slither v0.10.2+.

- Wyświetlanie opcji i mutatorów:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Przykład Foundry (przechwyć wyniki i zachowaj pełny log):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Jeśli nie używasz Foundry, zastąp `--test-cmd` poleceniem używanym do uruchamiania testów, np. `npx hardhat test` lub `npm test`.

Artefakty są domyślnie przechowywane w `./mutation_campaign`. Nieprzechwycone (przetrwałe) mutanty są tam kopiowane w celu ich analizy.<sup>[[5]](#references)</sup>

### Zrozumienie danych wyjściowych

Wiersze raportu wyglądają tak:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Tag w nawiasach kwadratowych to alias mutatora (np. `CR` = Comment Replacement).
- `UNCAUGHT` oznacza, że testy przeszły przy zmienionym zachowaniu → brak asercji.

## Skracanie czasu wykonania: priorytetyzacja istotnych mutantów

Kampanie mutacyjne mogą trwać wiele godzin lub dni. Wskazówki dotyczące ograniczania kosztów:<sup>[[1]](#references)[[2]](#references)</sup>
- Zakres: rozpocznij wyłącznie od krytycznych kontraktów/katalogów, a następnie rozszerz zakres.
- Priorytetyzuj mutatory: jeśli mutant o wysokim priorytecie w danej linii przetrwa (np. `revert()` lub comment-out), pomiń warianty o niższym priorytecie dla tej linii.
- Używaj kampanii dwuetapowych: najpierw uruchom ukierunkowane/szybkie testy, a następnie ponownie przetestuj wyłącznie mutanty `UNCAUGHT` z pełnym zestawem testów.
- W miarę możliwości mapuj cele mutacji na konkretne polecenia testowe (np. kod uwierzytelniania -> testy uwierzytelniania).
- Gdy czas jest ograniczony, ogranicz kampanie do mutantów o wysokim/średnim poziomie istotności.
- Uruchamiaj testy równolegle, jeśli runner na to pozwala; cache'uj zależności/buildy.
- Fail-fast: zatrzymaj się wcześnie, gdy zmiana wyraźnie ujawnia lukę w asercjach.

Obliczenia czasu są bezlitosne: `1000 mutants x 5-minute tests ~= 83 hours`, dlatego projekt kampanii jest równie ważny jak sam mutator.<sup>[[1]](#references)</sup>

## Kampanie trwałe i triage na dużą skalę

Jedną ze słabości starszych workflowów jest zapisywanie wyników wyłącznie do `stdout`. W przypadku długich kampanii utrudnia to wstrzymywanie/wznawianie, filtrowanie i przeglądanie wyników.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` rozwiązują ten problem, przechowując mutanty i wyniki w kampaniach opartych na SQLite. Korzyści:<sup>[[1]](#references)</sup>
- Wstrzymywanie i wznawianie długich uruchomień bez utraty postępu
- Filtrowanie wyłącznie mutantów `UNCAUGHT` w określonym pliku lub klasie mutacji
- Eksportowanie/tłumaczenie wyników do SARIF na potrzeby narzędzi do przeglądu
- Przekazywanie AI-assisted triage mniejszych, przefiltrowanych zestawów wyników zamiast surowych logów terminala

Trwałe wyniki są szczególnie przydatne, gdy mutation testing staje się częścią pipeline'u audytowego, a nie jednorazowym ręcznym przeglądem.

## Workflow triage dla przetrwałych mutantów

1) Sprawdź zmodyfikowaną linię i zachowanie.
- Odtwórz problem lokalnie, stosując zmodyfikowaną linię i uruchamiając ukierunkowany test.

2) Wzmocnij testy tak, aby sprawdzały stan, a nie tylko wartości zwracane.
- Dodaj sprawdzanie granic równości (np. przetestuj próg `==`).
- Sprawdzaj post-conditions: salda, całkowitą podaż, skutki autoryzacji i emitowane zdarzenia.

3) Zastąp nadmiernie liberalne mocki realistycznym zachowaniem.
- Upewnij się, że mocki wymuszają transfery, ścieżki błędów i emisję zdarzeń występujące on-chain.

4) Dodaj invariants do testów fuzz.
- Np. zachowanie wartości, nieujemne salda, invariants autoryzacji oraz monotoniczna podaż, jeśli ma zastosowanie.

5) Oddziel true positives od semantic no-ops.
- Przykład: `x > 0` -> `x != 0` nie ma znaczenia, gdy `x` jest unsigned.

6) Ponownie uruchamiaj kampanię, dopóki przetrwałe mutanty nie zostaną zabite lub ich istnienie nie zostanie wyraźnie uzasadnione.

## Case study: ujawnienie brakujących asercji stanu (protokół Arkis)

Kampania mutacyjna przeprowadzona podczas audytu protokołu DeFi Arkis ujawniła przetrwałe mutanty, takie jak:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Zakomentowanie przypisania nie spowodowało niepowodzenia testów, co dowiodło braku asercji dotyczących stanu końcowego. Przyczyna źródłowa: kod ufał kontrolowanej przez użytkownika wartości `_cmd.value` zamiast weryfikować faktyczne transfery tokenów. Atakujący mógł rozsynchronizować oczekiwane i rzeczywiste transfery, aby opróżnić środki. Rezultat: wysokie ryzyko dla wypłacalności protokołu.<sup>[[2]](#references)[[3]](#references)</sup>

Wskazówka: Traktuj przetrwałe mutacje wpływające na transfery wartości, księgowanie lub kontrolę dostępu jako wysokiego ryzyka do czasu ich zabicia.

## Nie generuj bezkrytycznie testów do zabicia każdej mutacji

Generowanie testów oparte na mutacjach może przynieść odwrotny skutek, jeśli bieżąca implementacja jest błędna. Przykład: zmiana `priority >= 2` na `priority > 2` zmienia zachowanie, ale właściwą poprawką nie zawsze jest „napisanie testu dla `priority == 2`”. To zachowanie samo w sobie może być błędem.<sup>[[1]](#references)</sup>

Bezpieczniejszy workflow:
- Użyj przetrwałych mutacji do identyfikacji niejednoznacznych wymagań
- Zweryfikuj oczekiwane zachowanie na podstawie specyfikacji, dokumentacji protokołu lub opinii reviewerów
- Dopiero potem zakoduj to zachowanie jako test/invariant

W przeciwnym razie ryzykujesz utrwaleniem przypadkowych cech implementacji w zestawie testów i uzyskaniem fałszywego poczucia pewności.

## Praktyczna checklista

- Uruchom ukierunkowaną kampanię:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Jeśli to możliwe, preferuj mutatory świadome składni (AST/Tree-sitter) zamiast mutacji opartej wyłącznie na regexach.
- Przeanalizuj przetrwałe mutacje i napisz testy/invariants, które nie przechodzą przy zmienionym zachowaniu.
- Sprawdzaj salda, podaż, uprawnienia i events.
- Dodaj testy wartości granicznych (`==`, przepełnienia/niedopełnienia, zero-address, zero-amount, puste tablice).
- Zastąp nierealistyczne mocki; symuluj tryby awarii.
- Utrwalaj wyniki, gdy tooling to obsługuje, i odfiltruj niewykryte mutacje przed triage.
- Używaj kampanii dwuetapowych lub kampanii per-target, aby utrzymać akceptowalny czas wykonania.
- Powtarzaj proces, aż wszystkie mutacje zostaną zabite albo uzasadnione komentarzami i opisem powodów.

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
