# Mutation Testing dla Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing „testuje twoje testy” poprzez systematyczne wprowadzanie niewielkich zmian (mutantów) do kodu kontraktu i ponowne uruchamianie zestawu testów. Jeśli test zakończy się niepowodzeniem, mutant zostaje zabity. Jeśli testy nadal przechodzą, mutant przetrwa, ujawniając lukę, której nie można wykryć za pomocą coverage linii/gałęzi.

Kluczowa idea: Coverage pokazuje, że kod został wykonany; mutation testing pokazuje, czy jego zachowanie jest faktycznie sprawdzane.<sup>[[2]](#references)</sup>

## Dlaczego coverage może wprowadzać w błąd

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
Testy jednostkowe, które sprawdzają tylko wartość poniżej i wartość powyżej progu, mogą osiągnąć 100% pokrycia linii/gałęzi, nie sprawdzając granicy równości (`==`). Refaktoryzacja do `deposit >= 2 ether` nadal przejdzie takie testy, po cichu psując logikę protokołu.<sup>[[2]](#references)</sup>

Mutation testing ujawnia tę lukę przez mutowanie warunku i sprawdzanie, czy testy zakończą się niepowodzeniem.

W przypadku smart contracts przetrwałe mutanty często wskazują na brakujące kontrole dotyczące:
- Autoryzacji i granic ról
- Niezmienników księgowania i transferu wartości
- Warunków revert i ścieżek błędów
- Warunków brzegowych (`==`, wartości zerowe, puste tablice, wartości maksymalne/minimalne)

## Operatory mutacji o najwyższym znaczeniu dla bezpieczeństwa

Przydatne klasy mutacji podczas audytu kontraktów:<sup>[[1]](#references)[[2]](#references)</sup>
- **Wysoka istotność**: zastępowanie instrukcji przez `revert()`, aby ujawnić niewykonane ścieżki
- **Średnia istotność**: komentowanie linii / usuwanie logiki w celu ujawnienia niezweryfikowanych efektów ubocznych
- **Niska istotność**: subtelne zamiany operatorów lub stałych, takie jak `>=` -> `>` lub `+` -> `-`
- Inne typowe modyfikacje: zastępowanie przypisań, odwracanie wartości logicznych, negowanie warunków i zmiany typów

Praktyczny cel: zabić wszystkie znaczące mutanty i wyraźnie uzasadnić przetrwanie tych, które są nieistotne lub semantycznie równoważne.

## Dlaczego mutation testing uwzględniający składnię jest lepszy niż regex

Starsze silniki mutacji opierały się na regex lub przepisywaniu zorientowanym na linie. To działa, ale ma istotne ograniczenia:<sup>[[1]](#references)</sup>
- Instrukcje wieloliniowe trudno bezpiecznie mutować
- Struktura języka nie jest rozumiana, więc komentarze/tokeny mogą być nieprawidłowo wybierane
- Generowanie każdego możliwego wariantu na podstawie słabej linii marnuje duże ilości czasu działania

Narzędzia oparte na AST lub Tree-sitter poprawiają ten proces, wybierając ustrukturyzowane węzły zamiast surowych linii:<sup>[[1]](#references)</sup>
- **slither-mutate** używa AST Solidity z Slither.<sup>[[4]](#references)</sup>
- **mewt** używa Tree-sitter jako niezależnego od języka rdzenia.<sup>[[6]](#references)</sup>
- **MuTON** bazuje na `mewt` i dodaje natywną obsługę języków TON, takich jak FunC, Tolk i Tact.<sup>[[7]](#references)</sup>

Dzięki temu konstrukcje wieloliniowe i mutacje na poziomie wyrażeń są znacznie bardziej niezawodne niż podejścia oparte wyłącznie na regex.

## Uruchamianie mutation testing za pomocą slither-mutate

Wymagania: Slither v0.10.2+.

- Wyświetlanie opcji i mutatorów:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Przykład Foundry (przechwytywanie wyników i zachowanie pełnego logu):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Jeśli nie używasz Foundry, zastąp `--test-cmd` poleceniem używanym do uruchamiania testów (np. `npx hardhat test`, `npm test`).

Artefakty są domyślnie przechowywane w `./mutation_campaign`. Niewykryte (ocalałe) mutacje są tam kopiowane w celu ich analizy.<sup>[[5]](#references)</sup>

### Zrozumienie danych wyjściowych

Wiersze raportu wyglądają następująco:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Tag w nawiasach to alias mutatora (np. `CR` = Comment Replacement).
- `UNCAUGHT` oznacza, że testy przeszły przy zmienionym zachowaniu → brakująca asercja.

## Skracanie czasu działania: priorytetyzacja istotnych mutantów

Kampanie mutation testing mogą trwać godziny lub dni. Wskazówki dotyczące ograniczania kosztów:<sup>[[1]](#references)[[2]](#references)</sup>
- Zakres: zacznij tylko od krytycznych kontraktów/katalogów, a następnie rozszerzaj zakres.
- Priorytetyzuj mutatory: jeśli mutant o wysokim priorytecie w danej linii przetrwa (na przykład `revert()` lub comment-out), pomiń warianty o niższym priorytecie dla tej linii.
- Używaj kampanii dwuetapowych: najpierw uruchom ukierunkowane/szybkie testy, a następnie ponownie przetestuj tylko nieprzechwycone mutanty za pomocą pełnego zestawu testów.
- W miarę możliwości mapuj cele mutacji na konkretne polecenia testów (na przykład auth code -> auth tests).
- Gdy czas jest ograniczony, ogranicz kampanie do mutantów o wysokim/średnim poziomie istotności.
- Wykonuj testy równolegle, jeśli runner na to pozwala; korzystaj z cache zależności/buildów.
- Fail-fast: zatrzymaj się wcześnie, gdy zmiana wyraźnie ujawnia lukę w asercjach.

Obliczenia czasu są bezlitosne: `1000 mutants x 5-minute tests ~= 83 hours`, dlatego projekt kampanii jest równie ważny jak sam mutator.<sup>[[1]](#references)</sup>

## Trwałe kampanie i triage na dużą skalę

Jedną ze słabości starszych workflow jest zapisywanie wyników wyłącznie do `stdout`. W przypadku długich kampanii utrudnia to wstrzymywanie/wznawianie, filtrowanie i przeglądanie wyników.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` poprawiają tę sytuację, przechowując mutanty i wyniki w kampaniach opartych na SQLite. Korzyści:<sup>[[1]](#references)</sup>
- Wstrzymywanie i wznawianie długich uruchomień bez utraty postępu
- Filtrowanie wyłącznie nieprzechwyconych mutantów w konkretnym pliku lub klasie mutacji
- Eksportowanie/tłumaczenie wyników do SARIF na potrzeby narzędzi do przeglądu
- Udostępnianie AI-assisted triage mniejszych, przefiltrowanych zestawów wyników zamiast surowych logów terminala

Trwałe wyniki są szczególnie przydatne, gdy mutation testing staje się częścią pipeline'u audytowego, a nie jednorazowym ręcznym przeglądem.

## Workflow triage dla mutantów, które przetrwały

1) Sprawdź zmodyfikowaną linię i zachowanie.
- Odtwórz problem lokalnie, stosując zmodyfikowaną linię i uruchamiając ukierunkowany test.

2) Wzmocnij testy tak, aby sprawdzały stan, a nie tylko wartości zwracane.
- Dodaj testy granic równości (np. przetestuj próg `==`).
- Sprawdzaj post-conditions: salda, całkowitą podaż, skutki autoryzacji i emitowane zdarzenia.

3) Zastąp nadmiernie liberalne mocki realistycznym zachowaniem.
- Upewnij się, że mocki egzekwują transfery, ścieżki błędów i emisję zdarzeń występujące on-chain.

4) Dodaj invariants do testów fuzz.
- Np. zachowanie wartości, nieujemne salda, invariants autoryzacji oraz monotoniczną podaż tam, gdzie ma to zastosowanie.

5) Oddziel true positives od semantic no-ops.
- Przykład: `x > 0` -> `x != 0` nie ma znaczenia, gdy `x` jest unsigned.

6) Ponownie uruchamiaj kampanię, aż wszystkie mutanty, które przetrwały, zostaną zabite lub wyraźnie uzasadnione.

## Studium przypadku: ujawnienie brakujących asercji stanu (protokół Arkis)

Kampania mutation testing przeprowadzona podczas audytu protokołu DeFi Arkis ujawniła mutanty, które przetrwały, takie jak:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Zakomentowanie przypisania nie spowodowało niepowodzenia testów, co dowodzi braku asercji stanu końcowego. Przyczyna: kod ufał kontrolowanej przez użytkownika wartości `_cmd.value`, zamiast weryfikować faktyczne transfery tokenów. Atakujący mógł rozdesynchronizować oczekiwane i rzeczywiste transfery, aby opróżnić środki. Wynik: ryzyko o wysokim poziomie istotności dla wypłacalności protokołu.<sup>[[2]](#references)[[3]](#references)</sup>

Wskazówka: Traktuj przetrwałe mutanty wpływające na transfery wartości, księgowanie lub kontrolę dostępu jako wysokiego ryzyka, dopóki nie zostaną zabite.

## Nie generuj bezmyślnie testów w celu zabicia każdego mutanta

Generowanie testów sterowane mutacjami może przynieść odwrotny skutek, jeśli bieżąca implementacja jest błędna. Przykład: mutacja `priority >= 2` do `priority > 2` zmienia zachowanie, ale właściwą poprawką nie zawsze jest „napisanie testu dla `priority == 2`”. To zachowanie samo w sobie może być błędem.<sup>[[1]](#references)</sup>

Bezpieczniejszy workflow:
- Używaj przetrwałych mutantów do identyfikowania niejednoznacznych wymagań
- Zweryfikuj oczekiwane zachowanie na podstawie specyfikacji, dokumentacji protokołu lub opinii reviewerów
- Dopiero potem zakoduj to zachowanie jako test/invariant

W przeciwnym razie ryzykujesz utrwaleniem przypadkowych cech implementacji w zestawie testów i uzyskaniem fałszywego poczucia bezpieczeństwa.

## Praktyczna checklista

- Uruchom ukierunkowaną kampanię:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Jeśli to możliwe, preferuj mutatory uwzględniające składnię (AST/Tree-sitter) zamiast mutacji opartej wyłącznie na regexach.
- Przeanalizuj przetrwałe mutanty i napisz testy/invarianty, które nie przechodziłyby przy zmodyfikowanym zachowaniu.
- Sprawdzaj salda, podaż, uprawnienia i eventy.
- Dodaj testy wartości brzegowych (`==`, przepełnienia/niedopełnienia, adres zerowy, kwota zerowa, puste tablice).
- Zastąp nierealistyczne mocki; symuluj scenariusze awarii.
- Zapisuj wyniki, jeśli narzędzie to obsługuje, i odfiltruj mutanty nierozpoznane przed analizą.
- Używaj kampanii dwuetapowych lub kampanii dla poszczególnych celów, aby utrzymać rozsądny czas wykonania.
- Iteruj, aż wszystkie mutanty zostaną zabite albo uzasadnione komentarzami i wyjaśnieniem.

## References

- [1] [Mutation testing w erze agentic](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Użyj mutation testing, aby znaleźć błędy, których nie wykrywają Twoje testy (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Przegląd bezpieczeństwa Arkis DeFi Prime Brokerage (Dodatek C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Dokumentacja Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
