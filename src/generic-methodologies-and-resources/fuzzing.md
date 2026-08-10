# Metodologia Fuzzing

## Mutational Grammar Fuzzing: Coverage vs. Semantyka

W **mutational grammar fuzzing** dane wejściowe są modyfikowane przy zachowaniu **poprawności względem gramatyki**. W trybie coverage-guided zapisywane jako seeds corpus są tylko próbki, które wywołują **nowy coverage**. W przypadku **language targets** (parserów, interpreterów, silników) może to pomijać błędy wymagające **łańcuchów semantycznych/dataflow**, w których wynik jednej konstrukcji staje się danymi wejściowymi innej.<sup>[[1]](#references)</sup>

**Tryb awarii:** fuzzer znajduje seeds, które indywidualnie wykonują `document()` i `generate-id()` (lub podobne primitives), ale **nie zachowuje połączonego dataflow**, więc próbka „bliższa błędowi” zostaje odrzucona, ponieważ nie dodaje coverage. Przy **3+ zależnych krokach** losowa rekombinacja staje się kosztowna, a feedback z coverage nie ukierunkowuje wyszukiwania.<sup>[[1]](#references)</sup>

**Wniosek:** w przypadku gramatyk z dużą liczbą zależności rozważ **hybridizing mutational and generative phases** lub ukierunkowanie generowania na wzorce **function chaining** (a nie wyłącznie na coverage).<sup>[[1]](#references)</sup>

## Pułapki różnorodności corpus

Mutacja coverage-guided jest **zachłanna**: próbka z nowym coverage jest od razu zapisywana, często z zachowaniem dużych, niezmienionych regionów. Z czasem corpora stają się **niemal identycznymi** próbkami o niskiej różnorodności strukturalnej. Agresywna minimalizacja może usunąć przydatny kontekst, dlatego praktycznym kompromisem jest **minimalizacja uwzględniająca gramatykę**, która **zatrzymuje się po osiągnięciu minimalnego progu tokenów** (redukuje szum, zachowując wystarczającą strukturę otoczenia, aby ułatwić mutacje).<sup>[[1]](#references)</sup>

Praktyczna zasada dotycząca corpus w mutational fuzzing brzmi: **preferuj niewielki zestaw strukturalnie różnych seeds maksymalizujących coverage** zamiast dużego zbioru niemal identycznych próbek. W praktyce zwykle oznacza to:<sup>[[1]](#references)[[3]](#references)</sup>

- Zacznij od **próbek z realnego świata** (publicznych corpora, crawlingu, przechwyconego ruchu, zestawów plików z ekosystemu targetu).
- Wyodrębnij z nich próbki za pomocą **minimalizacji corpus opartej na coverage**, zamiast zachowywać każdą poprawną próbkę.
- Zachowuj seeds na tyle **małe**, aby mutacje trafiały w znaczące pola, zamiast zużywać większość cykli na nieistotne bajty.
- Ponownie uruchamiaj minimalizację corpus po większych zmianach harnessu/instrumentacji, ponieważ „najlepszy” corpus zmienia się wraz ze zmianą osiągalności.

## Comparison-Aware Mutation For Magic Values

Częstą przyczyną zatrzymywania się fuzzerów nie jest składnia, lecz **trudne porównania**: magic bytes, sprawdzanie długości, strings enum, checksums lub wartości dispatch parsera chronione przez `memcmp`, tabele switch albo kaskadowe porównania. Czysto losowa mutacja marnuje cykle na próby odgadnięcia tych wartości bajt po bajcie.

W przypadku takich targetów używaj **comparison tracing** (na przykład workflow opartych na AFL++ `CMPLOG` / Redqueen), aby fuzzer mógł obserwować operandy z nieudanych porównań i ukierunkowywać mutacje na wartości, które je spełniają.<sup>[[3]](#references)</sup>
```bash
./configure --cc=afl-clang-fast
make
cp ./target ./target.afl

make clean
AFL_LLVM_CMPLOG=1 ./configure --cc=afl-clang-fast
make
cp ./target ./target.cmplog

afl-fuzz -i in -o out -c ./target.cmplog -- ./target.afl @@
```
**Praktyczne uwagi:**

- Jest to szczególnie przydatne, gdy target ukrywa głęboką logikę za **file signatures**, **protocol verbs**, **type tags** lub **version-dependent feature bits**.
- Połącz to ze **słownikami** wyodrębnionymi z rzeczywistych próbek, specyfikacji protokołów lub logów debugowania. Mały słownik zawierający tokeny gramatyki, nazwy chunków, czasowniki i delimitery jest często bardziej wartościowy niż ogromna, generyczna wordlista.
- Jeśli target wykonuje wiele sekwencyjnych sprawdzeń, najpierw rozwiąż najwcześniejsze porównania „magic”, a następnie ponownie zminimalizuj wynikowy korpus, aby późniejsze etapy rozpoczynały się od już poprawnych prefiksów.

## Stateful Fuzzing: Sequences Are Seeds

W przypadku **protokołów**, **uwierzytelnionych workflow** i **parserów wieloetapowych** interesującą jednostką często nie jest pojedynczy blob, lecz **sekwencja wiadomości**. Połączenie całego transkryptu w jeden plik i jego ślepe mutowanie jest zwykle nieefektywne, ponieważ fuzzer mutuje każdy krok w równym stopniu, nawet gdy tylko późniejsza wiadomość dociera do podatnego stanu.<sup>[[4]](#references)</sup>

Bardziej efektywnym podejściem jest traktowanie **samej sekwencji jako seeda** i używanie **obserwowalnego stanu** (kodów odpowiedzi, stanów protokołu, faz parsera, zwracanych typów obiektów) jako dodatkowego feedbacku.<sup>[[4]](#references)</sup>

- Zachowaj stabilność **poprawnych wiadomości prefiksowych** i skup mutacje na wiadomości **sterującej przejściem**.
- Cache'uj identyfikatory i wartości generowane przez serwer z poprzednich odpowiedzi, gdy kolejny krok od nich zależy.
- Preferuj mutację/splicing poszczególnych wiadomości zamiast mutowania całego zserializowanego transkryptu jako nieprzejrzystego bloba.
- Jeśli protokół udostępnia znaczące kody odpowiedzi, używaj ich jako **taniego oracle stanu**, aby priorytetyzować sekwencje, które docierają głębiej.

Z tego samego powodu błędy uwierzytelniania, ukryte przejścia lub błędy parsera występujące „dopiero po handshake” są często pomijane przez standardowe fuzzing w stylu plikowym: fuzzer musi zachowywać **kolejność, stan i zależności**, a nie tylko strukturę.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Praktycznym sposobem na połączenie **generative novelty** z **ponownym wykorzystaniem coverage** jest **restartowanie krótkotrwałych workerów** kierowanych do persistent servera. Każdy worker rozpoczyna z pustym korpusem, synchronizuje się po `T` sekundach, działa przez kolejne `T` sekund na połączonym korpusie, ponownie się synchronizuje, a następnie kończy działanie. Zapewnia to **świeże struktury w każdej generacji**, jednocześnie korzystając ze zgromadzonego coverage.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sekwencyjne workery (przykładowa pętla):**

<details>
<summary>Pętla restartowania workerów Jackalope</summary>
```python
import subprocess
import time

T = 3600

while True:
subprocess.run(["rm", "-rf", "workerout"])
p = subprocess.Popen([
"/path/to/fuzzer",
"-grammar", "grammar.txt",
"-instrumentation", "sancov",
"-in", "empty",
"-out", "workerout",
"-t", "1000",
"-delivery", "shmem",
"-iterations", "10000",
"-mute_child",
"-nthreads", "6",
"-server", "127.0.0.1:8337",
"-server_update_interval", str(T),
"--", "./harness", "-m", "@@",
])
time.sleep(T * 2)
p.kill()
```
</details>

**Uwagi:**

- `-in empty` wymusza użycie **fresh corpus** przy każdej generacji.
- `-server_update_interval T` przybliża **delayed sync** (najpierw novelty, później reuse).
- W trybie grammar fuzzing **initial server sync** jest domyślnie pomijany (nie ma potrzeby używania `-skip_initial_server_sync`).
- Optymalne `T` zależy od **targetu**; zwykle najlepiej sprawdza się przełączenie po tym, jak worker znajdzie większość „łatwego” coverage.

## Snapshot Fuzzing For Hard-To-Harness Targets

Gdy kod, który chcesz testować, staje się dostępny dopiero po dużym koszcie inicjalizacji (uruchomieniu VM, ukończeniu logowania, odebraniu pakietu, sparsowaniu kontenera, zainicjalizowaniu usługi), użyteczną alternatywą jest **snapshot fuzzing**: przechwyć stan gotowego procesu lub VM, wstrzyknij każdy test case do ścieżki wejściowej targetu, wykonuj go do crash/timeout, a następnie przywróć snapshot. Pozwala to uniknąć powtarzania inicjalizacji lub prefiksów protokołu i jest przydatne w przypadku **network services**, **firmware**, **post-auth attack surfaces** oraz **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Uruchom target do momentu, w którym interesujący stan będzie gotowy.
2. Wykonaj snapshot **pamięci + rejestrów** w tym momencie.
3. Dla każdego test case zapisz zmodyfikowane dane wejściowe bezpośrednio do odpowiedniego bufora guest/process.
4. Wykonuj do crash/timeout/reset.
5. Przywróć snapshot; w przypadku targetów VM, jeśli jest to obsługiwane, przywracaj tylko **dirty pages**, a następnie powtórz operację.

Umieść snapshot tak blisko, jak to praktyczne, pierwszego kosztownego etapu parsowania/dispatch, na przykład po punkcie `recv`/`read` lub deserializacji pakietu, i zapisz bufor wejściowy używany przez target. Jest to zgodne z zasadą adaptive placement, polegającą na przesuwaniu snapshotu głębiej w procesie przetwarzania wejścia, aby uniknąć powtarzania pracy.<sup>[[11]](#references)</sup>

## Harness Introspection: Find Shallow Fuzzers Early

Gdy kampania utknie, problemem często nie jest mutator, lecz **harness**. Użyj **reachability/coverage introspection**, aby znaleźć funkcje, które są statycznie osiągalne z fuzz targetu, ale rzadko lub nigdy nie są pokrywane dynamicznie. Funkcje te zwykle wskazują na jeden z trzech problemów.<sup>[[12]](#references)</sup>

- Harness wchodzi do targetu zbyt późno lub zbyt wcześnie.
- W seed corpus brakuje całej rodziny funkcji.
- Target rzeczywiście potrzebuje **drugiego harnessu**, zamiast jednego, nadmiernie rozbudowanego harnessu typu „zrób wszystko”.

Jeśli używasz workflow w stylu OSS-Fuzz / ClusterFuzz, Fuzz Introspector może porównywać statyczną reachability z runtime coverage i generować raporty na podstawie uruchomienia z określonym limitem czasu lub publicznego corpus.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Użyj raportu, aby zdecydować, czy dodać nowy harness dla nieprzetestowanej ścieżki parsera, rozszerzyć corpus dla konkretnej funkcji, czy podzielić monolityczny harness na mniejsze entrypointy.

## Wybór celu Fuzz i triage mutacji z wykorzystaniem grafu

Jeśli masz już **static-analysis findings**, **mutation-testing survivors** i **coverage reports**, nie analizuj ich jako niezależnych list. Najpierw zbuduj **call graph**, oznacz węzły za pomocą **cyclomatic complexity**, osiągalności z **entrypoint/untrusted-input** oraz wszelkich zewnętrznych ustaleń, a następnie zadawaj pytania dotyczące grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Które funkcje o wysokiej złożoności są osiągalne z niezaufanych danych wejściowych?
- Które mutation survivors znajdują się na ścieżkach od parserów/handlerów do security-critical code?
- Które funkcje są architektonicznymi wąskimi gardłami o wyjątkowo dużym **blast radius**?

Zwykle pozwala to wskazać lepsze cele fuzzingu niż samo „najniższe coverage”. Parser/decoder o **high complexity** i potwierdzonej **external reachability** jest lepszym kandydatem na harness niż odizolowany wewnętrzny helper o słabym coverage, ale bez ścieżki kontrolowanej przez atakującego.

### Praktyczny workflow triage

1. Zbuduj **code graph** na podstawie codebase i wyodrębnij metryki complexity/branch dla każdej funkcji.
2. Wymień **entrypoints**, które przyjmują dane wejściowe kontrolowane przez atakującego: request handlery, decodery, importery, parsery protokołów, czytniki CLI/plików.
3. Uruchom **path queries** od tych entrypointów do kandydackich funkcji, aby oddzielić osiągalną attack surface od kodu martwego lub dostępnego wyłącznie wewnętrznie.
4. Nadaj priorytet węzłom łączącym:
- wysoką **cyclomatic complexity**
- potwierdzoną **reachability from untrusted input**
- duży **blast radius** lub wielu downstream dependents
- dodatkowe dowody, takie jak ustalenia **SARIF**, notatki z audytu lub mutation survivors
5. Najpierw przygotuj ukierunkowane harnesses dla węzłów z najwyższymi wynikami, zwłaszcza dla **parserów/codecs**, takich jak dekodery hex/Base64/IP/message.

### Mutation survivors: równoważne a actionable

Mutation testing często generuje zaszumioną listę survivors. Zanim uznasz każdego survivora za lukę bezpieczeństwa, użyj grafu, aby sprawdzić:

- Czy zmodyfikowana funkcja jest osiągalna z entrypointu kontrolowanego przez atakującego?
- Czy wszystkie ścieżki wywołań są ograniczone przez silniejsze invariants niż zmodyfikowany check?
- Czy węzeł znajduje się w martwym kodzie, logice dotyczącej wyłącznie formatowania lub w wysokiego ryzyka ścieżce arithmetic/parser?

Survivors, które pozostają nieosiągalne lub są strukturalnie ograniczone, są często **equivalent mutants**. Survivors, które pozostają **reachable** i dotyczą **boundary conditions**, **overflow/carry paths** lub **security-critical arithmetic/parsing**, należy przekształcić w:

- nowe fuzz harnesses
- bezpośrednie property/invariant tests
- ukierunkowane edge-case vectors

### Koreluj zewnętrzne ustalenia z grafem

Jeśli pipeline SAST eksportuje **SARIF**, nanieś ustalenia na węzły grafu według **file + line range** i użyj grafu do określenia wpływu.<sup>[[6]](#references)</sup>

- oblicz **blast radius** oznaczonej funkcji
- sprawdź, czy ustalenie znajduje się na którejkolwiek ścieżce od entrypointu
- pogrupuj pobliskie ustalenia, które sprowadzają się do tego samego wąskiego gardła

Jest to przydatne przy decydowaniu, czy poświęcić czas fuzzingu na konkretną funkcję: węzeł, który jest **reachable**, złożony i ma już **SAST hits**, często stanowi lepszy cel niż jedynie złożony węzeł bez ścieżki ataku.

Przykładowy workflow z Trailmark.<sup>[[6]](#references)</sup>
```bash
uv pip install trailmark
trailmark analyze --complexity 10 path/to/project
```

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("path/to/project", language="c")
engine.preanalysis()
engine.complexity_hotspots(10)
engine.paths_between("handle_request", "parse_ipv6")
```
Ważną metodologią jest przecięcie: **złożoność x ekspozycja x wpływ**. Użyj wykresu, aby wybrać cele fuzzingu o najwyższej oczekiwanej wartości bezpieczeństwa, a następnie wykorzystaj mutation survivors do określenia, które granice i niezmienniki musi testować Twój harness.<sup>[[5]](#references)</sup>

## Go Fuzzing With gosentry: Silniejszy silnik, typowane dane wejściowe i kontrole różnicowe

Jeśli cel napisany w Go ma już natywny harness `testing.F`, praktyczną ścieżką rozbudowy jest uruchomienie tego samego harnessa za pomocą [gosentry](https://github.com/trailofbits/gosentry) — forked Go toolchain, który zachowuje `go test -fuzz`, ale zamienia backend na **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Jest to przydatne, gdy natywny fuzzer Go zatrzymuje się na **trudnych porównaniach**, **typowanych danych wejściowych** lub **formatach intensywnie wykorzystujących parsery**. Metodologia pozostaje taka sama:

- Nadal używaj `f.Add(...)` do seedów i `f.Fuzz(...)` dla callbacka.
- Użyj ponownie tego samego harnessu, ale uruchom go za pomocą pliku binarnego `go` z gosentry zamiast standardowego toolchainu.
- Traktuj wynikającą z tego kampanię jako zwykły run sterowany pokryciem kodu, ale z harmonogramowaniem/mutacjami LibAFL i lepszymi dodatkowymi detektorami.

### Zamiana cichych awarii na wyniki fuzzingu

Powtarzającym się problemem podczas assessmentów Go jest to, że niebezpieczne zachowanie często **domyślnie nie powoduje crasha**. W gosentry możesz przekształcić kilka klas „błędnych, lecz niewidocznych” stanów w wyniki.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` sprawia, że wybrane ścieżki logowania/obsługi błędów zachowują się jak crashe (przydatne w przypadku ścieżek kodu w stylu `log.Fatal`, które w przeciwnym razie tylko logują i działają dalej).
- `--catch-races=true` ponownie uruchamia nowo odkryte wpisy kolejki z użyciem race detectora Go.
- `--catch-leaks=true` ponownie uruchamia nowe wpisy kolejki za pomocą `goleak` i zatrzymuje się po wykryciu wycieków goroutines.
- Obsługa hangów przez LibAFL pozwala zachować **nieskończone pętle / bardzo wolne dane wejściowe** jako wyniki fuzzingu zamiast pozwalać, aby znikały jako timeouty.
- Domyślnie wbudowane kontrole przepełnienia arytmetycznego oraz opcjonalne kontrole obcięcia za pomocą instrumentacji w stylu go-panikint.

Jest to szczególnie przydatne w przypadku celów, w których wpływ na bezpieczeństwo wynika z **awarii parsera niewywołującej panic**, **błędu współbieżności** lub **zawieszenia powodującego wyłącznie DoS**, a nie z uszkodzenia pamięci.

### Fuzzing uwzględniający struktury dla typowanych API Go

Natywny fuzzing Go zakłada głównie skalary, takie jak `[]byte`, `string` i liczby. Jeśli testowany kod korzysta z typowanych obiektów, gosentry może bezpośrednio fuzzować **wartości złożone** (struktury, slices, arrays, pointers), jednocześnie mutując znajdujące się pod nimi bajty.<sup>[[7]](#references)[[8]](#references)</sup>
```go
type Input struct {
Data []byte
S    string
N    int
}

func FuzzStructInput(f *testing.F) {
f.Add(Input{Data: []byte("hello"), S: "world", N: 42})
f.Fuzz(func(t *testing.T, in Input) {
Process(in)
})
}
```
Użycie tego podczas tworzenia fałszywego wire format wyłącznie na potrzeby fuzzing ukrywałoby błędy logiczne za kodem parsowania używanym tylko przez harness. W przypadku kampanii differential lub grammar-based należy pozostawić wejście harness jako pojedynczy `[]byte` lub `string` i parsować je wewnątrz callbacku.

### Grammar-based fuzzing dla parserów i danych wejściowych protokołów

W przypadku parserów, formatów i języków wejściowych gosentry może uruchamiać **Nautilus grammar fuzzing** na bazie LibAFL. Gramatyka jest tablicą reguł produkcji w formacie JSON, a harness powinien zwykle przyjmować pojedynczy argument `[]byte` lub `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Uwagi dotyczące methodology:

- Używaj grammar mode, gdy mutacje na poziomie bajtów najczęściej odpadają podczas wczesnych kontroli składni.
- Skup grammar na **podzbiorze języka/protokołu istotnym z punktu widzenia bezpieczeństwa**, zamiast modelować całą specyfikację.
- Używaj dużych wartości granicznych w terminalach/nonterminalach, aby obciążyć krawędzie związane z liczbami całkowitymi, długością i maszyną stanów.
- Grammar mode utrzymuje poprawność wejść względem gramatyki, ale target nadal otrzymuje **bajty/ciągi znaków**, więc parsowanie i kontrole semantyczne nadal odbywają się wewnątrz instrumentowanego kodu.

### Differential fuzzing: porównuj implementacje, nie tylko crashe

Silnym wzorcem w ekosystemach Go jest **grammar-based differential fuzzing**: generowanie poprawnych, ustrukturyzowanych wejść i przekazywanie ich do dwóch parserów, klientów lub silników przejść stanów.<sup>[[7]](#references)[[8]](#references)</sup>
```go
f.Fuzz(func(t *testing.T, data []byte) {
gotA, errA := ParseA(data)
gotB, errB := ParseB(data)
if (errA == nil) != (errB == nil) {
t.Fatalf("parser disagreement: A=%v B=%v", errA, errB)
}
_ = gotA
_ = gotB
})
```
Traktuj poniższe sytuacje jako wyniki:

- jedna implementacja powoduje panic, podczas gdy druga poprawnie odrzuca dane
- niezgodność między zaakceptowanymi i odrzuconymi danymi wejściowymi
- różne drzewa parsowania lub zdekodowane obiekty
- rozbieżne przejścia stanu, nonce, salda lub korzenie stanu

To praktyczny sposób na wykrywanie **rozbieżności konsensusu**, **niejednoznaczności parsera** oraz **rozbieżności między specyfikacją a implementacją**, które często umykają podczas fuzzingu ukierunkowanego wyłącznie na crashe.

### Ponowne wykorzystanie corpus kampanii do raportowania pokrycia

Po zakończeniu kampanii odtwórz zapisany corpus kolejki, aby wygenerować raport pokrycia Go bez ręcznego eksportowania oddzielnego corpus.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Uruchom polecenie z **tego samego pakietu** i z **tym samym celem `-fuzz`**, aby gosentry rozpoznał właściwy stan kampanii zapisany w pamięci podręcznej.

## References

- [1] [Fuzzing z gramatyką mutacyjną](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing AFL++ od podstaw](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pięć lat później: fuzzing protokołów sterowany pokryciem](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark zamienia kod w grafy](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [W Go fuzzingowi brakowało połowy narzędzi. Rozwidlenie toolchaina naprawiło ten problem.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: szybki greybox fuzzer dla stanowych protokołów sieciowych wykorzystujący snapshoty](https://arxiv.org/abs/2202.03643)
- [10] [Brak gramatyki? Żaden problem: w kierunku fuzzingu jądra Linux bez opisów wywołań systemowych](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: wydajny fuzzing z adaptacyjnymi i modyfikowalnymi snapshotami](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
