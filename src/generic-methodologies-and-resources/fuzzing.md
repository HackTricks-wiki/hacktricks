# Metodologia fuzzingu

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

W **mutational grammar fuzzing** dane wejściowe są mutowane przy zachowaniu **poprawności względem gramatyki**. W trybie sterowanym przez coverage zapisywane są jako seeds corpus tylko próbki, które wywołują **nowy coverage**. W przypadku **celów językowych** (parserów, interpreterów, silników) może to pomijać błędy wymagające **łańcuchów semantycznych/dataflow**, w których wynik jednej konstrukcji staje się danymi wejściowymi kolejnej.<sup>[[1]](#references)</sup>

**Tryb awarii:** fuzzer znajduje seedy, które pojedynczo wykonują `document()` i `generate-id()` (lub podobne prymitywy), ale **nie zachowuje połączonego dataflow**, przez co próbka „bliższa błędowi” zostaje odrzucona, ponieważ nie dodaje coverage. Przy **3 lub większej liczbie zależnych kroków** losowa rekombinacja staje się kosztowna, a feedback z coverage nie pomaga w kierowaniu wyszukiwaniem.<sup>[[1]](#references)</sup>

**Wniosek:** w przypadku gramatyk z dużą liczbą zależności rozważ **hybrydyzację faz mutacyjnych i generatywnych** albo ukierunkowanie generowania na wzorce **function chaining** (a nie wyłącznie na coverage).<sup>[[1]](#references)</sup>

## Pułapki związane z różnorodnością corpus

Mutacja sterowana przez coverage jest **zachłanna**: próbka z nowym coverage jest zapisywana natychmiast, często z zachowaniem dużych, niezmienionych regionów. Z czasem corpus staje się zbiorem **niemal identycznych próbek** o małej różnorodności strukturalnej. Agresywna minimalizacja może usunąć użyteczny kontekst, dlatego praktycznym kompromisem jest **minimalizacja uwzględniająca gramatykę**, która **zatrzymuje się po osiągnięciu minimalnego progu tokenów** (redukuje szum, zachowując wystarczającą strukturę otoczenia, aby ułatwić mutacje).<sup>[[1]](#references)</sup>

Praktyczna zasada dotycząca corpus w mutational fuzzing brzmi: **preferuj niewielki zestaw strukturalnie różnych seedów maksymalizujących coverage** zamiast dużej liczby niemal identycznych próbek. W praktyce zwykle oznacza to:<sup>[[1]](#references)[[3]](#references)</sup>

- Zacznij od **próbek z rzeczywistego świata** (publicznych corpus, crawlingu, przechwyconego ruchu, zestawów plików z ekosystemu celu).
- Zredukuj je za pomocą **minimalizacji corpus na podstawie coverage**, zamiast zachowywać każdą poprawną próbkę.
- Utrzymuj seedy na tyle małe, aby mutacje trafiały w znaczące pola, zamiast poświęcać większość cykli na nieistotne bajty.
- Uruchamiaj ponownie minimalizację corpus po dużych zmianach harnessu lub instrumentacji, ponieważ „najlepszy” corpus zmienia się wraz ze zmianą osiągalności.

## Mutacja uwzględniająca porównania dla wartości magicznych

Częstym powodem plateau fuzzera nie jest składnia, lecz **trudne porównania**: magiczne bajty, kontrole długości, ciągi enum, sumy kontrolne lub wartości sterujące dispatch parsera zabezpieczone przez `memcmp`, tablice switch albo kaskadowe porównania. Czysto losowa mutacja marnuje cykle na próby odgadnięcia tych wartości bajt po bajcie.

W przypadku takich celów używaj **śledzenia porównań** (na przykład workflow w stylu AFL++ `CMPLOG` / Redqueen), aby fuzzer mógł obserwować operandy z nieudanych porównań i ukierunkowywać mutacje na wartości, które je spełniają.<sup>[[3]](#references)</sup>
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
**Uwagi praktyczne:**

- Jest to szczególnie przydatne, gdy target ukrywa głęboką logikę za **file signatures**, **protocol verbs**, **type tags** lub **version-dependent feature bits**.
- Połącz to ze **słownikami** wyodrębnionymi z rzeczywistych próbek, specyfikacji protokołów lub debug logs. Mały słownik zawierający tokeny gramatyki, nazwy chunków, czasowniki i delimitery jest często cenniejszy niż ogromna ogólna wordlista.
- Jeśli target wykonuje wiele sekwencyjnych sprawdzeń, najpierw rozwiąż najwcześniejsze porównania „magic”, a następnie ponownie zminimalizuj wynikowy corpus, aby późniejsze etapy rozpoczynały się od już poprawnych prefiksów.

## Stateful Fuzzing: Sequences Are Seeds

W przypadku **protokołów**, **uwierzytelnionych workflow** i **parserów wieloetapowych** interesującą jednostką często nie jest pojedynczy blob, lecz **sekwencja wiadomości**. Połączenie całego transcriptu w jeden plik i jego ślepe mutowanie jest zazwyczaj nieefektywne, ponieważ fuzzer mutuje każdy krok w równym stopniu, nawet gdy tylko późniejsza wiadomość dociera do podatnego stanu.<sup>[[4]](#references)</sup>

Bardziej efektywnym podejściem jest potraktowanie **samej sekwencji jako seeda** i użycie **obserwowalnego stanu** (kodów odpowiedzi, stanów protokołu, faz parsera, zwracanych typów obiektów) jako dodatkowego feedbacku.<sup>[[4]](#references)</sup>

- Zachowuj **poprawne wiadomości prefiksowe** bez zmian i skup mutacje na wiadomości **sterującej przejściem**.
- Cache'uj identyfikatory i wartości generowane przez server z poprzednich odpowiedzi, gdy kolejny krok od nich zależy.
- Preferuj mutację/splicing poszczególnych wiadomości zamiast mutowania całego zserializowanego transcriptu jako nieprzejrzystego bloba.
- Jeśli protokół udostępnia znaczące kody odpowiedzi, używaj ich jako **taniego oracle stanu**, aby nadawać priorytet sekwencjom przechodzącym głębiej.

Z tego samego powodu błędy związane z uwierzytelnianiem, ukrytymi przejściami lub błędy parsera występujące „dopiero po handshake” są często pomijane przez standardowy file-style fuzzing: fuzzer musi zachowywać **kolejność, stan i zależności**, a nie tylko strukturę.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Praktycznym sposobem połączenia **generative novelty** z **ponownym wykorzystaniem coverage** jest **restartowanie krótkotrwałych workerów** pracujących z persistent serverem. Każdy worker rozpoczyna z pustym corpus, synchronizuje się po `T` sekundach, działa przez kolejne `T` sekund na połączonym corpus, ponownie synchronizuje się, a następnie kończy działanie. Zapewnia to **świeże struktury w każdej generacji**, jednocześnie umożliwiając wykorzystanie zgromadzonego coverage.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sekwencyjne workery (przykładowa pętla):**

<details>
<summary>Pętla restartowania workera Jackalope</summary>
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

- `-in empty` wymusza **fresh corpus** przy każdej generacji.
- `-server_update_interval T` przybliża **delayed sync** (najpierw nowość, później ponowne użycie).
- W trybie grammar fuzzing **initial server sync** jest domyślnie pomijany (nie ma potrzeby używania `-skip_initial_server_sync`).
- Optymalna wartość `T` zależy od **targetu**; najlepsze rezultaty zwykle daje przełączenie po znalezieniu przez workera większości „łatwego” coverage.

## Snapshot Fuzzing dla trudnych do obsłużenia targetów

Gdy kod, który chcesz testować, staje się osiągalny dopiero po kosztownej konfiguracji (uruchomieniu VM, ukończeniu logowania, odebraniu pakietu, sparsowaniu kontenera, zainicjalizowaniu usługi), użyteczną alternatywą jest **snapshot fuzzing**: przechwyć stan gotowego procesu lub VM, wstrzykuj każdy przypadek testowy do ścieżki wejściowej targetu, wykonuj go do momentu crash/timeout, a następnie przywracaj snapshot. Pozwala to uniknąć powtarzania inicjalizacji lub prefiksów protokołu i jest przydatne w przypadku **usług sieciowych**, **firmware**, **powierzchni ataku po uwierzytelnieniu** oraz **targetów binarnych**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Uruchom target do momentu, gdy interesujący stan będzie gotowy.
2. Wykonaj snapshot **pamięci + rejestrów** w tym momencie.
3. Dla każdego przypadku testowego zapisz zmodyfikowane wejście bezpośrednio do odpowiedniego bufora guest/process.
4. Wykonuj do momentu crash/timeout/reset.
5. Przywróć snapshot; w przypadku targetów VM, jeśli jest to obsługiwane, przywracaj tylko **dirty pages**, a następnie powtórz działanie.

Umieść snapshot możliwie blisko pierwszego kosztownego kroku parsowania/dispatch, na przykład po punkcie `recv`/`read` lub deserializacji pakietu, i zapisz używany przez target bufor wejściowy. Jest to zgodne z zasadą adaptive-placement, polegającą na przesuwaniu snapshotu głębiej w procesie przetwarzania wejścia, aby uniknąć powtarzania pracy.<sup>[[11]](#references)</sup>

## Introspekcja harnessu: wcześnie znajdź płytkie fuzzery

Gdy campaign zatrzymuje się, problemem często nie jest mutator, lecz **harness**. Użyj introspekcji **reachability/coverage**, aby znaleźć funkcje, które są statycznie osiągalne z fuzz targetu, ale rzadko lub nigdy nie są pokrywane dynamicznie. Funkcje te zwykle wskazują na jeden z trzech problemów.<sup>[[12]](#references)</sup>

- Harness wchodzi do targetu zbyt późno lub zbyt wcześnie.
- Seed corpus nie zawiera całej rodziny funkcji.
- Target rzeczywiście potrzebuje **drugiego harnessu**, zamiast jednego zbyt rozbudowanego harnessu typu „zrób wszystko”.

Jeśli używasz workflow w stylu OSS-Fuzz / ClusterFuzz, Fuzz Introspector może porównać statyczną reachability z runtime coverage i wygenerować raporty na podstawie uruchomienia w określonym czasie lub publicznego corpusu.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Na podstawie raportu zdecyduj, czy dodać nowy harness dla nieprzetestowanej ścieżki parsera, rozszerzyć corpus dla konkretnej funkcji, czy podzielić monolityczny harness na mniejsze entry points.

## Selekcja celów fuzzingu i triage mutacji z podejściem graph-first

Jeśli masz już **static-analysis findings**, **mutation-testing survivors** i **coverage reports**, nie analizuj ich jako niezależnych list. Najpierw zbuduj **call graph**, dodaj do węzłów informacje o **cyclomatic complexity**, możliwości dotarcia z **entrypoint/untrusted-input** oraz wszelkie zewnętrzne findings, a następnie zadawaj pytania dotyczące grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Które funkcje o wysokiej złożoności są osiągalne z untrusted input?
- Które mutation survivors znajdują się na ścieżkach od parserów/handlerów do security-critical code?
- Które funkcje są architektonicznymi choke points o wyjątkowo dużym **blast radius**?

Zwykle pozwala to znaleźć lepsze cele fuzzingu niż samo „najniższe coverage”. Parser/decoder o **high complexity** i potwierdzonej **external reachability** jest lepszym kandydatem na harness niż odizolowany internal helper ze słabym coverage, ale bez ścieżki kontrolowanej przez atakującego.

### Praktyczny workflow triage

1. Zbuduj **code graph** na podstawie codebase i wyodrębnij metryki złożoności/branch dla każdej funkcji.
2. Wylicz **entrypoints**, które przyjmują dane kontrolowane przez atakującego: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Uruchom **path queries** od tych entrypoints do funkcji kandydujących, aby oddzielić osiągalną attack surface od kodu martwego lub dostępnego wyłącznie wewnętrznie.
4. Nadaj priorytet węzłom, które łączą:
- wysoką **cyclomatic complexity**
- potwierdzoną **reachability from untrusted input**
- duży **blast radius** lub wielu downstream dependents
- dodatkowe potwierdzenia, takie jak findings z **SARIF**, audit notes lub mutation survivors
5. Najpierw napisz focused harnesses dla węzłów z najwyższymi wynikami, zwłaszcza dla **parsers/codecs**, takich jak dekodery hex/Base64/IP/message.

### Mutation survivors: equivalent vs actionable

Mutation testing często generuje zaszumioną listę survivors. Zanim uznasz każdego survivora za security gap, użyj grafu i sprawdź:

- Czy zmodyfikowana funkcja jest osiągalna z entrypoint kontrolowanego przez atakującego?
- Czy wszystkie ścieżki wywołań są ograniczone przez silniejsze invariants niż zmodyfikowany check?
- Czy węzeł znajduje się w dead code, logice dotyczącej wyłącznie formatowania, czy w high-impact arithmetic/parser path?

Survivors, które pozostają nieosiągalne lub są strukturalnie ograniczone, są często **equivalent mutants**. Survivors, które pozostają **reachable** i dotyczą **boundary conditions**, **overflow/carry paths** lub **security-critical arithmetic/parsing**, należy przekształcić w:

- nowe fuzz harnesses
- bezpośrednie property/invariant tests
- targeted edge-case vectors

### Korelowanie zewnętrznych findings z grafem

Jeśli Twój pipeline SAST eksportuje **SARIF**, odwzoruj findings na węzły grafu według **file + line range** i użyj grafu do rozszerzenia analizy wpływu.<sup>[[6]](#references)</sup>

- oblicz **blast radius** oznaczonej funkcji
- sprawdź, czy finding znajduje się na którejkolwiek ścieżce od entrypoint
- pogrupuj pobliskie findings, które sprowadzają się do tego samego choke point

Jest to przydatne przy podejmowaniu decyzji, czy przeznaczyć czas fuzzingu na konkretną funkcję: węzeł, który jest **reachable**, złożony i ma już **SAST hits**, jest często lepszym celem niż węzeł tylko złożony, bez ścieżki prowadzącej od atakującego.

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
Ważną metodologią jest przecięcie: **complexity x exposure x impact**. Użyj wykresu, aby wybrać cele fuzzingu o najwyższej oczekiwanej wartości dla bezpieczeństwa, a następnie użyj mutation survivors, aby określić, które granice i invariants musi testować Twój harness.<sup>[[5]](#references)</sup>

## Go Fuzzing With gosentry: Silniejszy silnik, typowane dane wejściowe i kontrole różnicowe

Jeśli cel napisany w Go ma już natywny harness `testing.F`, praktyczną ścieżką ulepszenia jest uruchomienie tego samego harnessu za pomocą [gosentry](https://github.com/trailofbits/gosentry) — forkowanego toolchaina Go, który zachowuje `go test -fuzz`, ale zamienia backend na **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Jest to przydatne, gdy natywny Go fuzzer zatrzymuje się na **trudnych porównaniach**, **typowanych danych wejściowych** lub **formatach wymagających intensywnego parsowania**. Metodyka pozostaje taka sama:

- Nadal używaj `f.Add(...)` dla seedów i `f.Fuzz(...)` dla callbacka.
- Użyj ponownie tego samego harnessu, ale uruchom go za pomocą pliku binarnego `go` z gosentry zamiast standardowego toolchaina.
- Traktuj wynikową kampanię jak zwykłe fuzzing sterowane pokryciem kodu, ale z harmonogramowaniem/mutacjami LibAFL i lepszymi dodatkowymi detektorami.

### Zamiana cichych awarii w wyniki fuzzingu

Powtarzającym się problemem podczas assessmentów Go jest to, że niebezpieczne zachowanie często **domyślnie nie powoduje crasha**. Za pomocą gosentry możesz przekształcić kilka klas stanów „złych, ale cichych” w wyniki fuzzingu.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` powoduje, że wybrane ścieżki logowania/błędów zachowują się jak crashe (przydatne w ścieżkach kodu w stylu `log.Fatal`, które w przeciwnym razie tylko logują i działają dalej).
- `--catch-races=true` ponownie uruchamia nowo odkryte wpisy kolejki z detektorem race dla Go.
- `--catch-leaks=true` ponownie uruchamia nowe wpisy kolejki z `goleak` i zatrzymuje się po wykryciu wycieków goroutines.
- Obsługa hangów przez LibAFL pozwala zachować **nieskończone pętle / bardzo wolne dane wejściowe** jako wyniki fuzzingu, zamiast pozwalać, aby znikały jako timeouty.
- Domyślnie wbudowane kontrole przepełnienia arytmetycznego oraz opcjonalne kontrole truncation za pośrednictwem instrumentacji w stylu go-panikint.

Jest to szczególnie cenne w przypadku celów, w których wpływ na bezpieczeństwo wynika z **awarii parsera bez panic**, **błędu współbieżności** lub **hangów powodujących wyłącznie DoS**, a nie z uszkodzenia pamięci.

### Fuzzing uwzględniający struktury dla typowanych API Go

Natywny Go fuzzing obsługuje głównie skalary, takie jak `[]byte`, `string` i liczby. Jeśli testowany kod przyjmuje obiekty typowane, gosentry może fuzzować bezpośrednio **wartości złożone** (structs, slices, arrays, pointers), jednocześnie mutując znajdujące się pod nimi bajty.<sup>[[7]](#references)[[8]](#references)</sup>
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
Use this when building a fake wire format just for fuzzing would hide logic bugs behind harness-only parsing code. For differential or grammar-based campaigns, keep the harness input as a single `[]byte` or `string` and parse inside the callback instead.

### Grammar-based fuzzing for parsers and protocol inputs

For parsers, formats, and input languages, gosentry can run **Nautilus grammar fuzzing** on top of LibAFL. The grammar is a JSON array of production rules, and the harness should usually take a single `[]byte` or `string` argument.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Uwagi dotyczące metodologii:

- Używaj Grammar mode, gdy mutacje na poziomie bajtów przeważnie kończą działanie na wczesnych kontrolach składni.
- Skup Grammar na **podzbiorze języka/protokołu istotnym z punktu widzenia bezpieczeństwa**, zamiast modelować pełną specyfikację.
- Używaj dużych wartości granicznych w terminalach/ nieterminalach, aby obciążyć granice liczb całkowitych, długości i maszyn stanów.
- Grammar mode utrzymuje poprawność wejść względem gramatyki, ale cel nadal otrzymuje **bytes/strings**, więc parsowanie i kontrole semantyczne nadal odbywają się w kodzie objętym harnessingiem.

### Differential fuzzing: porównuj implementacje, a nie tylko crashe

Skutecznym wzorcem w ekosystemach Go jest **grammar-based differential fuzzing**: generowanie poprawnych, ustrukturyzowanych wejść i przekazywanie ich do dwóch parserów, klientów lub silników przejść między stanami.<sup>[[7]](#references)[[8]](#references)</sup>
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
Traktuj następujące sytuacje jako wyniki:

- jedna implementacja kończy działanie przez panic, podczas gdy druga odrzuca dane w kontrolowany sposób
- niezgodność między akceptowanymi i odrzucanymi danymi wejściowymi
- różne drzewa parsowania lub zdekodowane obiekty
- rozbieżne przejścia stanów, nonce, salda lub rooty stanu

To praktyczny sposób na wykrywanie **niezgodności konsensusu**, **niejednoznaczności parsera** oraz **rozbieżności między specyfikacją a implementacją**, które często umykają podczas fuzzingu ukierunkowanego wyłącznie na awarie.

### Ponowne wykorzystanie corpus kampanii do raportowania pokrycia

Po zakończeniu kampanii odtwórz zapisany corpus kolejki, aby wygenerować raport pokrycia Go bez konieczności ręcznego eksportowania osobnego corpus.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Uruchom polecenie z **tego samego pakietu** i z tym samym celem `-fuzz`, aby gosentry rozpoznał właściwy stan kampanii w cache.

## References

- [1] [Fuzzing gramatyczny z mutacjami](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing w praktyce](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pięć lat później: fuzzing protokołów sterowany pokryciem](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark zamienia kod w grafy](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [W Go brakowało połowy narzędzi do fuzzingu. Rozszerzyliśmy toolchain, aby to naprawić.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: szybki greybox fuzzer dla stanowych protokołów sieciowych wykorzystujący snapshoty](https://arxiv.org/abs/2202.03643)
- [10] [Brak gramatyki? Żaden problem: w kierunku fuzzingu jądra Linux bez opisów wywołań systemowych](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: wydajny fuzzing z adaptacyjnymi i zmiennymi snapshotami](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
