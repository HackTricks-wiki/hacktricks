# Metodologia fuzzingu

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage a semantyka

W **mutational grammar fuzzing** dane wejściowe są modyfikowane przy zachowaniu **poprawności względem gramatyki**. W trybie sterowanym coverage zapisywane są jako ziarna corpusu wyłącznie próbki wywołujące **nowy coverage**. W przypadku **targetów językowych** (parserów, interpreterów, silników) może to pomijać błędy wymagające **łańcuchów semantycznych/dataflow**, w których wynik jednego konstruktu staje się danymi wejściowymi kolejnego.<sup>[[1]](#references)</sup>

**Tryb awarii:** fuzzer znajduje ziarna, które niezależnie wykonują `document()` i `generate-id()` (lub podobne prymitywy), ale **nie zachowuje łańcuchowego dataflow**, więc próbka „bliższa błędowi” jest odrzucana, ponieważ nie zwiększa coverage. Przy **3+ zależnych krokach** losowa rekombinacja staje się kosztowna, a feedback z coverage nie ukierunkowuje wyszukiwania.<sup>[[1]](#references)</sup>

**Wniosek:** w przypadku gramatyk z dużą liczbą zależności rozważ **hybrydyzację faz mutational i generative** albo ukierunkowanie generowania na wzorce **łączenia funkcji** (a nie wyłącznie na coverage).<sup>[[1]](#references)</sup>

## Pułapki związane z różnorodnością corpusu

Mutacja sterowana coverage jest **zachłanna**: próbka z nowym coverage jest zapisywana natychmiast, często z zachowaniem dużych niezmienionych obszarów. Z czasem corpusy stają się **niemal identycznymi kopiami** o małej różnorodności strukturalnej. Agresywna minimalizacja może usunąć użyteczny kontekst, dlatego praktycznym kompromisem jest **minimalizacja uwzględniająca gramatykę**, która **kończy działanie po osiągnięciu minimalnego progu tokenów** (redukuje szum, zachowując wystarczającą strukturę otoczenia, aby dane pozostały podatne na mutacje).<sup>[[1]](#references)</sup>

Praktyczna zasada dotycząca corpusu w mutational fuzzingu brzmi: **preferuj mały zestaw strukturalnie różnych ziaren maksymalizujących coverage** zamiast dużego zbioru niemal identycznych kopii. W praktyce zwykle oznacza to następujące działania.<sup>[[1]](#references)[[3]](#references)</sup>

- Zacznij od **próbek z rzeczywistego świata** (publiczne corpusy, crawling, przechwycony ruch, zbiory plików z ekosystemu targetu).
- Wyodrębnij z nich zestaw za pomocą **minimalizacji corpusu na podstawie coverage**, zamiast zachowywać każdą poprawną próbkę.
- Utrzymuj ziarna na tyle małe, aby mutacje trafiały w znaczące pola, zamiast przeznaczać większość cykli na nieistotne bajty.
- Ponownie uruchamiaj minimalizację corpusu po dużych zmianach harnessu lub instrumentacji, ponieważ „najlepszy” corpus zmienia się wraz ze zmianą osiągalności.

## Mutacja uwzględniająca porównania dla wartości magicznych

Częstym powodem plateau fuzzera nie jest składnia, lecz **trudne porównania**: magiczne bajty, sprawdzanie długości, stringi enumów, sumy kontrolne lub wartości używane do wyboru parsera, zabezpieczone przez `memcmp`, tablice switch albo kaskadowe porównania. Czysto losowa mutacja marnuje cykle na próby odgadnięcia tych wartości bajt po bajcie.

W przypadku takich targetów używaj **śledzenia porównań** (na przykład workflowów AFL++ `CMPLOG` / w stylu Redqueen), aby fuzzer mógł obserwować operandy z nieudanych porównań i ukierunkowywać mutacje na wartości, które je spełniają.<sup>[[3]](#references)</sup>
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

- Jest to szczególnie przydatne, gdy target ukrywa głęboką logikę za **sygnaturami plików**, **czasownikami protokołu**, **tagami typów** lub **bitami funkcji zależnymi od wersji**.
- Połącz to ze **słownikami** wyodrębnionymi z rzeczywistych próbek, specyfikacji protokołów lub logów debugowania. Mały słownik zawierający tokeny gramatyki, nazwy chunków, czasowniki i delimitery jest często bardziej wartościowy niż ogromna ogólna wordlista.
- Jeśli target wykonuje wiele sekwencyjnych kontroli, najpierw rozwiąż najwcześniejsze porównania „magic”, a następnie ponownie zminimalizuj wynikowy corpus, aby późniejsze etapy zaczynały od już poprawnych prefiksów.

## Bogatszy feedback, gdy edge coverage scala różne ścieżki

Standardowe edge coverage nie potrafi rozróżnić dwóch wykonań, które przechodzą przez ten sam helper z użyciem różnych callerów lub wybierają różne kombinacje branchy wewnątrz funkcji. Ma to znaczenie we współdzielonych dekoderach, dispatcherach protokołów i helperach interpreterów, gdzie **ścieżka** prowadząca do krawędzi określa aktywny stan. Naiwne śledzenie każdego kontekstu wywołania jest również niebezpieczne: mapa coverage i kolejka mogą gwałtownie się rozrosnąć. Badania nad fuzzingiem uwzględniającym kontekst zalecają więc doprecyzowywanie wyłącznie obiecujących kontekstów, zamiast traktowania całego grafu wywołań jako zależnego od kontekstu.<sup>[[14]](#references)</sup>

Nowsze buildy AFL++ zapewniają **pokrycie ścieżek Ball-Larus dla poszczególnych funkcji** oprócz standardowego edge coverage. Przypisuje ono feature do każdej acyklicznej ścieżki przechodzącej przez funkcję; back-edge pętli są usuwane, więc ten feedback rozróżnia kombinacje branchy, ale **nie liczbę iteracji pętli**. Zacznij od luźnego poziomu `1`, a następnie ogranicz bardziej restrykcyjne tryby do podejrzanego kodu parserów i state machine, ponieważ liczba ścieżek może rosnąć wykładniczo.<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
W przypadku helpera wywoływanego z wielu miejsc istotnych z punktu widzenia bezpieczeństwa tryb LTO może łączyć każdą ścieżkę funkcji z jej bezpośrednim miejscem wywołania:<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LTO_CALLER=1
export AFL_LLVM_LTO_PATH=1
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
**Wskazówka dotycząca kampanii:** ostrożnie stosuj bogatszy feedback i monitoruj jego koszt dla coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Uruchom równolegle zwykłą instancję z edge coverage; bogatszy feedback jest użyteczny tylko wtedy, gdy dodatkowy koszt queue/map nie niszczy liczby executions per second.
- Użyj `AFL_LLVM_ALLOWLIST`, aby ograniczyć instrumentację ścieżek/callerów, gdy duże biblioteki z dużą liczbą template’ów lub ogólny kod narzędziowy dominują w mapie.
- Funkcje z nadmierną liczbą acyclic paths można pomijać w AFL++; ostrzeżenia podczas kompilacji wskazują, że target wymaga allowlistingu lub mniej restrykcyjnego poziomu.
- Caller + path coverage obsługuje tylko jeden poziom caller depth. Nie łącz tego z głębszymi context stacks.
- Path IDs mogą zmieniać się między głównymi wersjami LLVM. Utrzymuj stały toolchain podczas kampanii i nie synchronizuj korpusów opartych na PATH tak, jakby ich feature IDs były stabilne między buildami.
- Ten feedback uzupełnia `CMPLOG`: comparison tracing rozwiązuje **jaka wartość przechodzi przez guard**, natomiast path/caller feedback zachowuje **jaka trasa i kombinacja branchy doprowadziły do tego miejsca**.

## Stateful Fuzzing: Sekwencje to Seedy

W przypadku **protocols**, **authenticated workflows** i **multi-stage parsers** interesującą jednostką często nie jest pojedynczy blob, lecz **message sequence**. Połączenie całego transcriptu w jeden plik i jego ślepe mutowanie jest zwykle nieefektywne, ponieważ fuzzer mutuje każdy krok w równym stopniu, nawet gdy tylko późniejsza wiadomość dociera do podatnego stanu.<sup>[[4]](#references)</sup>

Bardziej skuteczny wzorzec polega na traktowaniu **samej sekwencji jako seeda** i używaniu **obserwowalnego stanu** (response codes, protocol states, parser phases, zwracane object types) jako dodatkowego feedbacku.<sup>[[4]](#references)</sup>

- Zachowuj **valid prefix messages** bez zmian i skup mutacje na wiadomości **sterującej przejściem**.
- Cache’uj identyfikatory i wartości generowane przez serwer z poprzednich odpowiedzi, gdy kolejny krok od nich zależy.
- Preferuj mutację/splicing per-message zamiast mutowania całego zserializowanego transcriptu jako nieprzejrzystego bloba.
- Jeśli protokół udostępnia znaczące response codes, używaj ich jako **taniego state oracle**, aby priorytetyzować sekwencje, które przechodzą głębiej.

Z tego samego powodu authenticated bugs, ukryte transitions lub parser bugs występujące „only-after-handshake” są często pomijane przez vanilla file-style fuzzing: fuzzer musi zachowywać **kolejność, stan i zależności**, a nie tylko strukturę.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Praktycznym sposobem połączenia **generative novelty** z **ponownym wykorzystaniem coverage** jest **restartowanie krótkotrwałych workerów** kierowanych do persistent servera. Każdy worker zaczyna z pustym corpusem, synchronizuje się po `T` sekundach, działa przez kolejne `T` sekund na połączonym corpusie, ponownie się synchronizuje, a następnie kończy pracę. Zapewnia to **świeże struktury w każdej generacji**, jednocześnie wykorzystując zgromadzony coverage.<sup>[[1]](#references)[[2]](#references)</sup>

**Serwer:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sekwencyjni workerzy (przykładowa pętla):**

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

- `-in empty` wymusza **świeży corpus** przy każdej generacji.
- `-server_update_interval T` przybliża **opóźnioną synchronizację** (najpierw nowe elementy, później ponowne użycie).
- W trybie grammar fuzzing początkowa synchronizacja z serverem jest domyślnie pomijana (nie ma potrzeby używania `-skip_initial_server_sync`).
- Optymalne `T` zależy od **targetu**; najlepsze rezultaty zwykle daje przełączenie po znalezieniu przez workera większości „łatwego” coverage.

## Snapshot Fuzzing dla targetów trudnych do objęcia harnessiem

Gdy kod, który chcesz testować, staje się dostępny dopiero po kosztownym przygotowaniu (uruchomieniu VM, ukończeniu logowania, odebraniu pakietu, sparsowaniu kontenera lub zainicjalizowaniu usługi), użyteczną alternatywą jest **snapshot fuzzing**: przechwyć stan gotowego procesu lub VM, wstrzykuj każdy przypadek testowy do ścieżki wejściowej targetu, wykonuj go do crashu/timeoutu i przywracaj snapshot. Pozwala to uniknąć powtarzania inicjalizacji lub prefiksów protokołu i jest przydatne w przypadku **usług sieciowych**, **firmware**, **powierzchni ataku dostępnych po uwierzytelnieniu** oraz **targetów binarnych**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Uruchom target do momentu, w którym interesujący stan będzie gotowy.
2. W tym momencie wykonaj snapshot **pamięci + rejestrów**.
3. Dla każdego przypadku testowego zapisz zmodyfikowane dane wejściowe bezpośrednio do odpowiedniego bufora guest/process.
4. Wykonuj kod do crashu/timeoutu/resetu.
5. Przywróć snapshot; w przypadku targetów VM, jeśli jest to obsługiwane, przywróć tylko **dirty pages**, a następnie powtórz operację.

Umieść snapshot możliwie blisko pierwszego kosztownego etapu parsowania/dispatchu, na przykład po punkcie `recv`/`read` lub deserializacji pakietu, i zapisz używany przez target bufor wejściowy. Jest to zgodne z zasadą adaptacyjnego umieszczania snapshotu, polegającą na przesuwaniu go głębiej w procesie przetwarzania danych wejściowych, aby uniknąć powtarzania pracy.<sup>[[11]](#references)</sup>

## Introspekcja harnessu: szybkie wykrywanie płytkich fuzzerów

Gdy kampania się zatrzymuje, problemem często nie jest mutator, lecz **harness**. Użyj introspekcji **osiągalności/coverage**, aby znaleźć funkcje, do których można statycznie dotrzeć z fuzz targetu, ale które podczas działania są rzadko pokrywane lub nie są pokrywane wcale. Takie funkcje zwykle wskazują na jeden z trzech problemów.<sup>[[12]](#references)</sup>

- Harness wchodzi do targetu zbyt późno lub zbyt wcześnie.
- W seed corpus brakuje całej rodziny funkcji.
- Target rzeczywiście potrzebuje **drugiego harnessu**, zamiast jednego, nadmiernie rozbudowanego harnessu typu „zrób wszystko”.

Jeśli korzystasz z workflow w stylu OSS-Fuzz / ClusterFuzz, Fuzz Introspector może porównać statyczną osiągalność z runtime coverage i wygenerować raporty na podstawie uruchomienia trwającego określony czas lub publicznego corpusu.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Użyj raportu, aby zdecydować, czy dodać nowy harness dla nieprzetestowanej ścieżki parsera, rozszerzyć corpus dla konkretnej funkcji czy podzielić monolityczny harness na mniejsze entrypointy.

## Wybór celów fuzzowania i triage mutacji w pierwszej kolejności na podstawie grafu

Jeśli masz już **static-analysis findings**, **mutation-testing survivors** i **coverage reports**, nie analizuj ich jako niezależnych list. Najpierw zbuduj **call graph**, opisz węzły za pomocą **cyclomatic complexity**, **entrypoint/untrusted-input reachability** oraz wszelkich zewnętrznych ustaleń, a następnie zadawaj pytania dotyczące grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Które funkcje o wysokiej złożoności są osiągalne z niezaufanego wejścia?
- Które mutation survivors znajdują się na ścieżkach od parserów/handlerów do kodu krytycznego dla bezpieczeństwa?
- Które funkcje są architektonicznymi choke points z niezwykle dużym **blast radius**?

Zwykle pozwala to znaleźć lepsze cele fuzzowania niż samo „najniższe coverage”. Parser/decoder o **high complexity** i potwierdzonym **external reachability** jest lepszym kandydatem na harness niż odizolowany wewnętrzny helper ze słabym coverage, ale bez ścieżki kontrolowanej przez atakującego.

### Praktyczny workflow triage

1. Zbuduj **code graph** na podstawie codebase'u i wyodrębnij metryki complexity/branch dla każdej funkcji.
2. Wymień **entrypoints** przyjmujące dane kontrolowane przez atakującego: request handlery, decodery, importery, parsery protokołów, czytniki CLI/plików.
3. Uruchom **path queries** od tych entrypointów do kandydackich funkcji, aby oddzielić osiągalną attack surface od martwego kodu lub kodu dostępnego wyłącznie wewnętrznie.
4. Nadaj priorytet węzłom łączącym:
- wysoką **cyclomatic complexity**
- potwierdzoną **reachability from untrusted input**
- duży **blast radius** lub wielu downstream dependents
- dodatkowe dowody, takie jak ustalenia **SARIF**, notatki z audytu lub mutation survivors
5. Najpierw napisz skoncentrowane harnesses dla węzłów z najwyższą oceną, szczególnie dla **parserów/codeców**, takich jak dekodery hex/Base64/IP/message.

### Mutation survivors: equivalent vs actionable

Mutation testing często generuje zaszumioną listę survivors. Zanim uznasz każdego survivora za lukę w bezpieczeństwie, użyj grafu, aby zadać pytania:

- Czy zmodyfikowana funkcja jest osiągalna z entrypointu kontrolowanego przez atakującego?
- Czy wszystkie ścieżki wywołań są ograniczane przez silniejsze invariants niż zmodyfikowany check?
- Czy węzeł znajduje się w martwym kodzie, logice dotyczącej wyłącznie formatowania czy w wysokiego wpływu ścieżce arithmetic/parser?

Survivors, które pozostają nieosiągalne lub są strukturalnie ograniczone, są często **equivalent mutants**. Survivors, które pozostają **reachable** i dotykają **boundary conditions**, **overflow/carry paths** lub **security-critical arithmetic/parsing**, powinny zostać przekształcone w:

- nowe fuzz harnesses
- bezpośrednie property/invariant tests
- ukierunkowane edge-case vectors

### Korelowanie zewnętrznych ustaleń z grafem

Jeśli Twój pipeline SAST eksportuje **SARIF**, nanieś ustalenia na węzły grafu według **file + line range** i użyj grafu do rozszerzenia analizy wpływu.<sup>[[6]](#references)</sup>

- oblicz **blast radius** oznaczonej funkcji
- sprawdź, czy ustalenie znajduje się na dowolnej ścieżce od entrypointu
- grupuj pobliskie ustalenia, które sprowadzają się do tego samego choke point

Jest to przydatne przy decydowaniu, czy poświęcić czas fuzzowania konkretnej funkcji: węzeł, który jest **reachable**, **complex** i ma już **SAST hits**, jest często lepszym celem niż jedynie złożony węzeł bez ścieżki ataku.

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
Najważniejszą metodologią jest przecięcie: **złożoność x ekspozycja x wpływ**. Użyj wykresu, aby wybrać cele fuzzingu o najwyższej oczekiwanej wartości z punktu widzenia bezpieczeństwa, a następnie wykorzystaj mutation survivors do określenia, które granice i niezmienniki musi testować Twój harness.<sup>[[5]](#references)</sup>

## Fuzzing Go za pomocą gosentry: silniejszy silnik, typowane dane wejściowe i kontrole różnicowe

Jeśli cel napisany w Go ma już natywny harness `testing.F`, praktyczną ścieżką ulepszenia jest uruchomienie tego samego harnessa za pomocą [gosentry](https://github.com/trailofbits/gosentry) — rozwidlonego toolchaina Go, który zachowuje `go test -fuzz`, ale zamienia backend na **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Jest to przydatne, gdy natywny Go fuzzer zatrzymuje się na **trudnych porównaniach**, **typowanych danych wejściowych** lub **formatach intensywnie wykorzystujących parsery**. Metodyka pozostaje taka sama:

- Nadal używaj `f.Add(...)` dla seedów i `f.Fuzz(...)` dla callbacka.
- Użyj ponownie tego samego harnessu, ale uruchom go za pomocą pliku binarnego `go` z gosentry zamiast standardowego toolchaina.
- Traktuj wynikową kampanię jako zwykłe uruchomienie sterowane pokryciem kodu, ale z harmonogramowaniem/mutacjami LibAFL i lepszymi dodatkowymi detektorami.

### Zamiana cichych awarii w ustalenia fuzzera

Powtarzającym się problemem w audytach Go jest to, że niebezpieczne zachowanie często **domyślnie nie powoduje crasha**. Dzięki gosentry można przekształcić kilka klas „złych, ale cichych” stanów w ustalenia fuzzera.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` sprawia, że wybrane ścieżki logowania/błędów zachowują się jak crashe (przydatne w ścieżkach kodu w stylu `log.Fatal`, które w przeciwnym razie tylko logują i działają dalej).
- `--catch-races=true` uruchamia ponownie nowo odkryte wpisy kolejki z detektorem race Go.
- `--catch-leaks=true` uruchamia ponownie nowe wpisy kolejki z `goleak` i zatrzymuje się po wykryciu wycieków goroutines.
- Obsługa zawieszeń LibAFL pozwala zachować **nieskończone pętle / bardzo wolne dane wejściowe** jako ustalenia fuzzera, zamiast pozwalać im zniknąć jako timeoutom.
- Domyślnie wbudowane kontrole przepełnienia arytmetycznego oraz opcjonalne kontrole obcięcia za pomocą instrumentacji w stylu go-panikint.

Jest to szczególnie wartościowe w przypadku celów, w których wpływem na bezpieczeństwo jest **awaria parsera bez paniki**, **błąd współbieżności** lub **zawieszenie powodujące wyłącznie DoS**, a nie uszkodzenie pamięci.

### Fuzzing uwzględniający struktury dla typowanych API Go

Natywny Go fuzzing obsługuje głównie skalary, takie jak `[]byte`, `string` i liczby. Jeśli testowany kod przyjmuje typowane obiekty, gosentry może fuzzować bezpośrednio **wartości złożone** (struktury, slice'y, tablice, wskaźniki), jednocześnie mutując znajdujące się pod nimi bajty.<sup>[[7]](#references)[[8]](#references)</sup>
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
Użyj tego, ponieważ tworzenie fikcyjnego wire format wyłącznie na potrzeby fuzzing ukrywałoby błędy logiczne za kodem parsowania używanym tylko przez harness. W przypadku kampanii differential lub grammar-based zachowaj dane wejściowe harness jako pojedynczy `[]byte` lub `string` i parsuj je wewnątrz callback zamiast tego.

### Grammar-based fuzzing dla parserów i danych wejściowych protokołów

W przypadku parserów, formatów i języków wejściowych gosentry może uruchamiać **Nautilus grammar fuzzing** na bazie LibAFL. Gramatyka jest tablicą reguł produkcji w formacie JSON, a harness powinien zwykle przyjmować pojedynczy argument `[]byte` lub `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Uwagi dotyczące metodologii:

- Używaj grammar mode, gdy mutacje na poziomie bajtów w większości kończą działanie na wczesnych kontrolach składni.
- Skup grammar na **podzbiorze języka/protokołu istotnym z punktu widzenia bezpieczeństwa**, zamiast modelować całą specyfikację.
- Używaj dużych wartości granicznych w terminalach/nieterminalach, aby obciążać granice liczb całkowitych, długości i maszyn stanów.
- Grammar mode utrzymuje poprawność danych wejściowych względem gramatyki, ale cel nadal otrzymuje `bytes/strings`, więc parsowanie i kontrole semantyczne nadal odbywają się wewnątrz kodu objętego harnessingiem.

### Differential fuzzing: porównuj implementacje, nie tylko crashe

Silnym wzorcem w ekosystemach Go jest **grammar-based differential fuzzing**: generowanie poprawnych, ustrukturyzowanych danych wejściowych i przekazywanie ich do dwóch parserów, klientów lub silników przejść między stanami.<sup>[[7]](#references)[[8]](#references)</sup>
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
Traktuj poniższe przypadki jako findings:

- jedna implementacja wywołuje panic, podczas gdy druga odrzuca dane w kontrolowany sposób
- niezgodność między zaakceptowanymi i odrzuconymi danymi wejściowymi
- różne drzewa parsowania lub zdekodowane obiekty
- rozbieżne przejścia stanu, nonce, salda lub state roots

To praktyczny sposób wykrywania **consensus mismatches**, **parser ambiguity** oraz **spec-vs-implementation drift**, których często nie wykrywa czyste crash fuzzing.

### Wykorzystaj corpus kampanii do raportowania coverage

Po zakończeniu kampanii odtwórz zapisany queue corpus, aby wygenerować raport Go coverage bez konieczności ręcznego eksportowania osobnego corpus.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Uruchom polecenie z **tego samego pakietu** i z tym samym celem `-fuzz`, aby gosentry rozwiązał właściwy stan buforowanej kampanii.



## References

- [1] [Fuzzing z gramatyką mutacyjną](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing AFL++ dogłębnie](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pięć lat później: fuzzing protokołów sterowany pokryciem](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark zamienia kod w grafy](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [W Go fuzzing nie obejmował połowy zestawu narzędzi. Rozwidłowaliśmy toolchain, aby to naprawić.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: szybki greybox fuzzer dla stanowych protokołów sieciowych wykorzystujący snapshoty](https://arxiv.org/abs/2202.03643)
- [10] [Brak gramatyki? Żaden problem: w kierunku fuzzingu jądra Linux bez opisów wywołań systemowych](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: wydajny fuzzing z adaptacyjnymi i mutowalnymi snapshotami](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentacja LLVM AFL++: pokrycie ścieżek i callerów](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predyktywny fuzzing wrażliwy na kontekst](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
{{#include ../banners/hacktricks-training.md}}
