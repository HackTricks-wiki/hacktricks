# Metodologia fuzzingu

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: pokrycie a semantyka

W **mutational grammar fuzzing** wejścia są modyfikowane z zachowaniem **poprawności gramatycznej**. W trybie sterowanym pokryciem jako ziarna korpusu zapisywane są tylko próbki, które powodują **nowe pokrycie**. W przypadku **celów językowych** (parserów, interpreterów, silników) takie podejście może nie wykryć błędów wymagających **łańcuchów semantycznych/przepływu danych**, w których wynik jednej konstrukcji staje się wejściem dla kolejnej.<sup>[[1]](#references)</sup>

**Tryb awarii:** fuzzer znajduje ziarna, które osobno uruchamiają `document()` i `generate-id()` (lub podobne prymitywy), ale **nie zachowuje łańcucha przepływu danych**, więc próbka „bliższa błędowi” zostaje odrzucona, bo nie zwiększa pokrycia. Przy **co najmniej 3 zależnych krokach** losowa rekombinacja staje się kosztowna, a informacja zwrotna o pokryciu nie pomaga w ukierunkowaniu wyszukiwania.<sup>[[1]](#references)</sup>

**Wniosek:** w przypadku gramatyk z licznymi zależnościami warto rozważyć **połączenie faz mutacyjnej i generatywnej** albo ukierunkowanie generowania na wzorce **łączenia funkcji** (a nie tylko na pokrycie).<sup>[[1]](#references)</sup>

## Pułapki związane z różnorodnością korpusu

Mutacje sterowane pokryciem są **zachłanne**: próbka zwiększająca pokrycie jest od razu zapisywana i często zachowuje duże, niezmienione fragmenty. Z czasem korpusy stają się **niemal identycznymi duplikatami** o niewielkiej różnorodności strukturalnej. Agresywna minimalizacja może usunąć przydatny kontekst, dlatego praktycznym kompromisem jest **minimalizacja uwzględniająca gramatykę**, która **zatrzymuje się po osiągnięciu minimalnego progu tokenów** (redukuje szum, zachowując wystarczająco dużo otaczającej struktury, by ułatwić mutacje).<sup>[[1]](#references)</sup>

Praktyczna zasada dotycząca korpusu w mutational fuzzing: **lepiej wybrać niewielki zestaw zróżnicowanych strukturalnie ziaren maksymalizujących pokrycie** niż dużą kolekcję niemal identycznych duplikatów. W praktyce zwykle oznacza to:<sup>[[1]](#references)[[3]](#references)</sup>

- Zacznij od **próbek z rzeczywistego świata** (publicznych korpusów, danych zebranych podczas crawlowania, przechwyconego ruchu, zbiorów plików z ekosystemu celu).
- Ogranicz ich liczbę za pomocą **minimalizacji korpusu opartej na pokryciu**, zamiast zachowywać każdą poprawną próbkę.
- Zachowuj odpowiednio **małe ziarna**, aby mutacje obejmowały znaczące pola, zamiast pochłaniać większość cykli na nieistotnych bajtach.
- Ponownie minimalizuj korpus po istotnych zmianach harnessu lub instrumentacji, ponieważ „najlepszy” korpus zmienia się wraz ze zmianą osiągalności.

## Mutacje uwzględniające porównania dla wartości magicznych

Częstym powodem, dla którego fuzzery przestają robić postępy, nie jest składnia, lecz **ścisłe porównania**: magiczne bajty, sprawdzanie długości, ciągi enum, sumy kontrolne lub wartości kierujące działaniem parsera, weryfikowane za pomocą `memcmp`, tablic `switch` lub serii porównań. Czysto losowe mutacje marnują cykle na odgadywanie tych wartości bajt po bajcie.

W przypadku takich celów używaj **śledzenia porównań** (na przykład `CMPLOG` w AFL++ lub przepływów pracy w stylu Redqueen), aby fuzzer mógł odczytywać operandy z nieudanych porównań i ukierunkowywać mutacje na wartości, które je spełniają.<sup>[[3]](#references)</sup>

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

- Jest to szczególnie przydatne, gdy cel blokuje dostęp do głębszej logiki za pomocą **sygnatur plików**, **czasowników protokołu**, **tagów typów** lub **bitów funkcji zależnych od wersji**.
- Połącz tę metodę ze **słownikami** wyodrębnionymi z rzeczywistych próbek, specyfikacji protokołów lub logów debugowania. Niewielki słownik tokenów gramatyki, nazw fragmentów, czasowników i separatorów często jest cenniejszy niż ogromna, ogólna lista słów.
- Jeśli cel wykonuje wiele kolejnych sprawdzeń, najpierw rozwiąż najwcześniejsze porównania „magic”, a następnie ponownie zminimalizuj uzyskany zbiór danych, by kolejne etapy rozpoczynały się od już poprawnych prefiksów.

## Bogatsze informacje zwrotne, gdy pokrycie krawędzi zlewa różne ścieżki

Zwykłe pokrycie krawędzi nie pozwala odróżnić dwóch wykonań, które przechodzą przez ten sam helper z różnymi funkcjami wywołującymi lub wybierają różne kombinacje gałęzi wewnątrz funkcji. Ma to znaczenie w przypadku współdzielonych dekoderów, dyspozytorów protokołów i helperów interpreterów, gdzie **ścieżka** prowadząca do krawędzi określa bieżący stan. Naiwne śledzenie każdego kontekstu wywołania również jest niebezpieczne: mapa pokrycia i kolejka mogą gwałtownie się rozrosnąć. Badania nad fuzzingiem uwzględniającym kontekst zalecają więc doprecyzowywanie tylko obiecujących kontekstów, zamiast traktowania całego grafu wywołań jako uwzględniającego kontekst.<sup>[[14]](#references)</sup>

Najnowsze wersje AFL++ zapewniają **pokrycie ścieżek per-function metodą Ball-Larus** oprócz zwykłego pokrycia krawędzi. Przypisuje ono cechę każdej acyklicznej ścieżce przez funkcję; krawędzie powrotne pętli są usuwane, więc te informacje zwrotne rozróżniają kombinacje gałęzi, ale **nie liczbę iteracji pętli**. Zacznij od łagodnego poziomu `1`, a następnie stosuj bardziej rygorystyczne tryby tylko do podejrzanego kodu parsera i maszyny stanów, ponieważ liczba ścieżek może rosnąć wykładniczo.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

W przypadku funkcji pomocniczej wywoływanej z wielu miejsc istotnych z punktu widzenia bezpieczeństwa tryb LTO może połączyć każdą ścieżkę funkcji z jej bezpośrednim miejscem wywołania:<sup>[[13]](#references)</sup>

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

**Wskazówki dotyczące kampanii:** ostrożnie stosuj bogatszy feedback i monitoruj jego koszt w postaci mapy pokrycia/kolejki.<sup>[[13]](#references)[[14]](#references)</sup>

- Uruchom równolegle zwykłą instancję z edge coverage; bogatszy feedback jest przydatny tylko wtedy, gdy dodatkowy koszt mapy/kolejki nie zmniejsza liczby wykonań na sekundę.
- Użyj `AFL_LLVM_ALLOWLIST`, aby ograniczyć instrumentację ścieżek/wywołujących, gdy duże biblioteki pełne szablonów lub ogólny kod narzędziowy zdominują mapę.
- Funkcje z nadmierną liczbą ścieżek acyklicznych można pominąć w AFL++; ostrzeżenia podczas kompilacji świadczą o tym, że cel wymaga allowlisty lub mniej rygorystycznego poziomu.
- Caller + path coverage obsługuje tylko jeden poziom wywołującego. Nie łącz tego z głębszymi stosami kontekstu.
- Identyfikatory ścieżek mogą się zmieniać między głównymi wersjami LLVM. W trakcie kampanii używaj niezmiennego toolchaina i nie synchronizuj korpusów opartych na PATH, zakładając, że ich identyfikatory cech pozostają stabilne między kompilacjami.
- Ten feedback uzupełnia `CMPLOG`: śledzenie porównań rozwiązuje problem **tego, jaka wartość przechodzi przez warunek**, a feedback dotyczący ścieżek/wywołujących zachowuje informację, **która trasa i kombinacja gałęzi doprowadziły do tego miejsca**.

## Stateful Fuzzing: sekwencje to seedy

W przypadku **protokołów**, **uwierzytelnionych przepływów pracy** i **parserów wieloetapowych** interesującą jednostką często nie jest pojedynczy blob, lecz **sekwencja komunikatów**. Połączenie całego transkryptu w jeden plik i jego bezmyślne mutowanie jest zwykle nieefektywne, ponieważ fuzzer mutuje wszystkie kroki jednakowo, nawet gdy tylko późniejszy komunikat prowadzi do podatnego stanu.<sup>[[4]](#references)</sup>

Skuteczniejszym podejściem jest traktowanie **samej sekwencji jako seedu** i wykorzystywanie **obserwowalnego stanu** (kodów odpowiedzi, stanów protokołu, faz parsera, typów zwracanych obiektów) jako dodatkowego feedbacku.<sup>[[4]](#references)</sup>

- Zachowuj **prawidłowe komunikaty prefiksowe** bez zmian i skup mutacje na komunikacie **sterującym przejściem**.
- Zachowuj identyfikatory i wartości generowane przez serwer z wcześniejszych odpowiedzi, gdy zależy od nich kolejny krok.
- W miarę możliwości mutuj i łącz poszczególne komunikaty zamiast mutować cały serializowany transkrypt jako nieprzezroczysty blob.
- Jeśli protokół udostępnia znaczące kody odpowiedzi, używaj ich jako **taniego oracle stanu**, aby nadawać priorytet sekwencjom, które docierają głębiej.

Z tego samego powodu błędy wymagające uwierzytelnienia, ukryte przejścia lub błędy parsera występujące „dopiero po uzgodnieniu połączenia” często umykają zwykłemu fuzzingowi plikowemu: fuzzer musi zachowywać **kolejność, stan i zależności**, a nie tylko strukturę.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing sterownika z wieloma klientami

Wysokie edge coverage nadal może nie wykryć błędów sterownika IPC, ponieważ pokrycie nie opisuje **własności obiektów, liczników referencji, oczekujących komunikatów, kolejności sprzątania ani przeplotów wątków**. Strona [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) omawia model obiektów sterownika; ten przykład skupia się na harnessie fuzzera. Android Binder to przydatny model: samo dotarcie do ścieżek alokacji i zwalniania nie wystarczy, jeśli fuzzer nie potrafi sprawić, by wiele procesów operowało na tym samym obiekcie jądra w wymaganej kolejności.<sup>[[15]](#references)</sup>

#### Modeluj protokół, a nie odizolowane bufory `ioctl`

Reprezentuj przypadek testowy jako uporządkowaną gramatykę **tożsamości klienta + operacji + ustrukturyzowanych argumentów**. Fuzzer Binder LKL używa protobuf i `libprotobuf-mutator`, z jednym trwałym klientem zarządzającym kontekstem oraz dwoma zwykłymi klientami. Semantyczny harness zachowuje relacje, które ślepa mutacja bajtów zniszczyłaby.<sup>[[15]](#references)</sup>

- Buforuj wartości zwracane przez wcześniejsze operacje. Na przykład `BC_FREE_BUFFER` musi ponownie użyć wskaźnika do bufora transakcji zwróconego przez wcześniejsze `ioctl`.
- Generuj prawidłowe domyślne odpowiedzi, aby transakcje synchroniczne mogły się zakończyć, a późniejsze operacje pozostały osiągalne.
- Odrzucaj niemożliwe przejścia, takie jak transakcje do samego siebie lub wiele oczekujących transakcji do tego samego celu.
- Zachowuj stan singletonu inicjalizacji poza resetem wykonywanym dla każdego wejścia. Binder dopuszcza tylko jedną rejestrację `BINDER_SET_CONTEXT_MGR` na uruchomienie systemu, więc wielokrotne niszczenie i odtwarzanie tego klienta unieważniłoby późniejsze wejścia.

Przydatny wzorzec wyścigu cyklu życia polega na tym, by jeden klient przekazał obiekt, rozpoczął sprzątanie wątku lub procesu, a klient odbierający równocześnie zwolnił bufor transakcji. W przykładzie CVE-2020-0423 przekazanie `BINDER_TYPE_WEAK_BINDER`, po którym `BINDER_THREAD_EXIT` ścigał się z `BC_FREE_BUFFER`, mogło zwolnić osadzony `binder_work`, gdy ścieżka sprzątania zamykającego się wątku wciąż z niego korzystała.<sup>[[15]](#references)</sup>

#### Przywróć kontrolowane przeploty w jądrze działającym w przestrzeni użytkownika

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) linkuje rzeczywisty kod jądra z harnessem w przestrzeni użytkownika i udostępnia jego interfejs wywołań systemowych przez `lkl_syscall`. Dzięki temu można łatwo koordynować stan protobuf, pokrycie i KASAN w jednym procesie. LKL zwykle wykonuje wywołanie systemowe bez przerywania go przez inny wątek jądra. W kampaniach wyścigów wstaw punkty `schedule()` przy wybranych granicach blokowania/odblokowywania i cyklu życia, a następnie pozwól harnessowi losowo wybierać kolejnego klienta w każdym punkcie ustąpienia. Ogranicz te punkty do wybranych miejsc, ponieważ każdy z nich zwiększa przestrzeń poszukiwań harmonogramu. Opisany przez badaczy losowy scheduler **nie jest częścią upstreamowego fuzzera Binder**.<sup>[[15]](#references)</sup>

#### Buduj i odtwarzaj serializowane seedy regresyjne

Upstreamowy harness przypina zgodną wersję `libprotobuf-mutator`, włącza instrumentację fuzzingu LKL i KASAN za pomocą `LKL_FUZZING=1`, a także włącza `CONFIG_MMU` dla Binder przez `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Po sprawdzeniu celowo podatnej rewizji lub zastosowaniu udokumentowanych upstream poprawek cofających zmiany zserializowany seed może odtworzyć cały przebieg zmiany stanu wielu klientów bez konieczności odtwarzania go w doraźnym proof of concept w C:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Potraktuj wynikowy błąd KASAN typu use-after-free jako potwierdzenie, że seed dotarł do podatnej ścieżki cyklu życia obiektu. **Nie** dowodzi on wystąpienia późniejszych prymitywów wymaganych do wykonania kodu w kernelu lub eskalacji uprawnień.<sup>[[16]](#references)</sup>

## Sztuczka zwiększania różnorodności na jednej maszynie (w stylu Jackalope)

Praktycznym sposobem na połączenie **generowania nowych przypadków** z **ponownym wykorzystaniem pokrycia** jest **restartowanie krótkotrwałych workerów** działających na trwałym serwerze. Każdy worker rozpoczyna pracę z pustym corpus, synchronizuje się po `T` sekundach, przez kolejne `T` sekund działa na połączonym corpus, ponownie się synchronizuje, a następnie kończy pracę. Dzięki temu **każda generacja tworzy nowe struktury**, a jednocześnie wykorzystuje zgromadzone pokrycie.<sup>[[1]](#references)[[2]](#references)</sup>

**Serwer:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Procesy robocze (przykładowa pętla):**

<details>
<summary>Pętla ponownego uruchamiania workera Jackalope</summary>

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

- `-in empty` wymusza **nowy corpus** przy każdej generacji.
- `-server_update_interval T` przybliża **opóźnioną synchronizację** (najpierw nowości, później ponowne użycie).
- W trybie grammar fuzzing **początkowa synchronizacja z serwerem jest domyślnie pomijana** (nie trzeba używać `-skip_initial_server_sync`).
- Optymalna wartość `T` **zależy od celu**; najlepiej przełączyć ją, gdy worker znajdzie już większość „łatwego” pokrycia.

## Snapshot Fuzzing dla celów trudnych do objęcia harness

Gdy kod, który chcesz testować, staje się dostępny dopiero **po kosztownym przygotowaniu** (uruchomieniu VM, zalogowaniu, odebraniu pakietu, sparsowaniu kontenera, zainicjalizowaniu usługi), przydatną alternatywą jest **snapshot fuzzing**: przechwyć gotowy stan procesu lub VM, wstrzyknij każdy przypadek testowy do ścieżki wejściowej celu, wykonuj go aż do crasha lub timeoutu, a następnie przywróć snapshot. Dzięki temu nie trzeba ponownie wykonywać inicjalizacji ani przetwarzać prefiksów protokołu. Metoda ta przydaje się w przypadku **usług sieciowych**, **firmware**, **powierzchni ataku dostępnych po uwierzytelnieniu** oraz **celów dostępnych wyłącznie w postaci binarnej**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Uruchom cel, aż osiągnie interesujący stan.
2. Wykonaj snapshot **pamięci i rejestrów** w tym momencie.
3. Dla każdego przypadku testowego zapisz zmodyfikowane dane wejściowe bezpośrednio w odpowiednim buforze gościa/procesu.
4. Wykonuj do crasha, timeoutu lub resetu.
5. Przywróć snapshot; w przypadku celów VM przywracaj tylko **zmodyfikowane strony**, jeśli jest to obsługiwane, a następnie powtórz.

Umieść snapshot możliwie blisko pierwszego kosztownego etapu parsowania lub dyspozycji, na przykład po `recv`/`read` albo po deserializacji pakietu, i zanotuj bufor wejściowy używany przez cel. Jest to zgodne z zasadą adaptacyjnego umieszczania snapshotu głębiej w przetwarzaniu danych wejściowych, aby uniknąć ponownego wykonywania tej samej pracy.<sup>[[11]](#references)</sup>

## Introspekcja harness: wcześnie wykrywaj płytkie fuzzery

Gdy kampania się zatrzymuje, problemem często nie jest mutator, lecz **harness**. Użyj **introspekcji osiągalności/pokrycia**, aby znaleźć funkcje, które są statycznie osiągalne z celu fuzzingu, ale rzadko lub nigdy nie są pokrywane dynamicznie. Zwykle wskazuje to na jeden z trzech problemów.<sup>[[12]](#references)</sup>

- Harness wchodzi do celu zbyt późno lub zbyt wcześnie.
- W seed corpus brakuje całej rodziny funkcji.
- Cel rzeczywiście wymaga **drugiego harness**, a nie jednego nadmiernie rozbudowanego harness typu „zrób wszystko”.

Jeśli korzystasz z przepływów pracy w stylu OSS-Fuzz / ClusterFuzz, Fuzz Introspector może porównać statyczną osiągalność z pokryciem w czasie działania i wygenerować raporty na podstawie uruchomienia o określonym czasie trwania lub publicznego corpus.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Użyj raportu, aby zdecydować, czy dodać nowy harness dla nieprzetestowanej ścieżki parsera, rozszerzyć korpus dla konkretnej funkcji czy podzielić monolityczny harness na mniejsze punkty wejścia.

## Wybór celów fuzzingu w pierwszej kolejności na podstawie grafu i analiza mutacji

Jeśli masz już wyniki **analizy statycznej**, **mutanty, które przetrwały testy mutacyjne**, oraz **raporty pokrycia**, nie analizuj ich jako niezależnych list. Najpierw zbuduj **graf wywołań**, opisz jego węzły za pomocą **złożoności cyklomatycznej**, **osiągalności z punktów wejścia/danych niezaufanych** oraz wszelkich zewnętrznych ustaleń, a następnie zadaj pytania dotyczące grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Które funkcje o wysokiej złożoności są osiągalne z niezaufanych danych?
- Które mutanty, które przetrwały, znajdują się na ścieżkach od parserów/handlerów do kodu krytycznego dla bezpieczeństwa?
- Które funkcje są architektonicznymi wąskimi gardłami o wyjątkowo dużym **blast radius**?

Zazwyczaj pozwala to znaleźć lepsze cele fuzzingu niż kierowanie się wyłącznie „najniższym pokryciem”. Parser/dekoder o **wysokiej złożoności** i potwierdzonej **osiągalności z zewnątrz** jest lepszym kandydatem na harness niż odizolowany wewnętrzny helper o słabym pokryciu, do którego nie prowadzi żadna ścieżka kontrolowana przez atakującego.

### Praktyczny przepływ pracy przy analizie

1. Zbuduj **graf kodu** na podstawie codebase’u i wyodrębnij metryki złożoności/rozgałęzień dla poszczególnych funkcji.
2. Wypisz **punkty wejścia** przyjmujące dane kontrolowane przez atakującego: handlery żądań, dekodery, importery, parsery protokołów, czytniki CLI/plików.
3. Wykonaj zapytania o ścieżki od tych punktów wejścia do kandydatów, aby oddzielić osiągalną powierzchnię ataku od kodu nieosiągalnego lub wyłącznie wewnętrznego.
4. Nadaj priorytet węzłom, które łączą:
   - wysoką **złożoność cyklomatyczną**
   - potwierdzoną **osiągalność z niezaufanych danych**
   - duży **blast radius** lub wiele zależnych od nich elementów
   - dodatkowe potwierdzające przesłanki, takie jak ustalenia **SARIF**, notatki z audytu lub mutanty, które przetrwały
5. W pierwszej kolejności przygotuj ukierunkowane harnessy dla najlepiej ocenionych węzłów, zwłaszcza **parserów/kodeków**, takich jak dekodery hex/Base64/IP/wiadomości.

### Mutanty, które przetrwały: równoważne czy istotne

Testowanie mutacyjne często generuje zaszumioną listę mutantów, które przetrwały. Zanim uznasz każdy z nich za lukę w bezpieczeństwie, użyj grafu, aby sprawdzić:

- Czy zmodyfikowana funkcja jest osiągalna z punktu wejścia kontrolowanego przez atakującego?
- Czy wszystkie ścieżki wywołań są ograniczone silniejszymi niezmiennikami niż zmodyfikowany warunek?
- Czy węzeł znajduje się w martwym kodzie, logice służącej wyłącznie formatowaniu czy w ścieżce arytmetycznej/parsera o dużym wpływie?

Mutanty, które pozostają nieosiągalne lub są strukturalnie ograniczone, są często **mutantami równoważnymi**. Mutanty, które pozostają **osiągalne** i dotyczą **warunków brzegowych**, **ścieżek przepełnienia/przeniesienia** lub **arytmetyki/parsingowania krytycznych dla bezpieczeństwa**, należy uwzględnić w:

- nowych harnessach fuzzingowych
- bezpośrednich testach właściwości/niezmienników
- ukierunkowanych wektorach przypadków brzegowych

### Powiąż zewnętrzne ustalenia z grafem

Jeśli Twój pipeline SAST eksportuje **SARIF**, nanieś ustalenia na węzły grafu na podstawie **pliku i zakresu linii**, a następnie użyj grafu, aby określić ich szerszy wpływ.<sup>[[6]](#references)</sup>

- oblicz **blast radius** oznaczonej funkcji
- sprawdź, czy ustalenie znajduje się na którejkolwiek ścieżce od punktu wejścia
- pogrupuj sąsiadujące ustalenia, które zbiegają się w tym samym wąskim gardle

Jest to przydatne przy podejmowaniu decyzji, czy poświęcić czas na fuzzing konkretnej funkcji: węzeł, który jest **osiągalny**, **złożony** i ma już ustalenia **SAST**, jest często lepszym celem niż węzeł jedynie złożony, do którego nie prowadzi żadna ścieżka kontrolowana przez atakującego.

Przykładowy przepływ pracy z Trailmark.<sup>[[6]](#references)</sup>

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

Najważniejsza jest metodologia oparta na przecięciu: **złożoność x ekspozycja x wpływ**. Użyj wykresu, aby wybrać cele fuzzingu o najwyższej oczekiwanej wartości dla bezpieczeństwa, a następnie wykorzystaj mutacje, które przetrwały, do określenia, które granice i niezmienniki musi testować Twój harness.<sup>[[5]](#references)</sup>

## Fuzzowanie Go za pomocą gosentry: wydajniejszy silnik, typowane dane wejściowe i kontrole różnicowe

Jeśli cel w Go ma już natywny harness `testing.F`, praktycznym sposobem na jego ulepszenie jest uruchomienie tego samego harnessu za pomocą [gosentry](https://github.com/trailofbits/gosentry) — forka toolchaina Go, który zachowuje `go test -fuzz`, ale zamienia backend na **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Jest to przydatne, gdy natywny fuzzer Go zatrzymuje się na **trudnych porównaniach**, **typowanych danych wejściowych** lub **formatach intensywnie wykorzystujących parsery**. Metodologia pozostaje taka sama:

- Nadal używaj `f.Add(...)` do seedów i `f.Fuzz(...)` do callbacka.
- Użyj ponownie tego samego harnessa, ale uruchom go za pomocą pliku binarnego `go` z gosentry zamiast standardowego toolchaina.
- Traktuj wynikową kampanię jak zwykły przebieg sterowany pokryciem, ale z harmonogramowaniem i mutacjami LibAFL oraz lepszymi detektorami.

### Zamienianie cichych awarii w wyniki fuzzingu

Częstym problemem podczas ocen bezpieczeństwa Go jest to, że niebezpieczne zachowanie często domyślnie **nie powoduje awarii**. Dzięki gosentry można przekształcić kilka klas „złych, ale cichych” stanów w wyniki fuzzingu.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` sprawia, że wybrane ścieżki logowania/błędów zachowują się jak awarie (przydatne w przypadku ścieżek w stylu `log.Fatal`, które w przeciwnym razie tylko logują i działają dalej).
- `--catch-races=true` ponownie odtwarza nowo odkryte wpisy kolejki z detektorem race w Go.
- `--catch-leaks=true` ponownie odtwarza nowe wpisy kolejki z `goleak` i zatrzymuje działanie po wykryciu wycieków goroutine.
- Obsługa zawieszeń w LibAFL pozwala zachować **nieskończone pętle / bardzo wolne dane wejściowe** jako wyniki fuzzingu, zamiast pomijać je jako przekroczenia limitu czasu.
- Domyślnie wbudowane kontrole przepełnienia arytmetycznego oraz opcjonalne kontrole obcięcia przez instrumentację w stylu go-panikint.

Jest to szczególnie przydatne w przypadku celów, w których skutkiem dla bezpieczeństwa jest **awaria parsera bez paniki**, **błąd współbieżności** lub zawieszenie powodujące wyłącznie **DoS**, a nie uszkodzenie pamięci.

### Fuzzing uwzględniający struktury dla typowanych API Go

Natywny fuzzing w Go oczekuje głównie typów skalarnych, takich jak `[]byte`, `string` i liczby. Jeśli testowany kod przyjmuje typowane obiekty, gosentry może bezpośrednio fuzzować **wartości złożone** (struktury, slice’y, tablice, wskaźniki), jednocześnie mutując leżące u ich podstaw bajty.<sup>[[7]](#references)[[8]](#references)</sup>

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

Użyj tego, gdy tworzenie fikcyjnego formatu przewodowego wyłącznie na potrzeby fuzzingu ukrywałoby błędy logiczne za kodem parsującym przeznaczonym tylko dla harnessu. W kampaniach różnicowych lub opartych na gramatyce pozostaw dane wejściowe harnessu jako pojedyncze `[]byte` lub `string` i parsuj je w callbacku.

### Fuzzing oparty na gramatyce dla parserów i danych wejściowych protokołów

W przypadku parserów, formatów i języków wejściowych gosentry może uruchomić **fuzzing gramatyczny Nautilus** na bazie LibAFL. Gramatyka to tablica reguł produkcji w formacie JSON, a harness powinien zazwyczaj przyjmować jeden argument typu `[]byte` lub `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Uwagi dotyczące metodologii:

- Używaj trybu gramatycznego, gdy mutacje na poziomie bajtów najczęściej kończą się na wczesnych kontrolach składni.
- Ogranicz gramatykę do **istotnego z punktu widzenia bezpieczeństwa podzbioru** języka/protokołu, zamiast modelować całą specyfikację.
- Stosuj duże wartości graniczne w terminalach/nieterminalach, aby testować granice liczb całkowitych, długości i automatów stanów.
- Tryb gramatyczny zapewnia poprawność gramatyczną danych wejściowych, ale cel nadal otrzymuje **bajty/ciągi znaków**, więc parsowanie i kontrole semantyczne pozostają w kodzie objętym harness.

### Fuzzing różnicowy: porównuj implementacje, nie tylko awarie

Skutecznym podejściem w ekosystemach Go jest **fuzzing różnicowy oparty na gramatyce**: generuj poprawne, ustrukturyzowane dane wejściowe i przekazuj je do dwóch parserów, klientów lub silników przejść stanów.<sup>[[7]](#references)[[8]](#references)</sup>

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

Traktuj następujące przypadki jako wyniki:

- jedna implementacja wywołuje panic, a druga poprawnie odrzuca dane
- niezgodności w akceptowaniu lub odrzucaniu danych wejściowych
- różne drzewa parsowania lub zdekodowane obiekty
- rozbieżne zmiany stanu, nonce, salda lub korzenie stanu

To praktyczny sposób na wykrywanie **niezgodności konsensusu**, **niejednoznaczności parsera** i **rozbieżności między specyfikacją a implementacją**, które często umykają fuzzingowi ukierunkowanemu wyłącznie na awarie.

### Ponowne użycie corpus kampanii do raportowania pokrycia

Po zakończeniu kampanii odtwórz zapisany corpus kolejki, aby wygenerować raport pokrycia Go — bez ręcznego eksportowania osobnego corpus.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Uruchom polecenie z tego samego pakietu i z tym samym celem `-fuzz`, aby gosentry rozpoznał właściwy stan kampanii zapisany w pamięci podręcznej.



## References

- [1] [Mutacyjne fuzzing gramatyczne](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing dogłębnie](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pięć lat później: fuzzing protokołów sterowany pokryciem](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark zamienia kod w grafy](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [W Go fuzzingu brakowało połowy zestawu narzędzi. Sforkowaliśmy toolchain, aby to naprawić.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: szybki greybox fuzzer dla stanowych protokołów sieciowych wykorzystujący snapshoty](https://arxiv.org/abs/2202.03643)
- [10] [Bez gramatyki? Żaden problem: w kierunku fuzzingu jądra Linux bez opisów wywołań systemowych](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: wydajny fuzzing z adaptacyjnymi i mutowalnymi snapshotami](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentacja LLVM w AFL++: pokrycie ścieżek i wywołujących](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predykcyjny, kontekstowy fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Android Offensive Security - fuzzing Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer Binder w LKL Android - dokumentacja kompilacji i seedów regresyjnych](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
{{#include ../banners/hacktricks-training.md}}
