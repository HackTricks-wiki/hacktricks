# Metodologia fuzzingu

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: pokrycie a semantyka

W **mutational grammar fuzzing** wejścia są mutowane z zachowaniem **poprawności gramatycznej**. W trybie sterowanym pokryciem tylko próbki wywołujące **nowe pokrycie** są zapisywane jako ziarna corpus. W przypadku **celów językowych** (parserów, interpreterów, silników) może to przeoczyć błędy wymagające **łańcuchów semantycznych/przepływu danych**, w których wynik jednej konstrukcji staje się wejściem innej.<sup>[[1]](#references)</sup>

**Tryb awarii:** fuzzer znajduje ziarna, które osobno wykonują `document()` i `generate-id()` (lub podobne prymitywy), ale **nie zachowuje łańcuchowego przepływu danych**, przez co próbka „bliższa błędowi” zostaje odrzucona, bo nie zwiększa pokrycia. Przy **co najmniej 3 zależnych krokach** losowa rekombinacja staje się kosztowna, a informacja zwrotna o pokryciu nie naprowadza wyszukiwania.<sup>[[1]](#references)</sup>

**Wniosek:** w przypadku gramatyk z wieloma zależnościami warto rozważyć **połączenie faz mutacyjnej i generatywnej** albo ukierunkowanie generowania na wzorce **łączenia funkcji** (a nie tylko na pokrycie).<sup>[[1]](#references)</sup>

## Pułapki związane z różnorodnością corpus

Mutacje sterowane pokryciem są **zachłanne**: próbka dająca nowe pokrycie jest od razu zapisywana, często z dużymi, niezmienionymi fragmentami. Z czasem w corpus gromadzą się **niemal identyczne próbki** o niewielkiej różnorodności strukturalnej. Agresywna minimalizacja może usunąć przydatny kontekst, dlatego praktycznym kompromisem jest **minimalizacja uwzględniająca gramatykę**, która **zatrzymuje się po osiągnięciu minimalnego progu tokenów** (ogranicza szum, zachowując dość otaczającej struktury, by ułatwić dalsze mutacje).<sup>[[1]](#references)</sup>

Praktyczna zasada dotycząca corpus w mutational fuzzing: **lepiej wybrać niewielki zestaw strukturalnie różnych ziaren maksymalizujących pokrycie niż dużą kolekcję niemal identycznych próbek**. W praktyce zwykle oznacza to, co następuje.<sup>[[1]](#references)[[3]](#references)</sup>

- Zacznij od **próbek z rzeczywistego świata** (publicznych corpus, danych z crawlowania, przechwyconego ruchu, zestawów plików z ekosystemu danego celu).
- Ogranicz ich liczbę za pomocą **minimalizacji corpus opartej na pokryciu**, zamiast zachowywać każdą poprawną próbkę.
- Zadbaj, by ziarna były **wystarczająco małe**, tak aby mutacje obejmowały znaczące pola, zamiast poświęcać większość cykli na nieistotne bajty.
- Ponownie przeprowadź minimalizację corpus po istotnych zmianach harnessu lub instrumentacji, ponieważ „najlepszy” corpus zmienia się wraz ze zmianą osiągalności.

## Mutacje uwzględniające porównania dla wartości magicznych

Częstym powodem, dla którego fuzzery przestają robić postępy, nie jest składnia, lecz **ścisłe porównania**: bajty magiczne, sprawdzanie długości, ciągi enum, sumy kontrolne lub wartości sterujące parserem, chronione przez `memcmp`, tablice `switch` lub kaskadowe porównania. Czysto losowe mutacje marnują cykle na próbę odgadnięcia tych wartości bajt po bajcie.

W przypadku takich celów użyj **śledzenia porównań** (na przykład przepływów pracy w stylu AFL++ `CMPLOG` / Redqueen), aby fuzzer mógł obserwować operandy nieudanych porównań i kierować mutacje ku wartościom, które je spełniają.<sup>[[3]](#references)</sup>

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

- Jest to szczególnie przydatne, gdy cel ukrywa głębszą logikę za **sygnaturami plików**, **czasownikami protokołu**, **tagami typów** lub **bitami funkcji zależnymi od wersji**.
- Połącz tę metodę ze **słownikami** wyodrębnionymi z rzeczywistych próbek, specyfikacji protokołów lub logów debugowania. Mały słownik zawierający tokeny gramatyki, nazwy chunków, czasowniki i separatory jest często bardziej wartościowy niż ogromna, ogólna wordlista.
- Jeśli cel wykonuje wiele kolejnych sprawdzeń, najpierw rozwiąż najwcześniejsze porównania „magic”, a następnie ponownie zminimalizuj uzyskowany korpus, aby kolejne etapy zaczynały od poprawnych prefiksów.

## Fuzzing API plików ukrywających język nazw plików

Parametr o nazwie `filename`, `path` lub `URL` może być punktem wejścia interpretera, a nie dosłownym wyszukiwaniem pliku. Na przykład CFITSIO Extended Filename Syntax (EFS) przetwarza selektory w nawiasach kwadratowych, wyrażenia wierszy/pikseli, obliczane kolumny, histogramy i transformacje przed zwróceniem otwartego obiektu; niektóre formy tworzą też tymczasowe kopie. Podczas mapowania powierzchni ataku sklasyfikuj każde API otwierania/importowania jako **literal-path** lub **interpreted-path**, a następnie fuzzuj produkcyjny punkt wejścia, z którego faktycznie korzystają aplikacje.<sup>[[20]](#references)[[22]](#references)</sup>

Informacje o uzyskanych prymitywach SSRF, kopiowania plików i obsługi protokołów — oraz bezpieczniejszych API literal-path — znajdziesz w [mini-językach nazw plików jako prymitywach SSRF/file](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Oddziel obiekt bazowy od fuzzowanego programu

Gdy gramatyka znajduje się w sufiksie nazwy pliku, modyfikowanie wyłącznie bajtów wskazywanego pliku omija parser. Zamiast tego niewielki harness może odczytać jeden testcase jako ciąg znaków i przekazać go do interpretującego API otwierania; kampania CFITSIO dotarła do większości parserów i ewaluatorów EFS, wywołując `fits_open_file()` w trybie tylko do odczytu. Udostępnij osobno poprawne pliki bazowe, aby mutacje mogły koncentrować się na języku selektorów/wyrażeń, zamiast nieustannie psuć ścieżkę bazową.<sup>[[22]](#references)</sup>

Użyj seedów, z których każdy dociera do innej rodziny gramatyki, a następnie utwórz zwięzły słownik na podstawie zarówno specyfikacji, jak i źródeł lexera/parsera. Jeśli pokrycie przestaje rosnąć, a wejścia wielokrotnie kończą w tej samej ścieżce błędu składni, zachowaj poprawne prefiksy i dodaj separatory, operatory, słowa kluczowe, nazwy funkcji oraz przykładowe nazwy pól, zamiast jedynie wydłużać czas losowych mutacji.<sup>[[22]](#references)</sup>

Uruchom harness ze słownikiem gramatyki, na przykład:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Ograniczanie skutków ubocznych harnessu w trybie „read-only”

Flaga biblioteki „read-only” nie gwarantuje, że testcase nie wywoła skutków ubocznych: język nazw plików może przepisać dane wejściowe, utworzyć pliki wyjściowe lub utworzyć obiekty tymczasowe. Kampania CFITSIO początkowo niszczyła pliki seed i pozostawiała nieoczekiwane pliki w całym systemie plików, dlatego konieczne były czyszczenie i izolacja.<sup>[[22]](#references)</sup>

- Przydziel każdemu workerowi jednorazowy katalog roboczy i prywatny katalog tymczasowy.
- Udostępniaj kopie kanonicznych plików zaplecza; nigdy nie pozwalaj, by target modyfikował jedyną kopię corpus.
- Wyłącz dostęp do sieci, chyba że zdalne backendy są celem testów, i ogranicz zapisywalne ścieżki za pomocą kontenera, przestrzeni nazw montowań lub równoważnej piaskownicy.
- Resetuj katalog po każdym uruchomieniu lub partii workerów, a nieoczekiwane zmiany w systemie plików traktuj jako dodatkowe znaleziska.

### Pętla: crash → patch → fuzzing

Pogrupuj crashe przed naprawą, aby tysiące artefaktów nie zamieniły się w tysiące zadań związanych z patchami. W ocenie CFITSIO AFLTriage zredukował początkowy zbiór crashy do kilku przyczyn źródłowych; powstałe advisory opisuje różne błędy, w tym nieprawidłowe sprawdzanie rozmiaru bufora docelowego, nieaktualne wskaźniki po `realloc()`, błędy arytmetyczne i niebezpieczne ścieżki czyszczenia parsera.<sup>[[21]](#references)[[22]](#references)</sup>

1. Zminimalizuj reprezentatywne dane wejściowe dla każdego klastra i odtwórz problem z użyciem AddressSanitizer.
2. Zapisz dokładnie, jaki dostęp spowodował błąd, lokalizację w kodzie źródłowym, historię alokacji/zwalniania oraz stan parsera, który doprowadził do naruszenia niezmiennika.
3. Zastosuj jeden wąsko zakrojony patch kandydujący i przebuduj program z użyciem tej samej instrumentacji pokrycia i sanitizera.
4. Odtwórz pierwotny przypadek reprodukujący **i każde wejście z jego klastra**; włącz też wykrywanie wycieków, ponieważ poprawka dotycząca bezpieczeństwa pamięci może naruszyć zarządzanie własnością w ścieżce obsługi błędu.
5. Uruchom testy funkcjonalne na rzeczywistych plikach, a następnie wznów fuzzing z użyciem zgromadzonej kolejki (lub zaimportuj tę kolejkę ponownie, jeśli silnik wymaga nowego katalogu wyjściowego po zmianie pliku binarnego).
6. Powtarzaj: usunięcie pierwszego, płytkiego crasha często pozwala istniejącym seedom przejść do głębszego stanu parsera.

LLM może przyspieszyć krok 2 i przygotować szkic kroku 3, jeśli otrzyma powodujące crash dane wejściowe, raport sanitizera, harness i odpowiedni kod źródłowy, ale jego patch pozostaje niezaufany. O tym, czy poprawka zostanie zaakceptowana, decydują odtworzenie problemu z użyciem sanitizera i bramki regresyjne — nie wyjaśnienie modelu.<sup>[[22]](#references)</sup>

## Bogatszy feedback, gdy pokrycie krawędzi zlewa różne ścieżki

Zwykłe pokrycie krawędzi nie pozwala rozróżnić dwóch wykonań, które przechodzą przez ten sam helper z różnymi wywołującymi lub wybierają różne kombinacje gałęzi wewnątrz funkcji. Ma to znaczenie w współdzielonych dekoderach, dispatcherach protokołów i helperach interpreterów, gdzie **ścieżka** prowadząca do krawędzi określa aktywny stan. Naiwne śledzenie każdego kontekstu wywołania również jest niebezpieczne: mapa pokrycia i kolejka mogą gwałtownie się rozrosnąć. Badania nad fuzzingiem uwzględniającym kontekst zalecają więc doprecyzowywanie tylko obiecujących kontekstów, zamiast traktowania całego grafu wywołań jako uwzględniającego kontekst.<sup>[[14]](#references)</sup>

Najnowsze kompilacje AFL++ zapewniają **pokrycie ścieżek Ball-Larus dla poszczególnych funkcji** oprócz zwykłego pokrycia krawędzi. Przypisuje ono cechę każdej acyklicznej ścieżce przez funkcję; krawędzie powrotne pętli są usuwane, więc ten feedback rozróżnia kombinacje gałęzi, ale **nie liczbę iteracji pętli**. Zacznij od łagodnego poziomu `1`, a następnie stosuj bardziej rygorystyczne tryby tylko do podejrzanego kodu parsera/maszyny stanów, ponieważ liczba ścieżek może rosnąć wykładniczo.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

W przypadku funkcji pomocniczej wywoływanej z wielu miejsc istotnych z punktu widzenia bezpieczeństwa tryb LTO może łączyć każdą ścieżkę funkcji z jej bezpośrednim miejscem wywołania:<sup>[[13]](#references)</sup>

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

**Wskazówki dotyczące kampanii:** ostrożnie stosuj bogatszy feedback i monitoruj jego koszt pod względem mapy coverage i kolejki.<sup>[[13]](#references)[[14]](#references)</sup>

- Uruchom równolegle zwykłą instancję z edge coverage; bogatszy feedback jest przydatny tylko wtedy, gdy dodatkowy koszt mapy/kolejki nie zmniejsza liczby wykonywań na sekundę.
- Użyj `AFL_LLVM_ALLOWLIST`, aby ograniczyć instrumentację ścieżek/wywołujących, gdy duże biblioteki oparte na szablonach lub ogólny kod narzędziowy dominują w mapie.
- Funkcje z nadmierną liczbą ścieżek acyklicznych można pominąć w AFL++; ostrzeżenia podczas kompilacji wskazują, że cel wymaga allowlisty albo mniej rygorystycznego poziomu.
- Coverage wywołującego i ścieżki obsługuje tylko jeden poziom wywołującego. Nie łącz go z głębszymi stosami kontekstu.
- Identyfikatory ścieżek mogą się zmieniać między głównymi wersjami LLVM. Utrzymuj stały toolchain podczas kampanii i nie synchronizuj korpusów opartych na PATH tak, jakby ich identyfikatory funkcji były stabilne między kompilacjami.
- Ten feedback uzupełnia `CMPLOG`: śledzenie porównań pozwala ustalić, **jaka wartość przechodzi kontrolę**, natomiast feedback ścieżek/wywołujących zachowuje informację o tym, **która trasa i kombinacja gałęzi doprowadziły do tego miejsca**.

## Stateful Fuzzing: sekwencje są seedami

W przypadku **protokołów**, **uwierzytelnionych przepływów pracy** i **parserów wieloetapowych** interesującą jednostką często nie jest pojedynczy blob, lecz **sekwencja komunikatów**. Złączenie całej wymiany w jeden plik i ślepe mutowanie go jest zazwyczaj nieefektywne, ponieważ fuzzer mutuje każdy krok jednakowo, nawet jeśli tylko późniejszy komunikat dociera do podatnego stanu.<sup>[[4]](#references)</sup>

Skuteczniejszym podejściem jest traktowanie **samej sekwencji jako seeda** i używanie **obserwowalnego stanu** (kodów odpowiedzi, stanów protokołu, faz parsera, typów zwracanych obiektów) jako dodatkowego feedbacku.<sup>[[4]](#references)</sup>

- Zachowuj **poprawne komunikaty prefiksowe** bez zmian i skupiaj mutacje na komunikacie **sterującym przejściem**.
- Zapisuj identyfikatory i wartości wygenerowane przez serwer w poprzednich odpowiedziach, jeśli kolejny krok od nich zależy.
- Preferuj mutowanie/łączenie poszczególnych komunikatów zamiast mutowania całego serializowanego przepływu jako nieprzezroczystego bloba.
- Jeśli protokół udostępnia znaczące kody odpowiedzi, używaj ich jako **taniego oracle stanu**, aby priorytetyzować sekwencje przechodzące głębiej.

To z tego samego powodu błędy uwierzytelniania, ukryte przejścia lub błędy parsera występujące „dopiero po handshake” są często pomijane przez zwykły fuzzing plików: fuzzer musi zachowywać **kolejność, stan i zależności**, a nie tylko strukturę.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing sterownika z wieloma klientami

Wysokie edge coverage nadal może nie wykryć błędów sterownika IPC, ponieważ coverage nie opisuje **własności obiektów, liczników referencji, oczekujących komunikatów, kolejności sprzątania ani przeplotów wątków**. Strona [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) omawia model obiektów sterownika; ten przykład koncentruje się na harnessie fuzzera. Android Binder jest użytecznym przykładem: dotarcie zarówno do ścieżek alokacji, jak i zwalniania nie wystarczy, jeśli fuzzer nie potrafi sprawić, by wiele procesów operowało na tym samym obiekcie jądra w wymaganej kolejności.<sup>[[15]](#references)</sup>

#### Modeluj protokół, a nie odizolowane bufory `ioctl`

Reprezentuj przypadek testowy jako uporządkowaną gramatykę **tożsamość klienta + operacja + ustrukturyzowane argumenty**. Fuzzer Binder LKL używa protobuf i `libprotobuf-mutator`, z jednym trwałym klientem menedżera kontekstu i dwoma zwykłymi klientami. Semantyczny harness zachowuje relacje, które ślepa mutacja bajtów by zniszczyła.<sup>[[15]](#references)</sup>

- Zapisuj wartości zwrócone przez wcześniejsze operacje. Na przykład `BC_FREE_BUFFER` musi ponownie użyć wskaźnika bufora transakcji zwróconego przez wcześniejsze `ioctl`.
- Generuj poprawne domyślne odpowiedzi, aby transakcje synchroniczne mogły się zakończyć, a późniejsze operacje pozostały osiągalne.
- Odrzucaj niemożliwe przejścia, takie jak transakcje do samego siebie lub wiele oczekujących transakcji do tego samego celu.
- Utrzymuj stan singletonu inicjalizacji poza resetowaniem wykonywanym dla każdego wejścia. Binder dopuszcza tylko jedną rejestrację `BINDER_SET_CONTEXT_MGR` podczas uruchomienia, więc wielokrotne niszczenie i odtwarzanie tego klienta unieważniłoby późniejsze wejścia.

Przydatny szablon wyścigu w cyklu życia obiektu polega na tym, by jeden klient przekazał obiekt, rozpoczął sprzątanie wątku lub procesu, a równocześnie klient odbierający zwolnił bufor transakcji. W przykładzie CVE-2020-0423 przekazanie `BINDER_TYPE_WEAK_BINDER`, po którym `BINDER_THREAD_EXIT` ścigało się z `BC_FREE_BUFFER`, mogło zwolnić osadzony `binder_work`, gdy ścieżka sprzątania kończącego się wątku nadal go używała.<sup>[[15]](#references)</sup>

#### Ponownie wprowadź kontrolowane przeploty w jądrze działającym w przestrzeni użytkownika

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) łączy rzeczywisty kod jądra z harnessem działającym w przestrzeni użytkownika i udostępnia jego interfejs syscall przez `lkl_syscall`. Dzięki temu można łatwo koordynować protobuf, coverage i KASAN w jednym procesie. LKL zwykle wykonuje syscall bez przerywania go przez inny wątek jądra. W kampaniach badających wyścigi wstaw punkty `schedule()` wokół wybranych granic blokowania/odblokowywania i cyklu życia, a następnie pozwól harnessowi losowo wybierać kolejnego klienta przy każdym ustąpieniu sterowania. Ogranicz te punkty do wybranych miejsc, ponieważ każdy z nich zwiększa przestrzeń wyszukiwania harmonogramu. Opisany przez badaczy losowy scheduler **nie jest częścią upstreamowego fuzzera Binder**.<sup>[[15]](#references)</sup>

#### Buduj i odtwarzaj serializowane seedy regresyjne

Upstreamowy harness przypina zgodną wersję `libprotobuf-mutator`, włącza instrumentację fuzzingu LKL i KASAN przez `LKL_FUZZING=1`, a dla Binder włącza `CONFIG_MMU` za pomocą `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Po przejściu na celowo podatną rewizję lub zastosowaniu udokumentowanych upstream poprawek cofających zmiany, zserializowany seed może odtworzyć cały przebieg zmiany stanu wielu klientów bez konieczności rekonstruowania go w doraźnym proof of concept w C:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Potraktuj wynikowy błąd KASAN typu use-after-free jako potwierdzenie, że seed dotarł do podatnej ścieżki życia obiektu. **Nie** dowodzi on istnienia późniejszych prymitywów wymaganych do wykonania kodu w kernelu ani eskalacji uprawnień.<sup>[[16]](#references)</sup>

## Trik różnorodności na jednej maszynie (w stylu Jackalope)

Praktycznym sposobem na połączenie **generowania nowych danych** z **ponownym wykorzystaniem pokrycia** jest uruchamianie krótkotrwałych workerów przeciwko trwałemu serwerowi. Każdy worker rozpoczyna od pustego corpus, synchronizuje się po `T` sekundach, przez kolejne `T` sekund działa na połączonym corpus, ponownie się synchronizuje, a następnie kończy działanie. Dzięki temu każda generacja tworzy **nowe struktury**, jednocześnie wykorzystując zgromadzone pokrycie.<sup>[[1]](#references)[[2]](#references)</sup>

**Serwer:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Pracownicy sekwencyjni (przykładowa pętla):**

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

- `-in empty` wymusza **świeży corpus** przy każdej generacji.
- `-server_update_interval T` przybliża **opóźnioną synchronizację** (najpierw nowe dane, później ponowne użycie).
- W trybie grammar fuzzing **początkowa synchronizacja z serwerem jest domyślnie pomijana** (nie trzeba używać `-skip_initial_server_sync`).
- Optymalna wartość `T` zależy od **targetu**; najlepiej przełączyć ją po tym, jak worker znajdzie większość „łatwego” coverage.

## Snapshot Fuzzing Dla Targetów Trudnych Do Przygotowania

Gdy kod, który chcesz testować, staje się dostępny dopiero **po kosztownym przygotowaniu** (uruchomieniu VM, zalogowaniu, odebraniu pakietu, sparsowaniu kontenera, zainicjalizowaniu usługi), przydatną alternatywą jest **snapshot fuzzing**: przechwyć gotowy stan procesu lub VM, wstrzyknij każdy przypadek testowy do ścieżki wejściowej targetu, wykonuj go do momentu crashu/timeoutu i przywróć snapshot. Pozwala to uniknąć powtarzania inicjalizacji lub prefiksów protokołu; metoda ta jest przydatna w przypadku **usług sieciowych**, **firmware**, **powierzchni ataku dostępnych po uwierzytelnieniu** i **targetów dostępnych wyłącznie jako pliki binarne**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Uruchom target, aż będzie gotowy interesujący stan.
2. Wykonaj snapshot **pamięci + rejestrów** w tym momencie.
3. Dla każdego przypadku testowego zapisz zmodyfikowane wejście bezpośrednio w odpowiednim buforze guestu/procesu.
4. Wykonuj do momentu crashu/timeoutu/resetu.
5. Przywróć snapshot; w przypadku targetów VM przywracaj tylko **zmodyfikowane strony**, jeśli jest to obsługiwane, a następnie powtórz.

Umieść snapshot możliwie blisko pierwszego kosztownego etapu parsowania/dispatchu, na przykład po `recv`/`read` lub deserializacji pakietu, i ustal, którego bufora wejściowego używa target. Jest to zgodne z zasadą adaptacyjnego rozmieszczania: przesuwania snapshotu głębiej w przetwarzanie wejścia, aby uniknąć powtarzania pracy.<sup>[[11]](#references)</sup>

## Eksploracja Wyścigów W Jądrze Linux Za Pomocą MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) przekształca wyścigi w jądrze Linux wrażliwe na timing w powtarzalne harmonogramy dostępu do pamięci. Może automatycznie wyliczać wykonania **A-B-A** w dwóch kontekstach lub pozwala analitykowi narzucić ograniczenia kolejności w terminalowym UI/GUI. To eksperymentalne narzędzie badawcze, a nie kompletny concurrency fuzzer: obecnie wymaga LLVM 23+ i zmodyfikowanego jądra z projektu, narzędzia wiersza poleceń obsługują dwa wątki testowe, a proponowana warstwa fuzzingu w userspace nie została zaimplementowana.<sup>[[17]](#references)[[18]](#references)</sup>

### Zbieranie punktów komunikacji między kontekstami

Zbuduj instrumentowane jądro z callbackami KASAN outline i zmodyfikowaną obsługą zapisu pamięci KCOV. README projektu zaleca również wyłączenie optymalizacji sibling-call, aby stosy wywołań pozostały użyteczne.<sup>[[17]](#references)[[18]](#references)</sup>

```text
CONFIG_KASAN=y
CONFIG_KASAN_OUTLINE=y
CONFIG_KCOV=y
CONFIG_KCOV_EXT_RECORDS=y
CONFIG_KCOV_MEMORY=y
CONFIG_KALLSYMS_ALL=y
CONFIG_DEBUG_INFO_DWARF5=y
CONFIG_PREEMPT=y
CONFIG_RANDOMIZE_BASE=n
```

```bash
export KCFLAGS="-fno-optimize-sibling-calls -mllvm -sanitizer-coverage-prune-blocks=false"
```

Tryb outline KASAN (`asan-instrumentation-with-call-threshold=0`) zamienia instrumentowane dostępy na wywołania funkcji pomocniczych. Łaty jądra MAccConc wyłączają `asan-opt-same-temp`, aby kolejne dostępy nie były scalane; wyłącz także optymalizację `asan-opt-globals`, gdy wyścigi dotyczące zmiennych globalnych mają być widoczne. KCOV przekazuje powstałe rekordy do przestrzeni użytkownika. Porównuj dostępy z różnych kontekstów wykonania i zachowuj pary, których zakresy bajtów nakładają się, a co najmniej jeden dostęp jest zapisem; traktuj `kfree()` jako zapis, aby przejścia cyklu życia również stawały się kandydatami.<sup>[[17]](#references)</sup>

W przypadku pracy wykonywanej poza zadaniem inicjującym, takiej jak przetwarzanie pakietów lub wywołania zwrotne RCU, podsystem musi propagować uchwyt zdalnego pokrycia KCOV. Zdalne KCOV w upstreamie jest opcjonalne i nie jest automatycznie dostępne dla dowolnej pracy w tle, więc brak propagacji może sprawić, że rzeczywista interakcja pozostanie niewidoczna.<sup>[[17]](#references)[[19]](#references)</sup>

### Identyfikuj ten sam dynamiczny dostęp przy każdym uruchomieniu

Nie odtwarzaj działania względem konkretnego adresu na stercie, który może się zmienić po każdej alokacji, ani wyłącznie względem adresu instrukcji, który jest niejednoznaczny wewnątrz funkcji pomocniczych, takich jak `memcpy()` i `spin_lock()`. MAccConc używa **śladu stosu wzbogaconego o liczniki**: każda ramka identyfikuje funkcję wywoływaną oraz licznik jej wywołań w funkcji wywołującej, a ostatni element identyfikuje instrukcję dostępu do pamięci. Rekordy wejścia do funkcji i wyjścia z niej generowane przez SanitizerCoverage pozwalają przestrzeni użytkownika odtworzyć ten dynamiczny identyfikator, który pozostaje stabilny mimo zmian adresów i niepowiązanych zakłóceń przepływu sterowania.<sup>[[17]](#references)</sup>

### Przekształcaj pary kandydatów w wymuszone harmonogramy

Łata `KCOV_SET_DI` wiąże identyfikator dostępu wzbogacony o liczniki z działaniem na współdzielonej fladze.<sup>[[17]](#references)</sup>

| Działanie | Semantyka |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Ustaw flagę *N* bezpośrednio przed wybranym dostępem. |
| `DI_STACK_WAIT` | Przed wybranym dostępem czekaj w pętli, aż flaga *N* zostanie ustawiona lub upłynie skonfigurowany limit. |
| `DI_STACK_WAKE_POST` | Ustaw flagę *N* bezpośrednio po wybranym dostępie. |

Aby narzucić częściowy warunek **A-happens-before-B**, przypisz `DI_STACK_WAKE_POST` do A, a `DI_STACK_WAIT` do B, używając tej samej flagi. W przypadku w pełni określonego harmonogramu dla dwóch kontekstów rozpocznij od zablokowania B, a następnie niech A odblokuje B i zaczeka w pierwszym punkcie przekazania; przy kolejnym przekazaniu B wykonuje odwrotną operację. To drugie rozwiązanie działa jak deterministyczne przełączanie kontekstów i jest używane przez automatyczny eksplorator A-B-A.<sup>[[17]](#references)</sup>

Minimalna kampania polega na skompilowaniu przypadku testowego z czterema hookami (`test_setup`, dwiema funkcjami wątków i `test_end`) jako biblioteki współdzielonej, zebraniu śladu bez ograniczeń, a następnie wyliczeniu kandydatów A-B-A lub dodaniu ręcznych ograniczeń wokół podejrzanych dostępów.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpretuj timeouty oddzielnie od udanych zmian kolejności: żądana kolejność może być niemożliwa, ponieważ blokada lub zależność związana z inicjalizacją/publikacją uniemożliwia drugiemu kontekstowi dotarcie do punktu wstrzyknięcia. Pamiętaj też o ograniczeniach KASAN: bezpośrednie dostępy do stosu zwykle nie są przechwytywane, chyba że mogą wykraczać poza jego granice; zmienne globalne są pomijane przy domyślnej optymalizacji, a obecne kompilatory nie mogą jednocześnie emitować hooków ASAN i TSAN. Ponadto prototyp traci bufor KCOV, gdy guest ulega awarii, dlatego zachowaj niezależną konsolę/oracle do wykrywania awarii.<sup>[[17]](#references)</sup>

Na potrzeby przyszłego fuzzingu sterowanego współbieżnością zapisuj podsumowania dostępów do pamięci dla każdego wejścia lub wywołania syscall, dobieraj operacje, które utworzyłyby punkty komunikacji między kontekstami, a następnie eksploruj tylko te kombinacje. Snapshoty VM stabilizują stan globalny i adresy; bez snapshotów metadane miejsca alokacji mogą służyć do abstrakcji obiektów między uruchomieniami. To proponowane rozszerzenie, a nie funkcja obecnych narzędzi userspace MAccConc.<sup>[[17]](#references)</sup>

## Introspekcja harnessa: wcześnie wykrywaj płytkie fuzzery

Gdy kampania utyka, problemem często nie jest mutator, lecz **harness**. Użyj **introspekcji osiągalności/pokrycia**, aby znaleźć funkcje statycznie osiągalne z celu fuzzingu, które są rzadko lub wcale niepokrywane dynamicznie. Takie funkcje zwykle wskazują na jeden z trzech problemów.<sup>[[12]](#references)</sup>

- Harness wchodzi do celu zbyt późno lub zbyt wcześnie.
- W korpusie seedów brakuje całej rodziny funkcji.
- Cel rzeczywiście wymaga **drugiego harnessa**, zamiast jednego, nadmiernie rozbudowanego harnessa typu „zrób wszystko”.

Jeśli korzystasz z przepływów pracy w stylu OSS-Fuzz / ClusterFuzz, Fuzz Introspector może porównać statyczną osiągalność z pokryciem w czasie działania i wygenerować raporty na podstawie uruchomienia z limitem czasu lub publicznego korpusu.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Użyj raportu, aby zdecydować, czy dodać nowy harness dla nieprzetestowanej ścieżki parsera, rozszerzyć corpus dla konkretnej funkcji czy podzielić monolityczny harness na mniejsze punkty wejścia.

## Wybór celów fuzzingu z wykorzystaniem grafu i triage wyników mutacji

Jeśli masz już **wyniki analizy statycznej**, **mutanty, które przetrwały testy mutacyjne**, oraz **raporty pokrycia**, nie analizuj ich jako niezależnych list. Najpierw zbuduj **graf wywołań**, opisz węzły za pomocą **złożoności cyklomatycznej**, **osiągalności z punktów wejścia/danych niezaufanych** i wszelkich zewnętrznych wyników, a następnie zadaj pytania dotyczące grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Które funkcje o wysokiej złożoności są osiągalne z danych niezaufanych?
- Które mutanty, które przetrwały testy, znajdują się na ścieżkach od parserów/handlerów do kodu krytycznego dla bezpieczeństwa?
- Które funkcje są architektonicznymi punktami krytycznymi o wyjątkowo **dużym promieniu rażenia**?

To zazwyczaj pozwala znaleźć lepsze cele fuzzingu niż samo kryterium „najniższego pokrycia”. Parser/dekoder o **wysokiej złożoności** i potwierdzonej **osiągalności z zewnątrz** jest lepszym kandydatem na harness niż odizolowany wewnętrzny helper o słabym pokryciu, do którego nie prowadzi żadna ścieżka kontrolowana przez atakującego.

### Praktyczny proces triage

1. Zbuduj **graf kodu** na podstawie bazy kodu i wyodrębnij metryki złożoności/gałęzi dla poszczególnych funkcji.
2. Wylicz **punkty wejścia** przyjmujące dane kontrolowane przez atakującego: handlery żądań, dekodery, importery, parsery protokołów, czytniki CLI/plików.
3. Wykonaj **zapytania o ścieżki** od tych punktów wejścia do kandydatów na cele, aby oddzielić osiągalną powierzchnię ataku od kodu martwego lub dostępnego wyłącznie wewnętrznie.
4. Priorytetowo potraktuj węzły łączące:
   - wysoką **złożoność cyklomatyczną**
   - potwierdzoną **osiągalność z danych niezaufanych**
   - duży **promień rażenia** lub wielu zależnych od nich elementów
   - dodatkowe potwierdzające dowody, takie jak wyniki **SARIF**, uwagi z audytu lub mutanty, które przetrwały testy
5. Najpierw przygotuj ukierunkowane harnessy dla najlepiej ocenionych węzłów, zwłaszcza **parserów/kodeków**, takich jak dekodery hex/Base64/IP/wiadomości.

### Mutanty, które przetrwały: równoważne czy istotne

Testy mutacyjne często generują zaszumioną listę mutantów, które przetrwały. Zanim uznasz każdy taki przypadek za lukę w zabezpieczeniach, wykorzystaj graf, aby ustalić:

- Czy zmodyfikowana funkcja jest osiągalna z punktu wejścia kontrolowanego przez atakującego?
- Czy wszystkie ścieżki wywołań są ograniczone silniejszymi niezmiennikami niż zmodyfikowany warunek?
- Czy węzeł znajduje się w martwym kodzie, logice służącej wyłącznie formatowaniu czy ścieżce o dużym wpływie, związanej z arytmetyką/parserem?

Mutanty, które pozostają nieosiągalne lub są strukturalnie ograniczone, są często **mutantami równoważnymi**. Mutanty, które pozostają **osiągalne** i dotyczą **warunków brzegowych**, **ścieżek przepełnienia/przeniesienia** lub **arytmetyki/parsingowania krytycznych dla bezpieczeństwa**, należy uwzględnić w:

- nowych harnessach fuzzingu
- bezpośrednich testach właściwości/niezmienników
- ukierunkowanych zestawach wektorów przypadków brzegowych

### Korelowanie zewnętrznych wyników z grafem

Jeśli Twój pipeline SAST eksportuje **SARIF**, przypisz wyniki do węzłów grafu na podstawie **pliku + zakresu wierszy** i użyj grafu, aby określić szerszy wpływ.<sup>[[6]](#references)</sup>

- oblicz **promień rażenia** wskazanej funkcji
- sprawdź, czy wynik znajduje się na którejkolwiek ścieżce od punktu wejścia
- pogrupuj pobliskie wyniki, które zbiegają się w tym samym punkcie krytycznym

Jest to przydatne przy podejmowaniu decyzji, czy poświęcić czas na fuzzing konkretnej funkcji: węzeł, który jest **osiągalny**, **złożony** i ma już wyniki **SAST**, jest często lepszym celem niż węzeł jedynie złożony, do którego nie prowadzi żadna ścieżka kontrolowana przez atakującego.

Przykładowy proces z użyciem Trailmark.<sup>[[6]](#references)</sup>

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

Ważna jest metodologia oparta na przecięciu: **złożoność x ekspozycja x wpływ**. Użyj wykresu, aby wybrać cele fuzzingu o najwyższej oczekiwanej wartości dla bezpieczeństwa, a następnie wykorzystaj mutacje, które przetrwały, aby określić, które granice i niezmienniki musi testować Twój harness.<sup>[[5]](#references)</sup>

## Differential fuzzing kodowania kluczy kryptograficznych

Zacznij od poprawnych kluczy serializowanych lub standardowych wektorów testowych. Mutuj zakodowane pola, nie naruszając długości ani struktury wymaganej do dotarcia do ścieżek importu i operacji, a następnie przekazuj te same bajty niezależnym implementacjom. Porównuj akceptację i błędy. Zrandomizowane podpisy i szyfrogramy wymagają wyroczni poprawności, a nie porównania bajt po bajcie: weryfikuj podpisy lub porównuj współdzielone sekrety z rundy enkapsulacji/dekapsulacji. Wektory testowe potwierdzają zgodność dla znanych przypadków; mutacje różnicowe badają niepoprawne kodowania, których nie obejmują.<sup>[[23]](#references)[[26]](#references)</sup>

W przypadku tych formatów kluczy używaj wyroczni specyficznych dla formatu:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Rozszerzone klucze podpisujące ML-DSA:** zmień spakowane współczynniki `s1` lub `s2`, tak aby znalazły się poza zakresem `[-η, η]`, zachowując możliwość parsowania klucza. Sprawdź, czy import lub podpisywanie odrzuca taki klucz oraz czy uzyskany podpis przechodzi weryfikację. Sama różnica w akceptacji nie oznacza naruszenia standardu, ponieważ FIPS 204 nie wymaga dodatkowych kontroli klucza prywatnego. Zobacz [mechanizm warunkowego wycieku](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Pary kluczy ML-KEM:** oddziel wymagane kontrole klucza enkapsulacji i wejścia dekapsulacji od opcjonalnej kontroli spójności pary (PCT) importowanej pary. Wykonaj enkapsulację za pomocą klucza publicznego, dekapsulację za pomocą klucza prywatnego i porównaj współdzielone sekrety; niezgodność może zakłócić szyfrowaną komunikację, nawet jeśli poszczególne klucze przejdą kontrole wejścia. Sprawdź, czy API weryfikuje wejścia podczas operacji, czy za pomocą osobnego wywołania; libcrux udostępnia `validate_public_key(pk)` i `validate_private_key(sk, ct)`, które nie zastępują PCT.
- **Surowe klucze XMSS/XMSSMT:** testuj rundy serializacji **kluczy podpisujących i weryfikujących** dla różnych zestawów parametrów, a nie tylko operacje na kluczach przechowywanych w pamięci. XMSS i XMSSMT mają osobne przestrzenie nazw OID o długości czterech bajtów, więc parser sprawdzający najpierw XMSS wyłącznie na podstawie OID może błędnie sklasyfikować kolidujący klucz XMSSMT i odrzucić import. Opisany parser RustCrypto ilustruje błąd interoperacyjności/dostępności, a nie fałszowanie podpisu.

## Fuzzing w Go z gosentry: mocniejszy silnik, typowane wejścia i kontrole różnicowe

Jeśli cel w Go ma już natywny harness `testing.F`, praktyczną ścieżką ulepszenia jest uruchomienie tego samego harnessu z użyciem [gosentry](https://github.com/trailofbits/gosentry), rozwidlonego toolchaina Go, który zachowuje `go test -fuzz`, ale zamienia backend na **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Jest to przydatne, gdy natywny fuzzer Go zatrzymuje się na **trudnych porównaniach**, **typowanych danych wejściowych** lub **formatach intensywnie wykorzystujących parsery**. Metodyka pozostaje taka sama:

- Nadal używaj `f.Add(...)` do seedów i `f.Fuzz(...)` jako callbacka.
- Wykorzystaj ten sam harness, ale uruchom go za pomocą binarium `go` z gosentry zamiast standardowego toolchaina.
- Traktuj uzyskaną kampanię jak zwykły run sterowany pokryciem, ale z planowaniem i mutacjami LibAFL oraz lepszymi dodatkowymi detektorami.

### Zamienianie cichych błędów w wyniki fuzzingu

Powracającym problemem podczas assessmentów Go jest to, że niebezpieczne zachowanie często domyślnie **nie powoduje awarii**. Dzięki gosentry kilka klas „złych, ale cichych” stanów można przekształcić w wyniki.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` sprawia, że wybrane ścieżki logowania/błędów zachowują się jak awarie (przydatne w przypadku ścieżek kodu w stylu `log.Fatal`, które w przeciwnym razie tylko logują i kontynuują działanie).
- `--catch-races=true` ponownie odtwarza nowo odkryte wpisy kolejki z detektorem race Go.
- `--catch-leaks=true` ponownie odtwarza nowe wpisy kolejki z `goleak` i zatrzymuje działanie w przypadku wycieków goroutine.
- Obsługa zawieszeń przez LibAFL pozwala zachować **nieskończone pętle / bardzo wolne dane wejściowe** jako wyniki fuzzingu, zamiast pomijać je jako timeouty.
- Domyślnie wbudowane sprawdzanie przepełnień arytmetycznych oraz opcjonalne sprawdzanie obcięć dzięki instrumentacji w stylu go-panikint.

Jest to szczególnie przydatne w przypadku celów, w których wpływ na bezpieczeństwo wynika z **błędu parsera bez paniki**, **błędu współbieżności** lub **zawieszenia powodującego wyłącznie DoS**, a nie z uszkodzenia pamięci.

### Fuzzing uwzględniający struktury dla typowanych API Go

Natywny fuzzing Go obsługuje głównie typy skalarne, takie jak `[]byte`, `string` i liczby. Jeśli testowany kod przyjmuje typowane obiekty, gosentry może bezpośrednio fuzzować **wartości złożone** (struktury, slice’y, tablice, wskaźniki), nadal mutując znajdujące się pod nimi bajty.<sup>[[7]](#references)[[8]](#references)</sup>

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

Użycie tego rozwiązania przy tworzeniu sztucznego formatu wire wyłącznie na potrzeby fuzzingu może ukryć błędy logiczne w kodzie parsującym używanym tylko przez harness. W kampaniach różnicowych lub opartych na gramatyce wejście harnessu powinno pozostać pojedynczym argumentem `[]byte` lub `string`, a parsowanie należy wykonywać wewnątrz callbacka.

### Fuzzing oparty na gramatyce dla parserów i danych wejściowych protokołów

W przypadku parserów, formatów i języków wejściowych gosentry może uruchamiać **Nautilus grammar fuzzing** na bazie LibAFL. Gramatyka to tablica reguł produkcji w formacie JSON, a harness powinien zazwyczaj przyjmować pojedynczy argument `[]byte` lub `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Uwagi dotyczące metodologii:

- Używaj trybu gramatycznego, gdy mutacje na poziomie bajtów w większości kończą się na wczesnych kontrolach składni.
- Ogranicz gramatykę do **podzbioru języka/protokołu istotnego z punktu widzenia bezpieczeństwa**, zamiast modelować pełną specyfikację.
- Używaj dużych wartości brzegowych w terminalach/nieterminalach, aby testować granice liczb całkowitych, długości i maszyn stanów.
- Tryb gramatyczny zapewnia poprawność gramatyczną wejść, ale cel nadal otrzymuje **bajty/ciągi znaków**, więc parsowanie i kontrole semantyczne wciąż odbywają się w kodzie objętym harnessami.

### Fuzzing różnicowy: porównuj implementacje, nie tylko awarie

Skutecznym podejściem w ekosystemach Go jest **gramatyczny fuzzing różnicowy**: generuj poprawne, ustrukturyzowane wejścia i przekazuj je do dwóch parserów, klientów lub silników przejść stanów.<sup>[[7]](#references)[[8]](#references)</sup>

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

Potraktuj poniższe jako ustalenia:

- jedna implementacja wywołuje panic, podczas gdy druga prawidłowo odrzuca dane
- niezgodność w akceptowaniu lub odrzucaniu danych wejściowych
- różne drzewa parsowania lub zdekodowane obiekty
- rozbieżne przejścia stanów, nonce, salda lub korzenie stanu

To praktyczny sposób na wykrywanie **niezgodności konsensusu**, **niejednoznaczności parsera** i **rozbieżności między specyfikacją a implementacją**, które często umykają podczas czystego fuzzingu pod kątem awarii.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Ponowne wykorzystanie korpusu kampanii do raportowania pokrycia

Po zakończeniu kampanii odtwórz zapisany korpus kolejki, aby wygenerować raport pokrycia Go bez ręcznego eksportowania osobnego korpusu.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Uruchom polecenie z **tego samego pakietu** i z **tym samym celem `-fuzz`**, aby gosentry rozpoznał właściwy stan buforowanej kampanii.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [Mutacyjne fuzzowanie gramatyczne](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++: fuzzowanie — szczegółowy przewodnik](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pięć lat później: fuzzowanie protokołów sterowane pokryciem](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark zamienia kod w grafy](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [W Go brakowało połowy narzędzi do fuzzowania. Rozwidlamy toolchain, by to naprawić.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: szybki fuzzer greybox dla stanowych protokołów sieciowych wykorzystujący migawki](https://arxiv.org/abs/2202.03643)
- [10] [Bez gramatyki też da się: fuzzowanie jądra Linuxa bez opisów wywołań systemowych](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: wydajne fuzzowanie z adaptacyjnymi i modyfikowalnymi migawkami](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentacja LLVM w AFL++: pokrycie ścieżek i wywołujących](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predykcyjne fuzzowanie uwzględniające kontekst](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Android Offensive Security — fuzzowanie Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer Binder w LKL Android — dokumentacja kompilacji i regresyjnych ziaren](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: badanie warunków wyścigu w jądrze Linuxa za pomocą kontrolowanych przeplotów dostępu do pamięci](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: pokrycie kodu na potrzeby fuzzowania](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Rozszerzona składnia nazw plików CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Ostrzeżenie Doyensec: CFITSIO, IV kwartał 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzowanie rozszerzonej składni nazw plików CFITSIO: 16 luk w bezpieczeństwie pamięci i analiza wspomagana przez Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Różnicowe fuzzowanie kryptografii](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: standard mechanizmu enkapsulacji klucza opartego na module kratowym](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Błąd parsowania OID w XMSSMT — zgłoszenie RustCrypto nr 1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Stan implementacji kryptografii postkwantowej](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
