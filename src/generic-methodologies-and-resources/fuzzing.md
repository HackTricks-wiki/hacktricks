# Metodologia fuzzingu

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: pokrycie a semantyka

W **mutational grammar fuzzing** wejścia są mutowane z zachowaniem **poprawności gramatycznej**. W trybie sterowanym pokryciem jako ziarna corpus zapisywane są tylko próbki wywołujące **nowe pokrycie**. W przypadku **celów językowych** (parserów, interpreterów, silników) może to pomijać błędy wymagające **łańcuchów semantycznych/przepływu danych**, w których wynik jednego konstruktu staje się wejściem dla innego.<sup>[[1]](#references)</sup>

**Tryb awarii:** fuzzer znajduje ziarna, które osobno wykorzystują `document()` i `generate-id()` (lub podobne prymitywy), ale **nie zachowuje łańcucha przepływu danych**, więc próbka „bliższa błędowi” zostaje odrzucona, ponieważ nie zwiększa pokrycia. Przy **co najmniej 3 zależnych krokach** losowa rekombinacja staje się kosztowna, a informacja zwrotna o pokryciu nie ukierunkowuje wyszukiwania.<sup>[[1]](#references)</sup>

**Wniosek:** w przypadku gramatyk z licznymi zależnościami rozważ **połączenie faz mutacyjnych i generatywnych** lub nadanie priorytetu wzorcom **łańcuchowego wywoływania funkcji** (a nie tylko pokryciu).<sup>[[1]](#references)</sup>

## Pułapki związane z różnorodnością corpus

Mutacje sterowane pokryciem są **zachłanne**: próbka zapewniająca nowe pokrycie jest od razu zapisywana, często z dużymi, niezmienionymi fragmentami. Z czasem corpora stają się **niemal identycznymi kopiami** o małej różnorodności strukturalnej. Agresywna minimalizacja może usunąć przydatny kontekst, dlatego praktycznym kompromisem jest **minimalizacja uwzględniająca gramatykę**, która **zatrzymuje się po osiągnięciu minimalnej liczby tokenów** (ogranicza szum, zachowując wystarczająco dużo otaczającej struktury, by ułatwić mutacje).<sup>[[1]](#references)</sup>

Praktyczna zasada dotycząca corpus w mutational fuzzing: **wybieraj mały zestaw strukturalnie różnych ziaren maksymalizujących pokrycie**, zamiast dużej kolekcji niemal identycznych próbek. W praktyce zazwyczaj oznacza to, co następuje.<sup>[[1]](#references)[[3]](#references)</sup>

- Zacznij od **próbek z rzeczywistego świata** (publicznych korpusów, danych z crawlowania, przechwyconego ruchu, zbiorów plików z ekosystemu celu).
- Ogranicz ich liczbę za pomocą **minimalizacji corpus opartej na pokryciu**, zamiast zachowywać każdą poprawną próbkę.
- Dbaj, by ziarna były **wystarczająco małe**, aby mutacje obejmowały znaczące pola, a nie zużywały większości cykli na nieistotne bajty.
- Ponownie uruchom minimalizację corpus po większych zmianach w harnessie lub instrumentacji, ponieważ „najlepszy” corpus zmienia się wraz ze zmianą osiągalności.

## Duże generowane programy i obciążenie przez timeouty

Podczas fuzzingu kompilatorów i interpreterów wejście może wymagać przekroczenia **progu rozmiaru generowanego kodu**, zamiast wejścia na nową gałąź parsera. W przykładzie V8 [dotyczącym offsetu obsługi wyjątków](../binary-exploitation/chrome-exploiting.md#exception-handler-offsets-narrower-than-maximum-bytecode-size) poprawny testcase musiał zawierać ponad 256 MiB bytecode’u, zanim znaczenie zyskał obcięty offset handlera. Powtarzane konstrukty `yield*` pozwalały osiągnąć ten próg, ale kompilacja testcase’u trwała na wersji debug kilka sekund. Preferowanie małych wejść i krótkie timeouty wykonywania mogą zniechęcać do testowania tej klasy przypadków, nawet przy dużym pokryciu gramatyki. Podczas audytu spakowanych offsetów lub innych metadanych zależnych od długości rozważ osobno progi rozmiaru i politykę timeoutów; ta porada dotycząca kampanii jest wnioskiem wyciągniętym z opisanego trybu awarii.<sup>[[29]](#references)</sup>

## Mutacje uwzględniające porównania dla wartości magicznych

Częstym powodem stagnacji fuzzerów nie jest składnia, lecz **ścisłe porównania**: magiczne bajty, kontrole długości, ciągi enumów, sumy kontrolne lub wartości sterujące wyborem parsera, sprawdzane przez `memcmp`, tabele `switch` albo kaskadowe porównania. Czysto losowe mutacje marnują cykle na próbę odgadnięcia tych wartości bajt po bajcie.

W przypadku takich celów użyj **śledzenia porównań** (na przykład `CMPLOG` z AFL++ lub procesów w stylu Redqueen), aby fuzzer mógł obserwować operandy nieudanych porównań i ukierunkowywać mutacje na wartości, które je spełniają.<sup>[[3]](#references)</sup>

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

- Jest to szczególnie przydatne, gdy cel ukrywa głębszą logikę za **sygnaturami plików**, **czasownikami protokołu**, **tagami typów** lub bitami funkcji zależnymi od wersji.
- Połącz tę metodę ze **słownikami** utworzonymi na podstawie rzeczywistych próbek, specyfikacji protokołów lub logów debugowania. Mały słownik zawierający tokeny gramatyczne, nazwy fragmentów, czasowniki i separatory często jest bardziej wartościowy niż ogromna, uniwersalna lista słów.
- Jeśli cel wykonuje wiele kolejnych kontroli, najpierw rozwiąż porównania „magic” występujące na początku, a następnie ponownie zminimalizuj uzyskany zbiór, aby kolejne etapy rozpoczynały się od już poprawnych prefiksów.

## Fuzzing API plików ukrywających język nazw plików

Parametr o nazwie `filename`, `path` lub `URL` może być punktem wejścia interpretera, a nie zwykłym wyszukiwaniem pliku. Na przykład CFITSIO Extended Filename Syntax (EFS) przetwarza selektory w nawiasach kwadratowych, wyrażenia dotyczące wierszy/pikseli, obliczane kolumny, histogramy i transformacje przed zwróceniem otwartego obiektu; niektóre formy tworzą również kopie tymczasowe. Podczas mapowania powierzchni ataku sklasyfikuj każde API otwierania/importu jako **literal-path** lub **interpreted-path**, a następnie fuzzuj produkcyjny punkt wejścia, z którego faktycznie korzystają aplikacje.<sup>[[20]](#references)[[22]](#references)</sup>

Informacje o wynikających z tego prymitywach SSRF, kopiowania plików i obsługi protokołów — oraz bezpieczniejszych API literal-path — znajdziesz w [Mini-języki nazw plików jako prymitywy SSRF/operacji na plikach](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Oddziel obiekt bazowy od fuzzowanego programu

Gdy gramatyka znajduje się w sufiksie nazwy pliku, modyfikowanie wyłącznie bajtów wskazanego pliku pomija parser. Zamiast tego niewielki harness może odczytać testcase jako ciąg znaków i przekazać go do API otwierania obsługującego interpretację; kampania CFITSIO dotarła do większości parserów i ewaluatorów EFS przez wywołanie `fits_open_file()` w trybie tylko do odczytu. Zapewnij osobno dostęp do poprawnych plików bazowych, aby mutacje mogły skupiać się na języku selektorów/wyrażeń, zamiast nieustannie uszkadzać ścieżkę bazową.<sup>[[22]](#references)</sup>

Użyj seedów, z których każdy dociera do innej rodziny gramatycznej, a następnie utwórz kompaktowy słownik na podstawie specyfikacji oraz kodu lexera/parsera. Jeśli pokrycie przestaje rosnąć, a wejścia wielokrotnie kończą się w tej samej ścieżce błędu składni, zachowaj poprawne prefiksy i dodaj separatory, operatory, słowa kluczowe, nazwy funkcji oraz przykładowe nazwy pól, zamiast jedynie wydłużać czas losowych mutacji.<sup>[[22]](#references)</sup>

Uruchom harness ze słownikiem gramatyki, na przykład:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Ograniczanie skutków ubocznych harnessu w trybie „read-only”

Flaga biblioteki „read-only” nie gwarantuje, że testcase nie wywoła skutków ubocznych: język nazw plików może przepisać wejście, utworzyć pliki wyjściowe lub utworzyć tymczasowe obiekty. Kampania CFITSIO początkowo niszczyła pliki seedów i pozostawiała nieoczekiwane pliki w różnych miejscach systemu plików, dlatego konieczne były czyszczenie i izolacja.<sup>[[22]](#references)</sup>

- Każdemu workerowi przydziel odrębny katalog roboczy i prywatny katalog tymczasowy.
- Udostępniaj kopie kanonicznych plików bazowych; nigdy nie pozwalaj, by target modyfikował jedyną kopię corpus.
- Wyłącz dostęp do sieci, chyba że zdalne backendy są celem testów, i ogranicz zapisywalne ścieżki za pomocą kontenera, przestrzeni nazw montowań lub równoważnego sandboxa.
- Resetuj katalog po każdym wykonaniu lub każdej partii workerów, a nieoczekiwane zmiany w systemie plików traktuj jako dodatkowe ustalenia.

### Pętla: crash → patch → fuzz

Pogrupuj crashe przed naprawą, aby tysiące artefaktów nie oznaczały tysięcy zadań związanych z poprawkami. W ocenie CFITSIO AFLTriage zredukował początkowy zbiór crashy do kilku głównych przyczyn; powstałe advisory opisuje odrębne błędy, w tym nieprawidłowe sprawdzanie rozmiaru bufora docelowego, nieaktualne wskaźniki po `realloc()`, błędy arytmetyczne oraz niebezpieczne ścieżki czyszczenia parsera.<sup>[[21]](#references)[[22]](#references)</sup>

1. Zminimalizuj reprezentatywne wejście dla każdego klastra i odtwórz błąd z użyciem AddressSanitizer.
2. Zapisz dokładny błędny dostęp, lokalizację w źródle, historię alokacji/zwalniania oraz stan parsera, który doprowadził do naruszenia niezmiennika.
3. Zastosuj jedną, wąsko zakrojoną poprawkę i przebuduj program z tym samym instrumentowaniem coverage i sanitizerów.
4. Odtwórz oryginalny reproducer **oraz każde wejście z jego klastra**; włącz też wykrywanie leaków, ponieważ poprawka dotycząca bezpieczeństwa pamięci może naruszyć zarządzanie własnością na ścieżce błędu.
5. Uruchom testy funkcjonalne na rzeczywistych plikach, a następnie wznów testy z wykorzystaniem zgromadzonej kolejki (lub zaimportuj ją ponownie, jeśli po zmianie binarnej silnik wymaga nowego katalogu wyjściowego).
6. Powtarzaj: usunięcie pierwszego, płytkiego crasha często pozwala istniejącym seedом przejść do głębszego stanu parsera.

LLM może przyspieszyć krok 2 i przygotować wstępny projekt poprawki w kroku 3, jeśli otrzyma crashujące wejście, raport sanitizera, harness i odpowiednie źródło, ale jego poprawka pozostaje niezweryfikowana. O jej przyjęciu decydują odtworzenie błędu z użyciem sanitizera i testy regresyjne, a nie wyjaśnienie modelu.<sup>[[22]](#references)</sup>

## Bogatsze informacje zwrotne, gdy coverage krawędzi nie rozróżnia ścieżek

Standardowe coverage krawędzi nie rozróżnia dwóch wykonań, które przechodzą przez ten sam helper, ale mają różnych wywołujących lub wybierają różne kombinacje gałęzi wewnątrz funkcji. Ma to znaczenie w współdzielonych dekoderach, dispatcherach protokołów i helperach interpreterów, gdzie **ścieżka** prowadząca do krawędzi określa aktywny stan. Naiwne śledzenie każdego kontekstu wywołania również jest ryzykowne: mapa coverage i kolejka mogą gwałtownie się rozrosnąć. Badania nad fuzzingiem uwzględniającym kontekst zalecają więc doprecyzowywanie tylko obiecujących kontekstów, zamiast traktowania całego grafu wywołań jako kontekstowego.<sup>[[14]](#references)</sup>

Nowsze wersje AFL++ zapewniają **coverage ścieżek Ball-Larus dla poszczególnych funkcji** jako uzupełnienie standardowego coverage krawędzi. Przypisuje ono cechę każdej acyklicznej ścieżce w funkcji; krawędzie powrotne pętli są usuwane, więc te informacje zwrotne rozróżniają kombinacje gałęzi, ale **nie liczbę iteracji pętli**. Zacznij od łagodnego poziomu `1`, a następnie stosuj bardziej restrykcyjne tryby tylko do podejrzanego kodu parsera lub maszyny stanów, ponieważ liczba ścieżek może rosnąć wykładniczo.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

W trybie LTO pomocnicza funkcja wywoływana z wielu miejsc istotnych z punktu widzenia bezpieczeństwa może łączyć każdą ścieżkę funkcji z jej bezpośrednim miejscem wywołania:<sup>[[13]](#references)</sup>

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

**Wskazówki dotyczące kampanii:** ostrożnie stosuj bogatszy feedback i monitoruj jego koszt pod względem coverage mapy/kolejki.<sup>[[13]](#references)[[14]](#references)</sup>

- Równolegle uruchom zwykłą instancję z edge coverage; bogatszy feedback jest przydatny tylko wtedy, gdy dodatkowy koszt kolejki/mapy nie obniża liczby wykonania na sekundę.
- Użyj `AFL_LLVM_ALLOWLIST`, aby ograniczyć instrumentację ścieżek/wywołujących, gdy duże biblioteki z dużą ilością szablonów lub ogólny kod narzędziowy dominują mapę.
- Funkcje z nadmierną liczbą ścieżek acyklicznych można pominąć w AFL++; ostrzeżenia podczas kompilacji wskazują, że cel wymaga allowlisty lub mniej restrykcyjnego poziomu.
- Coverage wywołujących + ścieżek obsługuje tylko jeden poziom wywołującego. Nie łącz go z głębszymi stosami kontekstu.
- Identyfikatory ścieżek mogą się zmieniać między głównymi wersjami LLVM. Na czas kampanii utrzymuj stały toolchain i nie synchronizuj korpusów opartych na PATH tak, jakby ich identyfikatory cech były stabilne między kompilacjami.
- Ten feedback uzupełnia `CMPLOG`: śledzenie porównań ustala, **jaka wartość przechodzi przez warunek**, a feedback ścieżek/wywołujących zachowuje informację o tym, **która trasa i kombinacja gałęzi do niego doprowadziła**.

## Stateful Fuzzing: sekwencje są seedami

W przypadku **protokołów**, **uwierzytelnionych przepływów pracy** i **parserów wieloetapowych** interesującą jednostką często nie jest pojedynczy blob, lecz **sekwencja komunikatów**. Połączenie całego transkryptu w jeden plik i ślepe mutowanie go jest zwykle nieefektywne, ponieważ fuzzer mutuje każdy krok jednakowo, nawet gdy tylko późniejszy komunikat dociera do podatnego stanu.<sup>[[4]](#references)</sup>

Skuteczniejszym podejściem jest traktowanie **samej sekwencji jako seeda** i wykorzystywanie **obserwowalnego stanu** (kody odpowiedzi, stany protokołu, fazy parsera, zwracane typy obiektów) jako dodatkowego feedbacku.<sup>[[4]](#references)</sup>

- Zachowuj **prawidłowe komunikaty prefiksowe** bez zmian i skup mutacje na komunikacie **sterującym przejściem**.
- Buforuj identyfikatory i wartości generowane przez serwer z wcześniejszych odpowiedzi, gdy kolejny krok od nich zależy.
- Preferuj mutowanie/łączenie poszczególnych komunikatów zamiast mutowania całego serializowanego transkryptu jako nieprzejrzystego bloba.
- Jeśli protokół udostępnia znaczące kody odpowiedzi, używaj ich jako **taniej wyroczni stanu**, aby priorytetowo traktować sekwencje, które docierają dalej.

Z tego samego powodu błędy uwierzytelniania, ukryte przejścia lub błędy parsera występujące „dopiero po uzgodnieniu” często umykają standardowemu fuzzingowi plikowemu: fuzzer musi zachować **kolejność, stan i zależności**, a nie tylko strukturę.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing sterownika z wieloma klientami

Wysokie edge coverage nadal może nie wykryć błędów sterownika IPC, ponieważ coverage nie opisuje **własności obiektów, liczników referencji, oczekujących komunikatów, kolejności sprzątania ani przeplotów wątków**. Strona [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) omawia model obiektów sterownika; ten przykład skupia się na harnessie fuzzera. Android Binder to użyteczny model: samo dotarcie do ścieżek alokacji i zwalniania nie wystarczy, jeśli fuzzer nie potrafi sprawić, by wiele procesów operowało na tym samym obiekcie jądra w wymaganej kolejności.<sup>[[15]](#references)</sup>

#### Modeluj protokół, a nie odizolowane bufory `ioctl`

Przedstaw przypadek testowy jako uporządkowaną gramatykę **tożsamość klienta + operacja + ustrukturyzowane argumenty**. Fuzzer Binder LKL używa protobuf i `libprotobuf-mutator`, z jednym trwałym klientem menedżera kontekstu i dwoma zwykłymi klientami. Semantyczny harness zachowuje relacje, które ślepa mutacja bajtów zniszczyłaby.<sup>[[15]](#references)</sup>

- Buforuj wartości zwrócone przez wcześniejsze operacje. Na przykład `BC_FREE_BUFFER` musi ponownie użyć wskaźnika bufora transakcji zwróconego przez wcześniejsze `ioctl`.
- Generuj prawidłowe domyślne odpowiedzi, aby transakcje synchroniczne mogły się zakończyć, a późniejsze operacje pozostały osiągalne.
- Odrzucaj niemożliwe przejścia, takie jak transakcje do samego siebie lub wiele oczekujących transakcji do tego samego celu.
- Przechowuj stan inicjalizacji singletona poza resetem wykonywanym dla każdego wejścia. Binder dopuszcza tylko jedną rejestrację `BINDER_SET_CONTEXT_MGR` na uruchomienie systemu, więc wielokrotne niszczenie i odtwarzanie tego klienta unieważniłoby kolejne wejścia.

Przydatny szablon wyścigu cyklu życia polega na tym, by jeden klient przekazał obiekt, uruchomił sprzątanie wątku lub procesu, a równocześnie klient odbierający zwolnił bufor transakcji. W przykładzie CVE-2020-0423 przekazanie `BINDER_TYPE_WEAK_BINDER`, po którym `BINDER_THREAD_EXIT` ścigało się z `BC_FREE_BUFFER`, mogło zwolnić osadzony `binder_work`, gdy ścieżka sprzątania kończącego się wątku nadal z niego korzystała.<sup>[[15]](#references)</sup>

#### Przywróć kontrolowane przeploty w jądrze przestrzeni użytkownika

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) łączy rzeczywisty kod jądra z harnessem w przestrzeni użytkownika i udostępnia jego interfejs wywołań systemowych przez `lkl_syscall`. Dzięki temu stan protobuf, coverage i KASAN można łatwo koordynować w jednym procesie. LKL zwykle wykonuje wywołanie systemowe bez przerywania go przez inny wątek jądra. W kampaniach wyścigów wstaw punkty `schedule()` wokół wybranych granic blokowania/odblokowywania i cyklu życia, a następnie pozwól harnessowi losowo wybierać kolejnego klienta przy każdym ustąpieniu sterowania. Umieszczaj te punkty w konkretnych miejscach, ponieważ każdy z nich powiększa przestrzeń przeszukiwania harmonogramu. Losowy scheduler opisany przez badaczy **nie jest częścią upstreamowego fuzzera Binder**.<sup>[[15]](#references)</sup>

#### Buduj i odtwarzaj serializowane seedy regresyjne

Upstreamowy harness przypina zgodną wersję `libprotobuf-mutator`, włącza instrumentację fuzzingu LKL i KASAN przez `LKL_FUZZING=1` oraz włącza `CONFIG_MMU` dla Binder za pomocą `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Po przejściu na celowo podatną rewizję lub zastosowaniu udokumentowanych upstream poprawek wycofujących zmiany, serializowany seed może odtworzyć całe przejście stanu wielu klientów bez konieczności rekonstruowania go w doraźnym proof of concept w C:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Potraktuj uzyskany błąd KASAN typu use-after-free jako potwierdzenie, że seed dotarł do podatnej ścieżki zarządzania czasem życia. **Nie** dowodzi on wystąpienia późniejszych prymitywów wymaganych do wykonania kodu w kernelu lub eskalacji uprawnień.<sup>[[16]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Praktycznym sposobem na połączenie **generowania nowych przypadków** z **ponownym wykorzystaniem pokrycia** jest **restartowanie krótkotrwałych workerów** obsługujących trwały serwer. Każdy worker rozpoczyna pracę z pustym corpus, synchronizuje dane po `T` sekundach, przez kolejne `T` sekund działa na połączonym corpus, ponownie synchronizuje dane, a następnie kończy działanie. Dzięki temu **każda generacja tworzy nowe struktury**, a jednocześnie wykorzystuje zgromadzone pokrycie.<sup>[[1]](#references)[[2]](#references)</sup>

**Serwer:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Pracownicy sekwencyjni (przykładowa pętla):**

<details>
<summary>Pętla ponownego uruchamiania procesu roboczego Jackalope</summary>

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

- `-in empty` wymusza **nowy corpus** w każdej generacji.
- `-server_update_interval T` przybliża **opóźnioną synchronizację** (najpierw nowe przypadki, później ponowne użycie).
- W trybie grammar fuzzing **początkowa synchronizacja z serwerem jest domyślnie pomijana** (nie trzeba używać `-skip_initial_server_sync`).
- Optymalna wartość `T` zależy od **testowanego celu**; najlepiej zmienić ją, gdy worker znajdzie już większość „łatwego” pokrycia.

## Snapshot Fuzzing dla celów trudnych do objęcia harnessami

Gdy kod, który chcesz testować, staje się dostępny dopiero **po kosztownym przygotowaniu** (uruchomieniu VM, zalogowaniu, odebraniu pakietu, sparsowaniu kontenera, zainicjalizowaniu usługi), przydatną alternatywą jest **snapshot fuzzing**: przechwyć gotowy stan procesu lub VM, wstrzykuj każdy przypadek testowy do ścieżki wejściowej celu, wykonuj go do awarii lub przekroczenia limitu czasu, a następnie przywracaj snapshot. Pozwala to uniknąć ponownego wykonywania inicjalizacji lub prefiksów protokołu i jest przydatne w przypadku **usług sieciowych**, **firmware**, **powierzchni ataku dostępnych po uwierzytelnieniu** oraz **celów binarnych**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Uruchom cel, aż osiągnie interesujący stan.
2. Zapisz snapshot **pamięci + rejestrów** w tym momencie.
3. Dla każdego przypadku testowego zapisz zmodyfikowane dane wejściowe bezpośrednio w odpowiednim buforze gościa/procesu.
4. Wykonuj program do awarii/przekroczenia limitu czasu/resetu.
5. Przywróć snapshot; w przypadku celów VM, jeśli jest to obsługiwane, przywracaj tylko **zmodyfikowane strony**, a następnie powtórz.

Umieść snapshot możliwie blisko pierwszego kosztownego etapu parsowania lub dyspozycji, na przykład po `recv`/`read` lub deserializacji pakietu, i zanotuj bufor wejściowy używany przez cel. Zgodnie z zasadą adaptacyjnego umieszczania snapshotu należy przesuwać go głębiej w przetwarzanie danych wejściowych, aby uniknąć ponownego wykonywania pracy.<sup>[[11]](#references)</sup>

### Przyrostowe snapshoty dla stanów protokołu

Stały snapshot pozwala uniknąć kosztów przygotowania, ale sam w sobie nie eksploruje przejść wymagających kilku poprawnych komunikatów. Harness LibAFL-Qemu może monitorować zapisy do pola stanu protokołu i zapisywać nowy snapshot po zmianie stanu. W [harnessie TCP libslirp](https://github.com/quarkslab/slirp_snapshots_stateful) monitorowane jest `tcpcb.t_state`; stany i flagi odpowiedzi są haszowane w celu usuwania duplikatów snapshotów, a zmodyfikowane strony są zapisywane względem snapshotu nadrzędnego. Przed modyfikacją kolejnego ustrukturyzowanego komunikatu przywracany jest wybrany snapshot wraz z jego łańcuchem nadrzędnym. Przypadek testowy przechowuje `SnapshotId` i wygenerowane bajty wejściowe (`gen_bytes`); menedżer snapshotów śledzi relacje nadrzędności potrzebne do odtworzenia przebiegu.<sup>[[27]](#references)[[28]](#references)</sup>

Tryb user-mode `SnapshotModule` w LibAFL-Qemu zapisuje mapowania i pamięć celu, ale nie rejestry CPU; w razie potrzeby zachowaj je osobno. Opisany menedżer obsługuje jedno drzewo snapshotów z jednym korzeniem i nie umożliwia współdzielenia identyfikatorów snapshotów między workerami. Jego tryb multi-snapshot nie może też bezpośrednio ponownie wykorzystać stanu shadow QASAN. W celu offline triage odtwórz łańcuch danych wejściowych w osobnym, instrumentowanym procesie. Przy użyciu `AsanHostModule` i `DrCovModule` wywołanie `fuzzer.evaluate_input` uruchamia wymagane callbacki `pre_exec`/`post_exec`; samo `qemu.run` tego nie robi.<sup>[[27]](#references)[[28]](#references)</sup>

### Wykrywanie logicznego odczytu poza ring bufferem

Odczyt poza *liczbą poprawnych danych* w buforze może nadal mieścić się w jego alokacji po stronie hosta i umknąć zwykłemu ASAN. Przykład z danymi pilnymi libslirp ([libslirp urgent-data example](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes)) powoduje również niedomiar bez znaku w liczbie bajtów. Jeśli dostępny jest kod źródłowy, instrumentacja przepełnień liczb całkowitych ze znakiem/bez znaku może wykryć ten efekt uboczny; przed wyciszeniem zgłoszeń odróżnij go od zamierzonego zawijania numerów sekwencyjnych TCP. Silniejszym proponowanym mechanizmem wykrywania jest oznaczenie niestandardowej alokacji ring buffera jako niedostępnej, oznaczanie jako dostępnych wyłącznie poprawnych zakresów w miarę przesuwania się wewnętrznego alokatora i ponowne oznaczanie zwolnionych zakresów jako niedostępnych. LibAFL-Qemu udostępnia API do oznaczania pamięci jako dostępną/niedostępną dla ASAN w celach, w których instrumentacja kodu źródłowego jest niepraktyczna.<sup>[[27]](#references)</sup>

## Eksploracja wyścigów w jądrze Linux za pomocą MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) zamienia zależne od czasu wyścigi w jądrze Linux w powtarzalne harmonogramy dostępu do pamięci. Może automatycznie enumerować wykonania **A-B-A** w dwóch kontekstach albo pozwalać analitykowi narzucać ograniczenia kolejności w terminalu lub GUI. To eksperymentalne narzędzie badawcze, a nie kompletny fuzzer współbieżności: obecnie wymaga LLVM 23+ i zmodyfikowanego jądra projektu, narzędzia wiersza poleceń obsługują dwa wątki testowe, a proponowana warstwa fuzzingu w przestrzeni użytkownika nie została zaimplementowana.<sup>[[17]](#references)[[18]](#references)</sup>

### Zbieranie punktów komunikacji między kontekstami

Zbuduj instrumentowane jądro z callbackami KASAN outline i zmodyfikowaną obsługą rejestrowania dostępu do pamięci KCOV. README projektu zaleca również wyłączenie optymalizacji sibling-call, aby stosy wywołań pozostały użyteczne.<sup>[[17]](#references)[[18]](#references)</sup>

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

Tryb outline KASAN (`asan-instrumentation-with-call-threshold=0`) zamienia instrumentowane dostępy na wywołania funkcji pomocniczych. Poprawki jądra MAccConc wyłączają `asan-opt-same-temp`, aby kolejne dostępy nie były łączone; wyłącz także optymalizację `asan-opt-globals`, gdy wyścigi dotyczące zmiennych globalnych muszą być widoczne. KCOV przekazuje powstałe rekordy do przestrzeni użytkownika. Porównuj dostępy z różnych kontekstów wykonania i zachowuj pary, których zakresy bajtów się nakładają, a co najmniej jedna strona wykonuje zapis; traktuj `kfree()` jak zapis, aby uwzględnić także kandydatów związanych ze zmianami czasu życia.<sup>[[17]](#references)</sup>

W przypadku pracy wykonywanej poza zadaniem inicjującym, takiej jak przetwarzanie pakietów lub wywołania zwrotne RCU, podsystem musi propagować uchwyt zdalnego pokrycia KCOV. Zdalne KCOV w wersji upstream jest opcjonalne i nie jest automatycznie dostępne dla dowolnej pracy w tle, więc brak propagacji może sprawić, że rzeczywista interakcja pozostanie niewidoczna.<sup>[[17]](#references)[[19]](#references)</sup>

### Identyfikuj ten sam dynamiczny dostęp przy każdym uruchomieniu

Nie odtwarzaj wykonania względem konkretnego adresu na stercie, który może się zmienić po każdej alokacji, ani wyłącznie względem adresu instrukcji, który jest niejednoznaczny wewnątrz funkcji pomocniczych, takich jak `memcpy()` i `spin_lock()`. MAccConc używa **śladu stosu rozszerzonego o liczniki**: każda ramka identyfikuje funkcję wywoływaną oraz licznik jej wywołań w funkcji wywołującej, a ostatni element identyfikuje instrukcję dostępu do pamięci. Rekordy wejścia/wyjścia z funkcji SanitizerCoverage pozwalają przestrzeni użytkownika odtworzyć ten dynamiczny identyfikator, który pozostaje stabilny mimo zmian adresów i niepowiązanego szumu w przepływie sterowania.<sup>[[17]](#references)</sup>

### Zamieniaj pary kandydatów na wymuszone harmonogramy

Poprawiony ioctl `KCOV_SET_DI` wiąże identyfikator dostępu rozszerzony o liczniki z akcją na wspólnej fladze.<sup>[[17]](#references)</sup>

| Akcja | Semantyka |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Ustawia flagę *N* bezpośrednio przed wybranym dostępem. |
| `DI_STACK_WAIT` | Przed wybranym dostępem czeka aktywnie, aż flaga *N* zostanie ustawiona lub upłynie skonfigurowany limit. |
| `DI_STACK_WAKE_POST` | Ustawia flagę *N* bezpośrednio po wybranym dostępie. |

Aby wymusić częściowy warunek **A-happens-before-B**, przypisz `DI_STACK_WAKE_POST` do A, a `DI_STACK_WAIT` do B, używając tej samej flagi. W pełni określony harmonogram dwóch kontekstów uzyskasz, blokując początkowo B, a następnie każąc A odblokować B i czekać przy pierwszym punkcie przekazania sterowania; B wykonuje odwrotną operację przy kolejnym przekazaniu. To drugie rozwiązanie działa jak deterministyczne przełączanie kontekstów i jest używane przez automatyczny eksplorator A-B-A.<sup>[[17]](#references)</sup>

Minimalna kampania polega na skompilowaniu przypadku testowego z czterema punktami zaczepienia (`test_setup`, dwie funkcje wątków i `test_end`) jako biblioteki współdzielonej, zebraniu śladu bez ograniczeń, a następnie wyliczeniu kandydatów A-B-A lub dodaniu ręcznych ograniczeń wokół podejrzanych dostępów.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpretuj timeouty oddzielnie od udanych zmian kolejności: żądana kolejność może być niemożliwa, ponieważ blokada lub zależność inicjalizacji/publikacji uniemożliwia drugiemu kontekstowi dotarcie do punktu wstrzyknięcia. Pamiętaj też o ślepych punktach KASAN: bezpośrednie dostępy do stosu zwykle nie są przechwytywane, chyba że mogą wykraczać poza jego granice, zmienne globalne są pomijane przy domyślnej optymalizacji, a obecne kompilatory nie mogą jednocześnie emitować hooków ASAN i TSAN. Ponadto prototyp traci bufor KCOV, gdy maszyna wirtualna gościa ulega awarii, dlatego zachowaj niezależną konsolę/wyrocznię awarii.<sup>[[17]](#references)</sup>

Na potrzeby przyszłego fuzzingu sterowanego współbieżnością zapisuj podsumowania dostępu do pamięci dla poszczególnych danych wejściowych lub wywołań systemowych, łącz operacje, które mogłyby tworzyć punkty komunikacji między kontekstami, a następnie badaj tylko te kombinacje. Migawki maszyn wirtualnych stabilizują stan globalny i adresy; bez migawek metadane miejsc alokacji mogą umożliwić abstrakcję obiektów między uruchomieniami. To proponowane rozszerzenie, a nie funkcja obecnych narzędzi użytkownika MAccConc.<sup>[[17]](#references)</sup>

## Introspekcja harnessa: wcześnie wykrywaj płytkie fuzzery

Gdy kampania utknie, problemem często nie jest mutator, lecz **harness**. Użyj **introspekcji osiągalności/pokrycia**, aby znaleźć funkcje statycznie osiągalne z celu fuzzingu, które rzadko lub nigdy nie są dynamicznie pokrywane. Takie funkcje zwykle wskazują na jeden z trzech problemów.<sup>[[12]](#references)</sup>

- Harness wchodzi do celu zbyt późno lub zbyt wcześnie.
- W korpusie początkowym brakuje całej rodziny funkcji.
- Cel rzeczywiście wymaga **drugiego harnessa**, zamiast jednego rozbudowanego harnessa typu „zrób wszystko”.

Jeśli używasz przepływów pracy w stylu OSS-Fuzz / ClusterFuzz, Fuzz Introspector może porównać statyczną osiągalność z pokryciem w czasie działania i wygenerować raporty na podstawie uruchomienia o określonym czasie trwania lub publicznego korpusu.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Użyj raportu, aby zdecydować, czy dodać nowy harness dla nieprzetestowanej ścieżki parsera, rozszerzyć corpus dla konkretnej funkcji, czy podzielić monolityczny harness na mniejsze punkty wejścia.

## Wybór fuzz targetów na podstawie grafu i analiza wyników mutacji

Jeśli masz już wyniki **analizy statycznej**, **mutanty, które przetrwały testy mutacyjne**, oraz **raporty pokrycia**, nie analizuj ich jako niezależnych list. Najpierw zbuduj **graf wywołań**, opisz węzły za pomocą **złożoności cyklomatycznej**, **osiągalności z punktów wejścia/niezaufanych danych wejściowych** i wszelkich zewnętrznych ustaleń, a następnie zadaj pytania dotyczące grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Które funkcje o wysokiej złożoności są osiągalne z niezaufanych danych wejściowych?
- Które mutanty, które przetrwały testy, znajdują się na ścieżkach od parserów/handlerów do kodu krytycznego dla bezpieczeństwa?
- Które funkcje są architektonicznymi wąskimi gardłami o wyjątkowo dużym **blast radius**?

Takie podejście zwykle pozwala znaleźć lepsze cele fuzzingu niż samo kierowanie się „najniższym pokryciem”. Parser/dekoder o **wysokiej złożoności** i potwierdzonej **osiągalności z zewnątrz** jest lepszym kandydatem na harness niż odizolowana wewnętrzna funkcja pomocnicza ze słabym pokryciem, ale bez ścieżki sterowanej przez atakującego.

### Praktyczny proces analizy

1. Zbuduj **graf kodu** na podstawie codebase i wyodrębnij metryki złożoności/liczby gałęzi dla każdej funkcji.
2. Wypisz **punkty wejścia** przyjmujące dane kontrolowane przez atakującego: handlery żądań, dekodery, importery, parsery protokołów oraz czytniki CLI/plików.
3. Wykonaj zapytania o ścieżki od tych punktów wejścia do wybranych funkcji, aby oddzielić osiągalną powierzchnię ataku od kodu martwego lub dostępnego wyłącznie wewnętrznie.
4. Nadaj priorytet węzłom, które łączą:
   - wysoką **złożoność cyklomatyczną**
   - potwierdzoną **osiągalność z niezaufanych danych wejściowych**
   - duży **blast radius** lub wielu zależnych elementów w dalszej części kodu
   - potwierdzające dowody, takie jak ustalenia **SARIF**, notatki z audytu lub mutanty, które przetrwały testy
5. Najpierw przygotuj ukierunkowane harnessy dla najlepiej ocenionych węzłów, zwłaszcza **parserów/kodeków**, takich jak dekodery hex/Base64/IP/wiadomości.

### Mutanty, które przetrwały testy: równoważne czy istotne?

Testy mutacyjne często generują zaszumioną listę mutantów, które przetrwały testy. Zanim uznasz każdy z nich za lukę w zabezpieczeniach, użyj grafu, aby sprawdzić:

- Czy zmodyfikowana funkcja jest osiągalna z punktu wejścia kontrolowanego przez atakującego?
- Czy wszystkie ścieżki wywołań są ograniczone silniejszymi niezmiennikami niż zmodyfikowane sprawdzenie?
- Czy węzeł znajduje się w martwym kodzie, logice służącej wyłącznie formatowaniu czy ścieżce o dużym wpływie, związanej z arytmetyką/parserem?

Mutanty, które pozostają nieosiągalne lub są strukturalnie ograniczone, są często **mutantami równoważnymi**. Mutanty, które są nadal **osiągalne** i dotyczą **warunków brzegowych**, **ścieżek przepełnienia/przeniesienia** lub **krytycznej dla bezpieczeństwa arytmetyki/parsowania**, należy uwzględnić w:

- nowych harnessach fuzzingu
- bezpośrednich testach właściwości/niezmienników
- ukierunkowanych zestawach przypadków brzegowych

### Nanieś zewnętrzne ustalenia na graf

Jeśli Twój pipeline SAST eksportuje **SARIF**, nanieś ustalenia na węzły grafu na podstawie **pliku i zakresu wierszy**, a następnie użyj grafu, aby rozszerzyć analizę wpływu.<sup>[[6]](#references)</sup>

- oblicz **blast radius** oznaczonej funkcji
- sprawdź, czy ustalenie znajduje się na którejkolwiek ścieżce od punktu wejścia
- pogrupuj sąsiadujące ustalenia, które zbiegają się w tym samym wąskim gardle

Przydaje się to przy podejmowaniu decyzji, czy poświęcić czas na fuzzing konkretnej funkcji: węzeł, który jest **osiągalny**, **złożony** i ma już ustalenia **SAST**, często jest lepszym celem niż węzeł jedynie złożony, bez ścieżki dostępnej dla atakującego.

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

Ważna metodologia to część wspólna: **złożoność x ekspozycja x wpływ**. Użyj grafu, aby wybrać cele fuzzingu o najwyższej oczekiwanej wartości dla bezpieczeństwa, a następnie wykorzystaj mutacje, które przeszły testy, aby ustalić, które granice i niezmienniki powinien sprawdzać harness.<sup>[[5]](#references)</sup>

## Differential fuzzing kodowań kluczy kryptograficznych

Zacznij od poprawnych serializowanych kluczy lub standardowych wektorów testowych. Modyfikuj zakodowane pola, nie naruszając długości ani struktury wymaganej do przejścia przez ścieżki importu i operacji, a następnie przekazuj te same bajty niezależnym implementacjom. Porównuj akceptację i błędy. Losowe podpisy i szyfrogramy wymagają orakli poprawności, a nie porównania bajt po bajcie: weryfikuj podpisy lub porównuj wspólne sekrety z rundy enkapsulacji/dekapsulacji. Wektory testowe potwierdzają zgodność dla znanych przypadków; różnicowe mutacje pozwalają badać niepoprawne kodowania, których nie obejmują.<sup>[[23]](#references)[[26]](#references)</sup>

Dla tych formatów kluczy stosuj orakle właściwe dla danego formatu:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Rozszerzone klucze podpisujące ML-DSA:** zmieniaj współczynniki `s1` lub `s2` w spakowanej postaci tak, aby wykraczały poza `[-η, η]`, zachowując możliwość parsowania klucza. Sprawdź, czy import lub podpisywanie odrzuca klucz oraz czy uzyskany podpis przechodzi weryfikację. Same różnice w akceptacji nie oznaczają naruszenia standardów, ponieważ FIPS 204 nie wymaga dodatkowych kontroli kluczy prywatnych. Zobacz [mechanizm warunkowego wycieku](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Pary kluczy ML-KEM:** odróżnij wymagane kontrole klucza enkapsulacji i danych wejściowych dekapsulacji od opcjonalnej kontroli spójności pary (PCT) przy imporcie pary. Wykonaj enkapsulację przy użyciu klucza publicznego, dekapsulację przy użyciu klucza prywatnego i porównaj wspólne sekrety; niezgodność może zakłócić szyfrowaną komunikację, nawet jeśli poszczególne klucze przejdą kontrole danych wejściowych. Sprawdź, czy API weryfikuje dane wejściowe podczas operacji, czy za pomocą osobnego wywołania; libcrux udostępnia `validate_public_key(pk)` i `validate_private_key(sk, ct)`, które nie zastępują PCT.
- **Surowe klucze XMSS/XMSSMT:** testuj rundy serializacji i deserializacji kluczy **podpisujących i weryfikujących** dla różnych zestawów parametrów, a nie tylko operacje na kluczach przechowywanych w pamięci. XMSS i XMSSMT mają odrębne czterobajtowe przestrzenie nazw OID, więc parser sprawdzający najpierw XMSS może błędnie rozpoznać kolidujący klucz XMSSMT i odrzucić import. Opisany parser RustCrypto jest przykładem błędu interoperacyjności/dostępności, a nie sfałszowania podpisu.

## Fuzzing Go z gosentry: mocniejszy silnik, typowane dane wejściowe i kontrole różnicowe

Jeśli cel w Go ma już natywny harness `testing.F`, praktyczną ścieżką ulepszenia jest uruchomienie tego samego harnessu z [gosentry](https://github.com/trailofbits/gosentry) — forkiem toolchaina Go, który zachowuje `go test -fuzz`, ale zamienia backend na **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Jest to przydatne, gdy natywny fuzzer Go zatrzymuje się na **trudnych porównaniach**, **typowanych danych wejściowych** lub **formatach wymagających intensywnego parsowania**. Metodologia pozostaje taka sama:

- Nadal używaj `f.Add(...)` do dodawania seedów i `f.Fuzz(...)` jako callbacka.
- Użyj ponownie tego samego harnessa, ale uruchom go za pomocą pliku binarnego `go` z gosentry zamiast standardowego toolchaina.
- Traktuj kampanię jak zwykły coverage-guided run, ale z harmonogramowaniem i mutacjami LibAFL oraz lepszymi dodatkowymi detektorami.

### Zamień ciche błędy w wyniki fuzzingu

Powtarzającym się problemem w testach bezpieczeństwa Go jest to, że niebezpieczne zachowanie często domyślnie **nie powoduje awarii**. Dzięki gosentry możesz zamienić kilka klas „złych, ale cichych” stanów w wyniki fuzzingu.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` sprawia, że wybrane ścieżki logowania/błędów zachowują się jak awarie (przydatne w ścieżkach kodu w stylu `log.Fatal`, które w przeciwnym razie tylko logują i działają dalej).
- `--catch-races=true` ponownie uruchamia nowo odkryte wpisy kolejki z detektorem wyścigów Go.
- `--catch-leaks=true` ponownie uruchamia nowe wpisy kolejki z `goleak` i zatrzymuje się w przypadku wycieków goroutine’ów.
- Obsługa zawieszeń w LibAFL pozwala zachować **nieskończone pętle / bardzo wolne dane wejściowe** jako wyniki fuzzingu zamiast odrzucać je jako przekroczenia limitu czasu.
- Domyślnie wbudowane sprawdzanie przepełnień arytmetycznych oraz opcjonalne sprawdzanie obcięć za pomocą instrumentacji w stylu go-panikint.

Jest to szczególnie przydatne w przypadku celów, w których skutkiem dla bezpieczeństwa jest **błąd parsera bez paniki**, **błąd współbieżności** lub **zawieszenie powodujące wyłącznie DoS**, a nie uszkodzenie pamięci.

### Fuzzing uwzględniający struktury dla typowanych API Go

Natywny fuzzing Go obsługuje głównie typy skalarne, takie jak `[]byte`, `string` i liczby. Jeśli testowany kod przyjmuje typowane obiekty, gosentry może bezpośrednio fuzzować **wartości złożone** (struktury, slice’y, tablice, wskaźniki), nadal modyfikując przy tym bajty.<sup>[[7]](#references)[[8]](#references)</sup>

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

Użyj tego, gdy tworzenie fałszywego formatu wire wyłącznie na potrzeby fuzzingu ukryłoby błędy logiki za kodem parsującym używanym tylko przez harness. W kampaniach różnicowych lub opartych na gramatyce pozostaw wejście harness jako pojedyncze `[]byte` lub `string` i parsuj je wewnątrz callbacka.

### Fuzzing oparty na gramatyce dla parserów i danych wejściowych protokołów

W przypadku parserów, formatów i języków wejściowych gosentry może uruchamiać **fuzzing gramatyczny Nautilus** na bazie LibAFL. Gramatyka to tablica reguł produkcji w formacie JSON, a harness powinien zwykle przyjmować pojedynczy argument `[]byte` lub `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Uwagi metodologiczne:

- Używaj trybu gramatycznego, gdy mutacje na poziomie bajtów najczęściej kończą się na wczesnych kontrolach składni.
- Ogranicz gramatykę do **podzbioru języka/protokołu istotnego z punktu widzenia bezpieczeństwa**, zamiast modelować całą specyfikację.
- Stosuj duże wartości graniczne w terminalach/nieterminalach, aby testować granice liczb całkowitych, długości i maszyny stanów.
- Tryb gramatyczny zapewnia poprawność składniową wejść, ale cel nadal otrzymuje **bajty/ciągi znaków**, więc parsowanie i kontrole semantyczne nadal odbywają się w kodzie objętym harness.

### Differential fuzzing: porównuj implementacje, nie tylko awarie

Skutecznym podejściem w ekosystemach Go jest **grammar-based differential fuzzing**: generowanie poprawnych, ustrukturyzowanych wejść i przekazywanie ich do dwóch parserów, klientów lub silników przejść stanów.<sup>[[7]](#references)[[8]](#references)</sup>

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

Traktuj poniższe jako wyniki:

- jedna implementacja kończy działanie panicą, podczas gdy druga poprawnie odrzuca dane wejściowe
- niezgodności w akceptowaniu/odrzucaniu danych wejściowych
- różne drzewa parsowania lub zdekodowane obiekty
- rozbieżne przejścia stanu, nonce, salda lub korzenie stanu

To praktyczny sposób na wykrywanie **niezgodności konsensusu**, **niejednoznaczności parsera** i **rozbieżności między specyfikacją a implementacją**, które często umykają podczas fuzzingu ukierunkowanego wyłącznie na awarie.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Ponowne wykorzystanie korpusu kampanii do raportowania pokrycia

Po kampanii odtwórz zapisany korpus kolejki, aby wygenerować raport pokrycia Go bez ręcznego eksportowania osobnego korpusu.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Uruchom polecenie z **tym samym pakietem** i tym samym celem `-fuzz`, aby gosentry rozpoznał właściwy stan buforowanej kampanii.

## References

- [1] [Fuzzing z gramatyką mutacyjną](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing w praktyce](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pięć lat później: fuzzing protokołów sterowany pokryciem](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark zamienia kod w grafy](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [W Go fuzzingowi brakowało połowy narzędzi. Rozwidliliśmy toolchain, aby to naprawić.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: szybki greybox fuzzer dla stanowych protokołów sieciowych wykorzystujący snapshoty](https://arxiv.org/abs/2202.03643)
- [10] [Bez gramatyki? Żaden problem: fuzzing jądra Linux bez opisów wywołań systemowych](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: wydajny fuzzing z adaptacyjnymi i modyfikowalnymi snapshotami](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentacja LLVM w AFL++: pokrycie ścieżek i wywołujących](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predykcyjny fuzzing uwzględniający kontekst](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Android Offensive Security - fuzzing Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer LKL dla Android Binder - dokumentacja budowania i seedów regresyjnych](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: badanie warunków wyścigu w jądrze Linux przy kontrolowanym przeplataniu dostępów do pamięci](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: pokrycie kodu na potrzeby fuzzingu](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Rozszerzona składnia nazw plików CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Porada Doyensec: CFITSIO, IV kwartał 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing rozszerzonej składni nazw plików CFITSIO: 16 luk w bezpieczeństwie pamięci i analiza wspomagana przez Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Fuzzing różnicowy w kryptografii](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: standard mechanizmu enkapsulacji klucza opartego na kratownicach modułowych](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Błąd parsowania OID w XMSSMT - zgłoszenie RustCrypto #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Stan implementacji kryptografii postkwantowej](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Jak snapshoty doprowadziły nas do CVE-2026-9539](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
- [29] [Project Zero - fuzzery kontra AI: porównanie Fuzzilli i BigSleep na silnikach JavaScript](https://projectzero.google/2026/10/fuzzing-v-AI.html)
{{#include ../banners/hacktricks-training.md}}
