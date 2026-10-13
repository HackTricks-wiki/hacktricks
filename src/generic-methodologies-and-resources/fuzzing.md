# Metodologia fuzzingu

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: pokrycie a semantyka

W **mutational grammar fuzzing** dane wejściowe są mutowane z zachowaniem **poprawności gramatycznej**. W trybie sterowanym pokryciem jako ziarna corpus zapisywane są tylko próbki wywołujące **nowe pokrycie**. W przypadku **celów językowych** (parserów, interpreterów, silników) może to pomijać błędy wymagające **łańcuchów semantycznych/przepływu danych**, w których wynik jednej konstrukcji staje się wejściem kolejnej.<sup>[[1]](#references)</sup>

**Tryb awarii:** fuzzer znajduje ziarna, które osobno wykonują `document()` i `generate-id()` (lub podobne prymitywy), ale **nie zachowuje łańcucha przepływu danych**, przez co próbka „bliższa błędowi” zostaje odrzucona, bo nie zwiększa pokrycia. Przy **co najmniej 3 zależnych krokach** losowe rekombinowanie staje się kosztowne, a informacja zwrotna o pokryciu nie ukierunkowuje wyszukiwania.<sup>[[1]](#references)</sup>

**Wniosek:** w przypadku gramatyk z wieloma zależnościami rozważ **połączenie faz mutacyjnych i generatywnych** albo ukierunkowanie generowania na wzorce **łańcuchowania funkcji** (a nie tylko na pokrycie).<sup>[[1]](#references)</sup>

## Pułapki związane z różnorodnością corpus

Mutowanie sterowane pokryciem jest **zachłanne**: próbka zapewniająca nowe pokrycie jest od razu zapisywana i często zachowuje duże, niezmienione fragmenty. Z czasem w corpus gromadzą się **niemal identyczne próbki** o małej różnorodności strukturalnej. Agresywna minimalizacja może usunąć przydatny kontekst, dlatego praktycznym kompromisem jest **minimalizacja uwzględniająca gramatykę**, która **zatrzymuje się po osiągnięciu minimalnego progu tokenów** (ogranicza szum, zachowując dość otaczającej struktury, by ułatwić mutowanie).<sup>[[1]](#references)</sup>

Praktyczna zasada dotycząca corpus w mutational fuzzing: **preferuj niewielki zestaw strukturalnie różnych ziaren maksymalizujących pokrycie** zamiast dużej puli niemal identycznych próbek. W praktyce zwykle oznacza to:<sup>[[1]](#references)[[3]](#references)</sup>

- Zacznij od **próbek z rzeczywistego świata** (publicznych corpus, danych z crawlowania, przechwyconego ruchu, zbiorów plików z ekosystemu celu).
- Ogranicz ich liczbę za pomocą **minimalizacji corpus opartej na pokryciu**, zamiast zachowywać każdą poprawną próbkę.
- Utrzymuj ziarna **na tyle małe**, by mutacje trafiały w znaczące pola, zamiast zużywać większość cykli na nieistotne bajty.
- Ponownie uruchom minimalizację corpus po istotnych zmianach harnessu lub instrumentacji, ponieważ „najlepszy” corpus zmienia się wraz ze zmianami osiągalności.

## Mutowanie uwzględniające porównania dla wartości magicznych

Częstą przyczyną zastoju fuzzerów nie jest składnia, lecz **ścisłe porównania**: magiczne bajty, sprawdzanie długości, ciągi enum, sumy kontrolne lub wartości używane do wyboru parsera, chronione przez `memcmp`, tablice `switch` lub kaskady porównań. Czysto losowe mutowanie marnuje cykle na zgadywanie tych wartości bajt po bajcie.

W przypadku takich celów używaj **śledzenia porównań** (na przykład przepływów pracy w stylu AFL++ `CMPLOG` / Redqueen), aby fuzzer mógł obserwować operandy nieudanych porównań i ukierunkowywać mutacje na wartości, które je spełniają.<sup>[[3]](#references)</sup>

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

**Praktyczne wskazówki:**

- Jest to szczególnie przydatne, gdy cel ukrywa złożoną logikę za **sygnaturami plików**, **czasownikami protokołu**, **tagami typów** lub **bitami funkcji zależnymi od wersji**.
- Połącz tę metodę ze **słownikami** utworzonymi na podstawie rzeczywistych próbek, specyfikacji protokołów lub logów debugowania. Niewielki słownik zawierający tokeny gramatyczne, nazwy fragmentów, czasowniki i separatory jest często bardziej wartościowy niż ogromna, uniwersalna lista słów.
- Jeśli cel wykonuje wiele kolejnych kontroli, najpierw rozwiąż najwcześniejsze porównania „magic”, a następnie ponownie zminimalizuj uzyskany korpus, aby kolejne etapy zaczynały od już poprawnych prefiksów.

## Fuzzing API plików ukrywających język nazw plików

Parametr o nazwie `filename`, `path` lub `URL` może być punktem wejścia interpretera, a nie zwykłym wyszukiwaniem pliku. Na przykład CFITSIO Extended Filename Syntax (EFS) przetwarza selektory w nawiasach kwadratowych, wyrażenia dotyczące wierszy/pikseli, obliczane kolumny, histogramy i transformacje, zanim zwróci otwarty obiekt; niektóre formy tworzą również kopie tymczasowe. Podczas mapowania powierzchni ataku klasyfikuj każde API otwierania/importowania jako **literal-path** lub **interpreted-path**, a następnie fuzzuj produkcyjny punkt wejścia, z którego faktycznie korzystają aplikacje.<sup>[[20]](#references)[[22]](#references)</sup>

Informacje o wynikających z tego prymitywach SSRF, kopiowania plików i obsługi protokołów — oraz o bezpieczniejszych API obsługujących literalne ścieżki — znajdziesz w [Mikrojęzyki nazw plików jako prymitywy SSRF/kopiowania plików](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Oddziel obiekt źródłowy od fuzzowanego programu

Gdy gramatyka znajduje się w sufiksie nazwy pliku, modyfikowanie wyłącznie bajtów wskazanego pliku pomija parser. Zamiast tego niewielki harness może odczytać pojedynczy testcase jako ciąg znaków i przekazać go do API otwierającego pliki w trybie interpretowanym; kampania dla CFITSIO dotarła do większości parserów i ewaluatorów EFS przez wywołanie `fits_open_file()` w trybie tylko do odczytu. Udostępniaj osobno poprawne pliki źródłowe, aby mutacje mogły skupiać się na języku selektorów/wyrażeń, zamiast ciągle uszkadzać ścieżkę bazową.<sup>[[22]](#references)</sup>

Użyj seedów, z których każdy dociera do innej rodziny gramatyk, a następnie utwórz zwięzły słownik na podstawie zarówno specyfikacji, jak i kodu źródłowego lexer/parsera. Jeśli pokrycie przestaje rosnąć, a wejścia wielokrotnie kończą się na tej samej ścieżce błędu składni, zachowaj poprawne prefiksy i dodaj separatory, operatory, słowa kluczowe, nazwy funkcji oraz przykładowe nazwy pól, zamiast jedynie wydłużać czas losowych mutacji.<sup>[[22]](#references)</sup>

Uruchom harness ze słownikiem gramatyki, na przykład:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Ograniczanie efektów ubocznych harnessu „tylko do odczytu”

Flaga biblioteki „tylko do odczytu” nie gwarantuje, że testcase nie wywoła efektów ubocznych: język nazw plików może przepisać dane wejściowe, utworzyć pliki wyjściowe lub utworzyć tymczasowe obiekty. Kampania CFITSIO początkowo niszczyła pliki seedów i pozostawiała nieoczekiwane pliki w systemie plików, dlatego konieczne były czyszczenie i izolacja.<sup>[[22]](#references)</sup>

- Przydziel każdemu workerowi jednorazowy katalog roboczy i prywatny katalog tymczasowy.
- Udostępniaj kopie kanonicznych plików bazowych; nigdy nie pozwalaj celowi modyfikować jedynej kopii corpus.
- Wyłącz dostęp do sieci, chyba że zdalne backendy są zamierzonym celem, i ogranicz zapisywalne ścieżki za pomocą kontenera, przestrzeni nazw montowań lub równoważnego sandboxa.
- Resetuj katalog po każdym wykonaniu lub partii workerów i traktuj nieoczekiwane zmiany w systemie plików jako dodatkowe znaleziska.

### Pętla: crash → patch → fuzz

Przed naprawą grupuj crashe, aby tysiące artefaktów nie przerodziły się w tysiące zadań związanych z patchowaniem. W ocenie CFITSIO narzędzie AFLTriage ograniczyło początkowy zbiór crashy do kilku przyczyn źródłowych; powstałe advisory opisuje odrębne błędy, w tym nieprawidłowe sprawdzanie rozmiaru bufora docelowego, nieaktualne wskaźniki po `realloc()`, błędy arytmetyczne i niebezpieczne ścieżki czyszczenia parsera.<sup>[[21]](#references)[[22]](#references)</sup>

1. Zminimalizuj reprezentatywne dane wejściowe dla każdego klastra i odtwórz błąd z użyciem AddressSanitizer.
2. Zapisz dokładny błędny dostęp, lokalizację w kodzie źródłowym, historię alokacji/zwalniania oraz stan parsera, który doprowadził do naruszenia niezmiennika.
3. Zastosuj jedną, wąsko zakrojoną poprawkę i przebuduj program z użyciem tych samych instrumentacji pokrycia i sanitizera.
4. Odtwórz pierwotny przypadek reprodukujący błąd **oraz wszystkie dane wejściowe z jego klastra**; włącz też wykrywanie wycieków, ponieważ poprawka dotycząca bezpieczeństwa pamięci może naruszyć zarządzanie własnością na ścieżce błędu.
5. Uruchom testy funkcjonalne na rzeczywistych plikach, a następnie wznów fuzzing z użyciem zgromadzonej kolejki (lub zaimportuj ją ponownie, jeśli silnik wymaga nowego katalogu wyjściowego po zmianie binarnej).
6. Powtarzaj ten proces: usunięcie pierwszego, płytkiego crasha często pozwala istniejącym seedom przejść do głębszego stanu parsera.

LLM może przyspieszyć krok 2 i przygotować szkic poprawki w kroku 3, jeśli otrzyma crashujące dane wejściowe, raport sanitizera, harness i odpowiedni kod źródłowy, ale jego poprawka pozostaje niezaufana. O przyjęciu poprawki decydują odtworzenie błędu z użyciem sanitizera i testy regresyjne, a nie wyjaśnienie modelu.<sup>[[22]](#references)</sup>

## Bogatsza informacja zwrotna, gdy pokrycie krawędzi nie rozróżnia różnych ścieżek

Zwykłe pokrycie krawędzi nie rozróżnia dwóch wykonań, które przechodzą przez tę samą funkcję pomocniczą, ale pochodzą od różnych wywołujących je funkcji albo wybierają różne kombinacje gałęzi wewnątrz funkcji. Ma to znaczenie w współdzielonych dekoderach, dispatcherach protokołów i funkcjach pomocniczych interpreterów, gdzie **ścieżka** prowadząca do krawędzi określa aktywny stan. Naiwne śledzenie każdego kontekstu wywołania również jest niebezpieczne: mapa pokrycia i kolejka mogą gwałtownie urosnąć. Badania nad fuzzingiem uwzględniającym kontekst zalecają więc uszczegóławianie wyłącznie obiecujących kontekstów, zamiast uwzględniania kontekstu w całym grafie wywołań.<sup>[[14]](#references)</sup>

Nowsze kompilacje AFL++ zapewniają **pokrycie ścieżek Ball-Larus dla poszczególnych funkcji** oprócz zwykłego pokrycia krawędzi. Przypisuje ono cechę każdej acyklicznej ścieżce przez funkcję; krawędzie powrotne pętli są usuwane, więc ta informacja zwrotna rozróżnia kombinacje gałęzi, ale **nie liczbę iteracji pętli**. Zacznij od łagodnego poziomu `1`, a następnie stosuj bardziej rygorystyczne tryby tylko do podejrzanego kodu parsera lub maszyny stanów, ponieważ liczba ścieżek może rosnąć wykładniczo.<sup>[[13]](#references)</sup>

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

**Wskazówki dotyczące kampanii:** ostrożnie stosuj bogatsze informacje zwrotne i monitoruj ich koszt w postaci mapy pokrycia i kolejki.<sup>[[13]](#references)[[14]](#references)</sup>

- Uruchom równolegle zwykłą instancję z pokryciem krawędzi; bogatsze informacje zwrotne są przydatne tylko wtedy, gdy dodatkowy koszt mapy i kolejki nie obniża liczby wykonań na sekundę.
- Użyj `AFL_LLVM_ALLOWLIST`, aby ograniczyć instrumentację ścieżek/wywołujących, gdy duże biblioteki oparte na szablonach lub ogólny kod narzędziowy dominują w mapie.
- Funkcje z nadmierną liczbą ścieżek acyklicznych można pominąć w AFL++; ostrzeżenia podczas kompilacji wskazują, że cel wymaga allowlisty lub mniej restrykcyjnego poziomu.
- Pokrycie wywołującego i ścieżki obsługuje tylko jeden poziom wywołującego. Nie łącz go z głębszymi stosami kontekstu.
- Identyfikatory ścieżek mogą się zmieniać między głównymi wersjami LLVM. Na czas kampanii używaj niezmiennego toolchaina i nie synchronizuj korpusów opartych na PATH tak, jakby ich identyfikatory funkcji były stabilne między kompilacjami.
- Te informacje zwrotne uzupełniają `CMPLOG`: śledzenie porównań pomaga ustalić, **jaka wartość przechodzi przez warunek**, natomiast informacje o ścieżce/wywołującym pozwalają zachować **która trasa i kombinacja gałęzi do niej doprowadziły**.

## Fuzzing stanowy: sekwencje są seedami

W przypadku **protokołów**, **uwierzytelnionych przepływów pracy** i **parserów wieloetapowych** interesującą jednostką często nie jest pojedynczy blob, lecz **sekwencja komunikatów**. Konkatenowanie całego zapisu interakcji w jeden plik i jego bezmyślna mutacja są zazwyczaj nieefektywne, ponieważ fuzzer mutuje każdy etap jednakowo, nawet jeśli tylko późniejszy komunikat dociera do podatnego stanu.<sup>[[4]](#references)</sup>

Skuteczniejszym podejściem jest traktowanie **samej sekwencji jako seeda** i wykorzystywanie **obserwowalnego stanu** (kodów odpowiedzi, stanów protokołu, faz parsera, typów zwracanych obiektów) jako dodatkowych informacji zwrotnych.<sup>[[4]](#references)</sup>

- Zachowuj **poprawne komunikaty prefiksowe** bez zmian i skup mutacje na komunikacie **sterującym przejściem**.
- Buforuj identyfikatory i wartości generowane przez serwer w poprzednich odpowiedziach, jeśli następny krok od nich zależy.
- W miarę możliwości mutuj lub łącz poszczególne komunikaty zamiast mutować cały zserializowany zapis interakcji jako nieprzejrzysty blob.
- Jeśli protokół udostępnia znaczące kody odpowiedzi, używaj ich jako **taniej wyroczni stanu**, aby nadawać priorytet sekwencjom wchodzącym głębiej w protokół.

Z tego samego powodu błędy uwierzytelniania, ukryte przejścia lub błędy parsera występujące „dopiero po uzgodnieniu” często umykają standardowemu fuzzingowi plikowemu: fuzzer musi zachować **kolejność, stan i zależności**, a nie tylko strukturę.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing sterownika z wieloma klientami

Wysokie pokrycie krawędzi nadal może nie wykryć błędów sterownika IPC, ponieważ pokrycie nie opisuje **własności obiektów, liczników referencji, oczekujących komunikatów, kolejności sprzątania ani przeplotów wątków**. Strona [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) omawia model obiektów sterownika; ten przykład skupia się na harnessie fuzzera. Android Binder to przydatny model: samo dotarcie zarówno do ścieżek alokacji, jak i zwalniania nie wystarczy, jeśli fuzzer nie potrafi sprawić, by wiele procesów operowało na tym samym obiekcie jądra w wymaganej kolejności.<sup>[[15]](#references)</sup>

#### Modeluj protokół, a nie pojedyncze bufory `ioctl`

Reprezentuj przypadek testowy jako uporządkowaną gramatykę **tożsamości klienta + operacji + ustrukturyzowanych argumentów**. Fuzzer Binder LKL używa protobuf i `libprotobuf-mutator`, z jednym trwałym klientem menedżera kontekstu i dwoma zwykłymi klientami. Semantyczny harness zachowuje następnie zależności, które ślepa mutacja bajtów zniszczyłaby.<sup>[[15]](#references)</sup>

- Buforuj wartości zwracane przez wcześniejsze operacje. Na przykład `BC_FREE_BUFFER` musi ponownie wykorzystać wskaźnik bufora transakcji zwrócony przez poprzednie `ioctl`.
- Generuj poprawne domyślne odpowiedzi, aby transakcje synchroniczne mogły się zakończyć, a późniejsze operacje pozostały osiągalne.
- Odrzucaj niemożliwe przejścia, takie jak transakcje do samego siebie lub wiele oczekujących transakcji skierowanych do tego samego celu.
- Utrzymuj stan singletonu inicjalizacyjnego poza resetem wykonywanym dla każdego wejścia. Binder pozwala na tylko jedną rejestrację `BINDER_SET_CONTEXT_MGR` podczas rozruchu, więc wielokrotne niszczenie i odtwarzanie tego klienta unieważniałoby kolejne wejścia.

Przydatny szablon wyścigu o czas życia polega na tym, by jeden klient przekazał obiekt, rozpoczął sprzątanie wątku lub procesu, a jednocześnie klient odbierający zwolnił bufor transakcji. W przykładzie CVE-2020-0423 przekazanie `BINDER_TYPE_WEAK_BINDER`, po którym `BINDER_THREAD_EXIT` ścigało się z `BC_FREE_BUFFER`, mogło zwolnić osadzony `binder_work`, gdy ścieżka sprzątania kończącego działanie wątku nadal z niego korzystała.<sup>[[15]](#references)</sup>

#### Przywróć kontrolowane przeploty w jądrze działającym w przestrzeni użytkownika

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) linkuje rzeczywisty kod jądra z harnesssem działającym w przestrzeni użytkownika i udostępnia jego interfejs wywołań systemowych za pomocą `lkl_syscall`. Dzięki temu można łatwo koordynować stan protobuf, pokrycie i KASAN w jednym procesie. Zwykle jednak LKL wykonuje wywołanie systemowe bez przerywania go przez inny wątek jądra. W kampaniach wyścigów wstaw punkty `schedule()` wokół wybranych granic blokowania/odblokowywania i czasu życia, a następnie pozwól harnessowi losowo wybierać następnego klienta przy każdym ustąpieniu sterowania. Ogranicz te punkty do wybranych miejsc, ponieważ każdy z nich zwielokrotnia przestrzeń przeszukiwania harmonogramu. Opisany przez badaczy losowy scheduler **nie jest częścią upstreamowego fuzzera Binder**.<sup>[[15]](#references)</sup>

#### Buduj i odtwarzaj zserializowane seedy regresyjne

Upstreamowy harness przypina zgodną wersję `libprotobuf-mutator`, włącza instrumentację fuzzingu LKL i KASAN za pomocą `LKL_FUZZING=1`, a także włącza `CONFIG_MMU` dla Binder przez `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Po sprawdzeniu celowo podatnej rewizji lub zastosowaniu udokumentowanych upstream poprawek cofających zmiany, serializowany seed może odtworzyć całe wieloklientowe przejście stanu bez rekonstruowania go w doraźnym proof of concept w C:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Potraktuj wynikający z tego błąd use-after-free wykryty przez KASAN jako potwierdzenie, że seed dotarł do podatnej ścieżki cyklu życia. **Nie** dowodzi on istnienia późniejszych prymitywów wymaganych do wykonania kodu w kernelu ani eskalacji uprawnień.<sup>[[16]](#references)</sup>

## Sztuczka różnorodności na jednej maszynie (w stylu Jackalope)

Praktycznym sposobem na połączenie **nowości generowanej** z **ponownym wykorzystaniem pokrycia** jest **restartowanie krótkotrwałych workerów** w połączeniu z trwałym serwerem. Każdy worker zaczyna z pustym korpusem, synchronizuje go po `T` sekundach, przez kolejne `T` sekund działa na połączonym korpusie, ponownie synchronizuje dane, a następnie kończy działanie. Dzięki temu **każda generacja tworzy świeże struktury**, a jednocześnie wykorzystuje zgromadzone pokrycie.<sup>[[1]](#references)[[2]](#references)</sup>

**Serwer:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Workery sekwencyjne (przykładowa pętla):**

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

- `-in empty` wymusza **nowy corpus** przy każdej generacji.
- `-server_update_interval T` przybliża **opóźnioną synchronizację** (najpierw nowe przypadki, później ponowne użycie).
- W trybie grammar fuzzing **początkowa synchronizacja z serwerem jest domyślnie pomijana** (nie trzeba używać `-skip_initial_server_sync`).
- Optymalna wartość `T` zależy od **testowanego celu**; najlepsze efekty zwykle daje jej zmiana, gdy worker znajdzie już większość „łatwego” coverage.

## Snapshot Fuzzing dla celów trudnych do przygotowania

Gdy kod, który chcesz testować, staje się dostępny dopiero **po kosztownym przygotowaniu** (uruchomieniu VM, zalogowaniu, odebraniu pakietu, sparsowaniu kontenera, zainicjowaniu usługi), przydatną alternatywą jest **snapshot fuzzing**: przechwyć gotowy stan procesu lub VM, wstrzyknij każdy przypadek testowy do ścieżki wejściowej celu, wykonuj go aż do crasha lub timeoutu, a następnie przywróć snapshot. Pozwala to uniknąć ponownego wykonywania inicjalizacji lub prefiksów protokołu i sprawdza się w przypadku **usług sieciowych**, **firmware**, **powierzchni ataku dostępnych po uwierzytelnieniu** oraz **celów binarnych**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Uruchom cel, aż osiągnie interesujący stan.
2. Zrób snapshot **pamięci + rejestrów** w tym momencie.
3. Dla każdego przypadku testowego zapisz zmodyfikowane wejście bezpośrednio w odpowiednim buforze gościa/procesu.
4. Wykonuj aż do crasha/timeoutu/resetu.
5. Przywróć snapshot; w przypadku celów VM przywracaj tylko **zmodyfikowane strony**, jeśli jest to obsługiwane, a następnie powtórz.

Umieść snapshot możliwie blisko pierwszego kosztownego etapu parsowania lub dispatchu, na przykład po `recv`/`read` albo deserializacji pakietu, i zapisz, którego bufora wejściowego używa cel. Jest to zgodne z zasadą adaptacyjnego umieszczania snapshotu coraz głębiej w przetwarzaniu wejścia, aby uniknąć powtarzania pracy.<sup>[[11]](#references)</sup>

## Eksploracja wyścigów w jądrze Linux za pomocą MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) zamienia zależne od czasu wyścigi w jądrze Linux w powtarzalne harmonogramy dostępu do pamięci. Może automatycznie wyliczać wykonania **A-B-A** w dwóch kontekstach albo pozwala analitykowi narzucać ograniczenia kolejności w terminalowym UI/GUI. To eksperymentalne narzędzie badawcze, a nie kompletny concurrency fuzzer: obecnie wymaga LLVM 23+ i zmodyfikowanego jądra z projektu, narzędzia wiersza poleceń obsługują dwa wątki testowe, a proponowana warstwa fuzzingu w userspace nie jest zaimplementowana.<sup>[[17]](#references)[[18]](#references)</sup>

### Zbieranie punktów komunikacji między kontekstami

Zbuduj instrumentowane jądro z callbackami KASAN outline i zmodyfikowaną obsługą rejestrowania pamięci w KCOV. README projektu zaleca również wyłączenie optymalizacji sibling-call, aby stosy wywołań pozostały użyteczne.<sup>[[17]](#references)[[18]](#references)</sup>

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

Tryb outline KASAN (`asan-instrumentation-with-call-threshold=0`) zamienia instrumentowane dostępy na wywołania funkcji pomocniczych. Poprawki jądra MAccConc wyłączają `asan-opt-same-temp`, aby kolejne dostępy nie były scalane; wyłącz także optymalizację `asan-opt-globals`, gdy wyścigi dotyczące zmiennych globalnych mają być widoczne. KCOV przekazuje powstałe rekordy do przestrzeni użytkownika. Porównuj dostępy z różnych kontekstów wykonania i zachowuj pary, których zakresy bajtów się nakładają i z których co najmniej jeden zapisuje dane; traktuj `kfree()` jako zapis, aby przejścia cyklu życia również mogły być kandydatami.<sup>[[17]](#references)</sup>

W przypadku zadań wykonywanych poza kontekstem zadania inicjującego, takich jak przetwarzanie pakietów lub wywołania zwrotne RCU, podsystem musi przekazywać uchwyt zdalnego pokrycia KCOV. Zdalne KCOV w upstreamie jest opt-in i nie jest automatycznie dostępne dla dowolnych zadań działających w tle, więc brak przekazania uchwytu może sprawić, że rzeczywista interakcja pozostanie niewidoczna.<sup>[[17]](#references)[[19]](#references)</sup>

### Identyfikuj ten sam dynamiczny dostęp podczas każdego uruchomienia

Nie odtwarzaj testu względem konkretnego adresu sterty, który może się zmienić po każdej alokacji, ani wyłącznie względem adresu instrukcji, który jest niejednoznaczny wewnątrz funkcji pomocniczych, takich jak `memcpy()` i `spin_lock()`. MAccConc używa **śladu stosu wzbogaconego o liczniki**: każda ramka identyfikuje funkcję wywoływaną oraz liczbę jej wywołań w funkcji wywołującej, a ostatni element identyfikuje instrukcję dostępu do pamięci. Rekordy wejścia/wyjścia z funkcji SanitizerCoverage pozwalają przestrzeni użytkownika odtworzyć ten dynamiczny identyfikator, który pozostaje stabilny mimo zmian adresów i niepowiązanych zakłóceń przepływu sterowania.<sup>[[17]](#references)</sup>

### Zamień pary kandydatów na wymuszone harmonogramy

Poprawiony ioctl `KCOV_SET_DI` wiąże identyfikator dostępu wzbogacony o liczniki z akcją na współdzielonej fladze.<sup>[[17]](#references)</sup>

| Akcja | Semantyka |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Ustaw flagę *N* bezpośrednio przed wybranym dostępem. |
| `DI_STACK_WAIT` | Przed wybranym dostępem czekaj aktywnie, aż flaga *N* zostanie ustawiona lub upłynie skonfigurowany limit. |
| `DI_STACK_WAKE_POST` | Ustaw flagę *N* bezpośrednio po wybranym dostępie. |

Aby wymusić częściowy warunek **A-happens-before-B**, przypisz `DI_STACK_WAKE_POST` do A, a `DI_STACK_WAIT` do B, używając tej samej flagi. W przypadku w pełni określonego harmonogramu dwóch kontekstów zablokuj najpierw B, a następnie każ A obudzić B i czekać w pierwszym punkcie przekazania sterowania; przy kolejnym przekazaniu B wykonuje odwrotną operację. To drugie rozwiązanie działa jak deterministyczne przełączanie kontekstu i jest używane przez automatyczny eksplorator A-B-A.<sup>[[17]](#references)</sup>

Minimalna kampania polega na skompilowaniu przypadku testowego z czterema punktami zaczepienia (`test_setup`, dwiema funkcjami wątków i `test_end`) jako biblioteki współdzielonej, zebraniu śladu bez ograniczeń, a następnie wyliczeniu kandydatów A-B-A lub dodaniu ręcznych ograniczeń wokół podejrzanych dostępów.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpretuj timeouty oddzielnie od udanych zmian kolejności: żądana kolejność może być niemożliwa, ponieważ blokada lub zależność inicjalizacji/publikacji uniemożliwia dotarcie drugiego kontekstu do punktu wstrzyknięcia. Pamiętaj też o ślepych punktach KASAN: bezpośrednie odwołania do stosu zwykle nie są przechwytywane, chyba że mogą wykraczać poza jego granice, zmienne globalne są pomijane przy domyślnej optymalizacji, a obecne kompilatory nie potrafią jednocześnie emitować hooków ASAN i TSAN. Ponadto prototyp traci bufor KCOV, gdy guest ulega awarii, dlatego zachowaj niezależną konsolę/wyrocznię awarii.<sup>[[17]](#references)</sup>

Na potrzeby przyszłego fuzzingu sterowanego współbieżnością zapisuj podsumowania dostępu do pamięci dla każdego wejścia lub wywołania systemowego, łącz operacje, które tworzyłyby punkty komunikacji między kontekstami, a następnie badaj tylko te kombinacje. Migawki VM stabilizują stan globalny i adresy; bez migawek metadane miejsca alokacji mogą służyć do abstrakcyjnego odwzorowywania obiektów między uruchomieniami. To proponowane rozszerzenie, a nie funkcja obecnych narzędzi userspace MAccConc.<sup>[[17]](#references)</sup>

## Harness Introspection: Wcześnie wykrywaj płytkie fuzzery

Gdy kampania utknie, problemem często nie jest mutator, lecz **harness**. Użyj **introspekcji osiągalności/pokrycia**, aby znaleźć funkcje statycznie osiągalne z celu fuzzingu, które dynamicznie są rzadko lub wcale nie pokrywane. Takie funkcje zwykle wskazują na jeden z trzech problemów.<sup>[[12]](#references)</sup>

- Harness wchodzi do celu zbyt późno lub zbyt wcześnie.
- W korpusie seedów brakuje całej rodziny funkcji.
- Cel naprawdę wymaga **drugiego harnessu**, zamiast jednego, nadmiernie rozbudowanego harnessu typu „robi wszystko”.

Jeśli korzystasz z przepływów pracy w stylu OSS-Fuzz / ClusterFuzz, Fuzz Introspector może porównać statyczną osiągalność z pokryciem w czasie działania i wygenerować raporty na podstawie uruchomienia o określonym czasie trwania lub publicznego korpusu.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Użyj raportu, aby zdecydować, czy dodać nowy harness dla nieprzetestowanej ścieżki parsera, rozszerzyć corpus dla konkretnej funkcji czy podzielić monolityczny harness na mniejsze entrypointy.

## Wybór celu fuzzingu w pierwszej kolejności na podstawie grafu i triage wyników mutacji

Jeśli masz już **wyniki analizy statycznej**, **mutanty, które przetrwały testy mutacyjne**, i **raporty pokrycia**, nie traktuj ich jako niezależnych list. Najpierw zbuduj **graf wywołań**, dodaj do węzłów adnotacje o **złożoności cyklomatycznej**, **osiągalności z entrypointów i punktów wejścia niezaufanych danych** oraz o wszelkich zewnętrznych wynikach, a następnie analizuj graf.<sup>[[5]](#references)[[6]](#references)</sup>

- Które funkcje o wysokiej złożoności są osiągalne z niezaufanych danych?
- Które mutanty, które przetrwały testy, leżą na ścieżkach od parserów/handlerów do kodu krytycznego z punktu widzenia bezpieczeństwa?
- Które funkcje są architektonicznymi wąskimi gardłami o wyjątkowo dużym **blast radius**?

Takie podejście zwykle pozwala znaleźć lepsze cele fuzzingu niż samo kierowanie się „najniższym pokryciem”. Parser/dekoder o **wysokiej złożoności** i potwierdzonej **osiągalności z zewnątrz** jest lepszym kandydatem na harness niż odizolowany wewnętrzny helper o słabym pokryciu, ale bez ścieżki kontrolowanej przez atakującego.

### Praktyczny proces triage

1. Zbuduj **graf kodu** na podstawie codebase i wyodrębnij metryki złożoności/gałęzi dla każdej funkcji.
2. Wymień **entrypointy** przyjmujące dane kontrolowane przez atakującego: handlery żądań, dekodery, importery, parsery protokołów, czytniki CLI/plików.
3. Wykonaj zapytania o ścieżki od tych entrypointów do kandydatów, aby oddzielić osiągalną powierzchnię ataku od kodu martwego lub dostępnego wyłącznie wewnętrznie.
4. Nadaj priorytet węzłom, które łączą:
   - wysoką **złożoność cyklomatyczną**
   - potwierdzoną **osiągalność z niezaufanych danych**
   - duży **blast radius** lub wiele zależnych elementów
   - dodatkowe potwierdzające dowody, takie jak wyniki **SARIF**, notatki z audytu lub mutanty, które przetrwały testy
5. Najpierw napisz ukierunkowane harnessy dla najlepiej ocenionych węzłów, zwłaszcza dla **parserów/kodeków**, takich jak dekodery hex/Base64/IP/wiadomości.

### Mutanty, które przetrwały testy: równoważne czy istotne?

Testy mutacyjne często generują zaszumioną listę mutantów, które przetrwały. Zanim uznasz każdy z nich za lukę w zabezpieczeniach, wykorzystaj graf, aby sprawdzić:

- Czy zmutowana funkcja jest osiągalna z entrypointu kontrolowanego przez atakującego?
- Czy wszystkie ścieżki wywołań są ograniczone przez silniejsze niezmienniki niż zmutowany warunek?
- Czy węzeł znajduje się w martwym kodzie, logice służącej wyłącznie formatowaniu czy w ścieżce o dużym wpływie, związanej z arytmetyką/parserem?

Mutanty, które pozostają nieosiągalne lub są strukturalnie ograniczone, często są **mutantami równoważnymi**. Mutanty, które pozostają **osiągalne** i dotyczą **przypadków brzegowych**, **ścieżek przepełnienia/przeniesienia** lub **krytycznej z punktu widzenia bezpieczeństwa arytmetyki/parsingу**, należy uwzględnić w:

- nowych harnessach fuzzingowych
- bezpośrednich testach właściwości/niezmienników
- ukierunkowanych wektorach przypadków brzegowych

### Odwzoruj zewnętrzne wyniki na grafie

Jeśli Twój pipeline SAST eksportuje **SARIF**, przypisz wyniki do węzłów grafu na podstawie **pliku i zakresu linii**, a następnie użyj grafu, aby rozszerzyć analizę wpływu.<sup>[[6]](#references)</sup>

- oblicz **blast radius** oznaczonej funkcji
- sprawdź, czy wynik znajduje się na którejkolwiek ścieżce od entrypointu
- pogrupuj pobliskie wyniki, które zbiegają się w tym samym wąskim gardle

To pomaga zdecydować, czy warto poświęcić czas na fuzzing konkretnej funkcji: węzeł, który jest **osiągalny**, **złożony** i ma już wyniki **SAST**, często jest lepszym celem niż węzeł, który jest tylko złożony, ale nie ma ścieżki dostępnej dla atakującego.

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

Ważna jest metodologia oparta na przecięciu: **złożoność x ekspozycja x wpływ**. Użyj wykresu, aby wybrać cele fuzzingu o najwyższej oczekiwanej wartości dla bezpieczeństwa, a następnie wykorzystaj mutacje, które przetrwały, aby zdecydować, które granice i niezmienniki powinien testować Twój harness.<sup>[[5]](#references)</sup>

## Fuzzing w Go z gosentry: wydajniejszy silnik, typowane dane wejściowe i kontrole różnicowe

Jeśli cel w Go ma już natywny harness `testing.F`, praktyczną ścieżką ulepszenia jest uruchomienie tego samego harnessu za pomocą [gosentry](https://github.com/trailofbits/gosentry) — rozwidlonego toolchaina Go, który zachowuje `go test -fuzz`, ale zmienia backend na **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Jest to przydatne, gdy natywny fuzzer Go zatrzymuje się na **trudnych porównaniach**, **typowanych danych wejściowych** lub **formatach złożonych parserów**. Metodyka pozostaje taka sama:

- Nadal używaj `f.Add(...)` dla seedów i `f.Fuzz(...)` dla callbacka.
- Użyj ponownie tego samego harnessa, ale uruchom go za pomocą binarnego `go` z gosentry zamiast standardowego toolchaina.
- Traktuj uzyskaną kampanię jak zwykły coverage-guided run, ale z planowaniem i mutacjami LibAFL oraz lepszymi detektorami.

### Zamiana cichych błędów w wyniki fuzzingu

Powracającym problemem podczas audytów Go jest to, że niebezpieczne zachowanie często domyślnie **nie powoduje awarii**. Dzięki gosentry możesz zamienić kilka kategorii „złych, ale cichych” stanów w wyniki fuzzingu.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` sprawia, że wybrane ścieżki logowania/błędów zachowują się jak awarie (przydatne w ścieżkach kodu w stylu `log.Fatal`, które w przeciwnym razie tylko logują i działają dalej).
- `--catch-races=true` ponownie uruchamia nowo wykryte wpisy kolejki z detektorem wyścigów Go.
- `--catch-leaks=true` ponownie uruchamia nowe wpisy kolejki z `goleak` i zatrzymuje działanie w przypadku wycieków goroutine.
- Obsługa zawieszeń przez LibAFL pozwala zachować **nieskończone pętle / bardzo wolne dane wejściowe** jako wyniki fuzzingu, zamiast pozwolić im zniknąć jako timeoutom.
- Domyślnie wbudowane kontrole przepełnienia arytmetycznego, a także opcjonalne kontrole obcięcia za pomocą instrumentacji w stylu go-panikint.

Jest to szczególnie przydatne w przypadku celów, w których wpływ na bezpieczeństwo wynika z **błędu parsera bez panic**, **błędu współbieżności** lub **zawieszenia powodującego wyłącznie DoS**, a nie z uszkodzenia pamięci.

### Fuzzing uwzględniający struktury dla typowanych API Go

Natywny fuzzing Go oczekuje głównie wartości skalarnych, takich jak `[]byte`, `string` i liczby. Jeśli testowany kod przyjmuje typowane obiekty, gosentry może bezpośrednio fuzzować **wartości złożone** (struktury, wycinki, tablice, wskaźniki), nadal mutując bajty pod spodem.<sup>[[7]](#references)[[8]](#references)</sup>

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

Użycie tego przy budowaniu fałszywego wire formatu wyłącznie na potrzeby fuzzingu ukryłoby błędy logiki za kodem parsującym używanym tylko przez harness. W kampaniach różnicowych lub opartych na gramatyce pozostaw dane wejściowe harnessu jako pojedyncze `[]byte` lub `string` i parsuj je w callbacku.

### Fuzzing oparty na gramatyce dla parserów i danych wejściowych protokołów

W przypadku parserów, formatów i języków wejściowych gosentry może uruchamiać **Nautilus grammar fuzzing** na bazie LibAFL. Gramatyka to tablica reguł produkcji w formacie JSON, a harness powinien zwykle przyjmować pojedynczy argument `[]byte` lub `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Uwagi dotyczące metodyki:

- Używaj trybu gramatyki, gdy mutacje na poziomie bajtów zwykle odpadają podczas wczesnych kontroli składni.
- Skup gramatykę na **podzbiorze języka/protokołu istotnym z punktu widzenia bezpieczeństwa**, zamiast modelować całą specyfikację.
- Używaj dużych wartości brzegowych w terminalach/nieterminalach, aby obciążyć granice liczb całkowitych, długości i maszyn stanów.
- Tryb gramatyki utrzymuje poprawność gramatyczną danych wejściowych, ale cel nadal otrzymuje **bajty/ciągi znaków**, więc parsowanie i kontrole semantyczne nadal odbywają się w kodzie objętym harness.

### Fuzzing różnicowy: porównuj implementacje, nie tylko awarie

Skutecznym wzorcem w ekosystemach Go jest **fuzzing różnicowy oparty na gramatyce**: generuj poprawne, ustrukturyzowane dane wejściowe i przekazuj je do dwóch parserów, klientów lub silników przejść stanów.<sup>[[7]](#references)[[8]](#references)</sup>

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

- jedna implementacja powoduje panic, podczas gdy druga poprawnie odrzuca dane
- niezgodność w akceptowaniu lub odrzucaniu danych wejściowych
- różne drzewa parsowania lub zdekodowane obiekty
- rozbieżne przejścia stanu, nonce, salda lub korzenie stanu

To praktyczny sposób na wykrywanie **niezgodności konsensusu**, **niejednoznaczności parsera** i **rozbieżności między specyfikacją a implementacją**, które często umykają fuzzingowi ukierunkowanemu wyłącznie na awarie.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Wykorzystaj ponownie corpus kampanii do raportowania pokrycia

Po zakończeniu kampanii odtwórz zapisany corpus kolejki, aby wygenerować raport pokrycia Go bez ręcznego eksportowania osobnego corpus.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Uruchom polecenie z tego samego pakietu i z tym samym celem `-fuzz`, aby gosentry rozpoznał właściwy stan kampanii z pamięci podręcznej.



## References

- [1] [Mutacyjne fuzzing gramatyczny](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing w praktyce](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pięć lat później: fuzzing protokołów sterowany pokryciem](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark zamienia kod w grafy](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [W Go fuzzing brakowało połowy narzędzi. Rozwidleniem toolchainu naprawiliśmy ten problem.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: szybki fuzzer greybox dla stanowych protokołów sieciowych wykorzystujący migawki](https://arxiv.org/abs/2202.03643)
- [10] [Brak gramatyki? Żaden problem: w kierunku fuzzingu jądra Linux bez opisów wywołań systemowych](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: wydajny fuzzing z adaptacyjnymi i modyfikowalnymi migawkami](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentacja LLVM w AFL++: pokrycie ścieżek i wywołujących](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predykcyjny fuzzing uwzględniający kontekst](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Android Offensive Security — fuzzing Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer Binder dla LKL Android — dokumentacja kompilacji i seedów regresyjnych](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: badanie warunków wyścigu w jądrze Linux za pomocą kontrolowanych przeplotów dostępu do pamięci](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: pokrycie kodu na potrzeby fuzzingu](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Rozszerzona składnia nazw plików CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Ujawnienie Doyensec: CFITSIO, IV kwartał 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing rozszerzonej składni nazw plików CFITSIO: 16 luk w bezpieczeństwie pamięci i analiza wspomagana przez Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
{{#include ../banners/hacktricks-training.md}}
