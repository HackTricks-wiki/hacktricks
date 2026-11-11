# Metodologia fuzzingu

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: pokrycie a semantyka

W **mutational grammar fuzzing** wejścia są mutowane z zachowaniem **poprawności gramatycznej**. W trybie sterowanym pokryciem jako ziarna corpusu zapisywane są tylko próbki, które zapewniają **nowe pokrycie**. W przypadku **celów związanych z językami** (parserów, interpreterów, silników) może to pomijać błędy wymagające **łańcuchów semantycznych/przepływu danych**, w których wynik jednego elementu staje się wejściem kolejnego.<sup>[[1]](#references)</sup>

**Tryb awarii:** fuzzer znajduje ziarna, które osobno wywołują `document()` i `generate-id()` (lub podobne prymitywy), ale **nie zachowuje łańcuchowego przepływu danych**, przez co próbka „bliższa błędowi” zostaje odrzucona, bo nie zwiększa pokrycia. Przy **co najmniej 3 zależnych krokach** losowa rekombinacja staje się kosztowna, a informacja zwrotna o pokryciu nie ukierunkowuje wyszukiwania.<sup>[[1]](#references)</sup>

**Wniosek:** w przypadku gramatyk z wieloma zależnościami warto rozważyć **połączenie faz mutacyjnych i generatywnych** lub nadanie priorytetu wzorcom **łańcuchowego wywoływania funkcji** (nie tylko pokryciu).<sup>[[1]](#references)</sup>

## Pułapki związane z różnorodnością corpusu

Mutacje sterowane pokryciem są **zachłanne**: próbka zapewniająca nowe pokrycie jest od razu zapisywana, często z dużymi, niezmienionymi fragmentami. Z czasem corpusy stają się **niemal identycznymi** zbiorami o niewielkiej różnorodności strukturalnej. Agresywna minimalizacja może usunąć przydatny kontekst, dlatego praktycznym kompromisem jest **minimalizacja uwzględniająca gramatykę**, która **zatrzymuje się po osiągnięciu minimalnego progu liczby tokenów** (ogranicza szum, zachowując wystarczająco dużo otaczającej struktury, by ułatwić mutacje).<sup>[[1]](#references)</sup>

Praktyczna zasada dotycząca corpusu w fuzzingu mutacyjnym: **wybieraj mały zbiór zróżnicowanych strukturalnie ziaren maksymalizujących pokrycie**, zamiast dużej sterty niemal identycznych próbek. W praktyce zwykle oznacza to, co następuje.<sup>[[1]](#references)[[3]](#references)</sup>

- Zacznij od **próbek z rzeczywistych zastosowań** (publicznych corpusów, danych z crawlowania, przechwyconego ruchu, zestawów plików z ekosystemu celu).
- Ogranicz ich liczbę za pomocą **minimalizacji corpusów opartej na pokryciu**, zamiast zachowywać każdą poprawną próbkę.
- Zadbaj, by ziarna były **wystarczająco małe**, aby mutacje trafiały w istotne pola, a nie zużywały większości cykli na nieistotne bajty.
- Ponownie przeprowadź minimalizację corpusów po dużych zmianach harnessu lub instrumentacji, ponieważ „najlepszy” corpus zmienia się wraz ze zmianą osiągalności.

## Mutacje uwzględniające porównania dla wartości magicznych

Częstą przyczyną stagnacji fuzzerów nie jest składnia, lecz **ścisłe porównania**: magiczne bajty, kontrole długości, ciągi enum, sumy kontrolne lub wartości sterujące wyborem parsera, sprawdzane za pomocą `memcmp`, tablic `switch` lub kaskadowych porównań. Czysto losowe mutacje marnują cykle na zgadywanie tych wartości bajt po bajcie.

W przypadku takich celów użyj **śledzenia porównań** (na przykład procesów opartych na AFL++ `CMPLOG` / Redqueen), aby fuzzer mógł obserwować operandy nieudanych porównań i kierować mutacje ku wartościom, które je spełniają.<sup>[[3]](#references)</sup>

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

- Jest to szczególnie przydatne, gdy cel ukrywa głębszą logikę za **sygnaturami plików**, **czasownikami protokołu**, **znacznikami typów** lub bitami funkcji zależnymi od wersji.
- Połącz tę metodę ze **słownikami** wyodrębnionymi z rzeczywistych próbek, specyfikacji protokołów lub logów debugowania. Niewielki słownik zawierający tokeny gramatyczne, nazwy fragmentów, czasowniki i delimitery jest często cenniejszy niż ogromna, ogólna lista słów.
- Jeśli cel wykonuje wiele sekwencyjnych testów, najpierw rozwiąż najwcześniejsze porównania „magic”, a następnie ponownie zminimalizuj uzyskany korpus, aby kolejne etapy zaczynały się od już poprawnych prefiksów.

## Fuzzing API plików ukrywających język nazw plików

Parametr o nazwie `filename`, `path` lub `URL` może być punktem wejściowym interpretera, a nie dosłownym odwołaniem do pliku. Na przykład CFITSIO Extended Filename Syntax (EFS) przetwarza selektory w nawiasach kwadratowych, wyrażenia dotyczące wierszy i pikseli, obliczane kolumny, histogramy i transformacje, zanim zwróci otwarty obiekt; niektóre formy tworzą również kopie tymczasowe. Podczas mapowania powierzchni ataku sklasyfikuj każde API otwierające/importujące pliki jako **literal-path** lub **interpreted-path**, a następnie fuzzuj produkcyjny punkt wejściowy, z którego faktycznie korzystają aplikacje.<sup>[[20]](#references)[[22]](#references)</sup>

Informacje o wynikających z tego prymitywach SSRF, kopiowania plików i obsługi protokołów — oraz bezpieczniejszych API literal-path — znajdziesz w [Mini-języki nazw plików jako prymitywy SSRF/kopiowania plików](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Oddziel obiekt bazowy od fuzzowanego programu

Gdy gramatyka znajduje się w sufiksie nazwy pliku, modyfikowanie wyłącznie bajtów wskazanego pliku nie trafia w parser. Zamiast tego niewielki harness może odczytać pojedynczy testcase jako ciąg znaków i przekazać go do API otwierającego plik w trybie interpretowanym; kampania CFITSIO dotarła do większości parserów i ewaluatorów EFS, wywołując `fits_open_file()` w trybie tylko do odczytu. Udostępniaj osobno poprawne pliki bazowe, aby mutacje mogły skupiać się na języku selektorów i wyrażeń, zamiast stale uszkadzać ścieżkę bazową.<sup>[[22]](#references)</sup>

Użyj seedów, z których każdy dociera do innej rodziny gramatyk, a następnie utwórz zwięzły słownik na podstawie specyfikacji oraz kodu leksera/parsera. Jeśli pokrycie przestaje rosnąć, a dane wejściowe wielokrotnie kończą w tej samej ścieżce błędu składni, zachowaj poprawne prefiksy i dodaj delimitery, operatory, słowa kluczowe, nazwy funkcji oraz przykładowe nazwy pól, zamiast jedynie wydłużać czas losowych mutacji.<sup>[[22]](#references)</sup>

Uruchom harness ze słownikiem gramatyki, na przykład:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Ograniczanie efektów ubocznych harnessu w trybie „read-only”

Flaga biblioteki „read-only” nie gwarantuje, że testcase nie wywoła efektów ubocznych: język nazw plików może przepisać dane wejściowe, utworzyć pliki wyjściowe lub zmaterializować obiekty tymczasowe. Kampania CFITSIO początkowo niszczyła pliki seedów i pozostawiała nieoczekiwane pliki w różnych miejscach systemu plików, dlatego konieczne były sprzątanie i izolacja.<sup>[[22]](#references)</sup>

- Przydziel każdemu workerowi jednorazowy katalog roboczy i prywatny katalog tymczasowy.
- Udostępniaj kopie kanonicznych plików bazowych; nigdy nie pozwalaj celowi modyfikować jedynej kopii corpus.
- Wyłącz dostęp do sieci, chyba że zdalne backendy są celem testów, i ogranicz zapisywalne ścieżki za pomocą kontenera, przestrzeni nazw montowań lub równoważnego sandboxa.
- Resetuj katalog po każdym uruchomieniu lub partii workerów, a nieoczekiwane zmiany w systemie plików traktuj jako dodatkowe ustalenia.

### Pętla crash-to-patch-to-fuzz

Pogrupuj crashe przed naprawą, aby tysiące artefaktów nie przełożyły się na tysiące zadań związanych z łataniem. W ocenie CFITSIO AFLTriage ograniczył początkowy zbiór crashy do kilku przyczyn źródłowych; powstały advisory opisuje odrębne błędy, w tym nieprawidłowe sprawdzanie rozmiaru bufora docelowego, nieaktualne wskaźniki po `realloc()`, błędy arytmetyczne i niebezpieczne ścieżki czyszczenia parsera.<sup>[[21]](#references)[[22]](#references)</sup>

1. Zminimalizuj reprezentatywne dane wejściowe dla każdego klastra i odtwórz błąd z użyciem AddressSanitizer.
2. Zapisz dokładny błędny dostęp, lokalizację w kodzie źródłowym, historię alokacji i zwalniania pamięci oraz stan parsera, który doprowadził do naruszenia niezmiennika.
3. Zastosuj jedną, wąsko zakrojoną, proponowaną łatkę i przebuduj program z użyciem tych samych instrumentacji do pomiaru coverage i wykrywania błędów.
4. Odtwórz pierwotny przypadek oraz **wszystkie dane wejściowe z jego klastra**; włącz też wykrywanie leaków, ponieważ poprawka błędu bezpieczeństwa pamięci może naruszyć zasady zarządzania pamięcią na ścieżce obsługi błędu.
5. Uruchom testy funkcjonalne na rzeczywistych plikach, a następnie wznów pracę na podstawie zgromadzonej kolejki (lub zaimportuj tę kolejkę ponownie, jeśli silnik wymaga nowego katalogu wyjściowego po zmianie binarnego pliku wykonywalnego).
6. Powtarzaj ten proces: usunięcie pierwszego, płytkiego crasha często pozwala istniejącym seedom przejść do głębszego stanu parsera.

LLM może przyspieszyć krok 2 i przygotować szkic łatki w kroku 3, jeśli otrzyma powodujące crash dane wejściowe, raport sanitizera, harness i odpowiedni kod źródłowy, ale jego łatka pozostaje niezaufana. O przyjęciu poprawki decydują ponowne testy z sanitizerem i testy regresyjne, a nie wyjaśnienie modelu.<sup>[[22]](#references)</sup>

## Bogatsza informacja zwrotna, gdy pokrycie krawędzi zlewa różne ścieżki

Zwykłe pokrycie krawędzi nie pozwala odróżnić dwóch wykonań, które przechodzą przez ten sam helper z różnych wywołujących je funkcji lub wybierają różne kombinacje gałęzi wewnątrz funkcji. Ma to znaczenie w przypadku współdzielonych dekoderów, dyspozytorów protokołów i helperów interpreterów, gdzie **ścieżka** prowadząca do krawędzi określa bieżący stan. Naiwne śledzenie każdego kontekstu wywołania również jest niebezpieczne: mapa pokrycia i kolejka mogą gwałtownie urosnąć. Dlatego badania nad fuzzingiem uwzględniającym kontekst zalecają doprecyzowywanie tylko obiecujących kontekstów, zamiast traktowania całego grafu wywołań jako zależnego od kontekstu.<sup>[[14]](#references)</sup>

Najnowsze kompilacje AFL++ udostępniają **pokrycie ścieżek Ball-Larus dla poszczególnych funkcji**, oprócz zwykłego pokrycia krawędzi. Przypisuje ono cechę każdej acyklicznej ścieżce przez funkcję; krawędzie powrotne pętli są usuwane, więc ta informacja zwrotna rozróżnia kombinacje gałęzi, ale **nie liczbę iteracji pętli**. Zacznij od łagodnego poziomu `1`, a następnie stosuj bardziej rygorystyczne tryby tylko do podejrzanego kodu parsera lub maszyny stanów, ponieważ liczba ścieżek może rosnąć wykładniczo.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

W przypadku funkcji pomocniczej wywoływanej z wielu miejsc istotnych z punktu widzenia bezpieczeństwa tryb LTO może łączyć ścieżkę każdej funkcji z jej bezpośrednim miejscem wywołania:<sup>[[13]](#references)</sup>

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

- Uruchom równolegle zwykłą instancję z pokryciem krawędzi; bogatszy feedback jest przydatny tylko wtedy, gdy dodatkowy koszt kolejki/mapy nie obniża liczby wykonań na sekundę.
- Użyj `AFL_LLVM_ALLOWLIST`, aby ograniczyć instrumentację ścieżek/wywołujących, gdy duże biblioteki z wieloma szablonami lub ogólny kod narzędziowy dominują w mapie.
- Funkcje z nadmierną liczbą ścieżek acyklicznych można pominąć w AFL++; ostrzeżenia podczas kompilacji wskazują, że cel wymaga allowlisty lub mniej rygorystycznego poziomu.
- Pokrycie wywołującego + ścieżek obsługuje tylko jeden poziom wywołującego. Nie łącz go z głębszymi stosami kontekstu.
- Identyfikatory ścieżek mogą się zmieniać między głównymi wersjami LLVM. Utrzymuj stały toolchain przez całą kampanię i nie synchronizuj korpusów opartych na PATH tak, jakby ich identyfikatory cech były stabilne między kompilacjami.
- Ten feedback uzupełnia `CMPLOG`: śledzenie porównań rozwiązuje kwestię **jaka wartość przechodzi przez zabezpieczenie**, podczas gdy feedback ścieżek/wywołujących zachowuje informację o tym, **która trasa i kombinacja gałęzi do niego doprowadziły**.

## Stateful Fuzzing: sekwencje są seedami

W przypadku **protokołów**, **uwierzytelnionych przepływów pracy** i **parserów wieloetapowych** interesującą jednostką często nie jest pojedynczy blob, lecz **sekwencja komunikatów**. Połączenie całej wymiany w jeden plik i ślepe mutowanie go jest zwykle nieefektywne, ponieważ fuzzer mutuje każdy krok jednakowo, nawet jeśli tylko późniejszy komunikat prowadzi do podatnego stanu.<sup>[[4]](#references)</sup>

Skuteczniejszym podejściem jest traktowanie **samej sekwencji jako seeda** i używanie **obserwowalnego stanu** (kodów odpowiedzi, stanów protokołu, faz parsera, typów zwracanych obiektów) jako dodatkowego feedbacku.<sup>[[4]](#references)</sup>

- Zachowuj **prawidłowe komunikaty prefiksowe** i skup mutacje na komunikacie **sterującym przejściem**.
- Buforuj identyfikatory i wartości generowane przez serwer z wcześniejszych odpowiedzi, gdy kolejny krok od nich zależy.
- Preferuj mutowanie/wstawianie na poziomie pojedynczych komunikatów zamiast mutowania całej zserializowanej wymiany jako nieprzejrzystego bloba.
- Jeśli protokół udostępnia znaczące kody odpowiedzi, wykorzystuj je jako **tani oracle stanu**, aby priorytetowo traktować sekwencje przechodzące dalej.

Z tego samego powodu błędy uwierzytelniania, ukryte przejścia lub błędy parsera występujące „dopiero po uzgadnianiu” często umykają zwykłemu fuzzingowi plikowemu: fuzzer musi zachować **kolejność, stan i zależności**, a nie tylko strukturę.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing sterownika z wieloma klientami

Wysokie pokrycie krawędzi nadal może nie wykryć błędów sterownika IPC, ponieważ pokrycie nie opisuje **własności obiektów, liczników referencji, oczekujących komunikatów, kolejności sprzątania ani przeplotów wątków**. Strona [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) omawia model obiektów sterownika; ten przykład skupia się na harnessie fuzzera. Android Binder to przydatny model: samo osiągnięcie ścieżek alokacji i zwalniania nie wystarczy, jeśli fuzzer nie potrafi sprawić, by wiele procesów operowało na tym samym obiekcie jądra w wymaganej kolejności.<sup>[[15]](#references)</sup>

#### Modeluj protokół, a nie odizolowane bufory `ioctl`

Przedstaw przypadek testowy jako uporządkowaną gramatykę **tożsamości klienta + operacji + ustrukturyzowanych argumentów**. Fuzzer Binder LKL używa protobuf i `libprotobuf-mutator`, a także jednego trwałego klienta menedżera kontekstu i dwóch zwykłych klientów. Harness semantyczny zachowuje następnie relacje, które zniszczyłaby ślepa mutacja bajtów.<sup>[[15]](#references)</sup>

- Buforuj wartości zwracane przez wcześniejsze operacje. Na przykład `BC_FREE_BUFFER` musi ponownie użyć wskaźnika bufora transakcji zwróconego przez wcześniejsze `ioctl`.
- Generuj prawidłowe domyślne odpowiedzi, aby transakcje synchroniczne mogły się zakończyć i późniejsze operacje pozostały osiągalne.
- Odrzucaj niemożliwe przejścia, takie jak transakcje do samego siebie lub wiele oczekujących transakcji do tego samego celu.
- Utrzymuj stan inicjalizacji singletona poza resetem wykonywanym dla każdego wejścia. Binder dopuszcza tylko jedną rejestrację `BINDER_SET_CONTEXT_MGR` podczas jednego uruchomienia systemu, więc wielokrotne niszczenie i odtwarzanie tego klienta unieważniłoby późniejsze wejścia.

Przydatny schemat wyścigu cyklu życia polega na tym, by jeden klient przekazał obiekt, uruchomił sprzątanie wątku lub procesu, a równolegle klient odbierający zwolnił bufor transakcji. W przykładzie CVE-2020-0423 przekazanie `BINDER_TYPE_WEAK_BINDER`, po którym następuje `BINDER_THREAD_EXIT` ścigające się z `BC_FREE_BUFFER`, mogło zwolnić osadzony `binder_work`, gdy ścieżka sprzątania kończącego działanie wątku nadal z niego korzystała.<sup>[[15]](#references)</sup>

#### Przywróć kontrolowane przeploty w jądrze przestrzeni użytkownika

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) linkuje rzeczywisty kod jądra z harnessem przestrzeni użytkownika i udostępnia jego interfejs wywołań systemowych przez `lkl_syscall`. Dzięki temu można łatwo koordynować stan protobuf, pokrycie i KASAN w jednym procesie. LKL zwykle wykonuje wywołanie systemowe bez przerywania go przez inny wątek jądra. W kampaniach dotyczących wyścigów wstawiaj jednak punkty `schedule()` w pobliżu wybranych granic blokowania/odblokowywania i cyklu życia, a następnie pozwól harnessowi losowo wybierać kolejnego klienta przy każdym ustąpieniu sterowania. Umieszczaj te punkty w wybranych miejscach, ponieważ każdy z nich zwiększa przestrzeń przeszukiwania harmonogramu. Opisany przez badaczy losowy harmonogram **nie jest częścią upstreamowego fuzzera Binder**.<sup>[[15]](#references)</sup>

#### Buduj i odtwarzaj zserializowane seedy regresyjne

Upstreamowy harness przypina zgodną wersję `libprotobuf-mutator`, włącza instrumentację fuzzingu LKL i KASAN za pomocą `LKL_FUZZING=1`, a także włącza `CONFIG_MMU` dla Binder przez `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Po sprawdzeniu celowo podatnej rewizji lub zastosowaniu opisanych upstream łatek cofających zmiany, serializowany seed może odtworzyć całe przejście stanu wielu klientów bez konieczności rekonstruowania go w doraźnym proof of concept w C:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Potraktuj uzyskany błąd KASAN use-after-free jako potwierdzenie, że seed dotarł do podatnej ścieżki cyklu życia. **Nie** dowodzi on wystąpienia późniejszych prymitywów wymaganych do wykonania kodu w jądrze lub eskalacji uprawnień.<sup>[[16]](#references)</sup>

## Sztuczka różnorodności na jednej maszynie (w stylu Jackalope)

Praktycznym sposobem na połączenie **nowości generatywnej** z **ponownym wykorzystaniem coverage** jest **restartowanie krótkotrwałych workerów** obsługujących trwały serwer. Każdy worker rozpoczyna od pustego corpus, synchronizuje się po `T` sekundach, przez kolejne `T` sekund działa na połączonym corpus, ponownie się synchronizuje, a następnie kończy działanie. Dzięki temu **każda generacja tworzy świeże struktury**, a jednocześnie wykorzystuje zgromadzone coverage.<sup>[[1]](#references)[[2]](#references)</sup>

**Serwer:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Pracownicy sekwencyjni (przykładowa pętla):**

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
- `-server_update_interval T` przybliża **opóźnioną synchronizację** (najpierw nowość, później ponowne użycie).
- W trybie grammar fuzzing **początkowa synchronizacja z serwerem jest domyślnie pomijana** (nie ma potrzeby używania `-skip_initial_server_sync`).
- Optymalna wartość `T` **zależy od celu**; najlepiej przełączyć ją, gdy worker znajdzie już większość „łatwego” coverage.

## Snapshot Fuzzing dla celów trudnych do przygotowania

Gdy kod, który chcesz testować, staje się dostępny dopiero **po kosztownym przygotowaniu** (uruchomieniu VM, ukończeniu logowania, otrzymaniu pakietu, parsowaniu kontenera, zainicjalizowaniu usługi), przydatną alternatywą jest **snapshot fuzzing**: przechwyć stan gotowego procesu lub VM, wstrzyknij każdy przypadek testowy do ścieżki wejściowej celu, wykonuj go do momentu crash/timeout i przywróć snapshot. Pozwala to uniknąć ponownego wykonywania inicjalizacji lub prefiksów protokołu i jest przydatne w przypadku **usług sieciowych**, **firmware**, **powierzchni ataku dostępnych po uwierzytelnieniu** oraz **celów binarnych**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Uruchom cel do momentu osiągnięcia interesującego stanu.
2. W tym momencie wykonaj snapshot **pamięci + rejestrów**.
3. Dla każdego przypadku testowego zapisz zmodyfikowane wejście bezpośrednio do odpowiedniego bufora gościa/procesu.
4. Wykonuj do momentu crash/timeout/reset.
5. Przywróć snapshot; w przypadku celów VM, jeśli jest to obsługiwane, przywracaj tylko **zmodyfikowane strony**, a następnie powtórz.

Umieść snapshot możliwie blisko pierwszego kosztownego etapu parsowania/dispatch, na przykład po `recv`/`read` lub deserializacji pakietu, i zanotuj bufor wejściowy używany przez cel. Jest to zgodne z zasadą adaptacyjnego umieszczania: przesuwaj snapshot głębiej w przetwarzanie wejścia, aby uniknąć powtarzania pracy.<sup>[[11]](#references)</sup>

### Przyrostowe snapshoty dla stanów protokołu

Stały snapshot eliminuje koszt przygotowania, ale sam w sobie nie pozwala eksplorować przejść wymagających kilku poprawnych komunikatów. Harness LibAFL-Qemu może obserwować zapisy do pola stanu protokołu i zapisywać nowy snapshot po zmianie stanu. W [harnessie TCP libslirp](https://github.com/quarkslab/slirp_snapshots_stateful) obserwuje `tcpcb.t_state`, hashuje stan i flagi odpowiedzi, aby eliminować duplikaty snapshotów, a także zapisuje zmodyfikowane strony względem nadrzędnego snapshotu. Przed modyfikacją kolejnego ustrukturyzowanego komunikatu przywraca wybrany snapshot poprzez łańcuch nadrzędnych snapshotów. Testcase przechowuje `SnapshotId` i wygenerowane bajty wejściowe (`gen_bytes`); menedżer snapshotów śledzi relację nadrzędności potrzebną do odtworzenia przebiegu.<sup>[[27]](#references)[[28]](#references)</sup>

`SnapshotModule` w trybie user-mode LibAFL-Qemu zapisuje mapowania i pamięć celu, ale nie rejestry CPU; w razie potrzeby zachowaj je osobno. Opisany menedżer obsługuje jedno drzewo głównych snapshotów i nie może współdzielić identyfikatorów snapshotów między workerami. Jego tryb multi-snapshot nie może też bezpośrednio ponownie wykorzystywać stanu shadow QASAN. Do offline triage odtwórz łańcuch wejściowy w osobnym, instrumentowanym procesie. Przy użyciu `AsanHostModule` i `DrCovModule` funkcja `fuzzer.evaluate_input` uruchamia wymagane callbacki `pre_exec`/`post_exec`; samo `qemu.run` tego nie robi.<sup>[[27]](#references)[[28]](#references)</sup>

### Wykrywanie logicznych odczytów poza buforem ring

Odczyt wykraczający poza *liczbę poprawnych danych* w buforze może nadal mieścić się w przydzielonym obszarze pamięci hosta i uniknąć wykrycia przez zwykły ASAN. Przykład danych pilnych w [libslirp](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) powoduje również underflow bez znaku przy liczbie bajtów. Jeśli dostępny jest kod źródłowy, instrumentacja przepełnień liczb całkowitych ze znakiem/bez znaku może wykryć ten efekt uboczny; przed wyciszeniem raportów odróżnij go od zamierzonego zawijania numeru sekwencyjnego TCP. Silniejszy, proponowany oracle polega na oznaczeniu niestandardowej alokacji ring jako niedostępnej, odznaczaniu jako dostępnych tylko poprawnych zakresów w miarę przesuwania się jej wewnętrznego alokatora oraz ponownym oznaczaniu zwolnionych zakresów jako niedostępnych. LibAFL-Qemu udostępnia API zatruwania ASAN dla celów, w których instrumentacja kodu źródłowego jest niepraktyczna.<sup>[[27]](#references)</sup>

## Eksploracja wyścigów w jądrze Linux za pomocą MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) przekształca zależne od czasu wyścigi w jądrze Linux w powtarzalne harmonogramy dostępu do pamięci. Może automatycznie wyliczać wykonania **A-B-A** w dwóch kontekstach lub pozwala analitykowi narzucać ograniczenia kolejności w terminalowym UI/GUI. To eksperymentalne narzędzie badawcze, a nie kompletny concurrency fuzzer: obecnie wymaga LLVM 23+ i poprawionego jądra projektu, narzędzia wiersza poleceń obsługują dwa wątki testowe, a proponowana warstwa fuzzingu w userspace nie została zaimplementowana.<sup>[[17]](#references)[[18]](#references)</sup>

### Zbieranie punktów komunikacji między kontekstami

Zbuduj instrumentowane jądro z callbackami KASAN outline i poprawioną obsługą KCOV rejestrującą dostęp do pamięci. README projektu zaleca również wyłączenie optymalizacji sibling-call, aby stosy wywołań pozostały użyteczne.<sup>[[17]](#references)[[18]](#references)</sup>

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

Tryb outline KASAN (`asan-instrumentation-with-call-threshold=0`) zamienia instrumentowane dostępy na wywołania funkcji pomocniczych. Łatki jądra MAccConc wyłączają `asan-opt-same-temp`, aby kolejne dostępy nie były scalane; wyłącz także optymalizację `asan-opt-globals`, gdy wyścigi dotyczące zmiennych globalnych mają być widoczne. KCOV przekazuje powstałe rekordy do przestrzeni użytkownika. Porównuj dostępy z różnych kontekstów wykonania i zachowuj pary, których zakresy bajtów się nakładają i w których co najmniej jeden dostęp jest zapisem; traktuj `kfree()` jako zapis, aby zmiany czasu życia również stawały się kandydatami.<sup>[[17]](#references)</sup>

W przypadku pracy wykonywanej poza zadaniem inicjującym, takiej jak przetwarzanie pakietów lub wywołania zwrotne RCU, podsystem musi propagować uchwyt zdalnego pokrycia KCOV. Zdalne KCOV w upstreamie jest opcjonalne i nie jest automatycznie dostępne dla dowolnej pracy w tle, więc brak propagacji może sprawić, że rzeczywista interakcja pozostanie niewidoczna.<sup>[[17]](#references)[[19]](#references)</sup>

### Identyfikacja tego samego dynamicznego dostępu w każdym uruchomieniu

Nie odtwarzaj przebiegu na podstawie konkretnego adresu sterty, który może się zmienić po każdej alokacji, ani wyłącznie na podstawie adresu instrukcji, który jest niejednoznaczny w funkcjach pomocniczych, takich jak `memcpy()` i `spin_lock()`. MAccConc używa **count-augmented stack trace**: każda ramka identyfikuje funkcję wywoływaną oraz liczbę jej wywołań w funkcji wywołującej, a ostatni element identyfikuje instrukcję dostępu do pamięci. Rekordy wejścia/wyjścia z funkcji SanitizerCoverage pozwalają przestrzeni użytkownika odtworzyć ten dynamiczny identyfikator, który pozostaje stabilny mimo zmian adresów i niezwiązanych z nimi zakłóceń przepływu sterowania.<sup>[[17]](#references)</sup>

### Zamiana par kandydatów na wymuszone harmonogramy

Łatka ioctl `KCOV_SET_DI` przypisuje identyfikator dostępu typu count-augmented do działania na współdzielonej fladze.<sup>[[17]](#references)</sup>

| Działanie | Semantyka |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Ustaw flagę *N* bezpośrednio przed wybranym dostępem. |
| `DI_STACK_WAIT` | Przed wybranym dostępem czekaj w pętli, aż flaga *N* zostanie ustawiona lub upłynie skonfigurowany limit. |
| `DI_STACK_WAKE_POST` | Ustaw flagę *N* bezpośrednio po wybranym dostępie. |

Aby wymusić częściowy warunek **A-happens-before-B**, przypisz `DI_STACK_WAKE_POST` do A, a `DI_STACK_WAIT` do B, używając tej samej flagi. W przypadku w pełni określonego harmonogramu dwóch kontekstów rozpocznij od zablokowania B, a następnie spraw, by A odblokowało B i czekało w pierwszym punkcie przekazania sterowania; przy kolejnym przekazaniu B wykonuje odwrotną operację. Drugi wariant działa jak deterministyczne przełączanie kontekstu i jest używany przez automatyczny eksplorator A-B-A.<sup>[[17]](#references)</sup>

Minimalna kampania polega na skompilowaniu przypadku testowego z czterema punktami zaczepienia (`test_setup`, dwiema funkcjami wątków i `test_end`) jako biblioteki współdzielonej, zebraniu nieograniczonego śladu, a następnie wyliczeniu kandydatów A-B-A lub dodaniu ręcznych ograniczeń wokół podejrzanych dostępów.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpretuj timeouty oddzielnie od udanych zmian kolejności: żądana kolejność może być niemożliwa, ponieważ blokada albo zależność związana z inicjalizacją lub publikacją uniemożliwia drugiemu kontekstowi dotarcie do punktu wstrzyknięcia. Pamiętaj też o ślepych punktach KASAN: bezpośrednie odwołania do stosu zwykle nie są przechwytywane, chyba że mogą wykraczać poza jego zakres, zmienne globalne są pomijane przy domyślnej optymalizacji, a obecne kompilatory nie mogą jednocześnie generować hooków ASAN i TSAN. Ponadto prototyp traci bufor KCOV, gdy gość ulega panic, dlatego zachowaj niezależną konsolę lub wyrocznię awarii.<sup>[[17]](#references)</sup>

W przypadku przyszłego fuzzingu kierowanego współbieżnością zapisuj podsumowania dostępu do pamięci dla każdego wejścia lub wywołania systemowego, łącz operacje, które mogłyby utworzyć punkty komunikacji między kontekstami, a następnie badaj tylko te kombinacje. Migawki VM stabilizują stan globalny i adresy; bez migawek metadane miejsca alokacji mogą pozwolić na abstrakcję obiektów między uruchomieniami. To proponowane rozszerzenie, a nie funkcja obecnych narzędzi userspace MAccConc.<sup>[[17]](#references)</sup>

## Introspekcja harnessa: wcześnie wykrywaj płytkie fuzzery

Gdy kampania traci postępy, problemem często nie jest mutator, lecz **harness**. Użyj **introspekcji osiągalności/pokrycia**, aby znaleźć funkcje, które są statycznie osiągalne z celu fuzzingu, ale rzadko lub nigdy nie są pokrywane dynamicznie. Takie funkcje zwykle wskazują na jeden z trzech problemów.<sup>[[12]](#references)</sup>

- Harness rozpoczyna działanie celu zbyt późno lub zbyt wcześnie.
- W zbiorze seedów brakuje całej grupy funkcji.
- Cel rzeczywiście wymaga **drugiego harnessa**, zamiast jednego, nadmiernie rozbudowanego harnessa „do wszystkiego”.

Jeśli korzystasz z przepływów pracy w stylu OSS-Fuzz / ClusterFuzz, Fuzz Introspector może porównać statyczną osiągalność z pokryciem w czasie działania i wygenerować raporty na podstawie uruchomienia o określonym czasie trwania lub publicznego korpusu.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Użyj raportu, aby zdecydować, czy dodać nowy harness dla nieprzetestowanej ścieżki parsera, rozszerzyć corpus dla konkretnej funkcji, czy podzielić monolityczny harness na mniejsze punkty wejścia.

## Wybór celów fuzzingu z priorytetem grafu i selekcja mutacji

Jeśli masz już wyniki **analizy statycznej**, **mutanty, które przetrwały testy mutacyjne**, oraz **raporty pokrycia**, nie traktuj ich jako niezależnych list. Najpierw zbuduj **graf wywołań**, dodaj do węzłów adnotacje dotyczące **złożoności cyklomatycznej**, **osiągalności z punktów wejścia/niezaufanych danych wejściowych** oraz wszelkich zewnętrznych ustaleń, a następnie zadaj pytania dotyczące grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Które funkcje o wysokiej złożoności są osiągalne z niezaufanych danych wejściowych?
- Które ocalałe mutanty znajdują się na ścieżkach od parserów/handlerów do kodu krytycznego dla bezpieczeństwa?
- Które funkcje są architektonicznymi wąskimi gardłami o wyjątkowo dużym **promieniu oddziaływania**?

To zazwyczaj pozwala znaleźć lepsze cele fuzzingu niż samo kierowanie się „najniższym pokryciem”. Parser/dekoder o **wysokiej złożoności** i potwierdzonej **osiągalności z zewnątrz** jest lepszym kandydatem na harness niż odizolowany wewnętrzny helper o słabym pokryciu, ale bez ścieżki sterowanej przez atakującego.

### Praktyczny proces triage

1. Zbuduj **graf kodu** na podstawie codebase i wyodrębnij metryki złożoności/rozgałęzień dla każdej funkcji.
2. Wypisz **punkty wejścia** przyjmujące dane kontrolowane przez atakującego: handlery żądań, dekodery, importery, parsery protokołów, czytniki CLI/plików.
3. Wykonaj **zapytania o ścieżki** od tych punktów wejścia do kandydatów, aby oddzielić osiągalną powierzchnię ataku od kodu martwego lub dostępnego wyłącznie wewnętrznie.
4. Nadaj priorytet węzłom, które łączą:
   - wysoką **złożoność cyklomatyczną**
   - potwierdzoną **osiągalność z niezaufanych danych wejściowych**
   - duży **promień oddziaływania** lub wiele zależnych funkcji
   - potwierdzające dowody, takie jak ustalenia **SARIF**, notatki z audytu lub ocalałe mutanty
5. Najpierw napisz ukierunkowane harnessy dla węzłów z najwyższymi wynikami, zwłaszcza dla **parserów/kodeków**, takich jak dekodery hex/Base64/IP/wiadomości.

### Ocalali mutanci: równoważni czy możliwi do wykorzystania

Testy mutacyjne często generują zaszumioną listę ocalałych mutantów. Zanim uznasz każdego z nich za lukę w zabezpieczeniach, użyj grafu, aby sprawdzić:

- Czy zmutowana funkcja jest osiągalna z punktu wejścia kontrolowanego przez atakującego?
- Czy wszystkie ścieżki wywołań są ograniczone przez silniejsze niezmienniki niż ten, którego dotyczy zmodyfikowany warunek?
- Czy węzeł znajduje się w martwym kodzie, logice dotyczącej wyłącznie formatowania czy w ścieżce arytmetycznej/parsera o dużym wpływie?

Mutanty, które pozostają nieosiągalne lub są strukturalnie ograniczone, często są **mutantami równoważnymi**. Mutanty, które pozostają **osiągalne** i dotyczą **warunków brzegowych**, **ścieżek przepełnienia/przeniesienia** lub **arytmetyki/parsingowania krytycznych dla bezpieczeństwa**, należy promować do:

- nowych harnessów fuzzingu
- bezpośrednich testów własności/niezmienników
- ukierunkowanych wektorów przypadków brzegowych

### Powiąż zewnętrzne ustalenia z grafem

Jeśli Twój pipeline SAST eksportuje **SARIF**, nanieś ustalenia na węzły grafu na podstawie **pliku + zakresu linii** i użyj grafu, aby rozszerzyć analizę wpływu.<sup>[[6]](#references)</sup>

- oblicz **promień oddziaływania** oznaczonej funkcji
- sprawdź, czy ustalenie znajduje się na którejkolwiek ścieżce od punktu wejścia
- grupuj pobliskie ustalenia, które zbiegają się w tym samym wąskim gardle

Jest to przydatne przy podejmowaniu decyzji, czy poświęcić czas na fuzzing konkretnej funkcji: węzeł, który jest **osiągalny**, **złożony** i ma już ustalenia **SAST**, często jest lepszym celem niż węzeł jedynie złożony, bez ścieżki dostępnej dla atakującego.

Przykładowy proces pracy z użyciem Trailmark.<sup>[[6]](#references)</sup>

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

Najważniejsza jest metodologia oparta na przecięciu: **złożoność x ekspozycja x wpływ**. Użyj wykresu, aby wybrać cele fuzzingu o najwyższej oczekiwanej wartości dla bezpieczeństwa, a następnie wykorzystaj mutacje, które przetrwały, aby ustalić, które granice i niezmienniki Twój harness musi testować.<sup>[[5]](#references)</sup>

## Różnicowy fuzzing kodowań kluczy kryptograficznych

Zacznij od poprawnych kluczy w postaci serializowanej lub standardowych wektorów testowych. Modyfikuj zakodowane pola, nie naruszając długości i struktury wymaganych do dotarcia do ścieżek importu i operacji, a następnie przekazuj te same bajty niezależnym implementacjom. Porównuj akceptację i błędy. Losowe podpisy i szyfrogramy wymagają oracle sprawdzających poprawność, a nie porównania bajt po bajcie: weryfikuj podpisy lub porównuj wspólne sekrety z rundy enkapsulacji i dekapsulacji. Wektory testowe potwierdzają zgodność dla znanych przypadków; różnicowe mutacje badają niepoprawne kodowania, których nie obejmują.<sup>[[23]](#references)[[26]](#references)</sup>

W przypadku tych formatów kluczy używaj oracle dostosowanych do danego formatu:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Rozwinięte klucze podpisywania ML-DSA:** zmodyfikuj współczynniki `s1` lub `s2` w spakowanej postaci tak, aby wykraczały poza `[-η, η]`, zachowując możliwość parsowania klucza. Sprawdź, czy import lub podpisywanie odrzuca klucz oraz czy powstały podpis przechodzi weryfikację. Sama różnica w akceptacji nie oznacza naruszenia standardów, ponieważ FIPS 204 nie wymaga dodatkowej weryfikacji kluczy prywatnych. Zobacz [mechanizm warunkowego wycieku](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Pary kluczy ML-KEM:** oddziel wymagane sprawdzanie klucza enkapsulacji i danych wejściowych dekapsulacji od opcjonalnego sprawdzania spójności pary (PCT) podczas importu pary. Wykonaj enkapsulację z użyciem klucza publicznego, dekapsulację z użyciem klucza prywatnego i porównaj wspólne sekrety; niezgodność może przerwać szyfrowaną komunikację, nawet jeśli poszczególne klucze przechodzą kontrolę danych wejściowych. Sprawdź, czy API weryfikuje dane wejściowe podczas operacji, czy w osobnym wywołaniu; libcrux udostępnia `validate_public_key(pk)` i `validate_private_key(sk, ct)`, które nie zastępują PCT.
- **Surowe klucze XMSS/XMSSMT:** testuj rundy serializacji i deserializacji kluczy **podpisywania i weryfikacji** dla różnych zestawów parametrów, a nie tylko operacje na kluczach przechowywanych w pamięci. XMSS i XMSSMT mają osobne czterobajtowe przestrzenie nazw OID, więc parser sprawdzający najpierw tylko OID XMSS może błędnie zaklasyfikować kolidujący klucz XMSSMT i odrzucić jego import. Opisany parser RustCrypto ilustruje problem interoperacyjności i dostępności, a nie fałszowanie podpisu.

## Fuzzing w Go z gosentry: wydajniejszy silnik, typowane dane wejściowe i kontrole różnicowe

Jeśli cel w Go ma już natywny harness `testing.F`, praktyczną ścieżką ulepszenia jest uruchomienie tego samego harnessu z [gosentry](https://github.com/trailofbits/gosentry) — rozwidloną toolchain Go, która zachowuje `go test -fuzz`, ale zmienia backend na **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Jest to przydatne, gdy natywny fuzzer Go zatrzymuje się na **trudnych porównaniach**, **typowanych danych wejściowych** lub **formatach wymagających intensywnego parsowania**. Metodologia pozostaje taka sama:

- Nadal używaj `f.Add(...)` dla seedów i `f.Fuzz(...)` dla callbacka.
- Użyj ponownie tego samego harnessa, ale uruchom go za pomocą pliku binarnego `go` z gosentry zamiast standardowego toolchaina.
- Traktuj wynikową kampanię jak zwykłe uruchomienie sterowane pokryciem, ale z harmonogramowaniem i mutacjami LibAFL oraz lepszymi detektorami.

### Zamień ciche awarie w wyniki fuzzingu

Powracającym problemem podczas ocen Go jest to, że niebezpieczne zachowanie często domyślnie **nie** powoduje awarii. Dzięki gosentry możesz przekształcić kilka klas „złych, ale cichych” stanów w wyniki fuzzingu.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` sprawia, że wybrane ścieżki logowania/błędów zachowują się jak awarie (przydatne w ścieżkach kodu w stylu `log.Fatal`, które w przeciwnym razie tylko logują błąd i działają dalej).
- `--catch-races=true` ponownie odtwarza nowo odkryte wpisy kolejki z detektorem race Go.
- `--catch-leaks=true` ponownie odtwarza nowe wpisy kolejki z `goleak` i zatrzymuje działanie po wykryciu wycieków gorutin.
- Obsługa zawieszeń LibAFL pozwala zachować **nieskończone pętle / bardzo wolne dane wejściowe** jako wyniki fuzzingu, zamiast pomijać je jako przekroczenia limitu czasu.
- Domyślnie wbudowane sprawdzanie przepełnień arytmetycznych oraz opcjonalne sprawdzanie obcięć za pomocą instrumentacji w stylu go-panikint.

Jest to szczególnie przydatne w przypadku celów, w których skutkiem dla bezpieczeństwa jest **awaria parsera bez paniki**, **błąd współbieżności** lub **zawieszenie powodujące wyłącznie DoS**, a nie uszkodzenie pamięci.

### Fuzzing uwzględniający struktury dla typowanych API Go

Natywny fuzzing Go oczekuje głównie wartości skalarnych, takich jak `[]byte`, `string` i liczby. Jeśli testowany kod przyjmuje typowane obiekty, gosentry może bezpośrednio fuzzować **wartości złożone** (struktury, slice’y, tablice, wskaźniki), nadal modyfikując przy tym bajty.<sup>[[7]](#references)[[8]](#references)</sup>

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

Użyj tego, gdy tworzenie fikcyjnego formatu wire wyłącznie na potrzeby fuzzingu ukrywałoby błędy logiki za kodem parsującym działającym tylko w harnessie. W kampaniach różnicowych lub opartych na gramatyce pozostaw wejście harnessu jako pojedyncze `[]byte` lub `string` i parsuj je wewnątrz callbacka.

### Fuzzing oparty na gramatyce dla parserów i danych wejściowych protokołów

W przypadku parserów, formatów i języków wejściowych gosentry może uruchamiać **Nautilus grammar fuzzing** w oparciu o LibAFL. Gramatyka to tablica reguł produkcji w formacie JSON, a harness powinien zwykle przyjmować pojedynczy argument `[]byte` lub `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Uwagi dotyczące metodologii:

- Używaj trybu gramatycznego, gdy mutacje na poziomie bajtów zwykle odpadają na wczesnych testach składni.
- Ogranicz gramatykę do **podzbioru języka/protokołu istotnego z punktu widzenia bezpieczeństwa**, zamiast modelować całą specyfikację.
- Używaj dużych wartości granicznych w terminalach i nieterminalach, aby testować granice liczb całkowitych, długości i maszyny stanów.
- Tryb gramatyczny zachowuje poprawność gramatyczną wejść, ale cel nadal otrzymuje **bajty/ciągi znaków**, więc parsowanie i kontrole semantyczne pozostają w kodzie objętym harnessingiem.

### Differential fuzzing: porównuj implementacje, nie tylko awarie

W ekosystemie Go skutecznym podejściem jest **grammar-based differential fuzzing**: generowanie poprawnych strukturalnie danych wejściowych i przekazywanie ich do dwóch parserów, klientów lub silników przejść stanów.<sup>[[7]](#references)[[8]](#references)</sup>

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

- jedna implementacja wywołuje panic, a druga poprawnie odrzuca dane wejściowe
- niezgodność w akceptowaniu lub odrzucaniu danych wejściowych
- różne drzewa parsowania lub zdekodowane obiekty
- rozbieżne przejścia stanów, nonce, salda lub korzenie stanu

To praktyczny sposób na wykrywanie **niezgodności konsensusu**, **niejednoznaczności parsera** i **rozbieżności między specyfikacją a implementacją**, które często umykają fuzzingowi ukierunkowanemu wyłącznie na awarie.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Ponowne wykorzystanie korpusu kampanii do raportowania pokrycia

Po kampanii odtwórz zapisany korpus kolejki, aby wygenerować raport pokrycia Go bez ręcznego eksportowania osobnego korpusu.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Uruchom polecenie z **tego samego pakietu** i z tym samym celem `-fuzz`, aby gosentry rozpoznało właściwy stan kampanii z pamięci podręcznej.

## References

- [1] [Mutacyjny fuzzing gramatyczny](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing z AFL++ — dogłębne omówienie](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pięć lat później: fuzzing protokołów sterowany pokryciem](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark zamienia kod w grafy](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [W Go fuzzing brakowało połowy narzędzi. Rozwidleniem toolchaina rozwiązaliśmy ten problem.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: szybki fuzzer greybox dla stanowych protokołów sieciowych wykorzystujący snapshoty](https://arxiv.org/abs/2202.03643)
- [10] [Brak gramatyki? Żaden problem: fuzzing jądra Linux bez opisów wywołań systemowych](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: wydajny fuzzing z adaptacyjnymi i modyfikowalnymi snapshotami](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentacja LLVM w AFL++: pokrycie ścieżek i wywołujących](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predykcyjny fuzzing uwzględniający kontekst](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Android Offensive Security — fuzzing Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer Binder w LKL dla Androida — dokumentacja kompilacji i seedów regresyjnych](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: badanie warunków wyścigu w jądrze Linux z kontrolowanym przeplataniem dostępów do pamięci](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: pokrycie kodu na potrzeby fuzzingu](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Rozszerzona składnia nazw plików CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Biuletyn Doyensec: CFITSIO, IV kwartał 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing rozszerzonej składni nazw plików CFITSIO: 16 luk w bezpieczeństwie pamięci i triage wspomagany przez Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Fuzzing różnicowy dla kryptografii](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: standard mechanizmu enkapsulacji klucza opartego na module i kracie](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Błąd parsowania OID w XMSSMT — zgłoszenie RustCrypto nr 1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Stan implementacji kryptografii postkwantowej](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Jak snapshoty doprowadziły nas do CVE-2026-9539](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
{{#include ../banners/hacktricks-training.md}}
