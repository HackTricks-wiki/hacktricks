# Metodologia fuzzingu

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: coverage a semantyka

W **mutational grammar fuzzing** dane wejściowe są mutowane z zachowaniem **zgodności z gramatyką**. W trybie sterowanym coverage jako corpus seeds zapisywane są tylko próbki, które zapewniają **nowe coverage**. W przypadku **celów językowych** (parserów, interpreterów, silników) może to powodować pominięcie błędów wymagających **łańcuchów semantycznych/przepływu danych**, w których wynik jednej konstrukcji staje się wejściem kolejnej.<sup>[[1]](#references)</sup>

**Tryb awarii:** fuzzer znajduje seedy, które osobno uruchamiają `document()` i `generate-id()` (lub podobne prymitywy), ale **nie zachowuje łańcucha przepływu danych**, przez co próbka „bliższa błędowi” jest odrzucana, ponieważ nie zwiększa coverage. Przy **co najmniej 3 zależnych krokach** losowa rekombinacja staje się kosztowna, a informacja zwrotna o coverage nie ukierunkowuje wyszukiwania.<sup>[[1]](#references)</sup>

**Wniosek:** w przypadku gramatyk z wieloma zależnościami warto rozważyć **połączenie faz mutacyjnej i generatywnej** albo nadanie generowaniu większej wagi wzorcom **łączenia funkcji** (a nie tylko coverage).<sup>[[1]](#references)</sup>

## Pułapki związane z różnorodnością corpus

Mutacje sterowane coverage są **zachłanne**: próbka zapewniająca nowe coverage jest zapisywana od razu, często z dużymi, niezmienionymi fragmentami. Z czasem w corpusie gromadzą się **niemal identyczne próbki** o małej różnorodności strukturalnej. Agresywna minimalizacja może usunąć przydatny kontekst, dlatego praktycznym kompromisem jest **minimalizacja uwzględniająca gramatykę**, która **zatrzymuje się po osiągnięciu minimalnego progu tokenów** (ogranicza szum, zachowując wystarczającą część otaczającej struktury, by ułatwić mutacje).<sup>[[1]](#references)</sup>

Praktyczna zasada dotycząca corpus w mutational fuzzing: **lepiej mieć niewielki zbiór strukturalnie różnych seedów maksymalizujących coverage niż dużą stertę niemal identycznych próbek**. W praktyce zazwyczaj oznacza to:<sup>[[1]](#references)[[3]](#references)</sup>

- Zacznij od **próbek z rzeczywistych zastosowań** (publicznych corpusów, danych z crawlingu, przechwyconego ruchu, zbiorów plików z ekosystemu danego celu).
- Ogranicz ich liczbę za pomocą **minimalizacji corpus opartej na coverage**, zamiast zachowywać każdą poprawną próbkę.
- Dbaj, by seedy były **wystarczająco małe**, tak aby mutacje trafiały w znaczące pola, zamiast zużywać większość cykli na nieistotne bajty.
- Ponownie przeprowadź minimalizację corpus po istotnych zmianach harnessu lub instrumentacji, ponieważ „najlepszy” corpus zmienia się wraz ze zmianą osiągalności kodu.

## Mutacje uwzględniające porównania dla wartości magicznych

Częstym powodem, dla którego fuzzery przestają robić postępy, nie jest składnia, lecz **ścisłe porównania**: magiczne bajty, kontrole długości, ciągi enum, sumy kontrolne lub wartości kierujące parserem, sprawdzane przez `memcmp`, tablice `switch` albo kaskadowe porównania. Czysto losowe mutacje marnują cykle na próby odgadnięcia tych wartości bajt po bajcie.

W przypadku takich celów użyj **śledzenia porównań** (na przykład przepływów pracy w stylu AFL++ `CMPLOG` / Redqueen), aby fuzzer mógł obserwować argumenty nieudanych porównań i kierować mutacje ku wartościom, które je spełniają.<sup>[[3]](#references)</sup>

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

- Jest to szczególnie przydatne, gdy cel blokuje dostęp do głębszej logiki za **sygnaturami plików**, **czasownikami protokołu**, **tagami typów** lub **bitami funkcji zależnymi od wersji**.
- Połącz tę metodę ze **słownikami** wyodrębnionymi z rzeczywistych próbek, specyfikacji protokołów lub logów debugowania. Mały słownik zawierający tokeny gramatyczne, nazwy chunków, czasowniki i delimitery jest często cenniejszy niż ogromna, ogólna lista słów.
- Jeśli cel wykonuje wiele kolejnych kontroli, najpierw rozwiąż najwcześniejsze porównania „magic”, a następnie ponownie zminimalizuj uzyskany corpus, aby kolejne etapy zaczynały od już poprawnych prefiksów.

## Bogatsza informacja zwrotna, gdy pokrycie krawędzi sprowadza różne ścieżki do tego samego wyniku

Zwykłe pokrycie krawędzi nie pozwala rozróżnić dwóch wykonań, które przechodzą przez tę samą funkcję pomocniczą, ale pochodzą od różnych wywołujących ją funkcji lub realizują różne kombinacje rozgałęzień wewnątrz funkcji. Ma to znaczenie w przypadku współdzielonych dekoderów, dyspozytorów protokołów i funkcji pomocniczych interpreterów, gdzie **ścieżka** prowadząca do krawędzi określa bieżący stan. Naiwne śledzenie każdego kontekstu wywołań również jest ryzykowne: mapa pokrycia i kolejka mogą gwałtownie urosnąć. Dlatego badania nad fuzzingiem uwzględniającym kontekst zalecają doprecyzowywanie tylko obiecujących kontekstów, zamiast traktowania całego grafu wywołań jako uwzględniającego kontekst.<sup>[[14]](#references)</sup>

Najnowsze kompilacje AFL++ zapewniają **pokrycie ścieżek Ball-Larus dla poszczególnych funkcji** oprócz zwykłego pokrycia krawędzi. Przypisują one cechę każdej acyklicznej ścieżce prowadzącej przez funkcję; krawędzie powrotne pętli są usuwane, więc ta informacja zwrotna rozróżnia kombinacje rozgałęzień, ale **nie liczbę iteracji pętli**. Zacznij od łagodnego poziomu `1`, a następnie stosuj bardziej rygorystyczne tryby tylko do podejrzanego kodu parserów i maszyn stanów, ponieważ liczba ścieżek może rosnąć wykładniczo.<sup>[[13]](#references)</sup>

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

**Wskazówki dotyczące kampanii:** stosuj bogatszy feedback z umiarem i monitoruj jego koszt związany z mapą pokrycia/kolejką.<sup>[[13]](#references)[[14]](#references)</sup>

- Uruchom równolegle zwykłą instancję z edge coverage; bogatszy feedback jest przydatny tylko wtedy, gdy dodatkowy koszt kolejki/mapy nie obniża liczby wykonanych testów na sekundę.
- Użyj `AFL_LLVM_ALLOWLIST`, aby ograniczyć instrumentację ścieżek/wywołujących, gdy duże biblioteki oparte na szablonach lub ogólny kod narzędziowy dominują w mapie.
- Funkcje z nadmierną liczbą ścieżek acyklicznych można pominąć w AFL++; ostrzeżenia podczas kompilacji wskazują, że cel wymaga allowlisty lub mniej restrykcyjnego poziomu.
- Pokrycie wywołujących + ścieżek obsługuje tylko jeden poziom wywołującego. Nie łącz go z głębszymi stosami kontekstu.
- Identyfikatory ścieżek mogą się zmieniać między głównymi wersjami LLVM. Utrzymuj stały toolchain przez całą kampanię i nie synchronizuj korpusów opartych na PATH, zakładając, że ich identyfikatory cech są stabilne między kompilacjami.
- Ten feedback uzupełnia `CMPLOG`: śledzenie porównań rozwiązuje problem **jaka wartość przechodzi przez warunek**, natomiast feedback ścieżek/wywołujących zachowuje informację o tym, **która trasa i kombinacja gałęzi doprowadziły do danego miejsca**.

## Fuzzing stanowy: sekwencje są seedami

W przypadku **protokołów**, **uwierzytelnionych przepływów pracy** i **parserów wieloetapowych** interesującą jednostką często nie jest pojedynczy blob, lecz **sekwencja komunikatów**. Łączenie całego zapisu komunikacji w jeden plik i ślepe mutowanie go jest zwykle nieefektywne, ponieważ fuzzer mutuje wszystkie kroki jednakowo, nawet jeśli tylko późniejszy komunikat dociera do podatnego stanu.<sup>[[4]](#references)</sup>

Skuteczniejszym podejściem jest traktowanie **samej sekwencji jako seedu** oraz wykorzystywanie **obserwowalnego stanu** (kodów odpowiedzi, stanów protokołu, faz parsera, typów zwracanych obiektów) jako dodatkowego feedbacku.<sup>[[4]](#references)</sup>

- Zachowuj **poprawne komunikaty prefiksowe** i skup mutacje na komunikacie **sterującym przejściem**.
- Zapisuj identyfikatory i wartości wygenerowane przez serwer na podstawie wcześniejszych odpowiedzi, gdy kolejny krok od nich zależy.
- Preferuj mutacje/splicing poszczególnych komunikatów zamiast mutowania całego zserializowanego zapisu komunikacji jako nieprzejrzystego bloba.
- Jeśli protokół udostępnia znaczące kody odpowiedzi, używaj ich jako **taniego oracle stanu**, aby nadawać priorytet sekwencjom, które przechodzą głębiej.

Z tego samego powodu błędy uwierzytelniania, ukryte przejścia lub błędy parsera występujące „dopiero po handshake” często umykają zwykłemu fuzzingowi plikowemu: fuzzer musi zachować **kolejność, stan i zależności**, a nie tylko strukturę.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing sterownika wieloklientowego

Wysokie edge coverage może nadal nie wykrywać błędów sterownika IPC, ponieważ pokrycie nie opisuje **własności obiektów, liczników referencji, oczekujących komunikatów, kolejności sprzątania ani przeplotów wątków**. Strona [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) omawia model obiektów sterownika; ten przykład koncentruje się na harnessie fuzzera. Android Binder to przydatny model: osiągnięcie zarówno ścieżek alokacji, jak i zwalniania nie wystarczy, jeśli fuzzer nie potrafi sprawić, by wiele procesów operowało na tym samym obiekcie jądra w wymaganej kolejności.<sup>[[15]](#references)</sup>

#### Modeluj protokół, a nie odizolowane bufory `ioctl`

Reprezentuj przypadek testowy jako uporządkowaną gramatykę **tożsamości klienta + operacji + ustrukturyzowanych argumentów**. Fuzzer Binder LKL używa protobuf i `libprotobuf-mutator`, z jednym trwałym klientem menedżera kontekstu oraz dwoma zwykłymi klientami. Następnie harness semantyczny zachowuje zależności, które ślepa mutacja bajtów by zniszczyła.<sup>[[15]](#references)</sup>

- Zapisuj wartości zwracane przez wcześniejsze operacje. Na przykład `BC_FREE_BUFFER` musi ponownie użyć wskaźnika bufora transakcji zwróconego przez wcześniejsze `ioctl`.
- Generuj poprawne domyślne odpowiedzi, aby transakcje synchroniczne mogły się zakończyć, a późniejsze operacje pozostały osiągalne.
- Odrzucaj niemożliwe przejścia, takie jak transakcje do samego siebie lub wiele oczekujących transakcji do tego samego celu.
- Utrzymuj stan singletona inicjalizacyjnego poza resetem wykonywanym dla każdego wejścia. Binder dopuszcza tylko jedną rejestrację `BINDER_SET_CONTEXT_MGR` podczas uruchomienia systemu, więc wielokrotne niszczenie i ponowne tworzenie tego klienta unieważniłoby późniejsze wejścia.

Przydatny szablon wyścigu cyklu życia polega na tym, by jeden klient przekazał obiekt, uruchomił sprzątanie wątku lub procesu, a równolegle nakazał klientowi odbierającemu zwolnić bufor transakcji. W przykładzie CVE-2020-0423 przekazanie `BINDER_TYPE_WEAK_BINDER`, po którym `BINDER_THREAD_EXIT` ścigało się z `BC_FREE_BUFFER`, mogło zwolnić osadzony `binder_work`, gdy ścieżka sprzątania kończącego się wątku nadal z niego korzystała.<sup>[[15]](#references)</sup>

#### Przywróć kontrolowane przeploty w jądrze działającym w przestrzeni użytkownika

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) linkuje rzeczywisty kod jądra z harnesssem działającym w przestrzeni użytkownika i udostępnia jego interfejs syscall przez `lkl_syscall`. Dzięki temu można łatwo koordynować stan protobuf, pokrycie i KASAN w jednym procesie. LKL zwykle uruchamia syscall bez przerywania go przez inny wątek jądra. W kampaniach wyścigów dodaj punkty `schedule()` w pobliżu wybranych granic blokowania/odblokowywania i cyklu życia, a następnie pozwól harnessowi losowo wybierać kolejnego klienta przy każdym ustąpieniu sterowania. Umieszczaj te punkty w konkretnych miejscach, ponieważ każdy z nich zwielokrotnia przestrzeń przeszukiwania harmonogramu. Opisany przez badaczy losowy scheduler **nie jest częścią upstreamowego fuzzera Binder**.<sup>[[15]](#references)</sup>

#### Buduj i odtwarzaj zserializowane seedy regresyjne

Upstreamowy harness przypina zgodną wersję `libprotobuf-mutator`, włącza instrumentację fuzzingu LKL i KASAN za pomocą `LKL_FUZZING=1`, a także włącza `CONFIG_MMU` dla Binder za pomocą `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Po sprawdzeniu celowo podatnej rewizji lub zastosowaniu opisanych upstream łatek wycofujących zmiany, serializowane ziarno może odtworzyć całe przejście stanu obejmujące wielu klientów bez konieczności rekonstruowania go w doraźnym proof of concept w C:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Potraktuj wykrycie KASAN use-after-free jako potwierdzenie, że seed dotarł do podatnej ścieżki cyklu życia. **Nie** dowodzi to istnienia późniejszych prymitywów wymaganych do wykonania kodu w kernelu lub eskalacji uprawnień.<sup>[[16]](#references)</sup>

## Sposób na różnorodność na jednej maszynie (w stylu Jackalope)

Praktycznym sposobem na połączenie **nowości generowanej** z **ponownym wykorzystaniem pokrycia** jest **uruchamianie krótkotrwałych workerów od nowa** i kierowanie ich do persistent servera. Każdy worker zaczyna z pustym corpus, synchronizuje się po `T` sekundach, przez kolejne `T` sekund działa na połączonym corpus, ponownie się synchronizuje, a następnie kończy działanie. Zapewnia to **świeże struktury w każdej generacji**, a zarazem pozwala wykorzystać zgromadzone pokrycie.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `-server_update_interval T` przybliża **opóźnioną synchronizację** (najpierw nowości, później ponowne użycie).
- W trybie grammar fuzzing **początkowa synchronizacja z serwerem jest domyślnie pomijana** (nie ma potrzeby używania `-skip_initial_server_sync`).
- Optymalne `T` **zależy od celu**; zwykle najlepiej zmienić jego wartość, gdy worker znajdzie już większość „łatwego” coverage.

## Snapshot Fuzzing dla celów trudnych do przygotowania do testów

Gdy kod, który chcesz przetestować, staje się dostępny dopiero **po kosztownym przygotowaniu** (uruchomieniu VM, zakończeniu logowania, odebraniu pakietu, sparsowaniu kontenera, zainicjowaniu usługi), przydatną alternatywą jest **snapshot fuzzing**: przechwyć stan gotowego procesu lub VM, wstrzyknij każdy przypadek testowy do ścieżki wejściowej celu, wykonuj go aż do crasha lub timeoutu, a następnie przywróć snapshot. Pozwala to uniknąć ponownego wykonywania inicjalizacji lub przetwarzania prefiksów protokołu i jest przydatne w przypadku **usług sieciowych**, **firmware**, **powierzchni ataku dostępnych po uwierzytelnieniu** oraz **celów dostępnych wyłącznie jako pliki binarne**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Uruchom cel, aż osiągnie interesujący stan.
2. W tym momencie utwórz snapshot **pamięci + rejestrów**.
3. Dla każdego przypadku testowego zapisz zmodyfikowane wejście bezpośrednio do odpowiedniego bufora guest/procesu.
4. Wykonuj go aż do crasha, timeoutu lub resetu.
5. Przywróć snapshot; w przypadku celów VM przywracaj tylko **zmodyfikowane strony**, jeśli jest to obsługiwane, a następnie powtórz.

Umieść snapshot możliwie blisko pierwszego kosztownego etapu parsowania lub dispatchu, na przykład po `recv`/`read` lub deserializacji pakietu, i zapisz, którego bufora wejściowego używa cel. Zgodnie z zasadą adaptacyjnego rozmieszczania snapshot należy przesuwać głębiej w procesie przetwarzania wejścia, aby uniknąć powtarzania wykonanej już pracy.<sup>[[11]](#references)</sup>

## Eksploracja wyścigów w jądrze Linux za pomocą MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) przekształca wrażliwe na czas wyścigi w jądrze Linux w powtarzalne harmonogramy dostępu do pamięci. Może automatycznie wyliczać wykonania **A-B-A** w dwóch kontekstach lub pozwolić analitykowi narzucać ograniczenia kolejności w terminalowym UI/GUI. To eksperymentalne narzędzie badawcze, a nie kompletny concurrency fuzzer: obecnie wymaga LLVM 23+ i załatanej wersji jądra z projektu, narzędzia wiersza poleceń obsługują dwa wątki testowe, a proponowana warstwa fuzzingu userspace nie została zaimplementowana.<sup>[[17]](#references)[[18]](#references)</sup>

### Zbieranie punktów komunikacji między kontekstami

Zbuduj instrumentowane jądro z callbackami KASAN outline i załatanym wsparciem KCOV do rejestrowania dostępu do pamięci. README projektu zaleca również wyłączenie optymalizacji sibling-call, aby stosy wywołań pozostały użyteczne.<sup>[[17]](#references)[[18]](#references)</sup>

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

Tryb KASAN outline (`asan-instrumentation-with-call-threshold=0`) zamienia instrumentowane dostępy na wywołania funkcji pomocniczych. Poprawki jądra MAccConc wyłączają `asan-opt-same-temp`, aby kolejne dostępy nie były łączone; wyłącz także optymalizację `asan-opt-globals`, gdy wyścigi dotyczące zmiennych globalnych mają być widoczne. KCOV przekazuje powstałe rekordy do przestrzeni użytkownika. Porównuj dostępy z różnych kontekstów wykonania i zachowuj pary, których zakresy bajtów się nakładają, a przynajmniej jedna strona zapisuje dane; traktuj `kfree()` jako zapis, aby przejścia związane z czasem życia również mogły być kandydatami.<sup>[[17]](#references)</sup>

W przypadku pracy wykraczającej poza zadanie inicjujące, takiej jak przetwarzanie pakietów lub wywołania zwrotne RCU, podsystem musi propagować uchwyt zdalnego pokrycia KCOV. Zdalne KCOV w upstreamie jest opt-in i nie jest automatycznie dostępne dla dowolnej pracy w tle, więc brak propagacji może sprawić, że rzeczywista interakcja pozostanie niewidoczna.<sup>[[17]](#references)[[19]](#references)</sup>

### Identyfikowanie tego samego dostępu dynamicznego przy każdym uruchomieniu

Nie odtwarzaj testu z użyciem konkretnego adresu na heapie, który może się zmieniać po każdej alokacji, ani wyłącznie adresu instrukcji, który jest niejednoznaczny wewnątrz funkcji pomocniczych takich jak `memcpy()` i `spin_lock()`. MAccConc używa **śladu stosu rozszerzonego o liczniki**: każda ramka identyfikuje funkcję wywoływaną oraz liczbę jej wywołań w ramach funkcji wywołującej, a ostatni element identyfikuje instrukcję dostępu do pamięci. Rekordy wejścia/wyjścia z funkcji SanitizerCoverage pozwalają przestrzeni użytkownika odtworzyć ten dynamiczny identyfikator, który pozostaje stabilny mimo zmian adresów i niepowiązanych zmian w przepływie sterowania.<sup>[[17]](#references)</sup>

### Przekształcanie par kandydatów w wymuszone harmonogramy

Poprawiony ioctl `KCOV_SET_DI` wiąże identyfikator dostępu rozszerzony o liczniki z akcją na współdzielonej fladze.<sup>[[17]](#references)</sup>

| Akcja | Semantyka |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Ustaw flagę *N* bezpośrednio przed wybranym dostępem. |
| `DI_STACK_WAIT` | Przed wybranym dostępem czekaj w pętli, aż flaga *N* zostanie ustawiona lub upłynie skonfigurowany limit. |
| `DI_STACK_WAKE_POST` | Ustaw flagę *N* bezpośrednio po wybranym dostępie. |

Aby wymusić częściowe ograniczenie **A-happens-before-B**, przypisz `DI_STACK_WAKE_POST` do A, a `DI_STACK_WAIT` do B, używając tej samej flagi. W przypadku w pełni określonego harmonogramu dwóch kontekstów rozpocznij od zablokowanego B, a następnie spraw, by A wybudziło B i zaczekało w pierwszym punkcie przekazania sterowania; przy kolejnym przekazaniu B wykonuje operację odwrotną. To drugie rozwiązanie działa jak deterministyczne przełączanie kontekstu i jest wykorzystywane przez automatyczny eksplorator A-B-A.<sup>[[17]](#references)</sup>

Minimalna kampania polega na skompilowaniu testu z czterema punktami zaczepienia (`test_setup`, dwiema funkcjami wątków i `test_end`) jako biblioteki współdzielonej, zebraniu śladu bez ograniczeń, a następnie wyliczeniu kandydatów A-B-A lub dodaniu ręcznych ograniczeń wokół podejrzanych dostępów.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interpretuj timeouty osobno od udanych zmian kolejności: żądana kolejność może być niemożliwa, ponieważ blokada albo zależność od inicjalizacji/publikacji uniemożliwia dotarcie drugiemu kontekstowi do punktu wstrzyknięcia. Pamiętaj też o martwych polach KASAN: bezpośrednie dostępy do stosu zwykle nie są przechwytywane, chyba że mogą wykraczać poza zakres, zmienne globalne są pomijane przy domyślnej optymalizacji, a obecne kompilatory nie mogą jednocześnie generować hooków ASAN i TSAN. Ponadto prototyp traci bufor KCOV, gdy guest ulega awarii, dlatego zachowaj niezależną konsolę/oracle do awarii.<sup>[[17]](#references)</sup>

Na potrzeby przyszłego fuzzingu sterowanego współbieżnością rejestruj podsumowania dostępów do pamięci dla każdego wejścia lub wywołania syscall, łącz operacje, które mogłyby utworzyć punkty komunikacji między kontekstami, a następnie eksploruj tylko te kombinacje. Migawki VM stabilizują stan globalny i adresy; bez migawek metadane miejsca alokacji mogą służyć do abstrakcji obiektów między uruchomieniami. To proponowane rozszerzenie, a nie funkcja obecnych narzędzi userspace MAccConc.<sup>[[17]](#references)</sup>

## Introspekcja harnessa: wcześnie wykrywaj płytkie fuzzery

Gdy kampania staje w miejscu, problemem często nie jest mutator, lecz **harness**. Użyj **introspekcji osiągalności/pokrycia**, aby znaleźć funkcje statycznie osiągalne z twojego celu fuzzingu, które w testach dynamicznych są pokrywane rzadko albo wcale. Zwykle wskazują one na jeden z trzech problemów.<sup>[[12]](#references)</sup>

- Harness wchodzi do celu zbyt późno lub zbyt wcześnie.
- W korpusie seedów brakuje całej rodziny funkcji.
- Cel naprawdę wymaga **drugiego harnessa**, zamiast jednego, przesadnie rozbudowanego harnessa „do wszystkiego”.

Jeśli korzystasz z przepływów pracy w stylu OSS-Fuzz / ClusterFuzz, Fuzz Introspector może porównać statyczną osiągalność z pokryciem w czasie działania i generować raporty na podstawie uruchomienia z limitem czasu lub publicznego korpusu.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Użyj raportu, aby zdecydować, czy dodać nowy harness dla nieprzetestowanej ścieżki parsera, rozszerzyć corpus dla określonej funkcji czy podzielić monolityczny harness na mniejsze punkty wejścia.

## Wybór celów fuzzingu z wykorzystaniem grafu i triage mutacji

Jeśli masz już **wyniki analizy statycznej**, **mutanty, które przetrwały testy mutacyjne** i **raporty pokrycia**, nie analizuj ich jako niezależnych list. Najpierw zbuduj **graf wywołań**, dodaj do węzłów adnotacje dotyczące **złożoności cyklomatycznej**, **osiągalności z punktów wejścia/niezaufanych danych** oraz wszelkich zewnętrznych ustaleń, a następnie zadawaj pytania dotyczące grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Które funkcje o wysokiej złożoności są osiągalne z niezaufanych danych?
- Które mutanty, które przetrwały testy, znajdują się na ścieżkach od parserów/handlerów do kodu krytycznego dla bezpieczeństwa?
- Które funkcje są architektonicznymi wąskimi gardłami o wyjątkowo dużym **blast radius**?

Takie podejście zwykle pozwala znaleźć lepsze cele fuzzingu niż samo kierowanie się „najniższym pokryciem”. Parser/dekoder o **wysokiej złożoności** i potwierdzonej **osiągalności z zewnątrz** jest lepszym kandydatem na harness niż odizolowana wewnętrzna funkcja pomocnicza o niskim pokryciu, do której nie prowadzi ścieżka kontrolowana przez atakującego.

### Praktyczny proces triage

1. Zbuduj **graf kodu** na podstawie codebase i wyodrębnij metryki złożoności/liczby gałęzi dla poszczególnych funkcji.
2. Wymień **punkty wejścia** przyjmujące dane kontrolowane przez atakującego: handlery żądań, dekodery, importery, parsery protokołów, czytniki CLI/plików.
3. Wykonaj zapytania o ścieżki od tych punktów wejścia do wybranych funkcji, aby oddzielić osiągalną powierzchnię ataku od kodu martwego lub dostępnego wyłącznie wewnętrznie.
4. Nadaj priorytet węzłom, które łączą:
   - wysoką **złożoność cyklomatyczną**
   - potwierdzoną **osiągalność z niezaufanych danych**
   - duży **blast radius** lub wiele zależnych elementów
   - dodatkowe dowody, takie jak ustalenia **SARIF**, notatki z audytu lub mutanty, które przetrwały testy
5. Najpierw napisz wyspecjalizowane harnessy dla najlepiej ocenionych węzłów, zwłaszcza **parserów/kodeków**, takich jak dekodery hex/Base64/IP/wiadomości.

### Mutanty, które przetrwały testy: równoważne czy warte działania?

Testy mutacyjne często generują zaszumioną listę mutantów, które przetrwały testy. Zanim uznasz każdego z nich za lukę w zabezpieczeniach, użyj grafu, aby ustalić:

- Czy zmodyfikowana funkcja jest osiągalna z punktu wejścia kontrolowanego przez atakującego?
- Czy wszystkie ścieżki wywołań są ograniczone silniejszymi niezmiennikami niż zmodyfikowany warunek?
- Czy węzeł znajduje się w martwym kodzie, logice służącej wyłącznie do formatowania czy w ważnej ścieżce arytmetycznej/parsera?

Mutanty, które pozostają nieosiągalne lub są strukturalnie ograniczone, są często **mutantami równoważnymi**. Mutanty, które nadal są **osiągalne** i dotyczą **warunków brzegowych**, **ścieżek przepełnienia/przeniesienia** lub **arytmetyki/parsingowania krytycznych dla bezpieczeństwa**, należy uwzględnić w:

- nowych harnessach fuzzingowych
- bezpośrednich testach właściwości/niezmienników
- ukierunkowanych zestawach przypadków brzegowych

### Korelowanie zewnętrznych ustaleń z grafem

Jeśli Twój pipeline SAST eksportuje **SARIF**, przypisz ustalenia do węzłów grafu na podstawie **pliku i zakresu wierszy**, a następnie użyj grafu, aby określić szerszy wpływ.<sup>[[6]](#references)</sup>

- oblicz **blast radius** oznaczonej funkcji
- sprawdź, czy ustalenie znajduje się na którejkolwiek ścieżce od punktu wejścia
- grupuj pobliskie ustalenia, które zbiegają się w tym samym wąskim gardle

Jest to przydatne przy podejmowaniu decyzji, czy poświęcić czas na fuzzing konkretnej funkcji: węzeł, który jest **osiągalny**, **złożony** i ma już ustalenia **SAST**, często jest lepszym celem niż węzeł, który jest jedynie złożony, ale nie leży na ścieżce dostępnej dla atakującego.

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

Najważniejsza jest część wspólna: **złożoność x ekspozycja x wpływ**. Użyj wykresu, aby wybrać cele fuzzingu o najwyższej oczekiwanej wartości z punktu widzenia bezpieczeństwa, a następnie wykorzystaj mutanty, które przetrwały, aby zdecydować, które granice i niezmienniki musi sprawdzać Twój harness.<sup>[[5]](#references)</sup>

## Go Fuzzing With gosentry: Mocniejszy silnik, typowane dane wejściowe i testy różnicowe

Jeśli cel w Go ma już natywny harness `testing.F`, praktyczną ścieżką ulepszenia jest uruchomienie tego samego harnessu za pomocą [gosentry](https://github.com/trailofbits/gosentry) — rozwidlonego łańcucha narzędzi Go, który zachowuje `go test -fuzz`, ale zmienia backend na **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Jest to przydatne, gdy natywny Go fuzzer zatrzymuje się na **trudnych porównaniach**, **typowanych danych wejściowych** lub **formatach wymagających intensywnego parsowania**. Metodologia pozostaje taka sama:

- Nadal używaj `f.Add(...)` do dodawania seedów i `f.Fuzz(...)` jako callbacka.
- Użyj ponownie tego samego harnessa, ale uruchom go za pomocą pliku binarnego `go` z gosentry zamiast standardowego toolchaina.
- Traktuj wynikową kampanię jak zwykły przebieg sterowany pokryciem, ale z harmonogramowaniem i mutacjami LibAFL oraz lepszymi detektorami dodatkowymi.

### Zamień ciche błędy w wyniki fuzzingu

Powracającym problemem w testach bezpieczeństwa Go jest to, że niebezpieczne zachowanie często **domyślnie nie powoduje awarii**. Za pomocą gosentry można zamienić kilka klas „złych, ale cichych” stanów w wyniki fuzzingu.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`, aby wybrane ścieżki logowania/błędów zachowywały się jak awarie (przydatne w ścieżkach kodu w stylu `log.Fatal`, które w przeciwnym razie tylko logują i kontynuują działanie).
- `--catch-races=true`, aby ponownie odtwarzać nowo odkryte wpisy kolejki z detektorem race condition w Go.
- `--catch-leaks=true`, aby ponownie odtwarzać nowe wpisy kolejki z `goleak` i zatrzymywać działanie w przypadku wycieków goroutine.
- Obsługa zawieszeń w LibAFL, która pozwala zachować **nieskończone pętle / bardzo wolne dane wejściowe** jako wyniki fuzzingu, zamiast pomijać je jako timeouty.
- Domyślnie wbudowane kontrole przepełnienia arytmetycznego oraz opcjonalne kontrole obcięcia za pomocą instrumentacji w stylu go-panikint.

Jest to szczególnie przydatne w przypadku celów, w których wpływ na bezpieczeństwo wynika z **błędu parsera bez panic**, **błędu współbieżności** lub **zawieszenia powodującego wyłącznie DoS**, a nie z uszkodzenia pamięci.

### Fuzzing uwzględniający struktury dla typowanych API Go

Natywny fuzzing Go oczekuje głównie typów skalarnych, takich jak `[]byte`, `string` i liczby. Jeśli testowany kod przyjmuje typowane obiekty, gosentry może bezpośrednio fuzzować **wartości złożone** (struktury, slice’y, tablice, wskaźniki), jednocześnie mutując znajdujące się pod nimi bajty.<sup>[[7]](#references)[[8]](#references)</sup>

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

Użyj tego, gdy tworzenie sztucznego formatu przewodowego wyłącznie na potrzeby fuzzingu ukrywałoby błędy logiczne za kodem parsującym używanym tylko przez harness. W kampaniach różnicowych lub opartych na gramatyce pozostaw dane wejściowe harnessu jako pojedyncze `[]byte` lub `string` i parsuj je wewnątrz callbacku.

### Fuzzing oparty na gramatyce dla parserów i danych wejściowych protokołów

W przypadku parserów, formatów i języków wejściowych gosentry może uruchamiać **Nautilus grammar fuzzing** w oparciu o LibAFL. Gramatyka jest tablicą reguł produkcji w formacie JSON, a harness powinien zwykle przyjmować pojedynczy argument `[]byte` lub `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Uwagi dotyczące metodyki:

- Używaj trybu gramatycznego, gdy mutacje na poziomie bajtów przeważnie kończą się na wczesnych kontrolach składni.
- Ogranicz gramatykę do **istotnego z punktu widzenia bezpieczeństwa podzbioru** języka/protokołu, zamiast modelować całą specyfikację.
- Używaj dużych wartości granicznych w terminalach/nieterminalach, aby obciążyć granice liczb całkowitych, długości i maszyn stanów.
- Tryb gramatyczny zapewnia zgodność wejść z gramatyką, ale cel nadal otrzymuje **bajty/ciągi znaków**, więc parsowanie i kontrole semantyczne nadal odbywają się w kodzie objętym harness.

### Differential fuzzing: porównywanie implementacji, nie tylko awarii

W ekosystemach Go skutecznym podejściem jest **grammar-based differential fuzzing**: generowanie poprawnych, ustrukturyzowanych danych wejściowych i przekazywanie ich do dwóch parserów, klientów lub silników przejść stanów.<sup>[[7]](#references)[[8]](#references)</sup>

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

Traktuj poniższe przypadki jako problemy:

- jedna implementacja kończy się paniką, a druga poprawnie odrzuca dane wejściowe
- rozbieżności w akceptowaniu lub odrzucaniu danych wejściowych
- różne drzewa parsowania lub zdekodowane obiekty
- rozbieżne zmiany stanu, nonce, salda lub korzenie stanu

To praktyczny sposób na wykrywanie **rozbieżności konsensusu**, **niejednoznaczności parsera** i **rozbieżności między specyfikacją a implementacją**, które często umykają fuzzingowi nastawionemu wyłącznie na awarie.

### Ponowne użycie korpusu kampanii do raportowania pokrycia

Po zakończeniu kampanii odtwórz zapisany korpus kolejki, aby wygenerować raport pokrycia Go bez ręcznego eksportowania osobnego korpusu.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Uruchom polecenie z **tego samego pakietu** i z tym samym celem `-fuzz`, aby gosentry rozpoznał właściwy stan kampanii z pamięci podręcznej.

## References

- [1] [Fuzzing z gramatyką mutacyjną](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing w AFL++ — dogłębne omówienie](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pięć lat później: fuzzing protokołów sterowany pokryciem](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark zamienia kod w grafy](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [W Go fuzzingowi brakowało połowy narzędzi. Zmieniliśmy toolchain, aby to naprawić.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: szybki greybox fuzzer dla protokołów sieciowych ze stanem, wykorzystujący migawki](https://arxiv.org/abs/2202.03643)
- [10] [Brak gramatyki? Żaden problem: w kierunku fuzzingu jądra Linuksa bez opisów wywołań systemowych](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: wydajny fuzzing z adaptacyjnymi i modyfikowalnymi migawkami](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentacja LLVM w AFL++: pokrycie ścieżek i wywołujących](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predykcyjny fuzzing uwzględniający kontekst](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Android Offensive Security — fuzzing Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer Binder w LKL Android — dokumentacja kompilacji i seedów regresyjnych](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: badanie warunków wyścigu w jądrze Linuksa za pomocą kontrolowanego przeplatania dostępów do pamięci](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: pokrycie kodu na potrzeby fuzzingu](https://docs.kernel.org/dev-tools/kcov.html)
{{#include ../banners/hacktricks-training.md}}
