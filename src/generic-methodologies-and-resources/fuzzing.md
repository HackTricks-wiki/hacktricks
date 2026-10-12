# Metodologia fuzzingu

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: pokrycie a semantyka

W **mutational grammar fuzzing** wejścia są mutowane z zachowaniem **poprawności gramatycznej**. W trybie sterowanym pokryciem jako ziarna corpus zapisywane są tylko próbki wywołujące **nowe pokrycie**. W przypadku **celów językowych** (parserów, interpreterów, silników) może to pomijać błędy wymagające **łańcuchów semantycznych/przepływu danych**, w których wynik jednej konstrukcji staje się wejściem dla kolejnej.<sup>[[1]](#references)</sup>

**Tryb awarii:** fuzzer znajduje ziarna, które osobno uruchamiają `document()` i `generate-id()` (lub podobne prymitywy), ale **nie zachowuje łańcuchowego przepływu danych**, przez co próbka „bliższa błędu” zostaje odrzucona, bo nie zwiększa pokrycia. Przy **co najmniej 3 zależnych krokach** losowe rekombinacje stają się kosztowne, a informacja zwrotna o pokryciu nie ukierunkowuje wyszukiwania.<sup>[[1]](#references)</sup>

**Wniosek:** w przypadku gramatyk z wieloma zależnościami warto rozważyć **połączenie faz mutacyjnej i generatywnej** albo ukierunkowanie generowania na wzorce **łańcuchowego wywoływania funkcji** (a nie tylko na pokrycie).<sup>[[1]](#references)</sup>

## Pułapki związane z różnorodnością corpus

Mutacje sterowane pokryciem są **zachłanne**: próbka zwiększająca pokrycie jest od razu zapisywana, często z dużymi, niezmienionymi fragmentami. Z czasem corpus staje się zbiorem **niemal identycznych próbek** o niewielkiej różnorodności strukturalnej. Agresywna minimalizacja może usunąć przydatny kontekst, dlatego praktycznym kompromisem jest **minimalizacja uwzględniająca gramatykę**, która **zatrzymuje się po osiągnięciu minimalnej liczby tokenów** (redukuje szum, zachowując wystarczającą ilość otaczającej struktury, by ułatwić mutacje).<sup>[[1]](#references)</sup>

Praktyczna zasada dotycząca corpus w mutational fuzzing: **wybieraj niewielki zbiór strukturalnie różnych ziaren maksymalizujących pokrycie**, zamiast dużej puli niemal identycznych próbek. W praktyce zwykle oznacza to:<sup>[[1]](#references)[[3]](#references)</sup>

- Zacznij od **próbek z rzeczywistych zastosowań** (publicznych corpus, danych z crawlowania, przechwyconego ruchu, zbiorów plików z ekosystemu celu).
- Ogranicz ich liczbę za pomocą **minimalizacji corpus opartej na pokryciu**, zamiast zachowywać każdą poprawną próbkę.
- Dbaj, by ziarna były **wystarczająco małe**, tak aby mutacje trafiały w znaczące pola, zamiast pochłaniać większość cykli na nieistotne bajty.
- Ponownie uruchamiaj minimalizację corpus po istotnych zmianach w harnessie lub instrumentacji, ponieważ „najlepszy” corpus zmienia się wraz ze zmianami osiągalności.

## Mutacje uwzględniające porównania dla wartości magicznych

Częstym powodem, dla którego fuzzery przestają robić postępy, nie jest składnia, lecz **trudne do spełnienia porównania**: magiczne bajty, kontrole długości, ciągi enum, sumy kontrolne lub wartości używane do wyboru parsera, chronione przez `memcmp`, tablice switch albo kaskadowe porównania. Czysto losowe mutacje marnują cykle na zgadywanie tych wartości bajt po bajcie.

W przypadku takich celów używaj **śledzenia porównań** (na przykład `CMPLOG` w AFL++ lub przepływów pracy w stylu Redqueen), aby fuzzer mógł obserwować operandy nieudanych porównań i kierować mutacje ku wartościom, które je spełniają.<sup>[[3]](#references)</sup>

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
- Połącz tę metodę ze **słownikami** wyodrębnionymi z rzeczywistych próbek, specyfikacji protokołów lub logów debugowania. Niewielki słownik zawierający tokeny gramatyki, nazwy chunków, czasowniki i separatory jest często cenniejszy niż ogromna, ogólna lista słów.
- Jeśli cel wykonuje wiele kolejnych testów, najpierw rozwiąż najwcześniejsze porównania „magic”, a następnie ponownie zminimalizuj uzyskany corpus, aby kolejne etapy zaczynały od już poprawnych prefiksów.

## Bogatszy feedback, gdy edge coverage scala różne ścieżki

Zwykłe edge coverage nie potrafi rozróżnić dwóch wykonań, które przechodzą przez ten sam helper z różnymi funkcjami wywołującymi lub przyjmują różne kombinacje gałęzi wewnątrz funkcji. Ma to znaczenie we współdzielonych dekoderach, dispatcherach protokołów i helperach interpreterów, gdzie **ścieżka** prowadząca do krawędzi określa bieżący stan. Naiwne śledzenie każdego kontekstu wywołania również jest niebezpieczne: mapa coverage i kolejka mogą gwałtownie urosnąć. Badania nad fuzzingiem uwzględniającym kontekst zalecają więc doprecyzowywanie tylko obiecujących kontekstów, zamiast traktowania całego grafu wywołań jako uwzględniającego kontekst.<sup>[[14]](#references)</sup>

Nowsze wersje AFL++ zapewniają **pokrycie ścieżek per funkcja metodą Ball-Larus** oprócz zwykłego edge coverage. Przypisuje ono feature każdej acyklicznej ścieżce w funkcji; krawędzie powrotne pętli są usuwane, więc ten feedback rozróżnia kombinacje gałęzi, ale **nie liczbę iteracji pętli**. Zacznij od łagodnego poziomu `1`, a następnie stosuj bardziej rygorystyczne tryby tylko w podejrzanym kodzie parserów i maszyn stanów, ponieważ liczba ścieżek może rosnąć wykładniczo.<sup>[[13]](#references)</sup>

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

**Wskazówki dotyczące kampanii:** stosuj bogatszy feedback z rozwagą i monitoruj jego koszt w postaci mapy pokrycia i kolejki.<sup>[[13]](#references)[[14]](#references)</sup>

- Uruchom równolegle zwykłą instancję z pokryciem krawędzi; bogatszy feedback jest przydatny tylko wtedy, gdy dodatkowy koszt mapy i kolejki nie zmniejsza liczby wykonań na sekundę.
- Użyj `AFL_LLVM_ALLOWLIST`, aby ograniczyć instrumentację ścieżek i wywołujących funkcji, gdy duże biblioteki oparte na szablonach lub ogólny kod narzędziowy dominują w mapie.
- Funkcje z nadmierną liczbą acyklicznych ścieżek można pominąć w AFL++; ostrzeżenia podczas kompilacji wskazują, że cel wymaga allowlisty lub mniej rygorystycznego poziomu.
- Pokrycie wywołujący + ścieżka obsługuje tylko jeden poziom wywołującego. Nie łącz go z głębszymi stosami kontekstu.
- Identyfikatory ścieżek mogą się zmieniać między głównymi wersjami LLVM. Używaj niezmiennego toolchaina przez całą kampanię i nie synchronizuj korpusów opartych na PATH tak, jakby ich identyfikatory cech były stabilne między kompilacjami.
- Ten feedback uzupełnia `CMPLOG`: śledzenie porównań rozwiązuje problem **tego, jaka wartość przechodzi przez warunek**, a feedback dotyczący ścieżek i wywołujących zachowuje informację o tym, **która trasa i kombinacja gałęzi doprowadziły do tego miejsca**.

## Stateful Fuzzing: sekwencje są seedami

W przypadku **protokołów**, **uwierzytelnionych przepływów pracy** i **parserów wieloetapowych** interesującą jednostką często nie jest pojedynczy blob, lecz **sekwencja wiadomości**. Połączenie całego transkryptu w jeden plik i bezmyślne mutowanie go jest zwykle nieefektywne, ponieważ fuzzer mutuje każdy krok jednakowo, nawet jeśli tylko późniejsza wiadomość dociera do podatnego stanu.<sup>[[4]](#references)</sup>

Skuteczniejszym podejściem jest potraktowanie **samej sekwencji jako seedu** i użycie **obserwowalnego stanu** (kodów odpowiedzi, stanów protokołu, etapów parsera, zwracanych typów obiektów) jako dodatkowego feedbacku.<sup>[[4]](#references)</sup>

- Zachowuj **prawidłowe wiadomości prefiksowe** bez zmian i skup mutacje na wiadomości **sterującej przejściem**.
- Buforuj identyfikatory i wartości wygenerowane przez serwer w poprzednich odpowiedziach, jeśli zależy od nich kolejny krok.
- Preferuj mutowanie lub łączenie poszczególnych wiadomości zamiast mutowania całego serializowanego transkryptu jako nieprzejrzystego bloba.
- Jeśli protokół udostępnia znaczące kody odpowiedzi, używaj ich jako **taniego wyroczni stanu**, aby nadawać priorytet sekwencjom, które docierają głębiej.

Z tego samego powodu błędy związane z uwierzytelnianiem, ukryte przejścia lub błędy parsera występujące „dopiero po handshake’u” często umykają klasycznemu fuzzingowi plikowemu: fuzzer musi zachować **kolejność, stan i zależności**, a nie tylko strukturę.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing sterownika z wieloma klientami

Wysokie pokrycie krawędzi nadal może nie wykryć błędów sterownika IPC, ponieważ pokrycie nie opisuje **własności obiektów, liczników referencji, oczekujących wiadomości, kolejności sprzątania ani przeplotów wątków**. Strona [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) omawia model obiektów sterownika; ten przykład skupia się na harnessie fuzzera. Android Binder to przydatny model: dotarcie zarówno do ścieżek alokacji, jak i zwalniania nie wystarczy, jeśli fuzzer nie potrafi sprawić, by wiele procesów operowało na tym samym obiekcie jądra w wymaganej kolejności.<sup>[[15]](#references)</sup>

#### Modeluj protokół, a nie odizolowane bufory `ioctl`

Reprezentuj przypadek testowy jako uporządkowaną gramatykę **tożsamości klienta + operacji + ustrukturyzowanych argumentów**. Fuzzer Binder LKL używa protobuf i `libprotobuf-mutator`, jednego trwałego klienta menedżera kontekstu oraz dwóch zwykłych klientów. Harness semantyczny zachowuje wtedy zależności, które ślepa mutacja bajtów by zniszczyła.<sup>[[15]](#references)</sup>

- Buforuj wartości zwrócone przez wcześniejsze operacje. Na przykład `BC_FREE_BUFFER` musi ponownie użyć wskaźnika do bufora transakcji zwróconego przez wcześniejsze `ioctl`.
- Generuj prawidłowe domyślne odpowiedzi, aby transakcje synchroniczne mogły się zakończyć, a późniejsze operacje pozostały osiągalne.
- Odrzucaj niemożliwe przejścia, takie jak transakcje do samego siebie lub wiele oczekujących transakcji do tego samego celu.
- Zachowuj stan inicjalizacji pojedynczej instancji poza resetem wykonywanym dla każdego wejścia. Binder dopuszcza tylko jedną rejestrację `BINDER_SET_CONTEXT_MGR` podczas jednego uruchomienia, więc wielokrotne niszczenie i odtwarzanie tego klienta unieważniłoby późniejsze wejścia.

Przydatny schemat testowania wyścigu o czas życia polega na tym, by jeden klient przekazał obiekt, rozpoczął sprzątanie wątku lub procesu, a klient odbierający równolegle zwolnił bufor transakcji. W przykładzie CVE-2020-0423 przekazanie `BINDER_TYPE_WEAK_BINDER`, po którym następował `BINDER_THREAD_EXIT` ścigający się z `BC_FREE_BUFFER`, mogło zwolnić osadzony `binder_work`, gdy ścieżka sprzątania kończącego działanie wątku nadal z niego korzystała.<sup>[[15]](#references)</sup>

#### Przywróć kontrolowane przeploty w jądrze działającym w przestrzeni użytkownika

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) łączy rzeczywisty kod jądra z harnessem działającym w przestrzeni użytkownika i udostępnia jego interfejs wywołań systemowych przez `lkl_syscall`. Dzięki temu można łatwo koordynować stan protobuf, pokrycie i KASAN w jednym procesie. LKL zwykle wykonuje wywołanie systemowe bez przerywania go przez inny wątek jądra. W kampaniach testujących wyścigi należy jednak wstawić punkty `schedule()` wokół wybranych granic blokowania/odblokowywania i czasu życia, a następnie pozwolić harnessowi losowo wybierać kolejnego klienta przy każdym ustąpieniu sterowania. Ogranicz te punkty do wybranych miejsc, ponieważ każdy z nich zwielokrotnia przestrzeń poszukiwań harmonogramu. Opisany przez badaczy losowy scheduler **nie jest częścią upstreamowego fuzzera Binder**.<sup>[[15]](#references)</sup>

#### Budowanie i odtwarzanie serializowanych seedów regresyjnych

Upstreamowy harness przypina zgodną wersję `libprotobuf-mutator`, włącza instrumentację LKL do fuzzingu i KASAN za pomocą `LKL_FUZZING=1`, a także włącza `CONFIG_MMU` dla Binder przez `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Po przejściu na celowo podatną rewizję lub zastosowaniu opisanych upstream poprawek cofających zmiany, serializowany seed może odtworzyć cały przebieg zmiany stanu obejmujący wielu klientów bez konieczności rekonstruowania go w doraźnym proof of concept w C:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Potraktuj wynikający use-after-free w KASAN jako potwierdzenie, że seed dotarł do podatnej ścieżki zarządzania czasem życia obiektu. Nie dowodzi to obecności późniejszych prymitywów niezbędnych do wykonania kodu w jądrze ani eskalacji uprawnień.<sup>[[16]](#references)</sup>

## Sztuczka różnorodności na jednej maszynie (w stylu Jackalope)

Praktycznym sposobem na połączenie **generatywnej nowości** z **ponownym wykorzystaniem pokrycia** jest uruchamianie **krótkotrwałych workerów** przeciwko stale działającemu serwerowi. Każdy worker zaczyna od pustego corpus, synchronizuje się po `T` sekundach, przez kolejne `T` sekund działa na połączonym corpus, ponownie się synchronizuje, a następnie kończy działanie. Dzięki temu każda generacja tworzy **nowe struktury**, a jednocześnie wykorzystuje zgromadzone pokrycie.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `-server_update_interval T` przybliża **opóźnioną synchronizację** (najpierw nowe przypadki, później ponowne użycie).
- W trybie grammar fuzzing **początkowa synchronizacja z serwerem jest domyślnie pomijana** (nie ma potrzeby używania `-skip_initial_server_sync`).
- Optymalna wartość `T` **zależy od celu**; najlepiej przełączyć ją, gdy worker znajdzie większość „łatwego” pokrycia.

## Snapshot Fuzzing dla celów trudnych do objęcia harnessami

Gdy kod, który chcesz testować, staje się dostępny dopiero **po kosztownej konfiguracji** (uruchomieniu maszyny wirtualnej, zalogowaniu, odebraniu pakietu, sparsowaniu kontenera, zainicjalizowaniu usługi), użyteczną alternatywą jest **snapshot fuzzing**: przechwyć stan gotowego procesu lub maszyny wirtualnej, wprowadź każdy przypadek testowy do ścieżki wejściowej celu, wykonuj go do awarii/przekroczenia limitu czasu, a następnie przywróć snapshot. Pozwala to uniknąć powtarzania inicjalizacji lub prefiksów protokołu i jest przydatne w przypadku **usług sieciowych**, **firmware**, **powierzchni ataku dostępnych po uwierzytelnieniu** oraz **celów wyłącznie binarnych**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Uruchom cel, aż osiągnie interesujący stan.
2. Wykonaj snapshot **pamięci + rejestrów** w tym momencie.
3. Dla każdego przypadku testowego zapisz zmodyfikowane dane wejściowe bezpośrednio do odpowiedniego bufora procesu/maszyny gościa.
4. Wykonuj do awarii/przekroczenia limitu czasu/resetu.
5. Przywróć snapshot; w przypadku celów działających na maszynie wirtualnej przywracaj tylko **zmodyfikowane strony**, jeśli jest to obsługiwane, a następnie powtórz.

Umieść snapshot możliwie blisko pierwszego kosztownego etapu parsowania/przekazywania, na przykład po `recv`/`read` lub deserializacji pakietu, i zapisz, którego bufora wejściowego używa cel. Zgodnie z zasadą adaptacyjnego umieszczania snapshotu, przesuwaj go w głąb przetwarzania danych wejściowych, aby uniknąć powtarzania pracy.<sup>[[11]](#references)</sup>

## Eksploracja wyścigów w jądrze Linux za pomocą MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) przekształca wrażliwe na timing wyścigi w jądrze Linux w powtarzalne harmonogramy dostępu do pamięci. Może automatycznie wyliczać wykonania **A-B-A** w dwóch kontekstach lub pozwolić analitykowi narzucić ograniczenia kolejności w terminalowym UI/GUI. To eksperymentalne narzędzie badawcze, a nie kompletny concurrency fuzzer: obecnie wymaga LLVM 23+ i zmodyfikowanego jądra projektu, narzędzia wiersza poleceń obsługują dwa wątki testowe, a proponowana warstwa fuzzingowa w przestrzeni użytkownika nie została zaimplementowana.<sup>[[17]](#references)[[18]](#references)</sup>

### Zbieranie punktów komunikacji między kontekstami

Zbuduj instrumentowane jądro z callbackami KASAN outline i zmodyfikowaną obsługą rejestrowania pamięci KCOV. README projektu zaleca również wyłączenie optymalizacji sibling-call, aby stosy wywołań pozostały użyteczne.<sup>[[17]](#references)[[18]](#references)</sup>

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

Tryb outline KASAN (`asan-instrumentation-with-call-threshold=0`) zamienia instrumentowane dostępy na wywołania funkcji pomocniczych. Poprawki MAccConc dla jądra wyłączają `asan-opt-same-temp`, aby kolejne dostępy nie były scalane; wyłącz także optymalizację `asan-opt-globals`, jeśli wyścigi dotyczące zmiennych globalnych mają być widoczne. KCOV przekazuje powstałe rekordy do przestrzeni użytkownika. Porównuj dostępy z różnych kontekstów wykonania i zachowuj pary, których zakresy bajtów się nakładają, a przynajmniej jedna ze stron wykonuje zapis; traktuj `kfree()` jak zapis, aby kandydatami stawały się również zmiany czasu życia obiektów.<sup>[[17]](#references)</sup>

W przypadku pracy, która wykracza poza zadanie inicjujące, takiej jak przetwarzanie pakietów lub wywołania zwrotne RCU, podsystem musi przekazywać uchwyt zdalnego pokrycia KCOV. Zdalny KCOV w upstreamie jest opt-in i nie jest automatycznie dostępny dla dowolnej pracy w tle, więc brak przekazania uchwytu może sprawić, że rzeczywista interakcja pozostanie niewidoczna.<sup>[[17]](#references)[[19]](#references)</sup>

### Identyfikowanie tego samego dostępu dynamicznego podczas każdego uruchomienia

Nie odtwarzaj wykonania, używając konkretnego adresu sterty, który może się zmienić po każdej alokacji, ani samego adresu instrukcji, który jest niejednoznaczny wewnątrz funkcji pomocniczych, takich jak `memcpy()` i `spin_lock()`. MAccConc używa **śladu stosu z licznikami**: każda ramka identyfikuje funkcję wywoływaną oraz liczbę jej wywołań w funkcji wywołującej, a ostatni element identyfikuje instrukcję dostępu do pamięci. Rekordy wejścia i wyjścia z funkcji z SanitizerCoverage pozwalają przestrzeni użytkownika odtworzyć ten dynamiczny identyfikator, który pozostaje stabilny mimo zmian adresów i niezwiązanych z nimi zmian przepływu sterowania.<sup>[[17]](#references)</sup>

### Konwertowanie par kandydatów na wymuszone harmonogramy

Poprawka do ioctl `KCOV_SET_DI` wiąże identyfikator dostępu ze śladem stosu z licznikami z akcją na współdzielonej fladze.<sup>[[17]](#references)</sup>

| Akcja | Semantyka |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Ustaw flagę *N* bezpośrednio przed wybranym dostępem. |
| `DI_STACK_WAIT` | Przed wybranym dostępem czekaj w pętli, aż flaga *N* zostanie ustawiona lub upłynie skonfigurowany limit. |
| `DI_STACK_WAKE_POST` | Ustaw flagę *N* bezpośrednio po wybranym dostępie. |

Aby wymusić częściowy warunek **A-happens-before-B**, przypisz `DI_STACK_WAKE_POST` do A, a `DI_STACK_WAIT` do B, używając tej samej flagi. W przypadku w pełni określonego harmonogramu dla dwóch kontekstów rozpocznij z zablokowanym B, a następnie spraw, by A obudziło B i czekało w pierwszym punkcie przekazania; przy następnym przekazaniu B wykonuje operację odwrotną. Drugi wariant działa jak deterministyczne przełączanie kontekstu i jest używany przez automatyczny eksplorator A-B-A.<sup>[[17]](#references)</sup>

Minimalna kampania polega na skompilowaniu przypadku testowego z czterema hookami (`test_setup`, dwiema funkcjami wątków i `test_end`) jako biblioteki współdzielonej, zebraniu śladu bez ograniczeń, a następnie wyliczeniu kandydatów A-B-A lub dodaniu ręcznych ograniczeń wokół podejrzanych dostępów.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Traktuj timeouty oddzielnie od udanych zmian kolejności: żądana kolejność może być niemożliwa, ponieważ blokada lub zależność związana z inicjalizacją/publikacją uniemożliwia drugiemu kontekstowi dotarcie do punktu wstrzyknięcia. Pamiętaj też o ograniczeniach KASAN: bezpośrednie dostępy do stosu zwykle nie są przechwytywane, chyba że mogą wykraczać poza jego granice, zmienne globalne są pomijane przy domyślnej optymalizacji, a obecne kompilatory nie mogą jednocześnie generować hooków ASAN i TSAN. Prototyp traci bufor KCOV, gdy maszyna gościa ulega awarii, dlatego zachowaj niezależną konsolę/oracle do obsługi awarii.<sup>[[17]](#references)</sup>

W przyszłości, na potrzeby fuzzingu sterowanego współbieżnością, zapisuj podsumowania dostępu do pamięci dla każdego wejścia lub wywołania syscall, łącz operacje, które utworzyłyby punkty komunikacji między kontekstami, a następnie badaj tylko te kombinacje. Migawki VM stabilizują stan globalny i adresy; bez migawek metadane miejsca alokacji mogą posłużyć do abstrakcji obiektów między uruchomieniami. To proponowane rozszerzenie, a nie funkcja obecnych narzędzi userspace MAccConc.<sup>[[17]](#references)</sup>

## Introspekcja harnessu: wcześnie wykrywaj płytkie fuzzery

Gdy kampania utknie, problemem często nie jest mutator, lecz **harness**. Użyj **introspekcji osiągalności/pokrycia**, aby znaleźć funkcje statycznie osiągalne z celu fuzzingu, ale rzadko lub nigdy dynamicznie niepokrywane. Takie funkcje zwykle wskazują na jeden z trzech problemów.<sup>[[12]](#references)</sup>

- Harness wchodzi do celu zbyt późno lub zbyt wcześnie.
- W korpusie seedów brakuje całej rodziny funkcji.
- Cel naprawdę wymaga **drugiego harnessu**, zamiast jednego, nadmiernie rozbudowanego harnessu typu „zrób wszystko”.

Jeśli korzystasz z przepływów pracy w stylu OSS-Fuzz / ClusterFuzz, Fuzz Introspector może porównywać osiągalność statyczną z pokryciem podczas działania i generować raporty na podstawie uruchomienia z limitem czasu lub publicznego korpusu.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Użyj raportu, aby zdecydować, czy dodać nowy harness dla nieprzetestowanej ścieżki parsera, rozszerzyć corpus dla konkretnej funkcji, czy podzielić monolityczny harness na mniejsze punkty wejścia.

## Wybór celów fuzzowania i analiza mutacji w pierwszej kolejności na podstawie grafu

Jeśli masz już wyniki **analizy statycznej**, **ocalałe mutacje z testowania mutacyjnego** i **raporty pokrycia**, nie analizuj ich jako niezależnych list. Najpierw zbuduj **graf wywołań**, oznacz węzły **złożonością cyklomatyczną**, **osiągalnością z punktów wejścia/niezaufanych danych** oraz zewnętrznymi ustaleniami, a następnie zadaj pytania dotyczące grafu.<sup>[[5]](#references)[[6]](#references)</sup>

- Które funkcje o wysokiej złożoności są osiągalne z niezaufanych danych?
- Które ocalałe mutacje znajdują się na ścieżkach od parserów/handlerów do kodu krytycznego dla bezpieczeństwa?
- Które funkcje są architektonicznymi wąskimi gardłami o wyjątkowo dużym **blast radius**?

Zwykle pozwala to znaleźć lepsze cele fuzzowania niż samo kierowanie się „najniższym pokryciem”. Parser/dekoder o **wysokiej złożoności** i potwierdzonej **osiągalności z zewnątrz** jest lepszym kandydatem na harness niż odizolowany wewnętrzny helper ze słabym pokryciem, ale bez ścieżki kontrolowanej przez atakującego.

### Praktyczny proces analizy

1. Zbuduj **graf kodu** na podstawie codebase i wyodrębnij metryki złożoności/gałęzi dla każdej funkcji.
2. Wypisz **punkty wejścia** przyjmujące dane kontrolowane przez atakującego: handlery żądań, dekodery, importery, parsery protokołów, czytniki CLI/plików.
3. Wykonaj zapytania o ścieżki od tych punktów wejścia do kandydatów, aby oddzielić osiągalną powierzchnię ataku od kodu martwego lub dostępnego wyłącznie wewnętrznie.
4. Nadaj priorytet węzłom łączącym:
   - wysoką **złożoność cyklomatyczną**
   - potwierdzoną **osiągalność z niezaufanych danych**
   - duży **blast radius** lub wielu zależnych funkcji
   - dodatkowe dowody, takie jak ustalenia **SARIF**, notatki z audytu lub ocalałe mutacje
5. Najpierw przygotuj ukierunkowane harnesses dla najlepiej ocenionych węzłów, zwłaszcza **parserów/kodeków**, takich jak dekodery hex/Base64/IP/wiadomości.

### Ocalałe mutacje: równoważne czy wymagające działania

Testowanie mutacyjne często generuje zaszumioną listę ocalałych mutacji. Zanim uznasz każdą z nich za lukę w bezpieczeństwie, użyj grafu, aby sprawdzić:

- Czy zmodyfikowana funkcja jest osiągalna z punktu wejścia kontrolowanego przez atakującego?
- Czy wszystkie ścieżki wywołań podlegają silniejszym niezmiennikom niż zmodyfikowany warunek?
- Czy węzeł znajduje się w martwym kodzie, logice służącej wyłącznie formatowaniu, czy w ścieżce arytmetycznej/parsera o dużym wpływie?

Mutacje, które pozostają nieosiągalne lub są strukturalnie ograniczone, są często **równoważnymi mutantami**. Mutacje, które pozostają **osiągalne** i dotyczą **warunków brzegowych**, **ścieżek przepełnienia/przeniesienia** lub **arytmetyki/parsing’u krytycznych dla bezpieczeństwa**, należy uwzględnić w:

- nowych harnessach fuzzingowych
- bezpośrednich testach właściwości/niezmienników
- ukierunkowanych zestawach przypadków brzegowych

### Powiąż zewnętrzne ustalenia z grafem

Jeśli twój pipeline SAST eksportuje **SARIF**, odwzoruj ustalenia na węzły grafu na podstawie **pliku i zakresu wierszy**, a następnie użyj grafu, aby określić szerszy wpływ.<sup>[[6]](#references)</sup>

- oblicz **blast radius** wskazanej funkcji
- sprawdź, czy ustalenie znajduje się na którejkolwiek ścieżce od punktu wejścia
- grupuj pobliskie ustalenia, które zbiegają się w tym samym wąskim gardle

Jest to przydatne przy podejmowaniu decyzji, czy poświęcić czas na fuzzing konkretnej funkcji: węzeł, który jest **osiągalny**, **złożony** i ma już ustalenia **SAST**, często jest lepszym celem niż węzeł jedynie złożony, bez ścieżki dostępnej dla atakującego.

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

Ważna jest metodologia oparta na przecięciu: **złożoność x ekspozycja x wpływ**. Użyj wykresu, aby wybrać cele fuzzingu o najwyższej oczekiwanej wartości z punktu widzenia bezpieczeństwa, a następnie wykorzystaj mutacje, które przetrwały, aby określić, które granice i niezmienniki musi testować Twój harness.<sup>[[5]](#references)</sup>

## Fuzzing w Go z gosentry: mocniejszy silnik, typowane dane wejściowe i kontrole różnicowe

Jeśli cel w Go ma już natywny harness `testing.F`, praktyczną ścieżką ulepszenia jest uruchomienie tego samego harnessu z [gosentry](https://github.com/trailofbits/gosentry) — rozwidleniem toolchaina Go, które zachowuje `go test -fuzz`, ale zamienia backend na **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Jest to przydatne, gdy natywny fuzzer Go zatrzymuje się na **trudnych porównaniach**, **typowanych danych wejściowych** lub **formatach wymagających intensywnego parsowania**. Metodyka pozostaje taka sama:

- Nadal używaj `f.Add(...)` do seedów i `f.Fuzz(...)` jako callbacka.
- Użyj ponownie tego samego harnessa, ale uruchom go za pomocą pliku binarnego `go` z gosentry zamiast standardowego toolchaina.
- Traktuj kampanię jak zwykły przebieg z guided coverage, ale z harmonogramowaniem i mutacjami LibAFL oraz lepszymi wbudowanymi detektorami.

### Zamiana cichych błędów w ustalenia fuzzingu

Powracającym problemem podczas ocen bezpieczeństwa Go jest to, że niebezpieczne zachowanie często domyślnie **nie powoduje crasha**. Dzięki gosentry można zamienić kilka klas „złych, ale cichych” stanów w ustalenia.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` sprawia, że wybrane ścieżki logowania/błędów zachowują się jak crashe (przydatne w przypadku ścieżek w stylu `log.Fatal`, które w przeciwnym razie tylko logują i działają dalej).
- `--catch-races=true` ponownie odtwarza nowo wykryte wpisy kolejki z detektorem race Go.
- `--catch-leaks=true` ponownie odtwarza nowe wpisy kolejki z `goleak` i zatrzymuje działanie w przypadku wycieków goroutine.
- Obsługa zawieszeń LibAFL pozwala zachować **nieskończone pętle / bardzo wolne dane wejściowe** jako ustalenia fuzzingu, zamiast pomijać je jako timeouty.
- Domyślnie wbudowane sprawdzanie przepełnień arytmetycznych oraz opcjonalne sprawdzanie obcięć za pomocą instrumentacji w stylu go-panikint.

Jest to szczególnie przydatne w przypadku celów, w których wpływ na bezpieczeństwo wynika z **błędu parsera bez paniki**, **błędu współbieżności** lub **zawieszenia powodującego wyłącznie DoS**, a nie z uszkodzenia pamięci.

### Fuzzing uwzględniający strukturę dla typowanych API Go

Natywny fuzzing Go oczekuje głównie wartości skalarnych, takich jak `[]byte`, `string` i liczby. Jeśli testowany kod przyjmuje typowane obiekty, gosentry może bezpośrednio fuzzować **wartości złożone** (struktury, slice'y, tablice, wskaźniki), jednocześnie mutując znajdujące się pod nimi bajty.<sup>[[7]](#references)[[8]](#references)</sup>

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

Użyj tego, gdy tworzenie sztucznego formatu wire wyłącznie na potrzeby fuzzingu ukrywałoby błędy logiki za kodem parsującym działającym tylko w harnessie. W kampaniach differential lub opartych na gramatyce pozostaw wejście harnessu jako pojedyncze `[]byte` lub `string` i parsuj je wewnątrz callbacku.

### Fuzzing oparty na gramatyce dla parserów i danych wejściowych protokołów

W przypadku parserów, formatów i języków wejściowych gosentry może uruchamiać **fuzzing gramatyczny Nautilus** z wykorzystaniem LibAFL. Gramatyka to tablica reguł produkcji w formacie JSON, a harness powinien zwykle przyjmować pojedynczy argument typu `[]byte` lub `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Uwagi dotyczące metodologii:

- Używaj trybu gramatycznego, gdy mutacje na poziomie bajtów najczęściej kończą się na wczesnych kontrolach składni.
- Ogranicz gramatykę do **podzbioru języka/protokołu istotnego z punktu widzenia bezpieczeństwa**, zamiast modelować całą specyfikację.
- Używaj dużych wartości granicznych w terminalach/nieterminalach, aby testować skrajne przypadki związane z liczbami całkowitymi, długością i maszyną stanów.
- Tryb gramatyczny zapewnia zgodność wejść z gramatyką, ale cel nadal otrzymuje **bajty/ciągi znaków**, więc parsowanie i kontrole semantyczne nadal odbywają się w testowanym kodzie.

### Differential fuzzing: porównuj implementacje, a nie tylko awarie

Skutecznym podejściem w ekosystemach Go jest **grammar-based differential fuzzing**: generowanie poprawnych, ustrukturyzowanych danych wejściowych i przekazywanie ich do dwóch parserów, klientów lub silników przejść stanów.<sup>[[7]](#references)[[8]](#references)</sup>

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
- niezgodność w akceptowaniu/odrzucaniu danych wejściowych
- różne drzewa parsowania lub zdekodowane obiekty
- rozbieżne przejścia stanu, nonce, salda lub korzenie stanu

To praktyczny sposób na wykrywanie **rozbieżności konsensusu**, **niejednoznaczności parsera** i **rozbieżności między specyfikacją a implementacją**, które często umykają podczas fuzzingu ukierunkowanego wyłącznie na awarie.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Ponowne użycie corpus kampanii do raportowania pokrycia

Po zakończeniu kampanii odtwórz zapisany corpus kolejki, aby wygenerować raport pokrycia Go bez ręcznego eksportowania osobnego corpus.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Uruchom polecenie z tego samego pakietu i z tym samym celem `-fuzz`, aby gosentry odnalazł właściwy stan kampanii w cache.



## References

- [1] [Fuzzing z gramatyką mutacyjną](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing w AFL++ — szczegółowe omówienie](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet pięć lat później: fuzzing protokołów sterowany pokryciem](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark zamienia kod w grafy](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Fuzzing w Go nie obejmował połowy dostępnych narzędzi. Rozwidleniem toolchaina naprawiliśmy ten problem.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: szybki greybox fuzzer dla protokołów sieciowych ze stanem, wykorzystujący migawki](https://arxiv.org/abs/2202.03643)
- [10] [Brak gramatyki? Żaden problem: fuzzing jądra Linuxa bez opisów wywołań systemowych](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: wydajny fuzzing z adaptacyjnymi i modyfikowalnymi migawkami](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentacja LLVM w AFL++: pokrycie ścieżek i wywołujących](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predykcyjny, wrażliwy na kontekst fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Android Offensive Security — fuzzing Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer LKL dla Android Binder — dokumentacja kompilacji i seedów regresyjnych](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: badanie warunków wyścigu w jądrze Linuxa z kontrolowanym przeplataniem dostępów do pamięci](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: pokrycie kodu na potrzeby fuzzingu](https://docs.kernel.org/dev-tools/kcov.html)
{{#include ../banners/hacktricks-training.md}}
