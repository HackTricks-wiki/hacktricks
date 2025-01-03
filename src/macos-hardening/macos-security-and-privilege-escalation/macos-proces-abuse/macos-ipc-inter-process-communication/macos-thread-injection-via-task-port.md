# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Przejęcie wątku

Początkowo funkcja **`task_threads()`** jest wywoływana na porcie zadania, aby uzyskać listę wątków z zdalnego zadania. Wątek jest wybierany do przejęcia. To podejście różni się od konwencjonalnych metod wstrzykiwania kodu, ponieważ tworzenie nowego zdalnego wątku jest zabronione z powodu nowej mitigacji blokującej `thread_create_running()`.

Aby kontrolować wątek, wywoływana jest **`thread_suspend()`**, zatrzymując jego wykonanie.

Jedynymi dozwolonymi operacjami na zdalnym wątku są **zatrzymywanie** i **uruchamianie** go, **pobieranie** i **modyfikowanie** wartości jego rejestrów. Zdalne wywołania funkcji są inicjowane przez ustawienie rejestrów `x0` do `x7` na **argumenty**, konfigurowanie **`pc`** w celu skierowania do pożądanej funkcji i aktywację wątku. Zapewnienie, że wątek nie ulegnie awarii po zwrocie, wymaga wykrycia zwrotu.

Jedna ze strategii polega na **rejestrowaniu obsługi wyjątków** dla zdalnego wątku za pomocą `thread_set_exception_ports()`, ustawiając rejestr `lr` na nieprawidłowy adres przed wywołaniem funkcji. To wywołuje wyjątek po wykonaniu funkcji, wysyłając wiadomość do portu wyjątków, co umożliwia inspekcję stanu wątku w celu odzyskania wartości zwrotnej. Alternatywnie, jak przyjęto z exploitacji triple_fetch Iana Beera, `lr` jest ustawiane na nieskończoną pętlę. Rejestry wątku są następnie ciągle monitorowane, aż **`pc` wskaże na tę instrukcję**.

## 2. Porty Mach do komunikacji

Kolejny etap polega na ustanowieniu portów Mach w celu ułatwienia komunikacji z zdalnym wątkiem. Porty te są niezbędne do transferu dowolnych praw do wysyłania i odbierania między zadaniami.

Dla komunikacji dwukierunkowej tworzone są dwa prawa odbioru Mach: jedno w lokalnym, a drugie w zdalnym zadaniu. Następnie prawo wysyłania dla każdego portu jest przekazywane do odpowiedniego zadania, co umożliwia wymianę wiadomości.

Skupiając się na lokalnym porcie, prawo odbioru jest posiadane przez lokalne zadanie. Port jest tworzony za pomocą `mach_port_allocate()`. Wyzwanie polega na przekazaniu prawa wysyłania do tego portu do zdalnego zadania.

Strategia polega na wykorzystaniu `thread_set_special_port()`, aby umieścić prawo wysyłania do lokalnego portu w `THREAD_KERNEL_PORT` zdalnego wątku. Następnie zdalny wątek jest instruowany do wywołania `mach_thread_self()`, aby odzyskać prawo wysyłania.

Dla zdalnego portu proces jest zasadniczo odwrócony. Zdalny wątek jest kierowany do wygenerowania portu Mach za pomocą `mach_reply_port()` (ponieważ `mach_port_allocate()` jest nieodpowiednie z powodu swojego mechanizmu zwrotu). Po utworzeniu portu wywoływana jest `mach_port_insert_right()` w zdalnym wątku, aby ustanowić prawo wysyłania. To prawo jest następnie przechowywane w jądrze za pomocą `thread_set_special_port()`. W lokalnym zadaniu używa się `thread_get_special_port()` na zdalnym wątku, aby uzyskać prawo wysyłania do nowo przydzielonego portu Mach w zdalnym zadaniu.

Zakończenie tych kroków skutkuje ustanowieniem portów Mach, kładąc podwaliny pod komunikację dwukierunkową.

## 3. Podstawowe prymitywy odczytu/zapisu pamięci

W tej sekcji skupiamy się na wykorzystaniu prymitywu wykonania do ustanowienia podstawowych prymitywów odczytu i zapisu pamięci. Te początkowe kroki są kluczowe dla uzyskania większej kontroli nad zdalnym procesem, chociaż prymitywy na tym etapie nie będą miały wielu zastosowań. Wkrótce zostaną one ulepszone do bardziej zaawansowanych wersji.

### Odczyt i zapis pamięci przy użyciu prymitywu wykonania

Celem jest wykonanie odczytu i zapisu pamięci przy użyciu określonych funkcji. Do odczytu pamięci używane są funkcje przypominające następującą strukturę:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
A do zapisywania w pamięci używane są funkcje o podobnej strukturze:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Te funkcje odpowiadają podanym instrukcjom asemblera:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identyfikacja Odpowiednich Funkcji

Skanowanie powszechnych bibliotek ujawniło odpowiednich kandydatów do tych operacji:

1. **Odczyt Pamięci:**
Funkcja `property_getName()` z [biblioteki czasu wykonania Objective-C](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) została zidentyfikowana jako odpowiednia funkcja do odczytu pamięci. Funkcja jest opisana poniżej:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Ta funkcja działa efektywnie jak `read_func`, zwracając pierwsze pole `objc_property_t`.

2. **Pisanie do pamięci:**
Znalezienie gotowej funkcji do pisania do pamięci jest bardziej wymagające. Jednak funkcja `_xpc_int64_set_value()` z libxpc jest odpowiednim kandydatem z następującą dekompilacją:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Aby wykonać zapis 64-bitowy pod określonym adresem, zdalne wywołanie jest zbudowane w następujący sposób:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Z tymi ustalonymi prymitywami, scena jest gotowa do stworzenia pamięci współdzielonej, co stanowi znaczący postęp w kontrolowaniu zdalnego procesu.

## 4. Ustawienie Pamięci Współdzielonej

Celem jest ustanowienie pamięci współdzielonej między lokalnymi a zdalnymi zadaniami, co upraszcza transfer danych i ułatwia wywoływanie funkcji z wieloma argumentami. Podejście polega na wykorzystaniu `libxpc` i jego typu obiektu `OS_xpc_shmem`, który oparty jest na wpisach pamięci Mach.

### Przegląd Procesu:

1. **Alokacja Pamięci**:

- Przydziel pamięć do współdzielenia za pomocą `mach_vm_allocate()`.
- Użyj `xpc_shmem_create()`, aby utworzyć obiekt `OS_xpc_shmem` dla przydzielonego regionu pamięci. Ta funkcja zarządza tworzeniem wpisu pamięci Mach i przechowuje prawo wysyłania Mach w przesunięciu `0x18` obiektu `OS_xpc_shmem`.

2. **Tworzenie Pamięci Współdzielonej w Zdalnym Procesie**:

- Przydziel pamięć dla obiektu `OS_xpc_shmem` w zdalnym procesie za pomocą zdalnego wywołania `malloc()`.
- Skopiuj zawartość lokalnego obiektu `OS_xpc_shmem` do zdalnego procesu. Jednak ta początkowa kopia będzie miała niepoprawne nazwy wpisów pamięci Mach w przesunięciu `0x18`.

3. **Korekta Wpisu Pamięci Mach**:

- Wykorzystaj metodę `thread_set_special_port()`, aby wstawić prawo wysyłania dla wpisu pamięci Mach do zdalnego zadania.
- Skoryguj pole wpisu pamięci Mach w przesunięciu `0x18`, nadpisując je nazwą zdalnego wpisu pamięci.

4. **Finalizacja Ustawienia Pamięci Współdzielonej**:
- Zweryfikuj zdalny obiekt `OS_xpc_shmem`.
- Ustanów mapowanie pamięci współdzielonej za pomocą zdalnego wywołania `xpc_shmem_remote()`.

Postępując zgodnie z tymi krokami, pamięć współdzielona między lokalnymi a zdalnymi zadaniami zostanie efektywnie skonfigurowana, co umożliwi proste transfery danych i wykonanie funkcji wymagających wielu argumentów.

## Dodatkowe Fragmenty Kodu

Do alokacji pamięci i tworzenia obiektu pamięci współdzielonej:
```c
mach_vm_allocate();
xpc_shmem_create();
```
Aby utworzyć i skorygować obiekt pamięci współdzielonej w zdalnym procesie:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
Pamiętaj, aby poprawnie obsługiwać szczegóły portów Mach i nazw wpisów pamięci, aby zapewnić prawidłowe działanie konfiguracji pamięci współdzielonej.

## 5. Osiąganie Pełnej Kontroli

Po pomyślnym ustanowieniu pamięci współdzielonej i uzyskaniu możliwości dowolnego wykonywania, zasadniczo zyskaliśmy pełną kontrolę nad docelowym procesem. Kluczowe funkcjonalności umożliwiające tę kontrolę to:

1. **Dowolne Operacje na Pamięci**:

- Wykonuj dowolne odczyty pamięci, wywołując `memcpy()`, aby skopiować dane z regionu współdzielonego.
- Wykonuj dowolne zapisy pamięci, używając `memcpy()`, aby przenieść dane do regionu współdzielonego.

2. **Obsługa Wywołań Funkcji z Wieloma Argumentami**:

- Dla funkcji wymagających więcej niż 8 argumentów, umieść dodatkowe argumenty na stosie zgodnie z konwencją wywołania.

3. **Transfer Portów Mach**:

- Przenieś porty Mach między zadaniami za pomocą wiadomości Mach przez wcześniej ustanowione porty.

4. **Transfer Deskryptorów Plików**:
- Przenieś deskryptory plików między procesami, używając fileports, techniki podkreślonej przez Iana Beera w `triple_fetch`.

Ta kompleksowa kontrola jest zawarta w bibliotece [threadexec](https://github.com/bazad/threadexec), która zapewnia szczegółową implementację i przyjazne API do interakcji z procesem ofiary.

## Ważne Rozważania:

- Zapewnij prawidłowe użycie `memcpy()` do operacji odczytu/zapisu pamięci, aby utrzymać stabilność systemu i integralność danych.
- Podczas transferu portów Mach lub deskryptorów plików, przestrzegaj odpowiednich protokołów i odpowiedzialnie zarządzaj zasobami, aby zapobiec wyciekom lub niezamierzonym dostępom.

Przestrzegając tych wytycznych i wykorzystując bibliotekę `threadexec`, można efektywnie zarządzać i interagować z procesami na szczegółowym poziomie, osiągając pełną kontrolę nad docelowym procesem.

## Odniesienia

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

{{#include ../../../../banners/hacktricks-training.md}}
