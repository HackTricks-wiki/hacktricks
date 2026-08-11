# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Przejęcie wątku

Początkowo funkcja `task_threads()` jest wywoływana na porcie task, aby pobrać listę wątków ze zdalnego task. Następnie wybierany jest wątek do przejęcia. To podejście różni się od konwencjonalnych metod code injection, ponieważ tworzenie nowego zdalnego wątku jest zabronione ze względu na mechanizm ochronny blokujący `thread_create_running()`.<sup>[[1]](#references)</sup>

Aby przejąć kontrolę nad wątkiem, wywoływana jest funkcja `thread_suspend()`, która zatrzymuje jego wykonywanie.<sup>[[1]](#references)</sup>

Jedyne operacje dozwolone na zdalnym wątku obejmują jego **zatrzymywanie** i **uruchamianie** oraz **pobieranie**/**modyfikowanie** wartości jego rejestrów. Zdalne wywołania funkcji są inicjowane przez ustawienie rejestrów `x0` do `x7` na **argumenty**, skonfigurowanie `pc` tak, aby wskazywał żądaną funkcję, a następnie wznowienie wątku. Aby zapobiec awarii wątku po powrocie, konieczne jest wykrycie momentu powrotu.<sup>[[1]](#references)</sup>

Jedna ze strategii polega na zarejestrowaniu **exception handlera** dla zdalnego wątku za pomocą `thread_set_exception_ports()` oraz ustawieniu rejestru `lr` na nieprawidłowy adres przed wywołaniem funkcji. Powoduje to wystąpienie wyjątku po wykonaniu funkcji i wysłanie komunikatu do portu wyjątku, co umożliwia sprawdzenie stanu wątku i odzyskanie wartości zwróconej. Alternatywnie, zgodnie z rozwiązaniem zastosowanym w exploicie *triple_fetch* autorstwa Iana Beera, `lr` jest ustawiany tak, aby wykonywać nieskończoną pętlę; następnie rejestry wątku są nieustannie monitorowane, aż `pc` wskaże tę instrukcję.<sup>[[1]](#references)</sup>

## 2. Mach ports do komunikacji

Kolejny etap obejmuje utworzenie Mach ports w celu umożliwienia komunikacji ze zdalnym wątkiem. Porty te służą do przesyłania dowolnych praw do wysyłania/odbierania między task.<sup>[[1]](#references)</sup>

W celu zapewnienia komunikacji dwukierunkowej tworzone są dwa prawa do odbierania Mach: jedno w lokalnym, a drugie w zdalnym task. Następnie prawo do wysyłania dla każdego portu jest przekazywane do odpowiadającego mu task, umożliwiając wymianę komunikatów.<sup>[[1]](#references)</sup>

W przypadku portu lokalnego prawo do odbierania jest posiadane przez lokalny task. Port jest tworzony za pomocą `mach_port_allocate()`. Trudność polega na przekazaniu prawa do wysyłania na ten port do zdalnego task.<sup>[[1]](#references)</sup>

Jedna ze strategii polega na wykorzystaniu `thread_set_special_port()` do umieszczenia prawa do wysyłania na lokalny port w `THREAD_KERNEL_PORT` zdalnego wątku. Następnie zdalny wątek otrzymuje polecenie wywołania `mach_thread_self()` w celu pobrania prawa do wysyłania.<sup>[[1]](#references)</sup>

W przypadku portu zdalnego proces jest zasadniczo odwrócony. Zdalny wątek otrzymuje polecenie utworzenia Mach port za pomocą `mach_reply_port()` (ponieważ `mach_port_allocate()` nie jest odpowiednia ze względu na sposób zwracania wyniku). Po utworzeniu portu w zdalnym wątku wywoływana jest funkcja `mach_port_insert_right()` w celu ustanowienia prawa do wysyłania. Następnie prawo to jest przechowywane w kernelu za pomocą `thread_set_special_port()`. W lokalnym task funkcja `thread_get_special_port()` jest używana na zdalnym wątku w celu uzyskania prawa do wysyłania na nowo przydzielony Mach port w zdalnym task.<sup>[[1]](#references)</sup>

Zakończenie tych kroków prowadzi do ustanowienia Mach ports, tworząc podstawę do komunikacji dwukierunkowej.<sup>[[1]](#references)</sup>

## 3. Podstawowe prymitywy odczytu/zapisu pamięci

W tej sekcji skupiono się na wykorzystaniu execute primitive do ustanowienia podstawowych prymitywów odczytu/zapisu pamięci. Te początkowe kroki mają kluczowe znaczenie dla uzyskania większej kontroli nad zdalnym procesem, choć prymitywy na tym etapie nie będą miały wielu zastosowań. Wkrótce zostaną one ulepszone do bardziej zaawansowanych wersji.<sup>[[1]](#references)</sup>

### Odczytywanie i zapisywanie pamięci za pomocą execute primitive

Celem jest odczytywanie i zapisywanie pamięci przy użyciu określonych funkcji. W przypadku **odczytu pamięci**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Dla **pamięci zapisu**:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Funkcje te odpowiadają następującemu kodowi asemblera:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identyfikowanie odpowiednich funkcji

Skanowanie common libraries ujawniło odpowiednich kandydatów do tych operacji:<sup>[[1]](#references)</sup>

1. **Odczytywanie pamięci — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Zapisywanie pamięci — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Aby wykonać 64-bitowy zapis pod dowolnym adresem:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Po ustanowieniu tych prymitywów można przystąpić do tworzenia pamięci współdzielonej, co stanowi istotny krok naprzód w kontrolowaniu zdalnego procesu.<sup>[[1]](#references)</sup>

## 4. Konfiguracja pamięci współdzielonej

Celem jest ustanowienie pamięci współdzielonej między zadaniami lokalnym i zdalnym, co upraszcza transfer danych oraz ułatwia wywoływanie funkcji z wieloma argumentami. Podejście wykorzystuje `libxpc` oraz typ obiektu `OS_xpc_shmem`, oparty na wpisach pamięci Mach.<sup>[[1]](#references)</sup>

### Przebieg procesu

1. **Alokacja pamięci**
* Alokuj pamięć do współdzielenia za pomocą `mach_vm_allocate()`.
* Użyj `xpc_shmem_create()`, aby utworzyć obiekt `OS_xpc_shmem` dla zaalokowanego obszaru.
2. **Tworzenie pamięci współdzielonej w zdalnym procesie**
* Alokuj pamięć dla obiektu `OS_xpc_shmem` w zdalnym procesie (`remote_malloc`).
* Skopiuj lokalny obiekt szablonowy; nadal konieczne jest poprawienie osadzonego prawa wysyłania Mach pod offsetem `0x18`.
3. **Korygowanie wpisu pamięci Mach**
* Wstaw prawo wysyłania za pomocą `thread_set_special_port()` i nadpisz pole `0x18` nazwą zdalnego wpisu.
4. **Finalizacja**
* Zweryfikuj zdalny obiekt i zmapuj go za pomocą zdalnego wywołania `xpc_shmem_remote()`.

## 5. Uzyskanie pełnej kontroli

Gdy dostępne są arbitralne wykonywanie kodu oraz kanał zwrotny oparty na pamięci współdzielonej, możesz skutecznie przejąć docelowy proces:<sup>[[1]](#references)</sup>

* **Arbitralny odczyt/zapis pamięci** — użyj `memcpy()` między obszarami lokalnym i współdzielonym.
* **Wywołania funkcji z > 8 argumentami** — umieść dodatkowe argumenty na stosie zgodnie z konwencją wywołań arm64.
* **Transfer portów Mach** — przekazuj prawa w komunikatach Mach za pośrednictwem ustanowionych portów.
* **Transfer deskryptorów plików** — wykorzystaj fileports (zobacz *triple_fetch*).

Całość jest opakowana w bibliotekę [`threadexec`](https://github.com/bazad/threadexec), co ułatwia ponowne wykorzystanie.

---

## 6. Niuanse Apple Silicon (arm64e)

Na urządzeniach Apple Silicon (arm64e) **Pointer Authentication Codes (PAC)** chronią wszystkie adresy powrotu oraz wiele wskaźników funkcji. Techniki przejmowania wątków, które *ponownie wykorzystują istniejący kod*, nadal działają, ponieważ oryginalne wartości w `lr`/`pc` zawierają już prawidłowe sygnatury PAC. Problemy pojawiają się przy próbie wykonania skoku do pamięci kontrolowanej przez atakującego:

1. Alokuj pamięć wykonywalną wewnątrz celu (zdalne `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Skopiuj swój payload.
3. W *zdalnym* procesie podpisz wskaźnik:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Ustaw `pc = ptr` w stanie przejętego thread.

Alternatywnie zachowaj zgodność z PAC, łącząc istniejące gadgets/functions (tradycyjny ROP).

## 7. Wykrywanie i hardening z EndpointSecurity

Framework **EndpointSecurity (ES)** udostępnia zdarzenia kernela, które pozwalają obrońcom obserwować lub blokować próby thread injection:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – generowane, gdy proces żąda portu task innego procesu (np. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – emitowane za każdym razem, gdy thread jest tworzony w *innym* task.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (dodane w macOS 14 Sonoma) – wskazuje na manipulację rejestrami istniejącego thread.

Minimalny klient Swift, który wyświetla zdarzenia remote-thread:
```swift
import EndpointSecurity

let client = try! ESClient(subscriptions: [.notifyRemoteThreadCreate]) {
(_, msg) in
if let evt = msg.remoteThreadCreate {
print("[ALERT] remote thread in pid \(evt.target.pid) by pid \(evt.thread.pid)")
}
}
RunLoop.main.run()
```
Odpytywanie za pomocą **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Uwagi dotyczące hardened runtime

Dystrybucja aplikacji **bez** entitlementu `com.apple.security.get-task-allow` uniemożliwia atakującym bez uprawnień root uzyskanie jej task-port. System Integrity Protection (SIP) nadal blokuje dostęp do wielu binariów Apple, ale oprogramowanie firm trzecich musi jawnie z tego zrezygnować.

## 8. Najnowsze publiczne narzędzia (2023-2025)

| Narzędzie | Rok | Uwagi |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Kompaktowy PoC demonstrujący przejmowanie wątków z obsługą PAC w Ventura/Sonoma<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | Helper EndpointSecurity używany przez kilku dostawców EDR do wykrywania zdarzeń `REMOTE_THREAD_CREATE` |

> Czytanie kodu źródłowego tych projektów pomaga zrozumieć zmiany API wprowadzone w macOS 13/14 oraz zachować kompatybilność między Intel a Apple Silicon.

## References

- [1] [Omijanie ograniczeń dotyczących binariów platformy za pomocą task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Dokumentacja Apple dla deweloperów](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)
{{#include ../../../../banners/hacktricks-training.md}}
