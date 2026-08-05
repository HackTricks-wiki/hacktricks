# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Początkowo funkcja `task_threads()` jest wywoływana na porcie task, aby pobrać listę threadów ze zdalnego taska. Następnie wybierany jest thread do przejęcia. To podejście różni się od konwencjonalnych metod code injection, ponieważ tworzenie nowego zdalnego threada jest zabronione przez mechanizm ochronny blokujący `thread_create_running()`.<sup>[[1]](#references)</sup>

Aby przejąć kontrolę nad threadem, wywoływana jest funkcja `thread_suspend()`, która zatrzymuje jego wykonywanie.<sup>[[1]](#references)</sup>

Jedyne operacje dozwolone na zdalnym threadzie obejmują jego **zatrzymywanie** i **uruchamianie** oraz **pobieranie**/**modyfikowanie** wartości jego rejestrów. Zdalne wywołania funkcji są inicjowane przez ustawienie rejestrów `x0` do `x7` na **argumenty**, skonfigurowanie `pc` tak, aby wskazywał żądaną funkcję, a następnie wznowienie threada. Aby upewnić się, że thread nie ulegnie awarii po powrocie z funkcji, konieczne jest wykrycie tego powrotu.<sup>[[1]](#references)</sup>

Jedna ze strategii polega na zarejestrowaniu **exception handlera** dla zdalnego threada za pomocą `thread_set_exception_ports()` i ustawieniu rejestru `lr` na nieprawidłowy adres przed wywołaniem funkcji. Powoduje to wystąpienie wyjątku po zakończeniu wykonywania funkcji i wysłanie komunikatu do exception portu, co umożliwia sprawdzenie stanu threada i odzyskanie wartości zwracanej. Alternatywnie, zgodnie z rozwiązaniem zastosowanym w exploicie *triple_fetch* autorstwa Iana Beera, `lr` jest ustawiany tak, aby wykonywać nieskończoną pętlę; następnie rejestry threada są stale monitorowane, dopóki `pc` nie będzie wskazywać tej instrukcji.<sup>[[1]](#references)</sup>

## 2. Mach ports for communication

Kolejny etap obejmuje ustanowienie Mach ports w celu umożliwienia komunikacji ze zdalnym threadem. Porty te służą do transferowania dowolnych send/receive rights pomiędzy taskami.<sup>[[1]](#references)</sup>

W celu zapewnienia komunikacji dwukierunkowej tworzone są dwa Mach receive rights: jeden w lokalnym, a drugi w zdalnym tasku. Następnie send right dla każdego portu jest przekazywany do odpowiadającego mu taska, co umożliwia wymianę komunikatów.<sup>[[1]](#references)</sup>

W przypadku lokalnego portu receive right jest przechowywany przez lokalny task. Port jest tworzony za pomocą `mach_port_allocate()`. Problem polega na przekazaniu send right do tego portu do zdalnego taska.<sup>[[1]](#references)</sup>

Jedna ze strategii polega na wykorzystaniu `thread_set_special_port()` w celu umieszczenia send right do lokalnego portu w `THREAD_KERNEL_PORT` zdalnego threada. Następnie zdalny thread otrzymuje polecenie wywołania `mach_thread_self()`, aby pobrać send right.<sup>[[1]](#references)</sup>

W przypadku zdalnego portu proces przebiega zasadniczo odwrotnie. Zdalny thread otrzymuje polecenie utworzenia Mach portu za pomocą `mach_reply_port()` (`mach_port_allocate()` nie jest odpowiednie ze względu na sposób zwracania wyniku). Po utworzeniu portu zdalny thread wywołuje `mach_port_insert_right()`, aby ustanowić send right. Następnie to uprawnienie jest przechowywane w kernelu za pomocą `thread_set_special_port()`. Z powrotem w lokalnym tasku funkcja `thread_get_special_port()` jest używana na zdalnym threadzie w celu uzyskania send right do nowo przydzielonego Mach portu w zdalnym tasku.<sup>[[1]](#references)</sup>

Zakończenie tych kroków prowadzi do ustanowienia Mach ports, tworząc podstawę do komunikacji dwukierunkowej.<sup>[[1]](#references)</sup>

## 3. Basic Memory Read/Write Primitives

W tej sekcji skupiono się na wykorzystaniu execute primitive w celu ustanowienia podstawowych memory read/write primitives. Te początkowe kroki mają kluczowe znaczenie dla uzyskania większej kontroli nad zdalnym procesem, choć primitives na tym etapie nie będą miały wielu zastosowań. Wkrótce zostaną zaktualizowane do bardziej zaawansowanych wersji.<sup>[[1]](#references)</sup>

### Memory reading and writing using the execute primitive

Celem jest odczytywanie i zapisywanie pamięci za pomocą określonych funkcji. Aby **odczytać pamięć**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
W przypadku **zapisu do pamięci**:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Te funkcje odpowiadają następującemu kodowi asemblera:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identyfikowanie odpowiednich funkcji

Analiza popularnych bibliotek ujawniła odpowiednich kandydatów do tych operacji:<sup>[[1]](#references)</sup>

1. **Odczyt pamięci — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Zapisywanie do pamięci — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Aby wykonać 64-bitowy zapis pod dowolnym adresem:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Po ustanowieniu tych prymitywów można przystąpić do tworzenia pamięci współdzielonej, co stanowi znaczący postęp w kontrolowaniu zdalnego procesu.<sup>[[1]](#references)</sup>

## 4. Konfiguracja pamięci współdzielonej

Celem jest ustanowienie pamięci współdzielonej między zadaniami lokalnymi i zdalnymi, co upraszcza transfer danych i ułatwia wywoływanie funkcji z wieloma argumentami. Podejście wykorzystuje `libxpc` oraz typ obiektu `OS_xpc_shmem`, który jest oparty na wpisach pamięci Mach.<sup>[[1]](#references)</sup>

### Przebieg procesu

1. **Alokacja pamięci**
* Alokuj pamięć do współdzielenia za pomocą `mach_vm_allocate()`.
* Użyj `xpc_shmem_create()`, aby utworzyć obiekt `OS_xpc_shmem` dla zaalokowanego obszaru.
2. **Tworzenie pamięci współdzielonej w zdalnym procesie**
* Alokuj pamięć dla obiektu `OS_xpc_shmem` w zdalnym procesie (`remote_malloc`).
* Skopiuj lokalny obiekt szablonowy; nadal wymagane jest poprawienie osadzonego prawa wysyłania Mach pod offsetem `0x18`.
3. **Korygowanie wpisu pamięci Mach**
* Wstaw prawo wysyłania za pomocą `thread_set_special_port()` i nadpisz pole `0x18` nazwą wpisu zdalnego.
4. **Finalizacja**
* Zweryfikuj zdalny obiekt i zmapuj go za pomocą zdalnego wywołania `xpc_shmem_remote()`.

## 5. Uzyskanie pełnej kontroli

Po uzyskaniu arbitrary execution i kanału zwrotnego opartego na pamięci współdzielonej można skutecznie przejąć docelowy proces:<sup>[[1]](#references)</sup>

* **Arbitrary memory R/W** — użyj `memcpy()` między regionami lokalnym i współdzielonym.
* **Wywoływanie funkcji z > 8 argumentami** — umieść dodatkowe argumenty na stosie zgodnie z konwencją wywołań arm64.
* **Transfer portów Mach** — przekazuj prawa w komunikatach Mach za pośrednictwem ustanowionych portów.
* **Transfer deskryptorów plików** — wykorzystaj fileports (zobacz *triple_fetch*).

Całość jest opakowana w bibliotekę [`threadexec`](https://github.com/bazad/threadexec), co ułatwia jej ponowne wykorzystanie.

---

## 6. Specyfika Apple Silicon (arm64e)

Na urządzeniach Apple Silicon (arm64e) **Pointer Authentication Codes (PAC)** chronią wszystkie adresy powrotu oraz wiele wskaźników funkcji. Techniki thread-hijacking, które *ponownie wykorzystują istniejący kod*, nadal działają, ponieważ oryginalne wartości w `lr`/`pc` zawierają już prawidłowe sygnatury PAC. Problemy pojawiają się, gdy próbujesz wykonać skok do pamięci kontrolowanej przez attackera:

1. Alokuj pamięć wykonywalną wewnątrz celu (`mach_vm_allocate` + `mprotect(PROT_EXEC)` po stronie zdalnej).
2. Skopiuj payload.
3. W zdalnym procesie podpisz wskaźnik:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Ustaw `pc = ptr` w stanie przejętego wątku.

Alternatywnie zachowaj zgodność z PAC, łańcuchując istniejące gadgets/functions (tradycyjne ROP).

## 7. Wykrywanie i hardening za pomocą EndpointSecurity

Framework **EndpointSecurity (ES)** udostępnia zdarzenia jądra, które pozwalają obrońcom monitorować lub blokować próby thread injection:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – wywoływane, gdy proces żąda portu task innego procesu (np. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – emitowane za każdym razem, gdy w innym task zostaje utworzony thread.<sup>[[3]](#references)</sup>
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

Dystrybuowanie aplikacji **bez** entitlementu `com.apple.security.get-task-allow` uniemożliwia atakującym bez uprawnień root uzyskanie jej task-port. System Integrity Protection (SIP) nadal blokuje dostęp do wielu binariów Apple, ale oprogramowanie firm trzecich musi jawnie z tego zrezygnować.

## 8. Recent Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Kompaktowy PoC demonstrujący przejmowanie wątków z uwzględnieniem PAC w Ventura/Sonoma |
| `remote_thread_es` | 2024 | Helper EndpointSecurity używany przez kilku dostawców EDR do wykrywania zdarzeń `REMOTE_THREAD_CREATE` |

> Czytanie kodu źródłowego tych projektów pomaga zrozumieć zmiany w API wprowadzone w macOS 13/14 oraz zachować kompatybilność między Intel a Apple Silicon.

## References

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
