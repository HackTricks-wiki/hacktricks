# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Przejęcie wątku

Początkowo wywoływana jest funkcja `task_threads()` na porcie zadania, aby uzyskać listę wątków z zdalnego zadania. Wątek jest wybierany do przejęcia. To podejście różni się od konwencjonalnych metod wstrzykiwania kodu, ponieważ tworzenie nowego zdalnego wątku jest zabronione z powodu zabezpieczenia, które blokuje `thread_create_running()`.

Aby kontrolować wątek, wywoływana jest funkcja `thread_suspend()`, zatrzymując jego wykonanie.

Jedynymi dozwolonymi operacjami na zdalnym wątku są **zatrzymywanie** i **uruchamianie** go oraz **pobieranie**/**modyfikowanie** wartości jego rejestrów. Zdalne wywołania funkcji są inicjowane przez ustawienie rejestrów `x0` do `x7` na **argumenty**, konfigurowanie `pc` w celu wskazania żądanej funkcji i wznowienie wątku. Zapewnienie, że wątek nie ulegnie awarii po zwrocie, wymaga wykrycia zwrotu.

Jedna ze strategii polega na zarejestrowaniu **obsługi wyjątków** dla zdalnego wątku za pomocą `thread_set_exception_ports()`, ustawiając rejestr `lr` na nieprawidłowy adres przed wywołaniem funkcji. To wywołuje wyjątek po wykonaniu funkcji, wysyłając wiadomość do portu wyjątków, co umożliwia inspekcję stanu wątku w celu odzyskania wartości zwrotnej. Alternatywnie, jak przyjęto z exploitacji *triple_fetch* Iana Beera, `lr` jest ustawiane na nieskończoną pętlę; rejestry wątku są następnie ciągle monitorowane, aż `pc` wskaże na tę instrukcję.

## 2. Porty Mach do komunikacji

Kolejny etap polega na ustanowieniu portów Mach w celu ułatwienia komunikacji z zdalnym wątkiem. Porty te są niezbędne do transferu dowolnych praw do wysyłania/odbierania między zadaniami.

Dla komunikacji dwukierunkowej tworzone są dwa prawa odbioru Mach: jedno w lokalnym, a drugie w zdalnym zadaniu. Następnie prawo wysyłania dla każdego portu jest przekazywane do odpowiedniego zadania, co umożliwia wymianę wiadomości.

Skupiając się na lokalnym porcie, prawo odbioru jest posiadane przez lokalne zadanie. Port jest tworzony za pomocą `mach_port_allocate()`. Wyzwanie polega na przekazaniu prawa wysyłania do tego portu do zdalnego zadania.

Strategia polega na wykorzystaniu `thread_set_special_port()`, aby umieścić prawo wysyłania do lokalnego portu w `THREAD_KERNEL_PORT` zdalnego wątku. Następnie zdalny wątek jest instruowany do wywołania `mach_thread_self()`, aby uzyskać prawo wysyłania.

Dla zdalnego portu proces jest zasadniczo odwrócony. Zdalny wątek jest kierowany do wygenerowania portu Mach za pomocą `mach_reply_port()` (ponieważ `mach_port_allocate()` jest nieodpowiednie z powodu swojego mechanizmu zwrotu). Po utworzeniu portu wywoływana jest `mach_port_insert_right()` w zdalnym wątku, aby ustanowić prawo wysyłania. To prawo jest następnie przechowywane w jądrze za pomocą `thread_set_special_port()`. W lokalnym zadaniu używa się `thread_get_special_port()` na zdalnym wątku, aby uzyskać prawo wysyłania do nowo przydzielonego portu Mach w zdalnym zadaniu.

Zakończenie tych kroków skutkuje ustanowieniem portów Mach, kładąc podwaliny pod komunikację dwukierunkową.

## 3. Podstawowe prymitywy odczytu/zapisu pamięci

W tej sekcji skupiamy się na wykorzystaniu prymitywu wykonania do ustanowienia podstawowych prymitywów odczytu/zapisu pamięci. Te początkowe kroki są kluczowe dla uzyskania większej kontroli nad zdalnym procesem, chociaż prymitywy na tym etapie nie będą miały wielu zastosowań. Wkrótce zostaną ulepszone do bardziej zaawansowanych wersji.

### Odczyt i zapis pamięci przy użyciu prymitywu wykonania

Celem jest wykonanie odczytu i zapisu pamięci przy użyciu określonych funkcji. Dla **odczytu pamięci**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Dla **zapisu pamięci**:
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
### Identyfikacja odpowiednich funkcji

Skanowanie powszechnych bibliotek ujawniło odpowiednich kandydatów do tych operacji:

1. **Odczyt pamięci — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Pisanie pamięci — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Aby wykonać zapis 64-bitowy pod dowolnym adresem:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Z tymi ustalonymi prymitywami, scena jest gotowa do stworzenia pamięci współdzielonej, co stanowi znaczący postęp w kontrolowaniu zdalnego procesu.

## 4. Ustawienie pamięci współdzielonej

Celem jest ustanowienie pamięci współdzielonej między lokalnymi a zdalnymi zadaniami, co upraszcza transfer danych i ułatwia wywoływanie funkcji z wieloma argumentami. Podejście to wykorzystuje `libxpc` i jego typ obiektu `OS_xpc_shmem`, który oparty jest na wpisach pamięci Mach.

### Przegląd procesu

1. **Alokacja pamięci**
* Przydziel pamięć do współdzielenia za pomocą `mach_vm_allocate()`.
* Użyj `xpc_shmem_create()`, aby utworzyć obiekt `OS_xpc_shmem` dla przydzielonego obszaru.
2. **Tworzenie pamięci współdzielonej w zdalnym procesie**
* Przydziel pamięć dla obiektu `OS_xpc_shmem` w zdalnym procesie (`remote_malloc`).
* Skopiuj lokalny obiekt szablonu; wymagana jest nadal korekta wbudowanego prawa do wysyłania Mach w offsetcie `0x18`.
3. **Korekta wpisu pamięci Mach**
* Wstaw prawo do wysyłania za pomocą `thread_set_special_port()` i nadpisz pole `0x18` nazwą zdalnego wpisu.
4. **Finalizacja**
* Zweryfikuj zdalny obiekt i zmapuj go za pomocą zdalnego wywołania `xpc_shmem_remote()`.

## 5. Osiągnięcie pełnej kontroli

Gdy dostępna jest dowolna egzekucja i kanał zwrotny pamięci współdzielonej, efektywnie posiadasz docelowy proces:

* **Dowolny odczyt/zapis pamięci** — użyj `memcpy()` między lokalnymi a współdzielonymi obszarami.
* **Wywołania funkcji z > 8 argumentami** — umieść dodatkowe argumenty na stosie zgodnie z konwencją wywołań arm64.
* **Transfer portu Mach** — przekazuj prawa w wiadomościach Mach za pośrednictwem ustalonych portów.
* **Transfer deskryptora pliku** — wykorzystaj fileports (zobacz *triple_fetch*).

Wszystko to jest opakowane w bibliotece [`threadexec`](https://github.com/bazad/threadexec) dla łatwego ponownego użycia.

---

## 6. Niuanse Apple Silicon (arm64e)

Na urządzeniach Apple Silicon (arm64e) **Kody uwierzytelniania wskaźników (PAC)** chronią wszystkie adresy powrotu i wiele wskaźników funkcji. Techniki przejmowania wątków, które *ponownie wykorzystują istniejący kod*, nadal działają, ponieważ oryginalne wartości w `lr`/`pc` już mają ważne podpisy PAC. Problemy pojawiają się, gdy próbujesz skoczyć do pamięci kontrolowanej przez atakującego:

1. Przydziel pamięć wykonywalną wewnątrz celu (zdalne `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Skopiuj swój ładunek.
3. W *zdalnym* procesie podpisz wskaźnik:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Ustaw `pc = ptr` w przechwyconym stanie wątku.

Alternatywnie, pozostań zgodny z PAC, łącząc istniejące gadżety/funkcje (tradycyjny ROP).

## 7. Wykrywanie i wzmacnianie z EndpointSecurity

Framework **EndpointSecurity (ES)** ujawnia zdarzenia jądra, które pozwalają obrońcom obserwować lub blokować próby wstrzykiwania wątków:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – wyzwalane, gdy proces żąda portu innego zadania (np. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – emitowane za każdym razem, gdy wątek jest tworzony w *innym* zadaniu.
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (dodane w macOS 14 Sonoma) – wskazuje na manipulację rejestrami istniejącego wątku.

Minimalny klient Swift, który drukuje zdarzenia zdalnych wątków:
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
Zapytanie z **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Rozważania dotyczące wzmocnionego czasu działania

Dystrybucja aplikacji **bez** uprawnienia `com.apple.security.get-task-allow` uniemożliwia atakującym niebędącym rootem uzyskanie jej portu zadania. Ochrona integralności systemu (SIP) nadal blokuje dostęp do wielu binarnych plików Apple, ale oprogramowanie firm trzecich musi wyraźnie zrezygnować z tego.

## 8. Ostatnie publiczne narzędzia (2023-2025)

| Narzędzie | Rok | Uwagi |
|-----------|-----|-------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Kompaktowy PoC, który demonstruje przejmowanie wątków z uwzględnieniem PAC na Ventura/Sonoma |
| `remote_thread_es` | 2024 | Pomocnik EndpointSecurity używany przez kilku dostawców EDR do wyświetlania zdarzeń `REMOTE_THREAD_CREATE` |

> Czytanie kodu źródłowego tych projektów jest przydatne do zrozumienia zmian w API wprowadzonych w macOS 13/14 oraz do utrzymania zgodności między Intel ↔ Apple Silicon.

## Odniesienia

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [https://github.com/rodionovd/task_vaccine](https://github.com/rodionovd/task_vaccine)
- [https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
