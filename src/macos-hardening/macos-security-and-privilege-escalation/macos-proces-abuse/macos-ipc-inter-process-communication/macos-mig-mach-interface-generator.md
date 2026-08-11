# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

MIG wurde entwickelt, um die Erstellung von **Mach-IPC**-Code zu **vereinfachen**. Es **generiert im Wesentlichen den erforderlichen Code**, damit Server und Client mit einer bestimmten Definition kommunizieren können. Auch wenn der generierte Code unschön ist, muss ein Entwickler ihn lediglich importieren, und sein Code wird wesentlich einfacher als zuvor.<sup>[[1]](#references)</sup>

Die Definition wird in der Interface Definition Language (IDL) mit der Erweiterung `.defs` angegeben.

Diese Definitionen bestehen aus 5 Abschnitten:

- **Subsystem declaration**: Das Schlüsselwort subsystem wird verwendet, um den **Namen** und die **id** anzugeben. Es ist auch möglich, sie als **`KernelServer`** zu kennzeichnen, wenn der Server im Kernel ausgeführt werden soll.<sup>[[4]](#references)</sup>
- **Inclusions and imports**: MIG verwendet den C-Präprozessor und kann daher Imports verwenden. Außerdem ist es möglich, `uimport` und `simport` für generierten User- oder Server-Code zu verwenden.
- **Type declarations**: Es ist möglich, Datentypen zu definieren, obwohl normalerweise `mach_types.defs` und `std_types.defs` importiert werden. Für benutzerdefinierte Typen kann folgende Syntax verwendet werden:
- \[i`n/out]tran`: Funktion, die von einer eingehenden oder für eine ausgehende Nachricht übersetzt werden muss
- `c[user/server]type`: Zuordnung zu einem anderen C-Typ.
- `destructor`: Ruft diese Funktion auf, wenn der Typ freigegeben wird.
- **Operations**: Dies sind die Definitionen der RPC-Methoden. Es gibt 5 verschiedene Typen:
- `routine`: Erwartet eine Antwort
- `simpleroutine`: Erwartet keine Antwort
- `procedure`: Erwartet eine Antwort
- `simpleprocedure`: Erwartet keine Antwort
- `function`: Erwartet eine Antwort

### Beispiel

Erstelle eine Definitionsdatei, in diesem Fall mit einer sehr einfachen Funktion:
```cpp:myipc.defs
subsystem myipc 500; // Arbitrary name and id

userprefix USERPREF;        // Prefix for created functions in the client
serverprefix SERVERPREF;    // Prefix for created functions in the server

#include <mach/mach_types.defs>
#include <mach/std_types.defs>

simpleroutine Subtract(
server_port :  mach_port_t;
n1          :  uint32_t;
n2          :  uint32_t);
```
Beachte, dass das erste **Argument der zu bindende Port ist** und MIG den **Antwort-Port automatisch verwaltet** (außer beim Aufruf von `mig_get_reply_port()` im Client-Code). Außerdem sind die **IDs der Operationen** **fortlaufend**, beginnend mit der angegebenen Subsystem-ID (wenn also eine Operation veraltet ist, wird sie gelöscht und `skip` verwendet, um ihre ID weiterhin zu nutzen).

Verwende nun MIG, um den Server- und Client-Code zu generieren, die miteinander kommunizieren können, um die Funktion Subtract aufzurufen:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Mehrere neue Dateien werden im aktuellen Verzeichnis erstellt.

> [!TIP]
> Ein komplexeres Beispiel finden Sie auf Ihrem System mit: `mdfind mach_port.defs`\
> Sie können es aus demselben Ordner wie die Datei kompilieren mit: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

In den Dateien **`myipcServer.c`** und **`myipcServer.h`** finden Sie die Deklaration und Definition der Struktur **`SERVERPREFmyipc_subsystem`**, die im Grunde die aufzurufende Funktion anhand der empfangenen Nachrichten-ID definiert (wir haben eine Startnummer von 500 angegeben):

{{#tabs}}
{{#tab name="myipcServer.c"}}
```c
/* Description of this subsystem, for use in direct RPC */
const struct SERVERPREFmyipc_subsystem SERVERPREFmyipc_subsystem = {
myipc_server_routine,
500, // start ID
501, // end ID
(mach_msg_size_t)sizeof(union __ReplyUnion__SERVERPREFmyipc_subsystem),
(vm_address_t)0,
{
{ (mig_impl_routine_t) 0,
// Function to call
(mig_stub_routine_t) _XSubtract, 3, 0, (routine_arg_descriptor_t)0, (mach_msg_size_t)sizeof(__Reply__Subtract_t)},
}
};
```
{{#endtab}}

{{#tab name="myipcServer.h"}}
```c
/* Description of this subsystem, for use in direct RPC */
extern const struct SERVERPREFmyipc_subsystem {
mig_server_routine_t	server;	/* Server routine */
mach_msg_id_t	start;	/* Min routine number */
mach_msg_id_t	end;	/* Max routine number + 1 */
unsigned int	maxsize;	/* Max msg size */
vm_address_t	reserved;	/* Reserved */
struct routine_descriptor	/* Array of routine descriptors */
routine[1];
} SERVERPREFmyipc_subsystem;
```
{{#endtab}}
{{#endtabs}}

Basierend auf der vorherigen Struktur erhält die Funktion **`myipc_server_routine`** die **Nachrichten-ID** und gibt die passende aufzurufende Funktion zurück:
```c
mig_external mig_routine_t myipc_server_routine
(mach_msg_header_t *InHeadP)
{
int msgh_id;

msgh_id = InHeadP->msgh_id - 500;

if ((msgh_id > 0) || (msgh_id < 0))
return 0;

return SERVERPREFmyipc_subsystem.routine[msgh_id].stub_routine;
}
```
In diesem Beispiel haben wir in den Definitionen nur eine Funktion definiert. Wenn wir jedoch mehrere Funktionen definiert hätten, wären sie im Array **`SERVERPREFmyipc_subsystem`** enthalten gewesen, wobei die erste Funktion der ID **500**, die zweite der ID **501** usw. zugewiesen worden wäre.

Wenn von der Funktion erwartet wurde, eine **reply** zu senden, wäre auch die Funktion `mig_internal kern_return_t __MIG_check__Reply__<name>` vorhanden.

Tatsächlich lässt sich diese Beziehung in der Struktur **`subsystem_to_name_map_myipc`** aus **`myipcServer.h`** (**`subsystem*to_name_map*\***`** in anderen Dateien) identifizieren:
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Schließlich ist eine weitere wichtige Funktion, damit der Server funktioniert, **`myipc_server`**. Diese ruft tatsächlich die **Funktion** auf, die zur empfangenen ID gehört:<sup>[[3]](#references)</sup>

<pre class="language-c"><code class="lang-c">mig_external boolean_t myipc_server
(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP)
{
/*
* typedef struct {
* 	mach_msg_header_t Head;
* 	NDR_record_t NDR;
* 	kern_return_t RetCode;
* } mig_reply_error_t;
*/

mig_routine_t routine;

OutHeadP->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REPLY(InHeadP->msgh_bits), 0);
OutHeadP->msgh_remote_port = InHeadP->msgh_reply_port;
/* Minimal size: routine() will update it if different */
OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
OutHeadP->msgh_local_port = MACH_PORT_NULL;
OutHeadP->msgh_id = InHeadP->msgh_id + 100;
OutHeadP->msgh_reserved = 0;

if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id < 500) ||
<strong>	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
</strong>		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
return FALSE;
}
<strong>	(*routine) (InHeadP, OutHeadP);
</strong>	return TRUE;
}
</code></pre>

Überprüfe die zuvor hervorgehobenen Zeilen, die anhand der ID auf die aufzurufende Funktion zugreifen.

Der folgende Code erstellt einen einfachen **Server** und **Client**, wobei der Client die Funktionen Subtract des Servers aufrufen kann:

{{#tabs}}
{{#tab name="myipc_server.c"}}
```c
// gcc myipc_server.c myipcServer.c -o myipc_server

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcServer.h"

kern_return_t SERVERPREFSubtract(mach_port_t server_port, uint32_t n1, uint32_t n2)
{
printf("Received: %d - %d = %d\n", n1, n2, n1 - n2);
return KERN_SUCCESS;
}

int main() {

mach_port_t port;
kern_return_t kr;

// Register the mach service
kr = bootstrap_check_in(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_check_in() failed with code 0x%x\n", kr);
return 1;
}

// myipc_server is the function that handles incoming messages (check previous exlpanation)
mach_msg_server(myipc_server, sizeof(union __RequestUnion__SERVERPREFmyipc_subsystem), port, MACH_MSG_TIMEOUT_NONE);
}
```
{{#endtab}}

{{#tab name="myipc_client.c"}}
```c
// gcc myipc_client.c myipcUser.c -o myipc_client

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcUser.h"

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("Port right name %d\n", port);
USERPREFSubtract(port, 40, 2);
}
```
{{#endtab}}
{{#endtabs}}

### The NDR_record

Der NDR_record wird von `libsystem_kernel.dylib` exportiert. Dabei handelt es sich um eine Struktur, die es MIG ermöglicht, **Daten so zu transformieren, dass sie systemunabhängig sind**, da MIG für die Kommunikation zwischen verschiedenen Systemen (und nicht nur innerhalb derselben Maschine) entwickelt wurde.

Dies ist interessant, weil das Auffinden von `_NDR_record` in einer Binärdatei als Abhängigkeit (`jtool2 -S <binary> | grep NDR` oder `nm`) bedeutet, dass die Binärdatei ein MIG-Client oder -Server ist.

Außerdem befindet sich bei **MIG-Servern** die Dispatch-Tabelle in `__DATA.__const` (im macOS-Kernel in `__CONST.__constdata` und in anderen \*OS-Kernels in `__DATA_CONST.__const`). Diese kann mit **`jtool2`** ausgelesen werden.

Und **MIG-Clients** verwenden `__NDR_record`, um ihn mit `__mach_msg` an die Server zu senden.

## Binäranalyse

### jtool

Da viele Binärdateien inzwischen MIG verwenden, um Mach-Ports bereitzustellen, ist es interessant zu wissen, wie man **erkennt, dass MIG verwendet wurde**, und welche **Funktionen MIG bei jeder Message-ID ausführt**.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) kann MIG-Informationen aus einer Mach-O-Binärdatei analysieren, die Message-ID angeben und die auszuführende Funktion identifizieren:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Darüber hinaus sind MIG functions Wrapper um die tatsächlich aufgerufene Funktion. Wenn Sie daher die Disassembly abrufen und nach `BL` suchen, können Sie möglicherweise die tatsächlich aufgerufene Funktion finden:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Zuvor wurde erwähnt, dass die Funktion, die sich um das **Aufrufen der korrekten Funktion abhängig von der empfangenen Message-ID** kümmert, `myipc_server` war. Allerdings verfügt man normalerweise nicht über die Symbole des Binaries (keine Funktionsnamen). Daher ist es interessant zu **überprüfen, wie sie dekompiliert aussieht**, da sie immer sehr ähnlich sein wird (der Code dieser Funktion ist unabhängig von den exponierten Funktionen):

{{#tabs}}
{{#tab name="myipc_server decompiled 1"}}

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Initial instructions to find the proper function ponters
*(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) <= 0x1f4 && *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Call to sign_extend_64 that can help to identifyf this function
// This stores in rax the pointer to the call that needs to be called
// Check the used of the address 0x100004040 (functions addresses array)
// 0x1f4 = 500 (the starting ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// If - else, the if returns false, while the else call the correct function and returns true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Calculated address that calls the proper function with 2 arguments
<strong>                    (var_20)(var_10, var_18);
</strong>                    var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
rax = var_4;
return rax;
}
</code></pre>

{{#endtab}}

{{#tab name="myipc_server decompiled 2"}}
Dies ist dieselbe Funktion, die mit einer anderen kostenlosen Hopper-Version dekompiliert wurde:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Initial instructions to find the proper function ponters
*(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f | 0x0;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 > 0x0) {
if (CPU_FLAGS & G) {
r8 = 0x1;
}
}
if ((r8 & 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 < 0x0) {
if (CPU_FLAGS & L) {
r8 = 0x1;
}
}
if ((r8 & 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
// 0x1f4 = 500 (the starting ID)
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
r8 = *(r8 + 0x8);
var_20 = r8;
r8 = r8 - 0x0;
if (r8 != 0x0) {
if (CPU_FLAGS & NE) {
r8 = 0x1;
}
}
// Same if else as in the previous version
// Check the used of the address 0x100004040 (functions addresses array)
<strong>                    if ((r8 & 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Call to the calculated address where the function should be
<strong>                            (var_20)(var_10, var_18);
</strong>                            var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
r0 = var_4;
return r0;
}

</code></pre>

{{#endtab}}
{{#endtabs}}

Wenn du tatsächlich zur Funktion **`0x100004000`** gehst, findest du dort das Array aus **`routine_descriptor`**-Strukturen. Das erste Element der Struktur ist die **Adresse**, an der die **Funktion** implementiert ist, und die **Struktur ist 0x28 Bytes groß**. Daher kann man alle 0x28 Bytes (beginnend bei Byte 0) 8 Bytes auslesen, die dann die **Adresse der aufzurufenden Funktion** enthalten:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Diese Daten können [**mithilfe dieses Hopper-Skripts extrahiert werden**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

### Debug

Der von MIG generierte Code ruft außerdem `kernel_debug` auf, um bei Eintritt und Austritt Logs über die Vorgänge zu erzeugen. Diese können mit **`trace`** oder **`kdv`** untersucht werden: `kdv all | grep MIG`

## References

- [1] [bootstrap_cmds — `migcom.tproj` (der MIG-Compiler selbst)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (Beispiel für eine MIG-Subsystemdefinition)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h` (Layout des Mach-Message-Headers)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs` (MIG-Definition des Task-Subsystems)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
{{#include ../../../../banners/hacktricks-training.md}}
