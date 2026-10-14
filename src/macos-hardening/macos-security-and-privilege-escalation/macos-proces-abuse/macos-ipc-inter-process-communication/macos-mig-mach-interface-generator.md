# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

MIG wurde entwickelt, um die Erstellung von Mach-IPC-Code zu **vereinfachen**. Es **generiert im Wesentlichen den benötigten Code**, damit Server und Client anhand einer vorgegebenen Definition kommunizieren können. Auch wenn der generierte Code unschön ist, muss ein Entwickler ihn lediglich importieren; sein eigener Code wird dadurch wesentlich einfacher als zuvor.<sup>[[1]](#references)</sup>

Die Definition wird in der Interface Definition Language (IDL) mit der Erweiterung `.defs` angegeben.

Diese Definitionen bestehen aus 5 Abschnitten:

- **Subsystem declaration**: Das Schlüsselwort subsystem wird verwendet, um den **Namen** und die **ID** anzugeben. Außerdem kann das Subsystem als **`KernelServer`** markiert werden, wenn der Server im Kernel ausgeführt werden soll.<sup>[[4]](#references)</sup>
- **Inclusions and imports**: MIG verwendet den C-Präprozessor und kann daher Importe verwenden. Außerdem können `uimport` und `simport` für generierten User- oder Server-Code verwendet werden.
- **Type declarations**: Es können Datentypen definiert werden, üblicherweise werden jedoch `mach_types.defs` und `std_types.defs` importiert. Für benutzerdefinierte Typen kann folgende Syntax verwendet werden:
  - \[i`n/out]tran`: Funktion, die eine eingehende oder ausgehende Nachricht übersetzen muss
  - `c[user/server]type`: Zuordnung zu einem anderen C-Typ.
  - `destructor`: Diese Funktion aufrufen, wenn der Typ freigegeben wird.
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

Beachten Sie, dass das erste **Argument der Port ist, an den gebunden werden soll**, und MIG **den Reply-Port automatisch verwaltet** (außer wenn im Client-Code `mig_get_reply_port()` aufgerufen wird). Außerdem sind die **IDs der Operationen** fortlaufend und beginnen bei der angegebenen Subsystem-ID (wenn also eine Operation veraltet ist, wird sie gelöscht und `skip` verwendet, damit ihre ID weiterhin belegt bleibt).

Verwenden Sie nun MIG, um den Server- und Client-Code zu generieren, mit dem sie miteinander kommunizieren und die Funktion Subtract aufrufen können:

```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```

Im aktuellen Verzeichnis werden mehrere neue Dateien erstellt.

> [!TIP]
> Ein komplexeres Beispiel findest du auf deinem System mit: `mdfind mach_port.defs`\
> Und du kannst es im selben Ordner wie die Datei kompilieren mit: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

In den Dateien **`myipcServer.c`** und **`myipcServer.h`** findest du die Deklaration und Definition der Struct **`SERVERPREFmyipc_subsystem`**, die im Wesentlichen anhand der empfangenen Nachrichten-ID festlegt, welche Funktion aufgerufen wird (wir haben eine Startnummer von 500 angegeben):

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

Basierend auf dem vorherigen struct erhält die Funktion **`myipc_server_routine`** die **Message-ID** und gibt die aufzurufende Funktion zurück:

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

In diesem Beispiel haben wir in den Definitionen nur eine Funktion definiert. Hätten wir jedoch weitere Funktionen definiert, wären sie im Array **`SERVERPREFmyipc_subsystem`** enthalten gewesen. Die erste wäre der ID **500**, die zweite der ID **501** zugewiesen worden ...

Falls die Funktion eine **reply** zurückgeben sollte, wäre auch die Funktion `mig_internal kern_return_t __MIG_check__Reply__<name>` vorhanden.

Tatsächlich lässt sich diese Zuordnung in der Struct **`subsystem_to_name_map_myipc`** aus **`myipcServer.h`** (**`subsystem*to_name_map*\***` in anderen Dateien) erkennen:

```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
    { "Subtract", 500 }
#endif
```

Schließlich wird eine weitere wichtige Funktion benötigt, damit der Server funktioniert: **`myipc_server`**. Sie **ruft tatsächlich die Funktion auf**, die der empfangenen ID zugeordnet ist:<sup>[[3]](#references)</sup>

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

Sieh dir die zuvor hervorgehobenen Zeilen an, in denen anhand der ID auf die aufzurufende Funktion zugegriffen wird.

Der folgende Code erstellt einen einfachen **Server** und **Client**, über den der Client die Funktionen des Servers aufrufen kann, die Subtract ausführen:

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

### Der NDR_record

Der NDR_record wird von `libsystem_kernel.dylib` exportiert. Es handelt sich um eine Struktur, mit der MIG **Daten so umwandeln kann, dass sie systemunabhängig sind**. MIG war dafür gedacht, zwischen verschiedenen Systemen verwendet zu werden (und nicht nur auf demselben Rechner).

Das ist interessant, denn wenn `_NDR_record` in einer Binärdatei als Abhängigkeit gefunden wird (`jtool2 -S <binary> | grep NDR` oder `nm`), bedeutet das, dass die Binärdatei ein MIG-Client oder -Server ist.

Außerdem haben **MIG-Server** ihre Dispatch-Tabelle in `__DATA.__const` (oder in `__CONST.__constdata` im macOS-Kernel und `__DATA_CONST.__const` in anderen \*OS-Kernels). Diese kann mit **`jtool2`** ausgegeben werden.

Und **MIG-Clients** verwenden den `__NDR_record`, um Nachrichten mit `__mach_msg` an die Server zu senden.

## Binäranalyse

### jtool

Da inzwischen viele Binärdateien MIG verwenden, um Mach-Ports bereitzustellen, ist es interessant zu wissen, wie man **erkennt, dass MIG verwendet wurde**, und welche **Funktionen MIG bei jeder Nachrichten-ID ausführt**.

[**jtool2 / disarm**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#disarm-old-jtool2) kann MIG-Informationen aus einer Mach-O-Binärdatei auslesen, darunter die Nachrichten-ID und die Funktion, die ausgeführt werden soll:

```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```

Außerdem sind MIG-Funktionen Wrapper um die tatsächlich aufgerufene Funktion. Daher können Sie möglicherweise die tatsächlich aufgerufene Funktion finden, indem Sie die Disassemblierung abrufen und nach `BL` suchen:

```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```

### Assembler

Zuvor wurde erwähnt, dass die Funktion, die **abhängig von der empfangenen Nachrichten-ID die richtige Funktion aufruft**, `myipc_server` ist. Normalerweise stehen dir jedoch keine Symbole der Binärdatei zur Verfügung (also keine Funktionsnamen). Daher ist es interessant, **zu prüfen, wie die Funktion dekompiliert aussieht**, da sie immer sehr ähnlich ist (der Code dieser Funktion ist unabhängig von den bereitgestellten Funktionen):

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
Dieselbe Funktion, dekompiliert mit einer anderen kostenlosen Hopper-Version:

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

Wenn du tatsächlich zur Funktion **`0x100004000`** gehst, findest du das Array mit den **`routine_descriptor`**-Strukturen. Das erste Element der Struktur ist die **Adresse**, an der die **Funktion** implementiert ist. Die **Struktur ist 0x28 Bytes groß**. Daher kannst du alle 0x28 Bytes (beginnend bei Byte 0) 8 Bytes auslesen; diese enthalten die **Adresse der aufzurufenden Funktion**:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Diese Daten lassen sich [**mit diesem Hopper-Skript**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py) extrahieren.

Einen Workflow zum Erzeugen von Seeds und Fuzzing zustandsbehafteter MIG-Nachrichtensequenzen findest du unter [Stateful Mach IPC fuzzing](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#stateful-mach-ipc-fuzzing).

### Debugging

Der von MIG generierte Code ruft außerdem `kernel_debug` auf, um Protokolle zu Vorgängen beim Eintritt und beim Verlassen zu erstellen. Diese lassen sich mit **`trace`** oder **`kdv`** untersuchen: `kdv all | grep MIG`



## References

- [1] [bootstrap_cmds — `migcom.tproj` (der MIG-Compiler selbst)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (Beispiel einer MIG-Subsystemdefinition)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h` (Layout des Mach-Nachrichtenheaders)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs` (MIG-Definition des Task-Subsystems)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
{{#include ../../../../banners/hacktricks-training.md}}
