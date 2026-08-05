# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Informations de base

MacOS Sandbox (initialement appelé Seatbelt) **limite les applications** exécutées dans le sandbox aux **actions autorisées spécifiées dans le profil Sandbox** avec lequel l'application s'exécute. Cela contribue à garantir que **l'application n'accédera qu'aux ressources attendues**.

Toute application possédant l'**entitlement** **`com.apple.security.app-sandbox`** sera exécutée dans le sandbox. Les **binaires Apple** sont généralement exécutés dans un Sandbox, et toutes les applications de l'**App Store possèdent cet entitlement**. Plusieurs applications seront donc exécutées dans le sandbox.<sup>[[4]](#references)</sup>

Afin de contrôler ce qu'un processus peut ou ne peut pas faire, le **Sandbox dispose de hooks** dans presque toutes les opérations qu'un processus peut tenter (y compris la plupart des syscalls), à l'aide de **MACF**. Cependant, s**elon** les **entitlements** de l'application, le Sandbox peut être plus permissif envers le processus.

Voici quelques composants importants du Sandbox :

- L'**extension du kernel** `/System/Library/Extensions/Sandbox.kext`
- Le **framework privé** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- Un **daemon** exécuté dans le userland `/usr/libexec/sandboxd`
- Les **containers** `~/Library/Containers`

### Containers

Chaque application sandboxée possède son propre container dans `~/Library/Containers/{CFBundleIdentifier}` :
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
Dans chaque dossier d’identifiant de bundle, vous trouverez le **plist** et le **répertoire Data** de l’App, avec une structure qui reproduit celle du dossier Home :
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
> [!CAUTION]
> Notez que même si les liens symboliques sont présents pour « escape » du Sandbox et accéder à d’autres dossiers, l’App doit tout de même **avoir les permissions** nécessaires pour y accéder. Ces permissions se trouvent dans le **`.plist`**, dans `RedirectablePaths`.

Le **`SandboxProfileData`** correspond au profil Sandbox compilé sous forme de CFData encodé en B64.
```bash
# Get container config
## You need FDA to access the file, not even just root can read it
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
> [!WARNING]
> Tout ce qui est créé/modifié par une application Sandbox recevra l’**attribut de quarantaine**. Cela empêchera un espace Sandbox de déclencher Gatekeeper si l’application Sandbox tente d’exécuter quelque chose avec **`open`**.

## Profils Sandbox

Les profils Sandbox sont des fichiers de configuration qui indiquent ce qui sera **autorisé/interdit** dans ce **Sandbox**. Ils utilisent le **Sandbox Profile Language (SBPL)**, qui s’appuie sur le langage de programmation [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>).

Voici un exemple :
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
> [!TIP]
> Consultez cette [**recherche**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **pour vérifier davantage d’actions qui pourraient être autorisées ou refusées.**<sup>[[5]](#references)</sup>
>
> Notez que dans la version compilée d’un profile, le nom des opérations est remplacé par leurs entrées dans un tableau connu de la dylib et du kext, ce qui rend la version compilée plus courte et plus difficile à lire.

D’importants **services système** s’exécutent également dans leur propre **sandbox** personnalisée, comme le service `mdnsresponder`. Vous pouvez consulter ces **sandbox profiles** personnalisés dans :

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- D’autres sandbox profiles peuvent être consultés sur [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- Dans iOS, le platform profile se trouve dans le `.kext` sandbox, à l’intérieur de `_platform_profile_data` dans le binaire.

Les applications de l’**App Store** utilisent le **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. Vous pouvez vérifier dans ce profile comment des entitlements tels que **`com.apple.security.network.server`** permettent à un processus d’utiliser le réseau.

Ensuite, certains **services daemon Apple** utilisent différents profiles situés dans `/System/Library/Sandbox/Profiles/*.sb` ou `/usr/share/sandbox/*.sb`. Ces sandboxes sont appliquées dans la fonction principale appelant l’API `sandbox_init_XXX`.<sup>[[3]](#references)</sup>

**SIP** est un sandbox profile appelé platform_profile dans `/System/Library/Sandbox/rootless.conf`.

### Exemples de Sandbox Profiles

Pour démarrer une application avec un **sandbox profile spécifique**, vous pouvez utiliser :
```bash
sandbox-exec -f example.sb /Path/To/The/Application
sandbox-exec -n no-internet ping 8.8.8.8
```
{{#tabs}}
{{#tab name="touch"}}
```scheme:touch.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```

```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```

```scheme:touch2.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```

```scheme:touch3.sb
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{{#endtab}}
{{#endtabs}}

> [!TIP]
> Notez que les **software** **authored by Apple** qui s’exécutent sous **Windows** ne disposent pas de **security precautions** supplémentaires, comme l’**application sandboxing**.

Exemples de bypass :

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (ils peuvent écrire des fichiers en dehors du Sandbox dont le nom commence par `~$`).<sup>[[7]](#references)</sup>

### Traçage du Sandbox

#### Via un profil

Il est possible de tracer tous les checks effectués par le Sandbox chaque fois qu’une action est vérifiée. Pour cela, créez simplement le profil suivant :
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
Et exécutez ensuite simplement quelque chose en utilisant ce profil :
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
Dans `/tmp/trace.out`, vous pourrez voir chaque vérification de la Sandbox effectuée à chaque appel (donc beaucoup de doublons).

Il est également possible de tracer la Sandbox à l'aide du paramètre **`-t`** : `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Via API

La fonction `sandbox_set_trace_path` exportée par `libsystem_sandbox.dylib` permet de spécifier un nom de fichier de trace dans lequel les vérifications de la Sandbox seront écrites.\
Il est également possible de faire quelque chose de similaire en appelant `sandbox_vtrace_enable()` puis en récupérant les logs d'erreur depuis le buffer avec `sandbox_vtrace_report()`.

### Inspection de la Sandbox

`libsandbox.dylib` exporte une fonction appelée sandbox_inspect_pid qui fournit une liste de l'état de la Sandbox d'un processus (y compris les extensions). Cependant, seuls les binaires de la plateforme peuvent utiliser cette fonction.

### Profils Sandbox macOS et iOS

macOS stocke les profils Sandbox système à deux emplacements : **/usr/share/sandbox/** et **/System/Library/Sandbox/Profiles**.

Et si une application tierce possède l'entitlement _**com.apple.security.app-sandbox**_, le système applique le profil **/System/Library/Sandbox/Profiles/application.sb** à ce processus.

Dans iOS, le profil par défaut s'appelle **container** et nous ne disposons pas de sa représentation textuelle SBPL. En mémoire, cette Sandbox est représentée sous la forme d'un arbre binaire Allow/Deny pour chacune des permissions de la Sandbox.

### SBPL personnalisé dans les apps de l'App Store

Il serait possible pour les entreprises de faire fonctionner leurs apps **avec des profils Sandbox personnalisés** (au lieu du profil par défaut). Elles doivent utiliser l'entitlement **`com.apple.security.temporary-exception.sbpl`**, qui doit être autorisé par Apple.

Il est possible de vérifier la définition de cet entitlement dans **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
This **évaluera la chaîne située après cette entitlement** comme un profil Sandbox.

### Compilation et décompilation d’un profil Sandbox

L’outil **`sandbox-exec`** utilise les fonctions `sandbox_compile_*` de `libsandbox.dylib`. Les principales fonctions exportées sont : `sandbox_compile_file` (attend un chemin de fichier, paramètre `-f`), `sandbox_compile_string` (attend une chaîne, paramètre `-p`), `sandbox_compile_name` (attend le nom d’un container, paramètre `-n`), `sandbox_compile_entitlements` (attend une plist d’entitlements).

Cette version inversée et [**open source de l’outil sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) permet à **`sandbox-exec`** d’écrire le profil Sandbox compilé dans un fichier.

De plus, pour confiner un processus dans un container, il peut appeler `sandbox_spawnattrs_set[container/profilename]` et transmettre un container ou un profil préexistant.

## Debug et contournement du Sandbox

Sur macOS, contrairement à iOS où les processus sont sandboxés dès le départ par le kernel, **les processus doivent eux-mêmes activer le Sandbox**. Cela signifie que sur macOS, un processus n’est pas restreint par le Sandbox tant qu’il ne décide pas activement d’y entrer, bien que les apps de l’App Store soient toujours sandboxées.

Les processus sont automatiquement sandboxés depuis le userland lorsqu’ils démarrent s’ils possèdent l’entitlement : `com.apple.security.app-sandbox`. Pour une explication détaillée de ce processus, consultez :

{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Les extensions permettent d’accorder des privilèges supplémentaires à un objet et sont attribuées par l’appel de l’une des fonctions suivantes :

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Les extensions sont stockées dans le second emplacement de label MACF, accessible depuis les credentials du processus. Le **`sbtool`** suivant peut accéder à ces informations.

Notez que les extensions sont généralement accordées par des processus autorisés. Par exemple, `tccd` accordera le token d’extension de `com.apple.tcc.kTCCServicePhotos` lorsqu’un processus tente d’accéder aux photos et y est autorisé dans un message XPC. Le processus devra ensuite consommer le token d’extension afin que celui-ci lui soit ajouté.\
Notez que les tokens d’extension sont de longues valeurs hexadécimales qui encodent les permissions accordées. Cependant, ils n’intègrent pas le PID autorisé, ce qui signifie que tout processus ayant accès au token peut être **consommé par plusieurs processus**.

Notez également que les extensions sont étroitement liées aux entitlements. Ainsi, la possession de certains entitlements peut automatiquement accorder certaines extensions.

### **Vérifier les privilèges d’un PID**

[**Selon cette source**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), les fonctions **`sandbox_check`** (il s’agit d’un `__mac_syscall`) peuvent vérifier **si une opération est autorisée ou non** par le Sandbox pour un PID, un audit token ou un identifiant unique.<sup>[[8]](#references)</sup>

L’[**outil sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (disponible [compilé ici](https://newosxbook.com/articles/hitsb.html)) peut vérifier si un PID peut effectuer certaines actions :
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Il est également possible de suspendre et de réactiver le sandbox à l'aide des fonctions `sandbox_suspend` et `sandbox_unsuspend` de `libsystem_sandbox.dylib`.

Notez que pour appeler la fonction de suspension, certains entitlements sont vérifiés afin d'autoriser l'appelant à l'utiliser, notamment :

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Cet appel système (#381) attend d'abord un argument sous forme de chaîne indiquant le module à exécuter, puis un code dans le deuxième argument indiquant la fonction à exécuter. Le troisième argument dépend ensuite de la fonction exécutée.<sup>[[2]](#references)</sup>

La fonction `___sandbox_ms` encapsule l'appel à `mac_syscall` en indiquant `"Sandbox"` comme premier argument, tout comme `___sandbox_msp` encapsule `mac_set_proc` (#387). Les codes pris en charge par `___sandbox_ms` sont notamment les suivants :

- **set_profile (#0)** : Appliquer un profile compilé ou nommé à un processus.
- **platform_policy (#1)** : Appliquer les vérifications de policy spécifiques à la plateforme (elles varient entre macOS et iOS).
- **check_sandbox (#2)** : Effectuer une vérification manuelle d'une opération spécifique du sandbox.
- **note (#3)** : Ajouter une annotation à un Sandbox.
- **container (#4)** : Attacher une annotation à un sandbox, généralement pour le debugging ou l'identification.
- **extension_issue (#5)** : Générer une nouvelle extension pour un processus.
- **extension_consume (#6)** : Consommer une extension donnée.
- **extension_release (#7)** : Libérer la mémoire associée à une extension consommée.
- **extension_update_file (#8)** : Modifier les paramètres d'une extension de fichier existante dans le sandbox.
- **extension_twiddle (#9)** : Ajuster ou modifier une extension de fichier existante (par exemple, TextEdit, rtf, rtfd).
- **suspend (#10)** : Suspendre temporairement toutes les vérifications du sandbox (nécessite les entitlements appropriés).
- **unsuspend (#11)** : Reprendre toutes les vérifications du sandbox précédemment suspendues.
- **passthrough_access (#12)** : Autoriser l'accès direct à une ressource en contournant les vérifications du sandbox.
- **set_container_path (#13)** : (iOS uniquement) Définir un chemin de container pour un app group ou un signing ID.
- **container_map (#14)** : (iOS uniquement) Récupérer un chemin de container depuis `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)** : (iOS 10+) Définir des métadonnées en mode utilisateur dans le sandbox.
- **inspect (#16)** : Fournir des informations de debugging sur un processus sandboxé.
- **dump (#18)** : (macOS 11) Extraire le profile actuel d'un sandbox pour l'analyser.
- **vtrace (#19)** : Tracer les opérations du sandbox à des fins de monitoring ou de debugging.
- **builtin_profile_deactivate (#20)** : (macOS < 11) Désactiver les profiles nommés (par exemple, `pe_i_can_has_debugger`).
- **check_bulk (#21)** : Effectuer plusieurs opérations `sandbox_check` en un seul appel.
- **reference_retain_by_audit_token (#28)** : Créer une référence pour un audit token à utiliser dans les vérifications du sandbox.
- **reference_release (#29)** : Libérer une référence d'audit token précédemment conservée.
- **rootless_allows_task_for_pid (#30)** : Vérifier si `task_for_pid` est autorisé (similaire aux vérifications `csr`).
- **rootless_whitelist_push (#31)** : (macOS) Appliquer un fichier manifeste de System Integrity Protection (SIP).
- **rootless_whitelist_check (preflight) (#32)** : Vérifier le fichier manifeste SIP avant son exécution.
- **rootless_protected_volume (#33)** : (macOS) Appliquer les protections SIP à un disque ou une partition.
- **rootless_mkdir_protected (#34)** : Appliquer la protection SIP/DataVault à un processus de création de répertoire.

## Sandbox.kext

Notez que dans iOS, l'extension du kernel contient **tous les profiles codés en dur** dans le segment `__TEXT.__const` afin d'empêcher leur modification. Voici quelques fonctions intéressantes de l'extension du kernel :

- **`hook_policy_init`** : Elle hooke `mpo_policy_init` et est appelée après `mac_policy_register`. Elle effectue la plupart des initialisations du Sandbox. Elle initialise également SIP.
- **`hook_policy_initbsd`** : Elle configure l'interface sysctl en enregistrant `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` et `security.mac.sandbox.debug_mode` (si le système a démarré avec `PE_i_can_has_debugger`).
- **`hook_policy_syscall`** : Elle est appelée par `mac_syscall` avec `"Sandbox"` comme premier argument et un code indiquant l'opération comme second argument. Un switch est utilisé pour trouver le code à exécuter en fonction du code demandé.

### MACF Hooks

**`Sandbox.kext`** utilise plus d'une centaine de hooks via MACF. La plupart des hooks vérifient simplement certains cas élémentaires qui permettent d'effectuer l'action ; dans le cas contraire, ils appellent **`cred_sb_evalutate`** avec les **credentials** provenant de MACF, un nombre correspondant à l'**opération** à effectuer et un **buffer** pour la sortie.<sup>[[1]](#references)</sup>

Un bon exemple est la fonction **`_mpo_file_check_mmap`**, qui hooke `mmap` et commence par vérifier si la nouvelle mémoire sera writable (et autorise l'exécution dans le cas contraire). Elle vérifie ensuite si la mémoire est utilisée pour le dyld shared cache et, si c'est le cas, autorise l'exécution. Enfin, elle appelle **`sb_evaluate_internal`** (ou l'un de ses wrappers) afin d'effectuer des vérifications d'autorisation supplémentaires.

Parmi la centaine de hooks utilisés par Sandbox, trois sont particulièrement intéressants :

- `mpo_proc_check_for` : Elle applique le profile si nécessaire et s'il n'a pas déjà été appliqué.
- `mpo_vnode_check_exec` : Appelée lorsqu'un processus charge le binaire associé ; une vérification du profile est alors effectuée, ainsi qu'une vérification interdisant les exécutions SUID/SGID.
- `mpo_cred_label_update_execve` : Cette fonction est appelée lorsque le label est assigné. C'est la plus longue, car elle est appelée lorsque le binaire est entièrement chargé, mais avant son exécution. Elle effectue notamment des actions telles que la création de l'objet sandbox, l'association de la structure sandbox aux credentials kauth et la suppression de l'accès aux ports mach.

Notez que **`_cred_sb_evalutate`** est un wrapper de **`sb_evaluate_internal`**. Cette fonction reçoit les credentials transmis, puis effectue l'évaluation à l'aide de la fonction **`eval`**, qui évalue généralement le **platform profile**, appliqué par défaut à tous les processus, puis le **profile spécifique au processus**. Notez que le platform profile est l'un des composants principaux de **SIP** dans macOS.

## Sandboxd

Sandbox possède également un daemon utilisateur qui expose le service XPC Mach `com.apple.sandboxd` et lie le port spécial 14 (`HOST_SEATBELT_PORT`), utilisé par l'extension du kernel pour communiquer avec lui. Il expose plusieurs fonctions à l'aide de MIG.

## References

- [1] [XNU — `security/mac_policy.h` (MACF hooks the Sandbox kext registers)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, the entry point behind `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` man page](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)

{{#include ../../../../banners/hacktricks-training.md}}
