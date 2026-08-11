# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Informations de base

MacOS Sandbox (initialement appelé Seatbelt) **limite les applications** exécutées à l'intérieur du sandbox aux **actions autorisées spécifiées dans le profil Sandbox** avec lequel l'application est exécutée. Cela contribue à garantir que **l'application accédera uniquement aux ressources attendues**.

Toute application disposant de l'**entitlement** **`com.apple.security.app-sandbox`** sera exécutée à l'intérieur du sandbox. Les **binaires Apple** sont généralement exécutés dans un Sandbox, et toutes les applications de l'**App Store disposent de cet entitlement**. Plusieurs applications seront donc exécutées dans le sandbox.<sup>[[4]](#references)</sup>

Afin de contrôler ce qu'un processus peut ou ne peut pas faire, le **Sandbox dispose de hooks** dans presque toutes les opérations qu'un processus pourrait tenter (y compris la plupart des syscalls), en utilisant **MACF**. Cependant, s**elon** les **entitlements** de l'application, le Sandbox peut être plus permissif envers le processus.

Voici quelques composants importants du Sandbox :

- L'**extension du kernel** `/System/Library/Extensions/Sandbox.kext`
- Le **framework privé** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- Un **daemon** s'exécutant dans le userland `/usr/libexec/sandboxd`
- Les **containers** `~/Library/Containers`

### Containers

Chaque application sandboxée dispose de son propre container dans `~/Library/Containers/{CFBundleIdentifier}` :
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
Dans chaque dossier bundle id, vous trouverez le **plist** et le **Data directory** de l’App, avec une structure qui reproduit le dossier Home :
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
> Notez que même si les symlinks sont présents pour « s’échapper » du Sandbox et accéder à d’autres dossiers, l’App doit tout de même **avoir les permissions** nécessaires pour y accéder. Ces permissions se trouvent dans le **`.plist`**, dans `RedirectablePaths`.

Le **`SandboxProfileData`** est le CFData du profil sandbox compilé, échappé en B64.
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
> Tout ce qui est créé ou modifié par une application sandboxed reçoit l’**attribut de quarantaine**. Cela peut empêcher un sandbox escape en déclenchant Gatekeeper si l’application sandboxed tente d’exécuter quelque chose avec **`open`**.

## Profils Sandbox

Les profils Sandbox sont des fichiers de configuration qui indiquent ce qui sera **autorisé/interdit** dans ce **Sandbox**. Ils utilisent le **Sandbox Profile Language (SBPL)**, qui utilise le langage de programmation [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>).

Vous trouverez ici un exemple :
```scheme
(version 1) ; First you get the version

(deny default) ; Then you should indicate the default action when no rule applies

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
> Consultez cette [**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **pour vérifier d'autres actions qui pourraient être autorisées ou refusées.**<sup>[[5]](#references)</sup>
>
> Notez que dans la version compilée d'un profile, le nom des opérations est remplacé par leurs entrées dans un array connu de la dylib et du kext, ce qui rend la version compilée plus courte et plus difficile à lire.

D'importants **system services** s'exécutent également dans leur propre **sandbox** personnalisée, comme le service `mdnsresponder`. Vous pouvez consulter ces **sandbox profiles** personnalisés dans :

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- D'autres sandbox profiles peuvent être consultés sur [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- Dans iOS, le platform profile se trouve dans le `.kext` de la sandbox, à l'intérieur de `_platform_profile_data`, dans le binaire.

Les applications **App Store** utilisent le **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. Vous pouvez vérifier dans ce profile comment des entitlements tels que **`com.apple.security.network.server`** permettent à un processus d'utiliser le réseau.

Ensuite, certains **Apple daemon services** utilisent différents profiles situés dans `/System/Library/Sandbox/Profiles/*.sb` ou `/usr/share/sandbox/*.sb`. Ces sandboxes sont appliquées dans la fonction principale qui appelle l'API `sandbox_init_XXX`.<sup>[[3]](#references)</sup>

**SIP** est un Sandbox profile appelé platform_profile dans `/System/Library/Sandbox/rootless.conf`.

### Exemples de sandbox profiles

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
> Notez que les **logiciels** **créés par Apple** qui s’exécutent sous **Windows** **ne disposent pas de précautions de sécurité supplémentaires**, telles que le sandboxing des applications.

Exemples de bypass :

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (ils parviennent à écrire des fichiers en dehors du sandbox dont le nom commence par `~$`).<sup>[[7]](#references)</sup>

### Traçage du sandbox

#### Via un profil

Il est possible de tracer toutes les vérifications effectuées par le sandbox chaque fois qu’une action est contrôlée. Pour cela, créez simplement le profil suivant :
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
Puis exécutez simplement quelque chose avec ce profil :
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
Dans `/tmp/trace.out`, vous pourrez voir chaque vérification du sandbox effectuée à chaque appel (et donc beaucoup de doublons).

Il est également possible de tracer le sandbox à l'aide du paramètre **`-t`** : `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Via API

La fonction `sandbox_set_trace_path` exportée par `libsystem_sandbox.dylib` permet de spécifier un nom de fichier de trace dans lequel les vérifications du sandbox seront écrites.\
Il est également possible de faire quelque chose de similaire en appelant `sandbox_vtrace_enable()` puis en récupérant les logs d'erreur depuis le buffer avec `sandbox_vtrace_report()`.

### Inspection du Sandbox

`libsandbox.dylib` exporte une fonction appelée sandbox_inspect_pid qui fournit une liste de l'état du sandbox d'un processus (y compris les extensions). Cependant, seuls les binaires de la plateforme peuvent utiliser cette fonction.

### Profils Sandbox de MacOS et iOS

MacOS stocke les profils sandbox système à deux emplacements : **/usr/share/sandbox/** et **/System/Library/Sandbox/Profiles**.

Et si une application tierce possède l'entitlement _**com.apple.security.app-sandbox**_, le système applique le profil **/System/Library/Sandbox/Profiles/application.sb** à ce processus.

Dans iOS, le profil par défaut s'appelle **container** et nous ne disposons pas de sa représentation textuelle SBPL. En mémoire, ce sandbox est représenté sous la forme d'un arbre binaire Allow/Deny pour chacune des permissions du sandbox.

### SBPL personnalisé dans les applications de l'App Store

Il serait possible pour les entreprises de faire fonctionner leurs applications **avec des profils Sandbox personnalisés** (au lieu du profil par défaut). Elles doivent utiliser l'entitlement **`com.apple.security.temporary-exception.sbpl`**, qui doit être autorisé par Apple.

Il est possible de vérifier la définition de cet entitlement dans **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Cela va **eval la chaîne située après cet entitlement** en tant que profil de Sandbox.

### Compilation et décompilation d’un profil de Sandbox

L’outil **`sandbox-exec`** utilise les fonctions `sandbox_compile_*` de `libsandbox.dylib`. Les principales fonctions exportées sont : `sandbox_compile_file` (attend un chemin de fichier, paramètre `-f`), `sandbox_compile_string` (attend une chaîne, paramètre `-p`), `sandbox_compile_name` (attend le nom d’un container, paramètre `-n`), `sandbox_compile_entitlements` (attend un fichier plist d’entitlements).

Cette version inversée et [**open source de l’outil sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) permet de demander à **`sandbox-exec`** d’écrire le profil de Sandbox compilé dans un fichier.

De plus, pour confiner un processus dans un container, il peut appeler `sandbox_spawnattrs_set[container/profilename]` et transmettre un container ou un profil préexistant.

## Debug et contournement du Sandbox

Sur macOS, contrairement à iOS où les processus sont sandboxés dès le départ par le kernel, les **processus doivent eux-mêmes activer le Sandbox**. Cela signifie que sur macOS, un processus n’est pas limité par le Sandbox tant qu’il ne décide pas activement d’y entrer, bien que les apps de l’App Store soient toujours sandboxées.

Les processus sont automatiquement sandboxés depuis le userland lorsqu’ils démarrent s’ils possèdent l’entitlement : `com.apple.security.app-sandbox`. Pour une explication détaillée de ce processus, consultez :


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Extensions de Sandbox**

Les extensions permettent d’accorder des privilèges supplémentaires à un objet et sont attribuées en appelant l’une des fonctions suivantes :

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Les extensions sont stockées dans le second emplacement de label MACF, accessible depuis les credentials du processus. Le programme **`sbtool`** suivant peut accéder à ces informations.

Notez que les extensions sont généralement accordées par des processus autorisés. Par exemple, `tccd` accorde le token d’extension de `com.apple.tcc.kTCCServicePhotos` lorsqu’un processus a tenté d’accéder aux photos et y a été autorisé dans un message XPC. Le processus doit ensuite consommer le token d’extension afin que celui-ci lui soit ajouté.\
Notez que les tokens d’extension sont de longues valeurs hexadécimales qui encodent les permissions accordées. Cependant, le PID autorisé n’y est pas codé en dur, ce qui signifie que tout processus ayant accès au token peut être **consommé par plusieurs processus**.

Notez que les extensions sont également très liées aux entitlements. Ainsi, certains entitlements peuvent automatiquement accorder certaines extensions.

### **Vérifier les privilèges d’un PID**

[**Selon cette source**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), les fonctions **`sandbox_check`** (il s’agit d’un `__mac_syscall`) peuvent vérifier **si une opération est autorisée ou non** par le Sandbox pour un PID, un audit token ou un identifiant unique.<sup>[[8]](#references)</sup>

L’[**outil sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (retrouvez-le [compilé ici](https://newosxbook.com/articles/hitsb.html)) peut vérifier si un PID peut effectuer certaines actions :
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Il est également possible de suspendre et de réactiver le sandbox à l'aide des fonctions `sandbox_suspend` et `sandbox_unsuspend` de `libsystem_sandbox.dylib`.

Notez que, pour appeler la fonction de suspension, certains entitlements sont vérifiés afin d'autoriser l'appelant à l'utiliser, notamment :

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Cet appel système (#381) attend une première chaîne de caractères qui indique le module à exécuter, puis un code comme deuxième argument qui indique la fonction à exécuter. Le troisième argument dépend ensuite de la fonction exécutée.<sup>[[2]](#references)</sup>

La fonction `___sandbox_ms` encapsule l'appel à `mac_syscall` en indiquant `"Sandbox"` comme premier argument, tout comme `___sandbox_msp` encapsule `mac_set_proc` (#387). Voici un tableau présentant certains des codes pris en charge par `___sandbox_ms` :

- **set_profile (#0)** : Applique un profile compilé ou nommé à un processus.
- **platform_policy (#1)** : Applique les vérifications de policy spécifiques à la plateforme (elles varient entre macOS et iOS).
- **check_sandbox (#2)** : Effectue une vérification manuelle d'une opération spécifique du sandbox.
- **note (#3)** : Ajoute une annotation à un Sandbox.
- **container (#4)** : Attache une annotation à un sandbox, généralement pour le debugging ou l'identification.
- **extension_issue (#5)** : Génère une nouvelle extension pour un processus.
- **extension_consume (#6)** : Consomme une extension donnée.
- **extension_release (#7)** : Libère la mémoire associée à une extension consommée.
- **extension_update_file (#8)** : Modifie les paramètres d'une extension de fichier existante dans le sandbox.
- **extension_twiddle (#9)** : Ajuste ou modifie une extension de fichier existante (par exemple, TextEdit, rtf, rtfd).
- **suspend (#10)** : Suspend temporairement toutes les vérifications du sandbox (nécessite les entitlements appropriés).
- **unsuspend (#11)** : Reprend toutes les vérifications du sandbox précédemment suspendues.
- **passthrough_access (#12)** : Autorise l'accès direct passthrough à une ressource, en contournant les vérifications du sandbox.
- **set_container_path (#13)** : (iOS uniquement) Définit un chemin de container pour un app group ou un signing ID.
- **container_map (#14)** : (iOS uniquement) Récupère un chemin de container depuis `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)** : (iOS 10+) Définit les metadata du user mode dans le sandbox.
- **inspect (#16)** : Fournit des informations de debugging sur un processus sandboxé.
- **dump (#18)** : (macOS 11) Extrait le profile actuel d'un sandbox pour analyse.
- **vtrace (#19)** : Trace les opérations du sandbox à des fins de monitoring ou de debugging.
- **builtin_profile_deactivate (#20)** : (macOS < 11) Désactive les profiles nommés (par exemple, `pe_i_can_has_debugger`).
- **check_bulk (#21)** : Effectue plusieurs opérations `sandbox_check` en un seul appel.
- **reference_retain_by_audit_token (#28)** : Crée une référence pour un audit token utilisable dans les vérifications du sandbox.
- **reference_release (#29)** : Libère une référence d'audit token précédemment conservée.
- **rootless_allows_task_for_pid (#30)** : Vérifie si `task_for_pid` est autorisé (similaire aux vérifications `csr`).
- **rootless_whitelist_push (#31)** : (macOS) Applique un fichier manifest System Integrity Protection (SIP).
- **rootless_whitelist_check (preflight) (#32)** : Vérifie le fichier manifest SIP avant l'exécution.
- **rootless_protected_volume (#33)** : (macOS) Applique les protections SIP à un disque ou une partition.
- **rootless_mkdir_protected (#34)** : Applique les protections SIP/DataVault à un processus de création de répertoire.

## Sandbox.kext

Notez que, dans iOS, l'extension du kernel contient **tous les profiles codés en dur** dans le segment `__TEXT.__const` afin d'éviter leur modification. Voici quelques fonctions intéressantes de l'extension du kernel :

- **`hook_policy_init`** : Intercepte `mpo_policy_init` et est appelée après `mac_policy_register`. Elle effectue la plupart des initialisations du Sandbox. Elle initialise également SIP.
- **`hook_policy_initbsd`** : Configure l'interface sysctl en enregistrant `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` et `security.mac.sandbox.debug_mode` (si le système est booté avec `PE_i_can_has_debugger`).
- **`hook_policy_syscall`** : Est appelée par `mac_syscall` avec `"Sandbox"` comme premier argument et un code indiquant l'opération comme deuxième argument. Un switch est utilisé pour trouver le code à exécuter en fonction du code demandé.

### MACF Hooks

**`Sandbox.kext`** utilise plus d'une centaine de hooks via MACF. La plupart des hooks vérifient simplement certains cas triviaux qui permettent d'effectuer l'action ; sinon, ils appellent **`cred_sb_evalutate`** avec les **credentials** provenant de MACF, un nombre correspondant à l'**opération** à effectuer et un **buffer** destiné à la sortie.<sup>[[1]](#references)</sup>

La fonction **`_mpo_file_check_mmap`**, qui hooke `mmap`, en est un bon exemple. Elle commence par vérifier si la nouvelle mémoire sera writable (et autorise l'exécution dans le cas contraire), puis vérifie si elle est utilisée pour le dyld shared cache et, si c'est le cas, autorise l'exécution. Enfin, elle appelle **`sb_evaluate_internal`** (ou l'un de ses wrappers) afin d'effectuer des vérifications d'autorisation supplémentaires.

De plus, parmi la centaine de hooks utilisés par Sandbox, 3 sont particulièrement intéressants :

- `mpo_proc_check_for` : Applique le profile si nécessaire et s'il n'a pas déjà été appliqué.
- `mpo_vnode_check_exec` : Appelée lorsqu'un processus charge le binaire associé ; une vérification du profile est alors effectuée, ainsi qu'une vérification interdisant les exécutions SUID/SGID.
- `mpo_cred_label_update_execve` : Appelée lorsque le label est attribué. C'est la plus longue, car elle est appelée lorsque le binaire est entièrement chargé, mais n'a pas encore été exécuté. Elle effectue notamment des actions telles que la création de l'objet sandbox, l'attachement de la structure sandbox aux credentials kauth et la suppression de l'accès aux mach ports.

Notez que **`_cred_sb_evalutate`** est un wrapper autour de **`sb_evaluate_internal`**. Cette fonction reçoit les credentials transmis, puis effectue l'évaluation à l'aide de la fonction **`eval`**, qui évalue généralement le **platform profile**, appliqué par défaut à tous les processus, puis le **profile spécifique au processus**. Notez que le platform profile est l'un des principaux composants de **SIP** dans macOS.

## Sandboxd

Sandbox dispose également d'un daemon user qui expose le service XPC Mach `com.apple.sandboxd` et se lie au port spécial 14 (`HOST_SEATBELT_PORT`), utilisé par l'extension du kernel pour communiquer avec lui. Il expose certaines fonctions à l'aide de MIG.

## References

- [1] [XNU — `security/mac_policy.h` (hooks MACF enregistrés par l'extension Sandbox)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, le point d'entrée derrière `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [Page de manuel `sandbox_init(3)`](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Guide Apple Sandbox v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Évasion du sandbox Mac](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Évasion du sandbox macOS d'Office365](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - Le Sandbox Apple : plus profondément dans le bourbier - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)
{{#include ../../../../banners/hacktricks-training.md}}
