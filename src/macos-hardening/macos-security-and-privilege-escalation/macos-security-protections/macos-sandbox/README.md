# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Informations de base

MacOS Sandbox (appelé initialement Seatbelt) **limite les applications** s'exécutant à l'intérieur du sandbox aux **actions autorisées spécifiées dans le profil Sandbox** avec lequel l'application s'exécute. Cela aide à garantir que **l'application n'accédera qu'aux ressources attendues**.

Toute application avec l'**entitlement** **`com.apple.security.app-sandbox`** sera exécutée à l'intérieur du sandbox. **Les binaires Apple** sont généralement exécutés à l'intérieur d'un Sandbox, et toutes les applications de l'**App Store ont cet entitlement**. Ainsi, plusieurs applications seront exécutées à l'intérieur du sandbox.

Pour contrôler ce qu'un processus peut ou ne peut pas faire, le **Sandbox a des hooks** dans presque toutes les opérations qu'un processus pourrait essayer (y compris la plupart des syscalls) en utilisant **MACF**. Cependant, d**épendant** des **entitlements** de l'application, le Sandbox peut être plus permissif avec le processus.

Certains composants importants du Sandbox sont :

- L'**extension du noyau** `/System/Library/Extensions/Sandbox.kext`
- Le **framework privé** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- Un **daemon** s'exécutant en userland `/usr/libexec/sandboxd`
- Les **conteneurs** `~/Library/Containers`

### Conteneurs

Chaque application sandboxée aura son propre conteneur dans `~/Library/Containers/{CFBundleIdentifier}` :
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
Dans chaque dossier d'identifiant de bundle, vous pouvez trouver le **plist** et le **répertoire de données** de l'application avec une structure qui imite le dossier personnel :
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
> Notez que même si les symlinks sont là pour "s'échapper" du Sandbox et accéder à d'autres dossiers, l'App doit toujours **avoir des permissions** pour y accéder. Ces permissions se trouvent dans le **`.plist`** dans les `RedirectablePaths`.

Le **`SandboxProfileData`** est le profil de sandbox compilé CFData échappé en B64.
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
> Tout ce qui est créé/modifié par une application en bac à sable recevra l'**attribut de quarantaine**. Cela empêchera un espace de bac à sable en déclenchant Gatekeeper si l'application en bac à sable essaie d'exécuter quelque chose avec **`open`**.

## Profils de Bac à Sable

Les profils de bac à sable sont des fichiers de configuration qui indiquent ce qui sera **autorisé/interdit** dans ce **bac à sable**. Il utilise le **Langage de Profil de Bac à Sable (SBPL)**, qui utilise le [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>) langage de programmation.

Ici, vous pouvez trouver un exemple :
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
> Consultez cette [**recherche**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **pour vérifier d'autres actions qui pourraient être autorisées ou refusées.**
>
> Notez que dans la version compilée d'un profil, le nom des opérations est remplacé par leurs entrées dans un tableau connu par le dylib et le kext, rendant la version compilée plus courte et plus difficile à lire.

Des **services système** importants s'exécutent également dans leur propre **sandbox** personnalisée, comme le service `mdnsresponder`. Vous pouvez consulter ces **profils de sandbox** personnalisés dans :

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- D'autres profils de sandbox peuvent être vérifiés sur [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Les applications de l'**App Store** utilisent le **profil** **`/System/Library/Sandbox/Profiles/application.sb`**. Vous pouvez vérifier dans ce profil comment des droits tels que **`com.apple.security.network.server`** permettent à un processus d'utiliser le réseau.

Ensuite, certains **services de démon Apple** utilisent différents profils situés dans `/System/Library/Sandbox/Profiles/*.sb` ou `/usr/share/sandbox/*.sb`. Ces sandboxes sont appliquées dans la fonction principale appelant l'API `sandbox_init_XXX`.

**SIP** est un profil de Sandbox appelé platform_profile dans `/System/Library/Sandbox/rootless.conf`.

### Exemples de Profils de Sandbox

Pour démarrer une application avec un **profil de sandbox spécifique**, vous pouvez utiliser :
```bash
sandbox-exec -f example.sb /Path/To/The/Application
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

> [!NOTE]
> Notez que le **logiciel** **développé par Apple** qui fonctionne sur **Windows** **n'a pas de précautions de sécurité supplémentaires**, telles que le sandboxing des applications.

Exemples de contournements :

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (ils peuvent écrire des fichiers en dehors du sandbox dont le nom commence par `~$`).

### Traçage du Sandbox

#### Via le profil

Il est possible de tracer toutes les vérifications que le sandbox effectue chaque fois qu'une action est vérifiée. Pour cela, il suffit de créer le profil suivant :
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
Et ensuite, exécutez simplement quelque chose en utilisant ce profil :
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
Dans `/tmp/trace.out`, vous pourrez voir chaque vérification de sandbox effectuée chaque fois qu'elle a été appelée (donc, beaucoup de doublons).

Il est également possible de tracer le sandbox en utilisant le **`-t`** paramètre : `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Via API

La fonction `sandbox_set_trace_path` exportée par `libsystem_sandbox.dylib` permet de spécifier un nom de fichier de trace où les vérifications de sandbox seront écrites.\
Il est également possible de faire quelque chose de similaire en appelant `sandbox_vtrace_enable()` et en obtenant ensuite les erreurs de journal à partir du tampon en appelant `sandbox_vtrace_report()`.

### Inspection du Sandbox

`libsandbox.dylib` exporte une fonction appelée sandbox_inspect_pid qui donne une liste de l'état du sandbox d'un processus (y compris les extensions). Cependant, seules les binaires de la plateforme peuvent utiliser cette fonction.

### Profils de Sandbox MacOS & iOS

MacOS stocke les profils de sandbox système à deux emplacements : **/usr/share/sandbox/** et **/System/Library/Sandbox/Profiles**.

Et si une application tierce porte le droit _**com.apple.security.app-sandbox**_, le système applique le profil **/System/Library/Sandbox/Profiles/application.sb** à ce processus.

Dans iOS, le profil par défaut s'appelle **container** et nous n'avons pas la représentation textuelle SBPL. En mémoire, ce sandbox est représenté comme un arbre binaire Allow/Deny pour chaque permission du sandbox.

### SBPL personnalisé dans les applications de l'App Store

Il pourrait être possible pour les entreprises de faire fonctionner leurs applications **avec des profils de Sandbox personnalisés** (au lieu de celui par défaut). Elles doivent utiliser le droit **`com.apple.security.temporary-exception.sbpl`** qui doit être autorisé par Apple.

Il est possible de vérifier la définition de ce droit dans **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Cela va **évaluer la chaîne après cette attribution** comme un profil Sandbox.

### Compilation et décompilation d'un profil Sandbox

L'outil **`sandbox-exec`** utilise les fonctions `sandbox_compile_*` de `libsandbox.dylib`. Les principales fonctions exportées sont : `sandbox_compile_file` (attend un chemin de fichier, param `-f`), `sandbox_compile_string` (attend une chaîne, param `-p`), `sandbox_compile_name` (attend un nom de conteneur, param `-n`), `sandbox_compile_entitlements` (attend un plist d'attributions).

Cette version inversée et [**open source de l'outil sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) permet de faire écrire à **`sandbox-exec`** dans un fichier le profil sandbox compilé.

De plus, pour confiner un processus à l'intérieur d'un conteneur, il peut appeler `sandbox_spawnattrs_set[container/profilename]` et passer un conteneur ou un profil préexistant.

## Déboguer et contourner le Sandbox

Sur macOS, contrairement à iOS où les processus sont sandboxés dès le départ par le noyau, **les processus doivent s'inscrire eux-mêmes dans le sandbox**. Cela signifie que sur macOS, un processus n'est pas restreint par le sandbox jusqu'à ce qu'il décide activement d'y entrer, bien que les applications de l'App Store soient toujours sandboxées.

Les processus sont automatiquement sandboxés depuis l'espace utilisateur lorsqu'ils démarrent s'ils ont l'attribution : `com.apple.security.app-sandbox`. Pour une explication détaillée de ce processus, consultez :

{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Extensions Sandbox**

Les extensions permettent de donner des privilèges supplémentaires à un objet et sont accordées en appelant l'une des fonctions :

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Les extensions sont stockées dans le deuxième emplacement d'étiquette MACF accessible depuis les informations d'identification du processus. Le **`sbtool`** suivant peut accéder à ces informations.

Notez que les extensions sont généralement accordées par des processus autorisés, par exemple, `tccd` accordera le jeton d'extension de `com.apple.tcc.kTCCServicePhotos` lorsqu'un processus essaie d'accéder aux photos et a été autorisé dans un message XPC. Ensuite, le processus devra consommer le jeton d'extension pour qu'il soit ajouté à celui-ci.\
Notez que les jetons d'extension sont de longs hexadécimaux qui codent les permissions accordées. Cependant, ils n'ont pas le PID autorisé codé en dur, ce qui signifie que tout processus ayant accès au jeton pourrait être **consommé par plusieurs processus**.

Notez que les extensions sont également très liées aux attributions, donc avoir certaines attributions pourrait automatiquement accorder certaines extensions.

### **Vérifier les privilèges PID**

[**Selon cela**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), les fonctions **`sandbox_check`** (c'est un `__mac_syscall`), peuvent vérifier **si une opération est autorisée ou non** par le sandbox dans un certain PID, un jeton d'audit ou un ID unique.

L'outil [**sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (trouvez-le [compilé ici](https://newosxbook.com/articles/hitsb.html)) peut vérifier si un PID peut effectuer certaines actions :
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Il est également possible de suspendre et de reprendre le sandbox en utilisant les fonctions `sandbox_suspend` et `sandbox_unsuspend` de `libsystem_sandbox.dylib`.

Notez que pour appeler la fonction de suspension, certaines autorisations sont vérifiées afin d'autoriser l'appelant à l'appeler, comme :

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Cet appel système (#381) attend un premier argument de type chaîne qui indiquera le module à exécuter, puis un code dans le deuxième argument qui indiquera la fonction à exécuter. Ensuite, le troisième argument dépendra de la fonction exécutée.

L'appel de fonction `___sandbox_ms` enveloppe `mac_syscall` en indiquant dans le premier argument `"Sandbox"`, tout comme `___sandbox_msp` est un wrapper de `mac_set_proc` (#387). Ensuite, certains des codes pris en charge par `___sandbox_ms` peuvent être trouvés dans ce tableau :

- **set_profile (#0)** : Appliquer un profil compilé ou nommé à un processus.
- **platform_policy (#1)** : Appliquer des vérifications de politique spécifiques à la plateforme (varie entre macOS et iOS).
- **check_sandbox (#2)** : Effectuer une vérification manuelle d'une opération de sandbox spécifique.
- **note (#3)** : Ajoute une annotation à un Sandbox.
- **container (#4)** : Attacher une annotation à un sandbox, généralement pour le débogage ou l'identification.
- **extension_issue (#5)** : Générer une nouvelle extension pour un processus.
- **extension_consume (#6)** : Consommer une extension donnée.
- **extension_release (#7)** : Libérer la mémoire liée à une extension consommée.
- **extension_update_file (#8)** : Modifier les paramètres d'une extension de fichier existante dans le sandbox.
- **extension_twiddle (#9)** : Ajuster ou modifier une extension de fichier existante (par exemple, TextEdit, rtf, rtfd).
- **suspend (#10)** : Suspendre temporairement toutes les vérifications de sandbox (nécessite des autorisations appropriées).
- **unsuspend (#11)** : Reprendre toutes les vérifications de sandbox précédemment suspendues.
- **passthrough_access (#12)** : Autoriser un accès direct en contournant les vérifications de sandbox.
- **set_container_path (#13)** : (iOS uniquement) Définir un chemin de conteneur pour un groupe d'applications ou un ID de signature.
- **container_map (#14)** : (iOS uniquement) Récupérer un chemin de conteneur depuis `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)** : (iOS 10+) Définir des métadonnées en mode utilisateur dans le sandbox.
- **inspect (#16)** : Fournir des informations de débogage sur un processus sandboxé.
- **dump (#18)** : (macOS 11) Dump le profil actuel d'un sandbox pour analyse.
- **vtrace (#19)** : Tracer les opérations de sandbox pour le suivi ou le débogage.
- **builtin_profile_deactivate (#20)** : (macOS < 11) Désactiver les profils nommés (par exemple, `pe_i_can_has_debugger`).
- **check_bulk (#21)** : Effectuer plusieurs opérations `sandbox_check` en un seul appel.
- **reference_retain_by_audit_token (#28)** : Créer une référence pour un jeton d'audit à utiliser dans les vérifications de sandbox.
- **reference_release (#29)** : Libérer une référence de jeton d'audit précédemment retenue.
- **rootless_allows_task_for_pid (#30)** : Vérifier si `task_for_pid` est autorisé (similaire aux vérifications `csr`).
- **rootless_whitelist_push (#31)** : (macOS) Appliquer un fichier manifeste de protection de l'intégrité du système (SIP).
- **rootless_whitelist_check (preflight) (#32)** : Vérifier le fichier manifeste SIP avant l'exécution.
- **rootless_protected_volume (#33)** : (macOS) Appliquer des protections SIP à un disque ou une partition.
- **rootless_mkdir_protected (#34)** : Appliquer une protection SIP/DataVault à un processus de création de répertoire.

## Sandbox.kext

Notez qu'en iOS, l'extension du noyau contient **tous les profils codés en dur** à l'intérieur du segment `__TEXT.__const` pour éviter qu'ils ne soient modifiés. Voici quelques fonctions intéressantes de l'extension du noyau :

- **`hook_policy_init`** : Il accroche `mpo_policy_init` et est appelé après `mac_policy_register`. Il effectue la plupart des initialisations du Sandbox. Il initialise également SIP.
- **`hook_policy_initbsd`** : Il configure l'interface sysctl en enregistrant `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` et `security.mac.sandbox.debug_mode` (si démarré avec `PE_i_can_has_debugger`).
- **`hook_policy_syscall`** : Il est appelé par `mac_syscall` avec "Sandbox" comme premier argument et un code indiquant l'opération dans le deuxième. Un switch est utilisé pour trouver le code à exécuter selon le code demandé.

### MACF Hooks

**`Sandbox.kext`** utilise plus d'une centaine de hooks via MACF. La plupart des hooks vérifieront simplement certains cas triviaux qui permettent d'effectuer l'action, sinon, ils appelleront **`cred_sb_evalutate`** avec les **identifiants** de MACF et un nombre correspondant à l'**opération** à effectuer et un **buffer** pour la sortie.

Un bon exemple de cela est la fonction **`_mpo_file_check_mmap`** qui accroche **`mmap`** et qui commencera à vérifier si la nouvelle mémoire va être modifiable (et si ce n'est pas le cas, autoriser l'exécution), puis elle vérifiera si elle est utilisée pour le cache partagé dyld et si c'est le cas, autoriser l'exécution, et enfin elle appellera **`sb_evaluate_internal`** (ou l'un de ses wrappers) pour effectuer d'autres vérifications d'autorisation.

De plus, parmi les centaines de hooks utilisés par Sandbox, il y en a 3 en particulier qui sont très intéressants :

- `mpo_proc_check_for` : Il applique le profil si nécessaire et s'il n'a pas été appliqué précédemment.
- `mpo_vnode_check_exec` : Appelé lorsqu'un processus charge le binaire associé, puis une vérification de profil est effectuée ainsi qu'une vérification interdisant les exécutions SUID/SGID.
- `mpo_cred_label_update_execve` : Cela est appelé lorsque l'étiquette est assignée. C'est le plus long car il est appelé lorsque le binaire est entièrement chargé mais qu'il n'a pas encore été exécuté. Il effectuera des actions telles que la création de l'objet sandbox, l'attachement de la structure sandbox aux identifiants kauth, la suppression de l'accès aux ports mach...

Notez que **`_cred_sb_evalutate`** est un wrapper autour de **`sb_evaluate_internal`** et cette fonction obtient les identifiants passés et effectue ensuite l'évaluation en utilisant la fonction **`eval`** qui évalue généralement le **profil de plateforme** qui est par défaut appliqué à tous les processus et ensuite le **profil de processus spécifique**. Notez que le profil de plateforme est l'un des principaux composants de **SIP** dans macOS.

## Sandboxd

Sandbox dispose également d'un démon utilisateur en cours d'exécution exposant le service XPC Mach `com.apple.sandboxd` et liant le port spécial 14 (`HOST_SEATBELT_PORT`) que l'extension du noyau utilise pour communiquer avec lui. Il expose certaines fonctions en utilisant MIG.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../../banners/hacktricks-training.md}}
