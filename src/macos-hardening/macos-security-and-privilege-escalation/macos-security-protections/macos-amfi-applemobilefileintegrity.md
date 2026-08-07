# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext et amfid

Il se concentre sur l’application de l’intégrité du code exécuté sur le système, en fournissant la logique derrière la vérification des signatures de code de XNU. Il est également capable de vérifier les entitlements et de gérer d’autres tâches sensibles, comme l’autorisation du debugging ou l’obtention de task ports.

De plus, pour certaines opérations, le kext préfère contacter le daemon exécuté en user space `/usr/libexec/amfid`. Cette relation de confiance a été exploitée dans plusieurs jailbreaks.

Dans les versions récentes de macOS, AMFI n’est plus exposé de manière pratique sous la forme d’un kext autonome présent sur le disque. Le reversing consiste donc généralement à travailler à partir du **kernelcache** ou d’un **KDK**, plutôt qu’à parcourir `/System/Library/Extensions`.

AMFI utilise des politiques **MACF** et enregistre ses hooks dès son démarrage. Empêcher son chargement ou le décharger peut également déclencher un kernel panic. Cependant, certains boot arguments permettent de désactiver AMFI :

- `amfi_unrestricted_task_for_pid` : Autorise task_for_pid sans les entitlements requis
- `amfi_allow_any_signature` : Autorise toute signature de code
- `cs_enforcement_disable` : Argument système utilisé pour désactiver l’application des signatures de code
- `amfi_prevent_old_entitled_platform_binaries` : Invalide les platform binaries avec des entitlements
- `amfi_get_out_of_my_way` : Désactive complètement amfi

Voici quelques-unes des politiques MACF qu’il enregistre :<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** : La mise à jour du label sera effectuée et retournera 1
- **`cred_label_associate`** : Met à jour le slot de label mac d’AMFI avec le label
- **`cred_label_destroy`** : Supprime le slot de label mac d’AMFI
- **`cred_label_init`** : Place 0 dans le slot de label mac d’AMFI
- **`cred_label_update_execve:`** : Vérifie les entitlements du processus afin de déterminer s’il doit être autorisé à modifier les labels.
- **`file_check_mmap:`** : Vérifie si mmap acquiert de la mémoire et la définit comme exécutable. Dans ce cas, il vérifie si la library validation est nécessaire et, si c’est le cas, appelle la fonction de library validation.
- **`file_check_library_validation`** : Appelle la fonction de library validation, qui vérifie notamment si une platform binary charge une autre platform binary ou si le processus et le nouveau fichier chargé possèdent le même TeamID. Certains entitlements permettent également de charger n’importe quelle library.
- **`policy_initbsd`** : Configure les trusted NVRAM Keys
- **`policy_syscall`** : Vérifie les politiques DYLD, par exemple si le binaire possède des segments unrestricted et si les variables d’environnement doivent être autorisées. Cette fonction est également appelée lorsqu’un processus est démarré via `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`** : Vérifie si, lorsqu’un processus exécute un nouveau binaire, les autres processus disposant de droits SEND sur le task port du processus doivent les conserver ou non. Les platform binaries sont autorisées, les entitlements `get-task-allow` et `task_for_pid-allow` le permettent, ainsi que les binaires possédant le même TeamID.
- **`proc_check_expose_task`** : Applique les entitlements
- **`amfi_exc_action_check_exception_send`** : Un message d’exception est envoyé au debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`** : Cycle de vie du label lors de la gestion des exceptions (debugging)
- **`proc_check_get_task`** : Vérifie des entitlements comme `get-task-allow`, qui permet à d’autres processus d’obtenir le task port du processus, et `task_for_pid-allow`, qui permet au processus d’obtenir les task ports d’autres processus. Si aucun des deux n’est présent, il appelle `amfid permitunrestricteddebugging` pour vérifier si cette opération est autorisée.
- **`proc_check_mprotect`** : Refuse l’opération si `mprotect` est appelé avec le flag `VM_PROT_TRUSTED`, qui indique que la région doit être traitée comme si elle possédait une signature de code valide.
- **`vnode_check_exec`** : Est appelé lorsque des fichiers exécutables sont chargés en mémoire et définit `cs_hard | cs_kill`, ce qui tuera le processus si l’une des pages devient invalide<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`** : macOS : Vérifie `com.apple.root.installed` et `isVnodeQuarantined()`
- **`vnode_check_setextattr`** : Comme get + entitlement `com.apple.private.allow-bless` et `internal-installer-equivalent`
- **`vnode_check_signature`** : Code qui appelle XNU pour vérifier la signature de code à l’aide des entitlements, du trust cache et d’`amfid`<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`** : Intercepte les appels `ptrace()` (`PT_ATTACH` et `PT_TRACE_ME`). Vérifie la présence de l’un des entitlements `get-task-allow`, `run-invalid-allow` et `run-unsigned-code`. Si aucun n’est présent, il vérifie si le debugging est autorisé.
- **`proc_check_map_anon`** : Si mmap est appelé avec le flag **`MAP_JIT`**, AMFI vérifie la présence de l’entitlement `dynamic-codesigning`.

`AMFI.kext` expose également une API destinée aux autres extensions du kernel, et il est possible de trouver ses dépendances avec :
```bash
kextstat | grep " 19 " | cut -c2-5,50- | cut -d '(' -f1
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
8   com.apple.kec.corecrypto
19   com.apple.driver.AppleMobileFileIntegrity
22   com.apple.security.sandbox
24   com.apple.AppleSystemPolicy
67   com.apple.iokit.IOUSBHostFamily
70   com.apple.driver.AppleUSBTDM
71   com.apple.driver.AppleSEPKeyStore
74   com.apple.iokit.EndpointSecurity
81   com.apple.iokit.IOUserEthernet
101   com.apple.iokit.IO80211Family
102   com.apple.driver.AppleBCMWLANCore
118   com.apple.driver.AppleEmbeddedUSBHost
134   com.apple.iokit.IOGPUFamily
135   com.apple.AGXG13X
137   com.apple.iokit.IOMobileGraphicsFamily
138   com.apple.iokit.IOMobileGraphicsFamily-DCP
162   com.apple.iokit.IONVMeFamily
```
## amfid

Il s'agit du daemon s'exécutant en mode utilisateur que `AMFI.kext` utilise pour vérifier les signatures de code en mode utilisateur.\
Pour que `AMFI.kext` communique avec le daemon, il utilise des messages Mach via le port `HOST_AMFID_PORT`, qui est le port spécial `18`.

Notez que dans macOS, il n'est plus possible pour les processus root de détourner les ports spéciaux, car ils sont protégés par `SIP` et seul launchd peut les obtenir. Dans iOS, il est vérifié que le processus envoyant la réponse possède le CDHash codé en dur de `amfid`.

Il est possible d'observer quand `amfid` est invité à vérifier un binaire ainsi que sa réponse en le déboguant et en plaçant un breakpoint dans `mach_msg`.

Lorsqu'un message est reçu via le port spécial, **MIG** est utilisé pour envoyer chaque fonction vers la fonction qu'il appelle. Les fonctions principales ont été reverse-engineered et expliquées dans le livre.

### Politique DYLD et validation des bibliothèques

Les versions récentes de `dyld` appellent `amfi_check_dyld_policy_self()` très tôt depuis `configureProcessRestrictions()` afin de demander à AMFI si le processus peut utiliser les variables de chemin `DYLD_*`, l'interposition, les chemins de fallback, les variables intégrées ou tolérer l'échec de l'insertion d'une bibliothèque. Par conséquent, lors de l'analyse d'une surface d'injection, il ne suffit pas d'inspecter uniquement les commandes de chargement Mach-O : vous devez également inspecter les entitlements et les flags runtime qu'AMFI traduira en politique `dyld`.

Une boucle pratique de triage est la suivante :
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Sur les versions modernes de macOS, de nombreux binaires Apple ne contiennent plus directement `com.apple.security.cs.disable-library-validation` et intègrent à la place `com.apple.private.security.clear-library-validation`. Dans ce cas, la validation des bibliothèques n'est pas désactivée au moment de l'`execve` : le processus doit appeler `csops(..., CS_OPS_CLEAR_LV, ...)` sur lui-même, et XNU n'autorise cette opération sur le processus appelant que lorsque l'entitlement est présent. Du point de vue offensif, cela est important, car une cible peut devenir injectable uniquement **après** avoir atteint le code path qui efface explicitement la LV (par exemple, peu avant le chargement de plugins optionnels).<sup>[[4]](#references)[[5]](#references)</sup>

## Profils de provisioning

Un profil de provisioning peut être utilisé pour signer du code. Il existe des profils **Developer**, qui peuvent être utilisés pour signer du code et le tester, ainsi que des profils **Enterprise**, qui peuvent être utilisés sur tous les appareils.

Après la soumission d'une App à l'Apple Store, si elle est approuvée, elle est signée par Apple et le profil de provisioning n'est plus nécessaire.

Un profil utilise généralement l'extension `.mobileprovision` ou `.provisionprofile` et peut être extrait avec :
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Bien que parfois appelés certificated, ces provisioning profiles contiennent plus qu'un certificat :

- **AppIDName:** L'identifiant de l'application
- **AppleInternalProfile**: Indique qu'il s'agit d'un profil Apple Internal
- **ApplicationIdentifierPrefix**: Ajouté en préfixe à AppIDName (identique à TeamIdentifier)
- **CreationDate**: Date au format `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Un tableau de certificat(s) (généralement un seul), encodé sous forme de données Base64
- **Entitlements**: Les entitlements autorisés avec les entitlements de ce profil
- **ExpirationDate**: Date d'expiration au format `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Le nom de l'application, identique à AppIDName
- **ProvisionedDevices**: Un tableau (pour les developer certificates) d'UDID pour lesquels ce profil est valide
- **ProvisionsAllDevices**: Une valeur booléenne (true pour les enterprise certificates)
- **TeamIdentifier**: Un tableau de chaîne(s) alphanumérique(s) (généralement une seule) utilisé pour identifier le développeur à des fins d'interaction entre applications
- **TeamName**: Un nom lisible par l'utilisateur utilisé pour identifier le développeur
- **TimeToLive**: Validité (en jours) du certificat
- **UUID**: Un identifiant universellement unique pour ce profil
- **Version**: Actuellement défini sur 1

Notez que l'entrée entitlements contient un ensemble restreint d'entitlements et que le provisioning profile ne pourra fournir que ces entitlements spécifiques, afin d'empêcher l'attribution d'entitlements privés Apple.

Notez que les profils se trouvent généralement dans `/var/MobileDeviceProvisioningProfiles` et qu'il est possible de les vérifier avec **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Il s'agit de la bibliothèque externe qu'`amfid` appelle pour demander s'il doit autoriser quelque chose ou non. Elle a historiquement été détournée dans le jailbreak en exécutant une version backdoored qui autorisait tout.

Dans macOS, elle se trouve dans `MobileDevice.framework`.

## AMFI Trust Caches

Les trust caches ne sont pas uniquement un concept d'iOS. Sur les versions modernes de macOS, en particulier sur **Apple silicon**, le static trust cache et les loadable trust caches font partie de la chaîne Secure Boot. Lorsqu'un **hash CodeDirectory** d'un Mach-O y est présent, AMFI peut lui accorder le **platform privilege** sans effectuer d'autres vérifications d'authenticité au moment du lancement. Cela signifie également qu'Apple peut verrouiller les binaires de la plateforme sur une version spécifique du système d'exploitation et empêcher que d'anciens binaires signés par Apple soient rejoués sur des systèmes plus récents.<sup>[[6]](#references)</sup>

Sur les versions récentes de macOS, les métadonnées des trust caches sont également liées aux **launch constraints**. Ainsi, les applications et binaires système copiés et démarrés depuis le mauvais parent ou le mauvais emplacement peuvent être rejetés par AMFI, même s'ils sont toujours signés par Apple. Le workflow détaillé d'extraction et de reversing est présenté dans :

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

Dans les recherches sur iOS et le jailbreak, vous trouverez toujours le modèle traditionnel des **loadable trust caches**, utilisés pour autoriser les binaires signés ad hoc.

## Références

- [1] [XNU — `security/mac_policy.h` (opérations de policy MACF enregistrées par AMFI, notamment `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (flags de code-signing `CS_*` définis par AMFI)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (analyse et validation du blob de code-signature)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (opérations `CS_OPS_*` et `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (handler de `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
