# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext et amfid

Il se concentre sur l'application de l'integrite du code execute sur le systeme, en fournissant la logique derriere la verification des signatures de code de XNU. Il est egalement capable de verifier les entitlements et de gerer d'autres taches sensibles, comme autoriser le debugging ou obtenir des task ports.

De plus, pour certaines operations, le kext prefere contacter le daemon execute dans le user space `/usr/libexec/amfid`. Cette relation de confiance a ete exploitee dans plusieurs jailbreaks.

Dans les versions recentes de macOS, AMFI n'est plus expose de maniere pratique sous la forme d'un kext autonome present sur le disque. Le reverse engineering implique donc generalement de travailler a partir du **kernelcache** ou d'un **KDK**, plutot que de parcourir `/System/Library/Extensions`.

AMFI utilise des policies **MACF** et enregistre ses hooks des son demarrage. Empecher son chargement ou son dechargement peut egalement declencher un kernel panic. Cependant, certains boot arguments permettent de desactiver AMFI :

- `amfi_unrestricted_task_for_pid`: Autorise task_for_pid sans les entitlements requis
- `amfi_allow_any_signature`: Autorise toute code signature
- `cs_enforcement_disable`: Argument system-wide utilise pour desactiver l'application des code signing
- `amfi_prevent_old_entitled_platform_binaries`: Invalide les platform binaries possedant des entitlements
- `amfi_get_out_of_my_way`: Desactive completement amfi

Voici certaines des policies MACF qu'il enregistre :<sup>[1]</sup>

- **`cred_check_label_update_execve:`** La mise a jour du label est effectuee et renvoie 1
- **`cred_label_associate`**: Met a jour le slot mac d'AMFI avec le label
- **`cred_label_destroy`**: Supprime le slot mac d'AMFI
- **`cred_label_init`**: Place 0 dans le slot mac d'AMFI
- **`cred_label_update_execve`:** Verifie les entitlements du processus afin de determiner s'il doit etre autorise a modifier les labels.
- **`file_check_mmap`:** Verifie si mmap acquiert de la memoire et la definit comme executable. Dans ce cas, il verifie si la library validation est necessaire et, si c'est le cas, appelle la fonction de library validation.
- **`file_check_library_validation`**: Appelle la fonction de library validation qui verifie notamment si une platform binary charge une autre platform binary ou si le processus et le nouveau fichier charge ont le meme TeamID. Certains entitlements permettent egalement de charger n'importe quelle library.
- **`policy_initbsd`**: Configure les Trusted NVRAM Keys
- **`policy_syscall`**: Verifie les policies DYLD, par exemple si le binaire possede des segments unrestricted ou si les env vars doivent etre autorisees. Cette fonction est egalement appelee lorsqu'un processus est demarre via `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Verifie si, lorsqu'un processus execute un nouveau binaire, les autres processus disposant de droits SEND sur le task port du processus doivent les conserver ou non. Les platform binaries sont autorisees, l'entitlement `get-task-allow` l'autorise, les entitlements `task_for_pid-allow` sont autorises et les binaires possedant le meme TeamID le sont egalement.
- **`proc_check_expose_task`**: Applique les entitlements
- **`amfi_exc_action_check_exception_send`**: Un message d'exception est envoye au debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Cycle de vie du label pendant la gestion des exceptions (debugging)
- **`proc_check_get_task`**: Verifie des entitlements tels que `get-task-allow`, qui permet a d'autres processus d'obtenir le task port du processus, et `task_for_pid-allow`, qui permet au processus d'obtenir les task ports d'autres processus. Si aucun des deux n'est present, il appelle `amfid permitunrestricteddebugging` pour verifier si l'operation est autorisee.
- **`proc_check_mprotect`**: Refuse l'operation si `mprotect` est appele avec le flag `VM_PROT_TRUSTED`, qui indique que la region doit etre traitee comme si elle possedait une code signature valide.
- **`vnode_check_exec`**: Est appele lorsque des fichiers executables sont charges en memoire et definit `cs_hard | cs_kill`, ce qui tuera le processus si l'une des pages devient invalide<sup>[2]</sup>
- **`vnode_check_getextattr`**: macOS : Verifie `com.apple.root.installed` et `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Comme get + les entitlements `com.apple.private.allow-bless` et `internal-installer-equivalent`
- **`vnode_check_signature`**: Code qui appelle XNU pour verifier la code signature a l'aide des entitlements, du trust cache et d'`amfid`<sup>[3]</sup>
- **`proc_check_run_cs_invalid`**: Intercepte les appels `ptrace()` (`PT_ATTACH` et `PT_TRACE_ME`). Verifie la presence de l'un des entitlements `get-task-allow`, `run-invalid-allow` et `run-unsigned-code` et, si aucun n'est present, verifie si le debugging est autorise.
- **`proc_check_map_anon`**: Si mmap est appele avec le flag **`MAP_JIT`**, AMFI verifie l'entitlement `dynamic-codesigning`.

`AMFI.kext` expose egalement une API pour les autres kernel extensions, et il est possible de trouver ses dependances avec :
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

Il s'agit du daemon exécuté en mode utilisateur que `AMFI.kext` utilise pour vérifier les code signatures en mode utilisateur.\
Pour que `AMFI.kext` communique avec le daemon, il utilise des messages mach via le port `HOST_AMFID_PORT`, qui est le port spécial `18`.

Notez que dans macOS, il n'est plus possible pour les processus root de détourner les ports spéciaux, car ils sont protégés par `SIP` et seul launchd peut les obtenir. Dans iOS, il est vérifié que le processus envoyant la réponse possède le CDHash hardcodé de `amfid`.

Il est possible de voir quand `amfid` est sollicité pour vérifier un binaire ainsi que sa réponse en le déboguant et en plaçant un breakpoint dans `mach_msg`.

Une fois qu'un message est reçu via le port spécial, **MIG** est utilisé pour envoyer chaque fonction vers la fonction qu'il appelle. Les fonctions principales ont été reverse et expliquées dans le livre.

### DYLD policy and library validation

Les versions récentes de `dyld` appellent `amfi_check_dyld_policy_self()` très tôt depuis `configureProcessRestrictions()` afin de demander à AMFI si le processus peut utiliser les variables de chemin `DYLD_*`, l'interposing, les fallback paths, les embedded variables ou tolérer l'échec de l'insertion d'une library. Par conséquent, lors du triage d'une injection surface, il ne suffit pas d'inspecter uniquement les load commands Mach-O : vous devez également inspecter les entitlements et les runtime flags qu'AMFI traduira en policy `dyld`.

Une boucle de triage pratique est la suivante :
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Sur les versions modernes de macOS, de nombreux binaires Apple ne contiennent plus directement `com.apple.security.cs.disable-library-validation` et intègrent à la place `com.apple.private.security.clear-library-validation`. Dans ce cas, la library validation n'est pas désactivée au moment de l'appel à `execve` : le processus doit appeler `csops(..., CS_OPS_CLEAR_LV, ...)` sur lui-même, et XNU n'autorise cette opération sur le processus appelant que lorsque l'entitlement est présent. Du point de vue offensif, cela est important, car une cible peut ne devenir injectable **qu'après** avoir atteint le code path qui efface explicitement la LV (par exemple, juste avant de charger des plugins optionnels).<sup>[4][5]</sup>

## Provisioning Profiles

Un provisioning profile peut être utilisé pour signer du code. Il existe des profils **Developer**, qui peuvent être utilisés pour signer du code et le tester, ainsi que des profils **Enterprise**, qui peuvent être utilisés sur tous les appareils.

Après la soumission d'une App à l'Apple Store, si elle est approuvée, elle est signée par Apple et le provisioning profile n'est plus nécessaire.

Un profil utilise généralement l'extension `.mobileprovision` ou `.provisionprofile` et peut être extrait avec :
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Bien que parfois appelés certificats, ces provisioning profiles contiennent plus qu’un certificat :

- **AppIDName:** L’identifiant de l’application
- **AppleInternalProfile**: Indique qu’il s’agit d’un profil interne Apple
- **ApplicationIdentifierPrefix**: Préfixé à AppIDName (identique à TeamIdentifier)
- **CreationDate**: Date au format `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Un tableau de certificat(s) (généralement un), encodé sous forme de données Base64
- **Entitlements**: Les entitlements autorisés avec les entitlements de ce profil
- **ExpirationDate**: Date d’expiration au format `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Nom de l’application, identique à AppIDName
- **ProvisionedDevices**: Un tableau (pour les certificats de développement) d’UDID pour lesquels ce profil est valide
- **ProvisionsAllDevices**: Un booléen (true pour les certificats enterprise)
- **TeamIdentifier**: Un tableau contenant une ou plusieurs chaînes alphanumériques (généralement une) utilisées pour identifier le développeur à des fins d’interaction entre applications
- **TeamName**: Un nom lisible par l’humain utilisé pour identifier le développeur
- **TimeToLive**: Durée de validité (en jours) du certificat
- **UUID**: Un identifiant unique universel pour ce profil
- **Version**: Actuellement défini sur 1

Notez que l’entrée entitlements contient un ensemble restreint d’entitlements et que le provisioning profile ne pourra fournir que ces entitlements spécifiques, afin d’empêcher l’attribution d’entitlements privés Apple.

Notez que les profils se trouvent généralement dans `/var/MobileDeviceProvisioningProfiles` et qu’il est possible de les vérifier avec **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Il s’agit de la bibliothèque externe appelée par `amfid` pour lui demander s’il doit autoriser quelque chose ou non. Elle a historiquement été exploitée dans le jailbreaking en exécutant une version backdoorée qui autorisait tout.

Dans macOS, elle se trouve dans `MobileDevice.framework`.

## AMFI Trust Caches

Les trust caches ne sont pas uniquement un concept iOS. Sur les versions modernes de macOS, en particulier sur **Apple silicon**, le static trust cache et les loadable trust caches font partie de la chaîne Secure Boot. Lorsqu’un **CodeDirectory hash** d’un Mach-O y est présent, AMFI peut lui accorder le **platform privilege** sans effectuer d’autres vérifications d’authenticité au moment du lancement. Cela permet également à Apple de verrouiller les binaires de la plateforme sur une version spécifique de l’OS et d’empêcher la réutilisation de binaires signés par Apple plus anciens sur des systèmes plus récents.<sup>[6]</sup>

Sur les versions récentes de macOS, les métadonnées des trust caches sont également liées aux **launch constraints**. Ainsi, les applications système et les binaires copiés, lancés depuis le mauvais parent ou le mauvais emplacement, peuvent être rejetés par AMFI même s’ils sont toujours signés par Apple. Le workflow détaillé d’extraction et de reversing est présenté dans :

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

Dans les recherches sur iOS et le jailbreaking, vous trouverez toujours le modèle traditionnel des **loadable trust caches** utilisé pour whitelister des binaires signés ad hoc.

## Références

- [1] [XNU — `security/mac_policy.h` (opérations de policy MACF enregistrées par AMFI, notamment `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (flags de code-signing `CS_*` définis par AMFI)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (parsing et validation du blob de code-signature)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (opérations `CS_OPS_*` et `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (handler de `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
