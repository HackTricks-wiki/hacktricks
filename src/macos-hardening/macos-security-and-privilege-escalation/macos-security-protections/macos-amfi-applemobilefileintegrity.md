# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext et amfid

Il se concentre sur l’application de l’intégrité du code exécuté sur le système, en fournissant la logique derrière la vérification des signatures de code de XNU. Il peut aussi vérifier les entitlements et gérer d’autres tâches sensibles, comme autoriser le débogage ou obtenir des task ports.

De plus, pour certaines opérations, le kext préfère contacter le daemon en user space `/usr/libexec/amfid`. Cette relation de confiance a été abusée dans plusieurs jailbreaks.

Sur les versions récentes de macOS, AMFI n’est plus exposé de manière pratique comme un kext autonome sur disque, donc le reverse consiste généralement à travailler à partir du **kernelcache** ou d’un **KDK** plutôt que de parcourir `/System/Library/Extensions`.

AMFI utilise des politiques **MACF** et enregistre ses hooks dès son démarrage. Aussi, empêcher son chargement ou le décharger peut déclencher un kernel panic. Cependant, certains boot arguments permettent d’affaiblir AMFI :

- `amfi_unrestricted_task_for_pid`: Permettre que task_for_pid soit autorisé sans les entitlements requis
- `amfi_allow_any_signature`: Autoriser n’importe quelle code signature
- `cs_enforcement_disable`: Argument système utilisé pour désactiver l’application de la signature de code
- `amfi_prevent_old_entitled_platform_binaries`: Invalider les platform binaries avec entitlements
- `amfi_get_out_of_my_way`: Désactive complètement amfi

Voici certaines des politiques MACF qu’il enregistre :

- **`cred_check_label_update_execve:`** La mise à jour du label sera effectuée et retournera 1
- **`cred_label_associate`**: Met à jour l’emplacement du mac label d’AMFI avec le label
- **`cred_label_destroy`**: Supprime l’emplacement du mac label d’AMFI
- **`cred_label_init`**: Place 0 dans l’emplacement du mac label d’AMFI
- **`cred_label_update_execve`:** Vérifie les entitlements du processus pour voir s’il doit être autorisé à modifier les labels.
- **`file_check_mmap`:** Vérifie si mmap acquiert de la mémoire et la définit comme exécutable. Dans ce cas, il vérifie si la library validation est nécessaire et, si oui, appelle la fonction de library validation.
- **`file_check_library_validation`**: Appelle la fonction de library validation qui vérifie, entre autres, si un platform binary charge un autre platform binary ou si le processus et le nouveau fichier chargé ont le même TeamID. Certains entitlements permettent aussi de charger n’importe quelle library.
- **`policy_initbsd`**: Configure les clés NVRAM de confiance
- **`policy_syscall`**: Vérifie les politiques DYLD, comme si le binaire a des segments unrestricted, s’il doit autoriser les variables d’environnement... ceci est aussi appelé quand un processus est lancé via `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Vérifie que, lorsqu’un processus exécute un nouveau binaire, les autres processus ayant des droits SEND sur le task port du processus doivent les conserver ou non. Les platform binaries sont autorisés, les entitlements `get-task-allow` l’autorisent, les entitlements `task_for_pid-allow` sont autorisés ainsi que les binaires avec le même TeamID.
- **`proc_check_expose_task`**: applique les entitlements
- **`amfi_exc_action_check_exception_send`**: Un message d’exception est envoyé au debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Cycle de vie du label pendant la gestion des exceptions (debugging)
- **`proc_check_get_task`**: Vérifie des entitlements comme `get-task-allow`, qui permet à d’autres processus d’obtenir les task ports, et `task_for_pid-allow`, qui permet au processus d’obtenir les task ports d’autres processus. Si aucun des deux n’est présent, il appelle `amfid permitunrestricteddebugging` pour vérifier si c’est autorisé.
- **`proc_check_mprotect`**: Refuse si `mprotect` est appelé avec le flag `VM_PROT_TRUSTED`, qui indique que la région doit être traitée comme si elle avait une signature de code valide.
- **`vnode_check_exec`**: Appelé quand des fichiers exécutables sont chargés en mémoire et définit `cs_hard | cs_kill`, ce qui tuera le processus si l’une des pages devient invalide
- **`vnode_check_getextattr`**: MacOS: vérifie `com.apple.root.installed` et `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Comme get + `com.apple.private.allow-bless` et l’entitlement internal-installer-equivalent
- **`vnode_check_signature`**: Code qui appelle XNU pour vérifier la code signature en utilisant les entitlements, trust cache et `amfid`
- **`proc_check_run_cs_invalid`**: Intercepte les appels `ptrace()` (`PT_ATTACH` et `PT_TRACE_ME`). Il vérifie la présence des entitlements `get-task-allow`, `run-invalid-allow` et `run-unsigned-code` et, si aucun n’est présent, il vérifie si le debugging est autorisé.
- **`proc_check_map_anon`**: Si mmap est appelé avec le flag **`MAP_JIT`**, AMFI vérifiera l’entitlement `dynamic-codesigning`.

`AMFI.kext` expose aussi une API pour d’autres kernel extensions, et il est possible de trouver ses dépendances avec :
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

C'est le daemon en mode utilisateur que `AMFI.kext` utilisera pour vérifier les signatures de code en mode utilisateur.\
Pour que `AMFI.kext` communique avec le daemon, il utilise des mach messages via le port `HOST_AMFID_PORT`, qui est le port spécial `18`.

Notez que sur macOS, il n'est plus possible pour les processus root de détourner les ports spéciaux, car ils sont protégés par `SIP` et seul launchd peut les obtenir. Sur iOS, il est vérifié que le processus qui renvoie la réponse a le CDHash codé en dur de `amfid`.

Il est possible de voir quand `amfid` est sollicité pour vérifier un binaire et la réponse correspondante en le déboguant et en définissant un breakpoint sur `mach_msg`.

Une fois qu'un message est reçu via le port spécial, **MIG** est utilisé pour envoyer chaque fonction à la fonction qu'il appelle. Les fonctions principales ont été inversées et expliquées dans le livre.

### DYLD policy and library validation

Les versions récentes de `dyld` appellent `amfi_check_dyld_policy_self()` très tôt depuis `configureProcessRestrictions()` pour demander à AMFI si le processus peut utiliser les variables de chemin `DYLD_*`, l'interposition, les fallback paths, les variables embarquées, ou tolérer un échec d'insertion de bibliothèque. Par conséquent, lors de l'évaluation d'une surface d'injection, il ne suffit pas d'inspecter uniquement les load commands Mach-O : vous devez aussi inspecter les entitlements et les drapeaux d'exécution que AMFI traduira en `dyld` policy.

Une boucle pratique d'évaluation est :
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Sur les versions modernes de macOS, beaucoup de binaires Apple ne portent plus directement `com.apple.security.cs.disable-library-validation` et utilisent à la place `com.apple.private.security.clear-library-validation`. Dans ce cas, la library validation n’est pas désactivée au moment de `execve` : le processus doit appeler `csops(..., CS_OPS_CLEAR_LV, ...)` sur lui-même, et XNU n’autorise cette opération sur le processus appelant que si l’entitlement est présent. D’un point de vue offensif, cela compte car une cible peut ne devenir injectable qu’**après** avoir atteint le chemin de code qui efface explicitement LV (par exemple, juste avant de charger des plugins optionnels).

## Provisioning Profiles

Un provisioning profile peut être utilisé pour signer du code. Il existe des profiles **Developer** qui peuvent être utilisés pour signer du code et le tester, et des profiles **Enterprise** qui peuvent être utilisés sur tous les appareils.

Après qu’une App est soumise à l’Apple Store, si elle est approuvée, elle est signée par Apple et le provisioning profile n’est plus nécessaire.

Un profile utilise généralement l’extension `.mobileprovision` ou `.provisionprofile` et peut être dumpé avec :
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Bien que parfois appelés certificats, ces profils de provisioning ont plus qu'un certificat :

- **AppIDName:** L'Application Identifier
- **AppleInternalProfile**: Désigne ceci comme un profil Apple Internal
- **ApplicationIdentifierPrefix**: Préfixé à AppIDName (identique à TeamIdentifier)
- **CreationDate**: Date au format `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Un tableau de certificat(s) (généralement un), encodé(s) en données Base64
- **Entitlements**: Les entitlements autorisés avec les entitlements pour ce profil
- **ExpirationDate**: Date d'expiration au format `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Le nom de l'application, identique à AppIDName
- **ProvisionedDevices**: Un tableau (pour les certificats de développeur) de UDIDs pour lesquels ce profil est valide
- **ProvisionsAllDevices**: Un booléen (true pour les certificats enterprise)
- **TeamIdentifier**: Un tableau de chaîne(s) alphanumérique(s) (généralement une) utilisé(s) pour identifier le développeur à des fins d'interaction inter-app
- **TeamName**: Un nom lisible par l'humain utilisé pour identifier le développeur
- **TimeToLive**: Validité (en jours) du certificat
- **UUID**: Un Universally Unique Identifier pour ce profil
- **Version**: Actuellement défini sur 1

Notez que l'entrée entitlements contiendra un ensemble restreint d'entitlements et que le provisioning profile ne pourra accorder que ces entitlements spécifiques afin d'éviter d'accorder les entitlements privés d'Apple.

Notez que les profils sont généralement situés dans `/var/MobileDeviceProvisioningProfiles` et qu'il est possible de les vérifier avec **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

C'est la bibliothèque externe que `amfid` appelle afin de demander s'il doit autoriser quelque chose ou non. Cela a historiquement été abusé dans le jailbreaking en exécutant une version backdoorée qui autorisait tout.

Sur macOS, elle se trouve dans `MobileDevice.framework`.

## AMFI Trust Caches

Les trust caches ne sont pas seulement un concept iOS. Sur macOS moderne, surtout sur **Apple silicon**, le trust cache statique et les loadable trust caches font partie de la chaîne Secure Boot. Lorsque le **CodeDirectory hash** d'un Mach-O s'y trouve, AMFI peut lui accorder le **platform privilege** sans effectuer d'autres vérifications d'authenticité au lancement. Cela signifie aussi qu'Apple peut verrouiller les binaires platform sur une version spécifique d'OS et empêcher la relecture d'anciens binaires signés par Apple sur des systèmes plus récents.

Sur les versions récentes de macOS, les métadonnées de trust-cache sont aussi liées aux **launch constraints**, de sorte que les applications système copiées et les binaires lancés depuis le mauvais parent/emplacement peuvent être rejetés par AMFI même s'ils sont toujours signés par Apple. Le workflow détaillé d'extraction et de reversing est couvert dans :

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

Dans la recherche iOS et jailbreak, vous trouverez encore le modèle traditionnel des **loadable trust caches** utilisé pour mettre en whitelist des binaires signés ad-hoc.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
