# Entitlements dangereux de macOS et perms TCC

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Notez que les entitlements commençant par **`com.apple`** ne sont pas disponibles pour les tiers, seul Apple peut les accorder... Ou, si vous utilisez un certificat d’entreprise, vous pourriez en fait créer vos propres entitlements commençant par **`com.apple`** et bypass les protections basées sur cela.

## Élevé

### `com.apple.rootless.install.heritable`

L’entitlement **`com.apple.rootless.install.heritable`** permet de **bypass SIP**. Consultez [ceci pour plus d’informations](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

L’entitlement **`com.apple.rootless.install`** permet de **bypass SIP**. Consultez[ ceci pour plus d’informations](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Cet entitlement permet d’obtenir le **task port de n’importe quel** processus, à l’exception du kernel. Consultez [**ceci pour plus d’informations**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Cet entitlement permet à d’autres processus possédant l’entitlement **`com.apple.security.cs.debugger`** d’obtenir le task port du processus exécuté par le binaire possédant cet entitlement et **d’y injecter du code**. Consultez [**ceci pour plus d’informations**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Les apps possédant le Debugging Tool Entitlement peuvent appeler `task_for_pid()` pour récupérer un task port valide pour les apps non signées et tierces ayant l’entitlement `Get Task Allow` défini sur `true`. Cependant, même avec le debugging tool entitlement, un debugger **ne peut pas obtenir les task ports** des processus qui **ne possèdent pas l’entitlement `Get Task Allow`**, et qui sont donc protégés par System Integrity Protection. Consultez [**ceci pour plus d’informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Cet entitlement permet de **charger des frameworks, plug-ins ou libraries sans qu’ils soient signés par Apple ou avec le même Team ID** que l’exécutable principal, de sorte qu’un attaquant pourrait abuser d’un chargement arbitraire de library pour injecter du code. Consultez [**ceci pour plus d’informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Cet entitlement est très similaire à **`com.apple.security.cs.disable-library-validation`**, mais **au lieu de désactiver directement** la validation des libraries, il permet au processus **d’appeler un appel système `csops` pour la désactiver** au runtime.

Le nom de l’entitlement est hardcodé dans XNU à côté de l’opération `csops` qui le consomme :<sup>[[2]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Le gestionnaire du kernel pour `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) montre exactement à quel point la primitive est limitée :<sup>[[3]](#references)</sup>
```c
case CS_OPS_CLEAR_LV: {
#if !defined(XNU_TARGET_OS_OSX)
// We only support dropping library validation on macOS
error = ENOTSUP;
#else
if (forself == 1 && IOTaskHasEntitlement(proc_task(pt), CLEAR_LV_ENTITLEMENT)) {
proc_lock(pt);
if (!(proc_getcsflags(pt) & CS_INSTALLER) && (pt->p_subsystem_root_path == NULL)) {
proc_csflags_clear(pt, CS_REQUIRE_LV | CS_FORCED_LV);
error = 0;
```
Ainsi, l’opération :

- Est **macOS-only** (`ENOTSUP` sur toutes les autres plateformes).
- Fonctionne uniquement sur **lui-même** (`forself == 1`) — il est impossible de supprimer la library validation d’un autre processus avec cette opération.
- Nécessite que le processus **détienne réellement l’entitlement**, et refuse d’agir si le processus est marqué `CS_INSTALLER` ou s’exécute sous un chemin racine de subsystem.
- Efface **`CS_REQUIRE_LV | CS_FORCED_LV`** des flags de code-signing du processus.

Le commentaire de XNU explique le cas d’utilisation prévu, ainsi que la raison pour laquelle cela est intéressant pour un attaquant :

> Cette option est utilisée pour supprimer la library validation d’un processus en cours d’exécution. Elle est utilisée dans les architectures à plugins lorsqu’un programme doit charger des libraries non fiables. [...] Une fois que le processus a chargé la library non fiable, il ne sera plus efficace de se fier à la library validation à l’avenir.

En d’autres termes, **tout binaire portant cet entitlement est une cible de dylib-injection** : faites exécuter du code à l’intérieur de celui-ci (ou convainquez-le de charger votre plug-in) après qu’il a supprimé `CS_REQUIRE_LV`, et vous héritez de tout ce que le processus hôte est autorisé à faire.

### `com.apple.security.cs.allow-dyld-environment-variables`

Cet entitlement permet d’**utiliser les variables d’environnement DYLD**, qui peuvent servir à injecter des libraries et du code. Consultez [**cette page pour plus d’informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` ou `com.apple.rootless.storage`.`TCC`

[**Selon ce blog**](https://objective-see.org/blog/blog_0x4C.html) **et** [**ce blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ces entitlements permettent de **modifier** la base de données **TCC**.

### **`system.install.apple-software`** et **`system.install.apple-software.standar-user`**

Ces entitlements permettent d’**installer des logiciels sans demander l’autorisation** de l’utilisateur, ce qui peut être utile pour une **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement nécessaire pour demander au **kernel de charger une kernel extension**.

### **`com.apple.private.icloud-account-access`**

Avec l’entitlement **`com.apple.private.icloud-account-access`**, il est possible de communiquer avec le service XPC **`com.apple.iCloudHelper`**, qui **fournira des tokens iCloud**.

**iMovie** et **Garageband** possédaient cet entitlement.

Pour plus d’**informations** sur l’exploit permettant d’**obtenir des tokens iCloud** grâce à cet entitlement, consultez la conférence : [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO : Je ne sais pas ce que cela permet de faire

### `com.apple.private.apfs.revert-to-snapshot`

TODO : Dans [**ce rapport**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/), **il est mentionné que cela pourrait servir à** mettre à jour le contenu protégé par SSV après un redémarrage. Si vous savez comment, envoyez un PR s’il vous plaît !

### `com.apple.private.apfs.create-sealed-snapshot`

TODO : Dans [**ce rapport**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/), **il est mentionné que cela pourrait servir à** mettre à jour le contenu protégé par SSV après un redémarrage. Si vous savez comment, envoyez un PR s’il vous plaît !

### `keychain-access-groups`

Cette liste d’entitlements indique les groupes **keychain** auxquels l’application a accès :
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

Accorde les permissions **Full Disk Access**, l’une des permissions TCC les plus élevées que vous puissiez avoir.

### **`kTCCServiceAppleEvents`**

Permet à l’application d’envoyer des événements à d’autres applications couramment utilisées pour **automatiser des tâches**. En contrôlant d’autres applications, elle peut exploiter les permissions accordées à ces dernières.

Par exemple, en leur faisant demander son mot de passe à l’utilisateur :
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Ou leur faire effectuer des **actions arbitraires**.

### **`kTCCServiceEndpointSecurityClient`**

Permet notamment d’**écrire dans la base de données TCC de l’utilisateur**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permet de **modifier** l’attribut **`NFSHomeDirectory`** d’un utilisateur, ce qui change le chemin de son dossier personnel et permet donc de **contourner TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permet de modifier les fichiers à l’intérieur des bundles d’applications (dans app.app), ce qui est **interdit par défaut**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Il est possible de vérifier qui dispose de cet accès dans _Réglages Système_ > _Confidentialité et sécurité_ > _Gestion des apps._

### `kTCCServiceAccessibility`

Le processus pourra **abuser des fonctionnalités d’accessibilité de macOS**, ce qui signifie que, par exemple, il pourra simuler des frappes clavier. Il pourrait donc demander l’autorisation de contrôler une app comme Finder et approuver la boîte de dialogue avec cette permission.

## Entitlements liés à Trustcache/CDhash

Certains entitlements peuvent être utilisés pour contourner les protections Trustcache/CDhash, qui empêchent l’exécution de versions rétrogradées des binaires Apple.

## Moyen

### `com.apple.security.cs.allow-jit`

Cet entitlement permet de **créer une mémoire accessible en écriture et exécutable** en transmettant l’indicateur `MAP_JIT` à la fonction système `mmap()`. Consultez [**ceci pour plus d’informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Cet entitlement permet de **remplacer ou de patcher du code C**, d’utiliser la fonction **`NSCreateObjectFileImageFromMemory`**, obsolète depuis longtemps (et fondamentalement non sécurisée), ou d’utiliser le framework **DVDPlayback**. Consultez [**ceci pour plus d’informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> L’inclusion de cet entitlement expose votre app aux vulnérabilités courantes des langages dont la gestion de la mémoire n’est pas sûre. Déterminez soigneusement si votre app a besoin de cette exception.

### `com.apple.security.cs.disable-executable-page-protection`

Cet entitlement permet de **modifier sur le disque les sections de ses propres fichiers exécutables** afin de forcer leur arrêt. Consultez [**ceci pour plus d’informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> L’Entitlement Disable Executable Memory Protection est un entitlement extrême qui supprime une protection de sécurité fondamentale de votre app, permettant à un attaquant de réécrire le code exécutable de votre app sans être détecté. Préférez si possible des entitlements plus ciblés.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Cet entitlement permet de monter un système de fichiers nullfs (interdit par défaut). Outil : [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Selon cet article de blog, cette permission TCC se trouve généralement sous la forme :
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Permet au processus de **demander toutes les permissions TCC**.

### **`kTCCServicePostEvent`**

Permet **d’injecter des événements synthétiques de clavier et de souris** dans tout le système via `CGEventPost()`. Un processus disposant de cette permission peut simuler des frappes au clavier, des clics de souris et des événements de défilement dans n’importe quelle application, offrant ainsi un **contrôle à distance** du bureau.

Cette permission est particulièrement dangereuse lorsqu’elle est combinée à `kTCCServiceAccessibility` ou `kTCCServiceListenEvent`, car elle permet à la fois de lire les entrées et d’en injecter.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Permet **d’intercepter tous les événements clavier et souris** à l’échelle du système (surveillance des entrées / keylogging). Un processus peut enregistrer un `CGEventTap` afin de capturer chaque touche saisie dans n’importe quelle application, y compris les mots de passe, les numéros de carte bancaire et les messages privés.

Pour les techniques d’exploitation détaillées, voir :

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Permet de **lire le tampon d’affichage** — prendre des screenshots et enregistrer la vidéo de l’écran de n’importe quelle application, y compris les champs de texte sécurisés. Combiné à l’OCR, cela peut extraire automatiquement les mots de passe et les données sensibles affichées à l’écran.

> [!WARNING]
> À partir de macOS Sonoma, le screen capture affiche un indicateur persistant dans la barre des menus. Sur les versions antérieures, l’enregistrement de l’écran peut être complètement silencieux.

### **`kTCCServiceCamera`**

Permet de **capturer des photos et des vidéos** depuis la caméra intégrée ou des caméras USB connectées. Une code injection dans un binaire autorisé à utiliser la caméra permet une surveillance visuelle silencieuse.

### **`kTCCServiceMicrophone`**

Permet **d’enregistrer l’audio** depuis tous les périphériques d’entrée. Les daemons en arrière-plan disposant d’un accès au microphone permettent une surveillance audio ambiante persistante, sans fenêtre d’application visible.

### **`kTCCServiceLocation`**

Permet d’interroger la **localisation physique** de l’appareil via la triangulation Wi-Fi ou des balises Bluetooth. Une surveillance continue révèle les adresses du domicile et du travail, les habitudes de déplacement et les routines quotidiennes.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Accès aux **Contacts** (noms, e-mails, numéros de téléphone — utiles pour le spear-phishing), au **Calendrier** (horaires des réunions, listes des participants) et aux **Photos** (photos personnelles, screenshots pouvant contenir des identifiants, métadonnées de localisation).

Pour les techniques complètes d’exploitation visant le vol d’identifiants via les permissions TCC, voir :

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Entitlements de Sandbox et de signature de code

### `com.apple.security.temporary-exception.mach-lookup.global-name`

Les **exceptions temporaires de Sandbox** affaiblissent l’App Sandbox en autorisant les communications avec des services Mach/XPC à l’échelle du système, que la sandbox bloque normalement. Il s’agit du **principal primitive d’évasion de sandbox** — une application compromise exécutée dans la sandbox peut utiliser des exceptions mach-lookup pour atteindre des daemons privilégiés et exploiter leurs interfaces XPC.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Pour une chaîne d'exploitation détaillée : sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, voir :

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

Les **DriverKit entitlements** permettent aux binaires de pilotes en espace utilisateur de communiquer directement avec le kernel via les interfaces IOKit. Les binaires DriverKit gèrent le matériel : USB, Thunderbolt, PCIe, périphériques HID, audio et réseau.

Compromettre un binaire DriverKit permet :
- **Surface d'attaque du kernel** via des appels `IOConnectCallMethod` malformés
- **Usurpation de périphériques USB** (émulation d'un clavier pour l'injection HID)
- **Attaques DMA** via les interfaces PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Pour une exploitation détaillée d’IOKit/DriverKit, voir :

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## Références

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h` (opérations `CS_OPS_*` et `CLEAR_LV_ENTITLEMENT)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (gestionnaire `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
