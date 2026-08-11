# Entitlements dangereux de macOS et perms TCC

{{#include ../../../banners/hacktricks-training.md}}

Les entitlements déclarent les capacités et les exceptions de sécurité que le système d’exploitation accorde au code signé. Les entrées ci-dessous se concentrent sur celles qui sont particulièrement utiles lors d’une revue offensive.<sup>[[13]](#references)</sup>

> [!WARNING]
> Notez que les entitlements commençant par **`com.apple`** ne sont pas disponibles pour les tiers : seul Apple peut les accorder... Ou, si vous utilisez un certificat d’entreprise, vous pourriez en fait créer vos propres entitlements commençant par **`com.apple`** et bypass les protections basées sur ce mécanisme.

## Élevé

### `com.apple.rootless.install.heritable`

L’entitlement **`com.apple.rootless.install.heritable`** permet à un processus de **bypass SIP**. Consultez [cette page pour plus d’informations](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

L’entitlement **`com.apple.rootless.install`** permet à un processus de **bypass SIP**. Consultez [cette page pour plus d’informations](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (précédemment appelé `task_for_pid-allow`)**

Cet entitlement permet à un processus d’obtenir le **task port de n’importe quel** processus, à l’exception du kernel. Consultez [**cette page pour plus d’informations**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Cet entitlement permet à d’autres processus possédant l’entitlement **`com.apple.security.cs.debugger`** d’obtenir le task port du processus exécuté par le binaire possédant cet entitlement et d’y **injecter du code**. Consultez [**cette page pour plus d’informations**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Les applications possédant le Debugging Tool Entitlement peuvent appeler `task_for_pid()` afin de récupérer un task port valide pour les applications non signées et tierces dont l’entitlement `Get Task Allow` est défini sur `true`. Cependant, même avec le debugging tool entitlement, un debugger **ne peut pas obtenir les task ports** des processus qui **ne possèdent pas l’entitlement `Get Task Allow`** et qui sont donc protégés par System Integrity Protection. Consultez [**cette page pour plus d’informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Cet entitlement permet à une application de **charger des frameworks, des plug-ins ou des libraries sans exiger qu’ils soient signés par Apple ou qu’ils possèdent le même Team ID** que l’exécutable principal ; un attaquant pourrait donc exploiter un chargement arbitraire de library pour injecter du code. Consultez [**cette page pour plus d’informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Cet entitlement est très similaire à **`com.apple.security.cs.disable-library-validation`**, mais **au lieu de désactiver directement** la validation des libraries, il permet au processus **d’appeler un appel système `csops` pour la désactiver** au runtime.

Le nom de l’entitlement est codé en dur dans XNU, à côté de l’opération `csops` qui l’utilise :<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Le gestionnaire du kernel pour `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) montre exactement à quel point la primitive est limitée :<sup>[[2]](#references)</sup>
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
Ainsi, l'opération :

- Est **uniquement disponible sur macOS** (`ENOTSUP` sur toutes les autres plateformes).
- Ne fonctionne que sur **lui-même** (`forself == 1`) — il est impossible de supprimer la library validation d'un autre processus avec cette opération.
- Nécessite que le processus **détienne réellement l'entitlement**, et échoue si le processus est marqué `CS_INSTALLER` ou s'exécute sous un chemin racine de subsystem.
- Supprime **`CS_REQUIRE_LV | CS_FORCED_LV`** des flags de signature du code du processus.

Le commentaire de XNU explique le cas d'utilisation prévu, ainsi que la raison pour laquelle il est intéressant pour un attaquant :

> Cette option sert à supprimer la library validation d'un processus en cours d'exécution. Elle est utilisée dans les architectures de plug-ins lorsqu'un programme doit charger des bibliothèques non fiables. [...] Une fois que le processus a chargé la bibliothèque non fiable, il ne sera plus efficace de s'appuyer à l'avenir sur la library validation.

En d'autres termes, **tout binaire portant cet entitlement est une cible de dylib-injection** : faites exécuter du code à l'intérieur (ou convainquez-le de charger votre plug-in) après qu'il a supprimé `CS_REQUIRE_LV`, et vous héritez de tout ce que le processus hôte est autorisé à faire.

### `com.apple.security.cs.allow-dyld-environment-variables`

Cet entitlement permet **d'utiliser les variables d'environnement DYLD**, qui peuvent servir à injecter des bibliothèques et du code. Consultez [**cette page pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` ou `com.apple.rootless.storage`.`TCC`

[**Selon cet article de blog**](https://objective-see.org/blog/blog_0x4C.html) **et** [**cet article de blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ces entitlements permettent à un processus de **modifier** la base de données **TCC**.<sup>[[6]](#references)[[7]](#references)</sup>

### Droits d'autorisation **`system.install.apple-software`** et **`system.install.apple-software.standard-user`**

Ces droits d'Authorization Services régissent l'installation des logiciels fournis par Apple. Un processus autorisé à les obtenir peut contourner le flux d'autorisation habituel, ce qui peut être utile pour une **élévation de privilèges**.<sup>[[14]](#references)</sup>

### `com.apple.private.security.kext-management`

Entitlement nécessaire pour demander au **kernel de charger une kernel extension**.

### **`com.apple.private.icloud-account-access`**

L'entitlement **`com.apple.private.icloud-account-access`** permet de communiquer avec le service XPC **`com.apple.iCloudHelper`**, qui **fournira des tokens iCloud**.

**iMovie** et **Garageband** disposaient de cet entitlement.

Pour plus d'**informations** sur l'exploit permettant d'**obtenir des tokens iCloud** grâce à cet entitlement, consultez la conférence : [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO : je ne sais pas ce que cela permet de faire

### `com.apple.private.apfs.revert-to-snapshot`

TODO : [**Ce rapport**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) mentionne que cet entitlement pourrait être utilisé pour mettre à jour des contenus protégés par SSV après un redémarrage. Si vous savez comment, envoyez un PR !<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO : [**Le même rapport**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) mentionne que la création d'un snapshot scellé pourrait être utilisée pour mettre à jour des contenus protégés par SSV après un redémarrage. Si vous savez comment, envoyez un PR !<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Cet entitlement liste les groupes **keychain** auxquels l'application a accès :
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

Accorde les permissions **Full Disk Access**, l’une des permissions TCC les plus élevées que vous puissiez obtenir.

### **`kTCCServiceAppleEvents`**

Permet à l’application d’envoyer des événements à d’autres applications couramment utilisées pour **automatiser des tâches**. En contrôlant d’autres applications, elle peut abuser des permissions accordées à ces dernières.

Par exemple, en leur faisant demander son mot de passe à l’utilisateur :
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Ou en leur faisant effectuer des **actions arbitraires**.

### **`kTCCServiceEndpointSecurityClient`**

Permet, entre autres permissions, d’**écrire dans la base de données TCC de l’utilisateur**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permet de **modifier** l’attribut **`NFSHomeDirectory`** d’un utilisateur, ce qui modifie le chemin de son dossier personnel et permet donc de **bypasser TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permet de modifier les fichiers à l’intérieur des bundles d’applications (dans app.app), ce qui est **interdit par défaut**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Il est possible de vérifier qui dispose de cet accès dans _Réglages Système_ > _Confidentialité et sécurité_ > _Gestion des applications._

### `kTCCServiceAccessibility`

Le processus pourra **abuser des fonctionnalités d’accessibilité de macOS**, ce qui signifie que, par exemple, il pourra simuler des frappes au clavier. Il pourra donc demander l’accès pour contrôler une application comme Finder et approuver la boîte de dialogue avec cette permission.

## Entitlements liés à Trustcache/CDhash

Certains entitlements pourraient être utilisés pour bypasser les protections Trustcache/CDhash, qui empêchent l’exécution de versions rétrogradées des binaires Apple.

## Moyen

### `com.apple.security.cs.allow-jit`

Cet entitlement permet à un processus de **créer une mémoire à la fois inscriptible et exécutable** en transmettant le flag `MAP_JIT` à la fonction système `mmap()`. Consultez [**cette page pour plus d’informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Cet entitlement permet de **remplacer ou patcher du code C**, d’utiliser le **`NSCreateObjectFileImageFromMemory`** obsolète depuis longtemps (qui est fondamentalement non sécurisé) ou d’utiliser le framework **DVDPlayback**. Consultez [**cette page pour plus d’informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Inclure cet entitlement expose votre application aux vulnérabilités courantes des langages dont le code n’est pas sécurisé vis-à-vis de la mémoire. Examinez attentivement si votre application a besoin de cette exception.

### `com.apple.security.cs.disable-executable-page-protection`

Cet entitlement permet de **modifier sur le disque des sections de ses propres fichiers exécutables** afin de forcer sa fermeture. Consultez [**cette page pour plus d’informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> L’Entitlement Disable Executable Memory Protection est un entitlement extrême qui supprime une protection de sécurité fondamentale de votre application, permettant à un attaquant de réécrire le code exécutable de votre application sans être détecté. Privilégiez des entitlements plus ciblés si possible.

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
Autorise le processus à **demander toutes les permissions TCC**.

### **`kTCCServicePostEvent`**

Autorise **l’injection d’événements synthétiques du clavier et de la souris** à l’échelle du système via `CGEventPost()`. Un processus disposant de cette permission peut simuler des frappes, des clics de souris et des événements de défilement dans n’importe quelle application, ce qui lui fournit effectivement un **contrôle à distance** du bureau.

C’est particulièrement dangereux lorsqu’elle est combinée à `kTCCServiceAccessibility` ou `kTCCServiceListenEvent`, car cela permet à la fois de lire les entrées et d’en injecter.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Permet **d'intercepter tous les événements du clavier et de la souris** à l'échelle du système (input monitoring / keylogging). Un processus peut enregistrer un `CGEventTap` pour capturer chaque frappe saisie dans n'importe quelle application, notamment les mots de passe, les numéros de carte bancaire et les messages privés.

Pour des techniques d'exploitation détaillées, voir :

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Permet de **lire le buffer d'affichage** — prendre des captures d'écran et enregistrer la vidéo de l'écran de n'importe quelle application, y compris les champs de texte sécurisés. Combiné à l'OCR, cela peut extraire automatiquement les mots de passe et les données sensibles affichés à l'écran.

> [!WARNING]
> Depuis macOS Sonoma, la capture d'écran affiche un indicateur persistant dans la barre des menus. Sur les versions antérieures, l'enregistrement de l'écran peut être totalement silencieux.

### **`kTCCServiceCamera`**

Permet de **capturer des photos et des vidéos** depuis la caméra intégrée ou des caméras USB connectées. Une code injection dans un binaire disposant de l'entitlement caméra permet une surveillance visuelle silencieuse.

### **`kTCCServiceMicrophone`**

Permet **d'enregistrer l'audio** depuis tous les périphériques d'entrée. Les daemons en arrière-plan disposant d'un accès au microphone permettent une surveillance audio ambiante persistante, sans fenêtre d'application visible.

### **`kTCCServiceLocation`**

Permet d'interroger la **localisation physique** de l'appareil via la triangulation Wi-Fi ou des balises Bluetooth. Une surveillance continue révèle les adresses du domicile et du travail, les habitudes de déplacement et les routines quotidiennes.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Accès aux **Contacts** (noms, adresses e-mail, numéros de téléphone — utiles pour le spear-phishing), au **Calendrier** (horaires des réunions, listes de participants) et aux **Photos** (photos personnelles, captures d'écran pouvant contenir des identifiants, métadonnées de localisation).

Pour les techniques complètes d'exploitation permettant le vol d'identifiants via les permissions TCC, voir :

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Entitlements de Sandbox et de Code Signing

### `com.apple.security.temporary-exception.mach-lookup.global-name`

Les **exceptions temporaires de Sandbox** affaiblissent l'App Sandbox en permettant la communication avec des services Mach/XPC accessibles à l'échelle du système, que la Sandbox bloque normalement. Il s'agit de la **primitive principale d'évasion de Sandbox** — une application compromise dans la Sandbox peut utiliser les exceptions mach-lookup pour atteindre des daemons privilégiés et exploiter leurs interfaces XPC.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
For detailed exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, see:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

Les **DriverKit entitlements** permettent aux binaires de pilotes en espace utilisateur de communiquer directement avec le kernel via les interfaces IOKit. Les binaires DriverKit gèrent le matériel : USB, Thunderbolt, PCIe, périphériques HID, audio et réseau.

La compromission d’un binaire DriverKit permet :
- **Surface d’attaque du kernel** via des appels `IOConnectCallMethod` malformés
- **Usurpation de périphériques USB** (émulation d’un clavier pour l’injection HID)
- **Attaques DMA** via les interfaces PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Pour une analyse détaillée de l’exploitation d’IOKit/DriverKit, voir :

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (opérations `CS_OPS_*` et `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (gestionnaire `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Entitlement pour les outils de débogage (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement pour désactiver la validation des libraries](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement pour autoriser les variables d’environnement DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934 : contournement de TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Jouer de la musique et contourner TCC, alias CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0 : « What Happens on your Mac, Stays on Apple's iCloud?! » - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Le cauchemar de la mise à jour OTA d’Apple : contournement de la vérification de signature et prise de contrôle du kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement pour autoriser l’exécution de code compilé par JIT (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement pour autoriser la mémoire exécutable non signée](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement pour désactiver la protection de la mémoire exécutable](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [14] [Apple Developer Archive — Guide de programmation des Authorization Services](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/01introduction/introduction.html)
{{#include ../../../banners/hacktricks-training.md}}
