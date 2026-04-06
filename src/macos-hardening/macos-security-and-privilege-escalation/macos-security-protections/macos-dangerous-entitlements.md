# macOS Entitlements dangereuses & permissions TCC

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Notez que les entitlements commençant par **`com.apple`** ne sont pas disponibles pour des tiers, seul Apple peut les accorder... Ou si vous utilisez un certificat d'entreprise vous pourriez en réalité créer vos propres entitlements commençant par **`com.apple`** et ainsi contourner des protections basées sur cela.

## Élevé

### `com.apple.rootless.install.heritable`

L'entitlement **`com.apple.rootless.install.heritable`** permet de **contourner SIP**. Consultez [ceci pour plus d'informations](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

L'entitlement **`com.apple.rootless.install`** permet de **contourner SIP**. Consultez [ceci pour plus d'informations](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Cet entitlement permet d'obtenir le **task port pour n'importe quel** processus, à l'exception du kernel. Consultez [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Cet entitlement permet à d'autres processus possédant l'entitlement **`com.apple.security.cs.debugger`** d'obtenir le task port du processus exécuté par le binaire ayant cet entitlement et d'**y injecter du code**. Consultez [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Les apps avec le Debugging Tool Entitlement peuvent appeler `task_for_pid()` pour récupérer un task port valide pour des apps non signées et tierces dont l'entitlement `Get Task Allow` est réglé sur `true`. Cependant, même avec le debugging tool entitlement, un débogueur **ne peut pas obtenir les task ports** des processus qui **n'ont pas l'entitlement `Get Task Allow`**, et qui sont donc protégés par System Integrity Protection. Consultez [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Cet entitlement permet de **charger des frameworks, plug-ins ou librairies sans qu'ils soient signés par Apple ou signés avec le même Team ID** que l'exécutable principal, de sorte qu'un attaquant pourrait abuser d'un chargement arbitraire de librairie pour injecter du code. Consultez [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Cet entitlement est très similaire à **`com.apple.security.cs.disable-library-validation`** mais **au lieu** de **désactiver directement** la validation des librairies, il permet au processus d'**appeler un syscall `csops` pour la désactiver**.\
Consultez [**this for more info**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Cet entitlement permet d'**utiliser les variables d'environnement DYLD** qui peuvent être utilisées pour injecter des librairies et du code. Consultez [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**Selon ce blog**](https://objective-see.org/blog/blog_0x4C.html) **et** [**ce blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ces entitlements permettent de **modifier** la base de données **TCC**.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

Ces entitlements permettent d'**installer des logiciels sans demander les permissions** à l'utilisateur, ce qui peut être utile pour une **élévation de privilèges**.

### `com.apple.private.security.kext-management`

Entitlement nécessaire pour demander au **kernel de charger une kernel extension**.

### **`com.apple.private.icloud-account-access`**

Avec l'entitlement **`com.apple.private.icloud-account-access`**, il est possible de communiquer avec le service XPC **`com.apple.iCloudHelper`** qui fournira des **jetons iCloud**.

**iMovie** et **Garageband** avaient cet entitlement.

Pour plus d'**informations** sur l'exploit permettant d'**obtenir des jetons iCloud** à partir de cet entitlement, regardez la conférence : [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO : Je ne sais pas ce que cela permet de faire

### `com.apple.private.apfs.revert-to-snapshot`

TODO : Dans [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) il est mentionné que cela pourrait être utilisé pour mettre à jour le contenu protégé par SSV après un redémarrage. Si vous savez comment, envoyez un PR s'il vous plaît !

### `com.apple.private.apfs.create-sealed-snapshot`

TODO : Dans [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) il est mentionné que cela pourrait être utilisé pour mettre à jour le contenu protégé par SSV après un redémarrage. Si vous savez comment, envoyez un PR s'il vous plaît !

### `keychain-access-groups`

Cet entitlement liste les groupes du **keychain** auxquels l'application a accès :
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

Accorde la permission **Accès complet au disque**, l'une des permissions TCC les plus élevées qu'on peut obtenir.

### **`kTCCServiceAppleEvents`**

Permet à l'application d'envoyer des événements à d'autres applications couramment utilisées pour **l'automatisation des tâches**. En contrôlant d'autres applications, elle peut abuser des permissions accordées à ces applications.

Par exemple, les forcer à demander à l'utilisateur son mot de passe :
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Ou les faire effectuer des **actions arbitraires**.

### **`kTCCServiceEndpointSecurityClient`**

Permet, entre autres permissions, d'**écrire la base de données TCC de l'utilisateur**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permet de **modifier** l'attribut **`NFSHomeDirectory`** d'un utilisateur, ce qui change le chemin de son dossier personnel et permet donc de **contourner TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permet de modifier des fichiers à l'intérieur du bundle d'une app (dans app.app), ce qui est **interdit par défaut**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Il est possible de vérifier qui a cet accès dans _Paramètres Système_ > _Confidentialité & Security_ > _App Management._

### `kTCCServiceAccessibility`

Le processus pourra **abuser des fonctionnalités d'accessibilité de macOS**, ce qui signifie par exemple qu'il pourra simuler des frappes au clavier. Il pourrait donc demander l'accès pour contrôler une app comme Finder et approuver la boîte de dialogue avec cette permission.

## Autorisations liées à Trustcache/CDhash

Certaines autorisations peuvent être utilisées pour contourner les protections Trustcache/CDhash, qui empêchent l'exécution de versions rétrogradées de binaires Apple.

## Medium

### `com.apple.security.cs.allow-jit`

Cette autorisation permet de **créer de la mémoire à la fois modifiable et exécutable** en passant le flag `MAP_JIT` à la fonction système `mmap()`. Consultez [**plus d'infos**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Cette autorisation permet de **remplacer ou patcher du code C**, d'utiliser la fonction obsolète **`NSCreateObjectFileImageFromMemory`** (qui est fondamentalement peu sûre), ou d'utiliser le framework **DVDPlayback**. Consultez [**plus d'infos**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> L'inclusion de cette autorisation expose votre app aux vulnérabilités courantes des langages non sécurisés en mémoire. Réfléchissez attentivement à la nécessité de cette exception pour votre app.

### `com.apple.security.cs.disable-executable-page-protection`

Cette autorisation permet de **modifier des sections de ses propres fichiers exécutables** sur disque pour forcer la sortie. Consultez [**plus d'infos**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> L'entitlement Disable Executable Memory Protection est une autorisation extrême qui supprime une protection de sécurité fondamentale de votre app, rendant possible pour un attaquant de réécrire le code exécutable de votre app sans détection. Préférez des autorisations plus restreintes si possible.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Cette autorisation permet de monter un système de fichiers nullfs (interdit par défaut). Outil : [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Selon ce billet de blog, cette permission TCC se trouve généralement sous la forme :
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Autoriser le processus à **demander toutes les autorisations TCC**.

### **`kTCCServicePostEvent`**

Permet d'**injecter des événements clavier et souris synthétiques** à l'échelle du système via `CGEventPost()`. Un processus disposant de cette autorisation peut simuler des frappes, des clics de souris et des événements de défilement dans n'importe quelle application — offrant de facto un **contrôle à distance** du bureau.

Ceci est particulièrement dangereux combiné avec `kTCCServiceAccessibility` ou `kTCCServiceListenEvent`, car cela permet à la fois de lire ET d'injecter des entrées.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Permet d'**intercepter tous les événements clavier et souris** à l'échelle du système (input monitoring / keylogging). Un processus peut enregistrer un `CGEventTap` pour capturer chaque frappe effectuée dans n'importe quelle application, y compris les mots de passe, numéros de carte bancaire et messages privés.

Pour des techniques d'exploitation détaillées, voir :

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Permet de **lire le tampon d'affichage** — prendre des captures d'écran et enregistrer la vidéo de l'écran de n'importe quelle application, y compris les champs de texte sécurisés. Associé à de l'OCR, cela peut extraire automatiquement les mots de passe et données sensibles affichées à l'écran.

> [!WARNING]
> À partir de macOS Sonoma, la capture d'écran affiche un indicateur permanent dans la barre de menu. Sur les versions antérieures, l'enregistrement d'écran peut être totalement silencieux.

### **`kTCCServiceCamera`**

Permet de **capturer des photos et des vidéos** depuis la caméra intégrée ou des caméras USB connectées. L'injection de code dans un binaire doté de l'entitlement camera permet une surveillance visuelle silencieuse.

### **`kTCCServiceMicrophone`**

Permet d'**enregistrer l'audio** depuis tous les périphériques d'entrée. Des daemons en arrière-plan disposant de l'accès au micro offrent une surveillance audio ambiante persistante sans fenêtre d'application visible.

### **`kTCCServiceLocation`**

Permet d'interroger la **position physique** de l'appareil via la triangulation Wi‑Fi ou des balises Bluetooth. Une surveillance continue révèle adresses domicile/travail, trajets et routines quotidiennes.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Accès aux **Contacts** (noms, e‑mails, numéros de téléphone — utile pour le spear-phishing), **Calendrier** (horaires des réunions, listes de participants) et **Photos** (photos personnelles, captures d'écran pouvant contenir des identifiants, métadonnées de localisation).

Pour des techniques complètes de vol d'identifiants via les permissions TCC, voir :

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** affaiblissent l'App Sandbox en permettant la communication avec des services Mach/XPC système que le sandbox bloque normalement. Il s'agit de la **primitive principale d'évasion du sandbox** — une application sandboxée compromise peut utiliser des exceptions mach-lookup pour atteindre des daemons privilégiés et exploiter leurs interfaces XPC.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Pour la chaîne d'exploitation détaillée : sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, voir :

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** permettent aux binaires de pilotes en espace utilisateur de communiquer directement avec le kernel via les interfaces IOKit. Les binaires DriverKit gèrent le matériel : USB, Thunderbolt, PCIe, périphériques HID, audio et réseau.

La compromission d'un binaire DriverKit permet :
- **Kernel attack surface** par des appels `IOConnectCallMethod` malformés
- **USB device spoofing** (simuler un clavier pour l'injection HID)
- **DMA attacks** à travers les interfaces PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Pour une exploitation détaillée d'IOKit/DriverKit, voir:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}



{{#include ../../../banners/hacktricks-training.md}}
