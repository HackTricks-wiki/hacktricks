# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

I/O Kit est une **infrastructure open source de pilotes de périphériques**, orientée objet, intégrée au kernel XNU, qui gère les **pilotes de périphériques chargés dynamiquement**. Elle permet d'ajouter du code modulaire au kernel à la volée, prenant ainsi en charge divers matériels.

Les pilotes IOKit vont essentiellement **exporter des fonctions depuis le kernel**. Les **types** des paramètres de ces fonctions sont **prédéfinis** et vérifiés. De plus, comme XPC, IOKit n'est qu'une autre couche **au-dessus des messages Mach**.

Le **code IOKit du kernel XNU** est open source et publié par Apple sur [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). De plus, les composants IOKit de l'espace utilisateur sont également open source sur [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Cependant, **aucun pilote IOKit** n'est open source. Quoi qu'il en soit, il arrive parfois qu'une version d'un pilote soit publiée avec des symboles facilitant son debug. Découvrez ici comment [**récupérer les extensions de pilotes depuis le firmware**](#ipsw)**.**

Il est écrit en **C++**. Vous pouvez obtenir les symboles C++ demangled avec :
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> Les **fonctions exposées** d’IOKit peuvent effectuer des **vérifications de sécurité supplémentaires** lorsqu’un client tente d’appeler une fonction, mais notez que les applications sont généralement **limitées** par le **sandbox** quant aux fonctions d’IOKit avec lesquelles elles peuvent interagir.

## Pilotes

Dans macOS, ils se trouvent dans :

- **`/System/Library/Extensions`**
- Fichiers KEXT intégrés au système d’exploitation OS X.
- **`/Library/Extensions`**
- Fichiers KEXT installés par des logiciels tiers

Dans iOS, ils se trouvent dans :

- **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
Jusqu'au numéro 9, les pilotes listés sont **chargés à l'adresse 0**. Cela signifie que ce ne sont pas de véritables pilotes, mais qu'ils font **partie du kernel et ne peuvent pas être déchargés**.

Pour trouver des extensions spécifiques, vous pouvez utiliser :
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Pour charger et décharger les extensions du noyau, utilisez :
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

L'**IORegistry** est un composant crucial du framework IOKit dans macOS et iOS, qui sert de base de données représentant la configuration et l'état du matériel du système. Il s'agit d'une **collection hiérarchique d'objets représentant tout le matériel et les drivers** chargés sur le système, ainsi que leurs relations mutuelles.

Vous pouvez obtenir l'IORegistry à l'aide de la **CLI** **`ioreg`** afin de l'inspecter depuis la console (particulièrement utile pour iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Vous pouvez télécharger **`IORegistryExplorer`** depuis **Xcode Additional Tools** à l’adresse [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) et inspecter le **macOS IORegistry** via une interface **graphique**.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

Dans IORegistryExplorer, les « planes » servent à organiser et à afficher les relations entre les différents objets de l’IORegistry. Chaque plane représente un type spécifique de relation ou une vue particulière de la configuration matérielle et des drivers du système. Voici quelques-uns des planes courants que vous pouvez rencontrer dans IORegistryExplorer :

1. **IOService Plane** : Il s’agit du plane le plus général. Il affiche les objets de service qui représentent les drivers et les nubs (canaux de communication entre les drivers). Il montre les relations provider-client entre ces objets.
2. **IODeviceTree Plane** : Ce plane représente les connexions physiques entre les devices lorsqu’ils sont connectés au système. Il est souvent utilisé pour visualiser la hiérarchie des devices connectés via des bus comme USB ou PCI.
3. **IOPower Plane** : Affiche les objets et leurs relations en matière de gestion de l’alimentation. Il peut montrer quels objets affectent l’état d’alimentation d’autres objets, ce qui est utile pour déboguer les problèmes liés à l’alimentation.
4. **IOUSB Plane** : Se concentre spécifiquement sur les devices USB et leurs relations, en affichant la hiérarchie des hubs USB et des devices connectés.
5. **IOAudio Plane** : Ce plane sert à représenter les devices audio et leurs relations au sein du système.
6. ...

## Driver Comm Code Example

Le code suivant se connecte au service IOKit `YourServiceNameHere` et appelle le selector 0 :

- Il appelle d’abord **`IOServiceMatching`** et **`IOServiceGetMatchingServices`** pour obtenir le service.
- Il établit ensuite une connexion en appelant **`IOServiceOpen`**.
- Enfin, il appelle une fonction avec **`IOConnectCallScalarMethod`**, en indiquant le selector 0 (le selector correspond au numéro attribué à la fonction que vous souhaitez appeler).

<details>
<summary>Example user-space call to a driver selector</summary>
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
</details>

Il existe **d'autres** fonctions qui peuvent être utilisées pour appeler des fonctions IOKit en plus de **`IOConnectCallScalarMethod`**, comme **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reversing driver entrypoint

Vous pouvez par exemple les obtenir depuis une [**firmware image (ipsw)**](#ipsw). Chargez-la ensuite dans votre décompilateur préféré.

Vous pouvez commencer par décompiler la fonction **`externalMethod`**, car il s'agit de la fonction du driver qui recevra l'appel et appellera la fonction appropriée :

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Cet appel démêlé affreux signifie :
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Notez que dans la définition précédente, le paramètre **`self`** est omis ; la bonne définition serait :
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
En réalité, vous pouvez trouver la définition réelle dans [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388) :
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Avec ces informations, vous pouvez réécrire Ctrl+Right -> `Edit function signature` et définir les types connus :

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Le nouveau code décompilé ressemblera à ceci :

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Pour l'étape suivante, nous devons avoir défini la struct **`IOExternalMethodDispatch2022`**. Elle est open source sur [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), vous pouvez donc la définir :

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Maintenant, en suivant `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, vous pouvez voir beaucoup de données :

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Modifiez le type de données en **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

après la modification :

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Et comme nous savons qu'il s'agit d'un **array de 7 éléments** (consultez le code décompilé final), cliquez pour créer un array de 7 éléments :

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Une fois l'array créé, vous pouvez voir toutes les fonctions exportées :

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si vous vous en souvenez, pour **call** une fonction **exported** depuis user space, nous n'avons pas besoin d'appeler le nom de la fonction, mais son **selector number**. Ici, vous pouvez voir que le selector **0** correspond à la fonction **`initializeDecoder`**, le selector **1** correspond à **`startDecoder`**, le selector **2** à **`initializeEncoder`**...

## Surface d'attaque IOKit récente (2023–2025)

- **Capture de frappes via IOHIDFamily** – CVE-2024-27799 (14.5) a montré qu'un client `IOHIDSystem` permissif pouvait récupérer les événements HID même avec la saisie sécurisée activée ; assurez-vous que les handlers `externalMethod` appliquent les entitlements au lieu de vérifier uniquement le type de user-client.<sup>[[2]](#references)</sup>
- **Corruption mémoire dans IOGPUFamily** – CVE-2024-44197 et CVE-2025-24257 ont corrigé des écritures OOB accessibles depuis des applications sandboxées qui transmettent des données de longueur variable malformées aux user clients GPU ; le bug habituel vient de contrôles de limites insuffisants autour des arguments de `IOConnectCallStructMethod`.<sup>[[1]](#references)</sup>
- **Surveillance legacy des frappes** – CVE-2023-42891 (14.2) a confirmé que les user clients HID restent un vecteur de sandbox escape ; fuzz tout driver exposant des files d'attente de clavier/événements.<sup>[[3]](#references)</sup>

### Conseils rapides de triage et de fuzzing

- Énumérez toutes les méthodes externes d'un user client depuis le userland afin d'alimenter un fuzzer :
```bash
# list selectors for a service
python3 - <<'PY'
from ioreg import IORegistry
svc = 'IOHIDSystem'
reg = IORegistry()
obj = reg.get_service(svc)
for sel, name in obj.external_methods():
print(f"{sel:02d} {name}")
PY
```
- Lors du reverse, faites attention aux counts de `IOExternalMethodDispatch2022`. Un bug fréquent dans les CVE récentes est l’incohérence entre `structureInputSize`/`structureOutputSize` et la longueur réelle de `copyin`, ce qui peut entraîner un heap OOB dans `IOConnectCallStructMethod`.
- L’accessibilité depuis la Sandbox dépend toujours des entitlements. Avant de consacrer du temps à une cible, vérifiez si le client est autorisé depuis une application tierce :
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Pour les bugs GPU/iomfb, le passage de tableaux surdimensionnés via `IOConnectCallMethod` suffit souvent à déclencher des problèmes de limites. Minimal harness (selector X) pour déclencher une size confusion :
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — Pilotes en espace utilisateur

### Informations de base

**DriverKit** est le remplacement par Apple des extensions du kernel (kexts) en espace utilisateur, introduit dans macOS 10.15. Les binaires DriverKit (bundles `.dext`) s'exécutent comme des processus en espace utilisateur, mais communiquent directement avec le kernel via une interface IOKit privilégiée.<sup>[[4]](#references)</sup>

Les extensions DriverKit gèrent le matériel :
- Contrôleurs et périphériques **USB**
- Périphériques **Thunderbolt** / PCIe
- **HID** (claviers, souris, manettes de jeu)
- Matériel **audio**
- Interfaces **réseau**
- Périphériques **série** et de **stockage en mode bloc**

Contrairement aux kexts (qui nécessitaient un démarrage avec SIP désactivé ou une notarisation), les extensions DriverKit sont installées via `SystemExtensions.framework` et nécessitent uniquement une **approbation utilisateur unique**.<sup>[[5]](#references)</sup>

### Découverte et énumération
```bash
# List all installed system extensions (includes DriverKit)
systemextensionsctl list

# Find all DriverKit extension bundles
find / -name "*.dext" -type d 2>/dev/null

# Check a binary's DriverKit entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 | grep driverkit

# Common DriverKit entitlements:
# com.apple.developer.driverkit                    — Base DriverKit
# com.apple.developer.driverkit.transport.usb      — USB device access
# com.apple.developer.driverkit.transport.hid      — HID device access
# com.apple.developer.driverkit.transport.pci      — PCIe device access
# com.apple.developer.driverkit.transport.serial   — Serial port access
# com.apple.developer.driverkit.family.networking  — Network interface
# com.apple.developer.driverkit.family.audio       — Audio device
```
### Implications de sécurité

> [!WARNING]
> Les binaires DriverKit disposent d’un **canal de communication direct avec le kernel**. L’envoi de messages malformés via ce canal peut déclencher des vulnérabilités du kernel. Chaque driver enregistre des classes user-client spécifiques, et des appels `IOConnectCallMethod` malformés peuvent provoquer une corruption de la mémoire du kernel.

**Surface d’attaque :**
1. **Fuzzing des messages IOKit du kernel** — Chaque user-client DriverKit expose des selectors appelables depuis l’espace utilisateur. Des arguments malformés déclenchent des bugs du kernel.
2. **USB device spoofing** — Un binaire USB DriverKit compromis peut présenter le profil d’un périphérique USB malveillant (par exemple, émuler un clavier pour effectuer une injection HID).
3. **DMA attacks** — Les extensions DriverKit PCIe/Thunderbolt peuvent potentiellement accéder à la mémoire physique.
4. **Persistance** — Une fois installés en tant que system extension, les binaires DriverKit persistent après les redémarrages et les mises à jour des applications.

### Fuzzing des user-client IOKit de DriverKit
```bash
# Enumerate DriverKit user-client classes from entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 \
| grep -A5 "com.apple.developer.driverkit.transport"

# List IOService matching for DriverKit drivers
ioreg -l | grep -i "UserClientClass" | sort -u

# Check if the driver's user-client is reachable from a sandboxed app
ioreg -c IOService -r -d 1 | grep -E '"IOClass"|"CFBundleIdentifier"' | head -40

# Minimal fuzzing harness for a DriverKit selector:
```

```c
#include <IOKit/IOKitLib.h>

io_connect_t conn;
// ... open connection to the DriverKit service ...

// Fuzz selector X with oversized struct input
uint8_t buf[0x2000];
memset(buf, 'A', sizeof(buf));
size_t outSz = sizeof(buf);
kern_return_t kr = IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
// If the driver doesn't validate structureInputSize, this causes kernel OOB
```
### CVE DriverKit

| CVE | Description |
|---|---|
| CVE-2022-26766 | Vulnérabilité de la stack USB DriverKit — exécution de code dans le kernel |
| CVE-2021-30838 | Confusion de type user-client IOKit dans les pilotes graphiques |
| CVE-2024-44197 | Écriture OOB via des arguments DriverKit malformés dans IOGPUFamily |

## Références

- [1] [Mises à jour de sécurité Apple – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – résumé de IOHIDFamily CVE-2024-27799](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Mises à jour de sécurité Apple – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — System Extensions](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
