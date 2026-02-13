# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

The I/O Kit is an open-source, object-oriented **device-driver framework** in the XNU kernel, handles **dynamically loaded device drivers**. Il permet d'ajouter du code modulaire au noyau à la volée, prenant en charge du matériel varié.

IOKit drivers will basically **export functions from the kernel**. These function parameter **types** are **predefined** and are verified. Moreover, similar to XPC, IOKit is just another layer on **top of Mach messages**.

**IOKit XNU kernel code** is opensourced by Apple in [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Moreover, the user space IOKit components are also opensource [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

However, **no IOKit drivers** are opensource. Anyway, from time to time a release of a driver might come with symbols that makes it easier to debug it. See how to [**get the driver extensions from the firmware here**](#ipsw)**.**

It's written in **C++**. You can get demangled C++ symbols with:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> Les **fonctions exposées** d'IOKit peuvent effectuer des **vérifications de sécurité supplémentaires** lorsqu'un client essaie d'appeler une fonction, mais notez que les apps sont généralement **limitées** par le **sandbox** quant aux fonctions IOKit avec lesquelles elles peuvent interagir.

## Pilotes

Sur macOS, ils se trouvent dans :

- **`/System/Library/Extensions`**
- Fichiers KEXT intégrés au système d'exploitation OS X.
- **`/Library/Extensions`**
- Fichiers KEXT installés par des logiciels tiers

Sur iOS, ils se trouvent dans :

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
Jusqu'au numéro 9, les drivers listés sont **loaded in the address 0**. Cela signifie que ceux-ci ne sont pas de vrais drivers mais **part of the kernel and they cannot be unloaded**.

Pour trouver des extensions spécifiques, vous pouvez utiliser :
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Pour charger et décharger des kernel extensions, faites :
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

L'**IORegistry** est une partie essentielle du framework IOKit dans macOS et iOS qui sert de base de données pour représenter la configuration matérielle et l'état du système. C'est une **collection hiérarchique d'objets représentant tout le matériel et les pilotes** chargés sur le système, et leurs relations entre eux.

Vous pouvez obtenir l'IORegistry en utilisant la cli **`ioreg`** pour l'inspecter depuis la console (particulièrement utile pour iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Vous pouvez télécharger **`IORegistryExplorer`** depuis **Xcode Additional Tools** sur [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) et inspecter le **macOS IORegistry** via une interface **graphique**.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

Dans IORegistryExplorer, les « planes » sont utilisés pour organiser et afficher les relations entre différents objets dans l'IORegistry. Chaque plane représente un type spécifique de relation ou une vue particulière de la configuration matérielle et des drivers du système. Voici quelques-unes des planes courantes que vous pouvez rencontrer dans IORegistryExplorer :

1. **IOService Plane** : C'est la plane la plus générale, affichant les objets de service qui représentent les drivers et les nubs (canaux de communication entre drivers). Elle montre les relations fournisseur-client entre ces objets.
2. **IODeviceTree Plane** : Cette plane représente les connexions physiques entre les périphériques tels qu'ils sont attachés au système. Elle est souvent utilisée pour visualiser la hiérarchie des périphériques connectés via des bus comme USB ou PCI.
3. **IOPower Plane** : Affiche les objets et leurs relations en termes de gestion de l'alimentation. Elle peut montrer quels objets affectent l'état d'alimentation des autres, utile pour déboguer des problèmes liés à l'alimentation.
4. **IOUSB Plane** : Spécifiquement axée sur les périphériques USB et leurs relations, montrant la hiérarchie des hubs USB et des périphériques connectés.
5. **IOAudio Plane** : Cette plane sert à représenter les périphériques audio et leurs relations au sein du système.
6. ...

## Exemple de code de communication avec le driver

Le code suivant se connecte au service IOKit `YourServiceNameHere` et appelle le selector 0 :

- Il appelle d'abord **`IOServiceMatching`** et **`IOServiceGetMatchingServices`** pour obtenir le service.
- Il établit ensuite une connexion appelant **`IOServiceOpen`**.
- Et il appelle enfin une fonction avec **`IOConnectCallScalarMethod`** en indiquant le selector 0 (le selector est le numéro assigné à la fonction que vous voulez appeler).

<details>
<summary>Exemple d'appel en espace utilisateur vers un selector de driver</summary>
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

Il existe **d'autres** fonctions qui peuvent être utilisées pour appeler des fonctions IOKit en dehors de **`IOConnectCallScalarMethod`** comme **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Rétro-ingénierie du point d'entrée du driver

Vous pouvez obtenir celles-ci par exemple à partir d'une [**firmware image (ipsw)**](#ipsw). Ensuite, chargez-les dans votre decompiler préféré.

Vous pouvez commencer à décompiler la fonction **`externalMethod`**, car c'est la fonction du driver qui recevra l'appel et appellera la fonction correcte :

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Cet horrible call demangled signifie :
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Notez que dans la définition précédente le paramètre **`self`** est manquant, la bonne définition serait :
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
En fait, vous pouvez trouver la définition réelle dans [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Avec ces informations vous pouvez réécrire Ctrl+Right -> `Edit function signature` et définir les types connus :

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Le nouveau code décompilé ressemblera à :

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Pour l'étape suivante, il faut avoir défini la struct **`IOExternalMethodDispatch2022`**. Elle est open source dans [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), vous pouvez la définir :

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Maintenant, en suivant `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` vous pouvez voir beaucoup de données :

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Changez le Data Type en **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

après le changement :

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Et comme nous y sommes maintenant nous avons un **array of 7 elements** (vérifiez le code décompilé final), cliquez pour créer un array of 7 elements :

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Après la création de l'array vous pouvez voir toutes les fonctions exportées :

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si vous vous souvenez, pour **call** une fonction **exported** depuis l'espace utilisateur nous n'avons pas besoin d'appeler le nom de la fonction, mais le **selector number**. Ici vous pouvez voir que le selector **0** est la fonction **`initializeDecoder`**, le selector **1** est **`startDecoder`**, le selector **2** **`initializeEncoder`**...

## Surface d'attaque IOKit récente (2023–2025)

- **Keystroke capture via IOHIDFamily** – CVE-2024-27799 (14.5) a montré qu'un client permissif `IOHIDSystem` pouvait capter des HID events même avec secure input ; assurez-vous que les handlers `externalMethod` appliquent les entitlements au lieu de se baser uniquement sur le type du user-client.
- **IOGPUFamily memory corruption** – CVE-2024-44197 et CVE-2025-24257 ont corrigé des OOB writes accessibles depuis des apps sandboxed qui passent des données de longueur variable malformées aux GPU user clients ; le bug habituel est un mauvais contrôle des bornes autour des arguments de `IOConnectCallStructMethod`.
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) a confirmé que les HID user clients restent un vecteur d'évasion de sandbox ; fuzzez tout driver exposant keyboard/event queues.

### Conseils rapides de triage & fuzzing

- Enumérez toutes les external methods pour un user client depuis userland pour seed un fuzzer:
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
- When reversing, faites attention aux compteurs `IOExternalMethodDispatch2022`. Un motif de bug fréquent dans des CVE récentes est l'incohérence entre `structureInputSize`/`structureOutputSize` et la longueur réelle de `copyin`, entraînant un heap OOB dans `IOConnectCallStructMethod`.
- Sandbox reachability dépend toujours des entitlements. Avant de passer du temps sur une cible, vérifiez si le client est autorisé depuis une third‑party app :
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Pour les bugs GPU/iomfb, passer des tableaux surdimensionnés via `IOConnectCallMethod` suffit souvent à déclencher des vérifications de limites incorrectes. Banc d'essai minimal (sélecteur X) pour déclencher une confusion de tailles :
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## Références

- [Mises à jour de sécurité Apple – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [Rapid7 – Résumé de IOHIDFamily CVE-2024-27799](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [Mises à jour de sécurité Apple – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
{{#include ../../../banners/hacktricks-training.md}}
