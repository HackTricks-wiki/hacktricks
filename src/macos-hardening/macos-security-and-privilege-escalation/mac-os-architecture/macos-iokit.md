# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Le I/O Kit est un **framework de pilote de périphérique** open-source et orienté objet dans le noyau XNU, gérant les **pilotes de périphérique chargés dynamiquement**. Il permet d'ajouter du code modulaire au noyau à la volée, prenant en charge un matériel diversifié.

Les pilotes IOKit vont essentiellement **exporter des fonctions du noyau**. Ces paramètres de fonction **types** sont **prédéfinis** et sont vérifiés. De plus, similaire à XPC, IOKit est juste une autre couche au **dessus des messages Mach**.

Le **code IOKit du noyau XNU** est open-source par Apple sur [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). De plus, les composants IOKit de l'espace utilisateur sont également open-source [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Cependant, **aucun pilote IOKit** n'est open-source. Quoi qu'il en soit, de temps en temps, une version d'un pilote peut venir avec des symboles qui facilitent son débogage. Vérifiez comment [**obtenir les extensions de pilote à partir du firmware ici**](#ipsw)**.**

Il est écrit en **C++**. Vous pouvez obtenir des symboles C++ démanglés avec :
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> Les fonctions **exposées** d'IOKit pourraient effectuer des **vérifications de sécurité supplémentaires** lorsqu'un client essaie d'appeler une fonction, mais notez que les applications sont généralement **limitées** par le **sandbox** avec lequel elles peuvent interagir avec les fonctions d'IOKit.

## Pilotes

Dans macOS, ils se trouvent dans :

- **`/System/Library/Extensions`**
- Fichiers KEXT intégrés au système d'exploitation OS X.
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
Jusqu'au numéro 9, les pilotes listés sont **chargés à l'adresse 0**. Cela signifie qu'il ne s'agit pas de véritables pilotes mais **d'une partie du noyau et qu'ils ne peuvent pas être déchargés**.

Pour trouver des extensions spécifiques, vous pouvez utiliser :
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Pour charger et décharger des extensions de noyau, faites :
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

Le **IORegistry** est une partie cruciale du framework IOKit dans macOS et iOS qui sert de base de données pour représenter la configuration matérielle et l'état du système. C'est une **collection hiérarchique d'objets qui représentent tout le matériel et les pilotes** chargés sur le système, et leurs relations entre eux.

Vous pouvez obtenir l'IORegistry en utilisant le cli **`ioreg`** pour l'inspecter depuis la console (particulièrement utile pour iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Vous pouvez télécharger **`IORegistryExplorer`** depuis **Xcode Additional Tools** à partir de [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) et inspecter le **macOS IORegistry** via une interface **graphique**.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

Dans IORegistryExplorer, les "plans" sont utilisés pour organiser et afficher les relations entre différents objets dans l'IORegistry. Chaque plan représente un type spécifique de relation ou une vue particulière de la configuration matérielle et des pilotes du système. Voici quelques-uns des plans courants que vous pourriez rencontrer dans IORegistryExplorer :

1. **IOService Plane** : C'est le plan le plus général, affichant les objets de service qui représentent les pilotes et les nubs (canaux de communication entre les pilotes). Il montre les relations fournisseur-client entre ces objets.
2. **IODeviceTree Plane** : Ce plan représente les connexions physiques entre les appareils tels qu'ils sont attachés au système. Il est souvent utilisé pour visualiser la hiérarchie des appareils connectés via des bus comme USB ou PCI.
3. **IOPower Plane** : Affiche les objets et leurs relations en termes de gestion de l'alimentation. Il peut montrer quels objets affectent l'état d'alimentation des autres, utile pour le débogage des problèmes liés à l'alimentation.
4. **IOUSB Plane** : Spécifiquement axé sur les appareils USB et leurs relations, montrant la hiérarchie des hubs USB et des appareils connectés.
5. **IOAudio Plane** : Ce plan est destiné à représenter les appareils audio et leurs relations au sein du système.
6. ...

## Exemple de code de communication de pilote

Le code suivant se connecte au service IOKit `"YourServiceNameHere"` et appelle la fonction à l'intérieur du sélecteur 0. Pour cela :

- il appelle d'abord **`IOServiceMatching`** et **`IOServiceGetMatchingServices`** pour obtenir le service.
- Il établit ensuite une connexion en appelant **`IOServiceOpen`**.
- Et enfin, il appelle une fonction avec **`IOConnectCallScalarMethod`** en indiquant le sélecteur 0 (le sélecteur est le numéro que la fonction que vous souhaitez appeler a assigné).
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
Il existe d'autres fonctions qui peuvent être utilisées pour appeler des fonctions IOKit en plus de **`IOConnectCallScalarMethod`** comme **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Inversion du point d'entrée du pilote

Vous pourriez les obtenir par exemple à partir d'une [**image de firmware (ipsw)**](#ipsw). Ensuite, chargez-la dans votre décompilateur préféré.

Vous pourriez commencer à décompiler la fonction **`externalMethod`** car c'est la fonction du pilote qui recevra l'appel et appellera la fonction correcte :

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Cet appel horrible démanglé signifie :
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Notez comment dans la définition précédente le paramètre **`self`** est manquant, la bonne définition serait :
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
En fait, vous pouvez trouver la véritable définition dans [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388) :
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Avec ces informations, vous pouvez réécrire Ctrl+Right -> `Edit function signature` et définir les types connus :

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Le nouveau code décompilé ressemblera à :

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Pour l'étape suivante, nous devons avoir défini la structure **`IOExternalMethodDispatch2022`**. Elle est open source dans [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), vous pourriez la définir :

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Maintenant, en suivant le `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, vous pouvez voir beaucoup de données :

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Changez le type de données en **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

après le changement :

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Et comme nous le savons maintenant, nous avons un **tableau de 7 éléments** (vérifiez le code décompilé final), cliquez pour créer un tableau de 7 éléments :

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Après la création du tableau, vous pouvez voir toutes les fonctions exportées :

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Si vous vous souvenez, pour **appeler** une fonction **exportée** depuis l'espace utilisateur, nous n'avons pas besoin d'appeler le nom de la fonction, mais le **numéro de sélecteur**. Ici, vous pouvez voir que le sélecteur **0** est la fonction **`initializeDecoder`**, le sélecteur **1** est **`startDecoder`**, le sélecteur **2** **`initializeEncoder`**...

{{#include ../../../banners/hacktricks-training.md}}
