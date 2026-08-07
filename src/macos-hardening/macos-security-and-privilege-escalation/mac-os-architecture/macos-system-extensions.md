# Extensions système de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Extensions système / Endpoint Security Framework

Contrairement aux Kernel Extensions, les **System Extensions s’exécutent dans l’espace utilisateur** plutôt que dans l’espace noyau, ce qui réduit le risque de crash du système dû à un dysfonctionnement de l’extension.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Il existe trois types d’extensions système : les extensions **DriverKit**, les extensions **Network** et les extensions **Endpoint Security**.

### **Extensions DriverKit**

DriverKit remplace les extensions du noyau qui **fournissent la prise en charge du matériel**. Il permet aux pilotes de périphériques (comme les pilotes USB, Serial, NIC et HID) de s’exécuter dans l’espace utilisateur plutôt que dans l’espace noyau. Le framework DriverKit inclut des **versions espace utilisateur de certaines classes I/O Kit**, et le noyau transmet les événements I/O Kit normaux à l’espace utilisateur, offrant ainsi un environnement plus sûr pour l’exécution de ces pilotes.<sup>[[2]](#references)</sup>

### **Network Extensions**

Les Network Extensions permettent de personnaliser les comportements réseau. Il existe plusieurs types de Network Extensions :

- **App Proxy** : utilisé pour créer un client VPN qui implémente un protocole VPN personnalisé orienté flux. Cela signifie qu’il gère le trafic réseau en fonction des connexions (ou flux), plutôt que des paquets individuels.
- **Packet Tunnel** : utilisé pour créer un client VPN qui implémente un protocole VPN personnalisé orienté paquets. Cela signifie qu’il gère le trafic réseau en fonction des paquets individuels.
- **Filter Data** : utilisé pour filtrer les « flux » réseau. Il peut surveiller ou modifier les données réseau au niveau des flux.
- **Filter Packet** : utilisé pour filtrer les paquets réseau individuels. Il peut surveiller ou modifier les données réseau au niveau des paquets.
- **DNS Proxy** : utilisé pour créer un fournisseur DNS personnalisé. Il peut être utilisé pour surveiller ou modifier les requêtes et réponses DNS.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security est un framework fourni par Apple dans macOS qui offre un ensemble d’API dédiées à la sécurité du système. Il est destiné aux **fournisseurs de solutions de sécurité et aux développeurs souhaitant créer des produits capables de surveiller et de contrôler l’activité du système** afin d’identifier les activités malveillantes et de s’en protéger.

Ce framework fournit une **collection d’API permettant de surveiller et de contrôler l’activité du système**, notamment les exécutions de processus, les événements du système de fichiers, ainsi que les événements réseau et noyau.

Le cœur de ce framework est implémenté dans le noyau sous la forme d’une Kernel Extension (KEXT) située à **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[[2]](#references)</sup> Cette KEXT est composée de plusieurs éléments clés :

- **EndpointSecurityDriver** : agit comme le « point d’entrée » de l’extension du noyau. Il constitue le principal point d’interaction entre l’OS et le framework Endpoint Security.
- **EndpointSecurityEventManager** : ce composant est chargé d’implémenter les hooks du noyau. Les hooks du noyau permettent au framework de surveiller les événements système en interceptant les appels système.
- **EndpointSecurityClientManager** : gère la communication avec les clients de l’espace utilisateur, en suivant les clients connectés et ceux qui doivent recevoir les notifications d’événements.
- **EndpointSecurityMessageManager** : envoie des messages et des notifications d’événements aux clients de l’espace utilisateur.

Les événements que le framework Endpoint Security peut surveiller sont répartis dans les catégories suivantes :

- Événements liés aux fichiers
- Événements liés aux processus
- Événements liés aux sockets
- Événements liés au noyau (comme le chargement/déchargement d’une extension du noyau ou l’ouverture d’un périphérique I/O Kit)

### Architecture du Endpoint Security Framework

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

La **communication depuis l’espace utilisateur** avec le framework Endpoint Security s’effectue via la classe IOUserClient. Deux sous-classes différentes sont utilisées, selon le type d’appelant :

- **EndpointSecurityDriverClient** : nécessite l’entitlement `com.apple.private.endpoint-security.manager`, qui est uniquement détenu par le processus système `endpointsecurityd`.
- **EndpointSecurityExternalClient** : nécessite l’entitlement `com.apple.developer.endpoint-security.client`. Il est généralement utilisé par les logiciels de sécurité tiers qui doivent interagir avec le framework Endpoint Security.<sup>[[1]](#references)</sup>

Les Endpoint Security Extensions utilisent **`libEndpointSecurity.dylib`**, la bibliothèque C, pour communiquer avec le noyau. Cette bibliothèque utilise I/O Kit (`IOKit`) pour communiquer avec la KEXT Endpoint Security.<sup>[[2]](#references)</sup>

**`endpointsecurityd`** est un daemon système essentiel impliqué dans la gestion et le lancement des extensions système Endpoint Security, notamment pendant le processus de démarrage précoce. **Seules les extensions système** marquées avec **`NSEndpointSecurityEarlyBoot`** dans leur fichier `Info.plist` bénéficient de ce traitement au démarrage précoce.<sup>[[2]](#references)</sup>

Un autre daemon système, **`sysextd`**, **valide les extensions système** et les déplace vers les emplacements système appropriés. Il demande ensuite au daemon concerné de charger l’extension. Le **`SystemExtensions.framework`** est responsable de l’activation et de la désactivation des extensions système.<sup>[[2]](#references)</sup>

## Contournement de l’ESF

L’ESF est utilisé par des outils de sécurité qui tenteront de détecter un red teamer ; toute information sur la manière d’éviter cette détection est donc intéressante.

### CVE-2021-30965

Le problème est que l’application de sécurité doit disposer des **permissions Full Disk Access**. Ainsi, si un attaquant pouvait les supprimer, il pourrait empêcher le logiciel de fonctionner :<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
Pour **plus d'informations** sur ce bypass et ceux qui y sont liés, consultez la présentation [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)<sup>[[3]](#references)</sup>

Finalement, ce problème a été corrigé en accordant la nouvelle permission **`kTCCServiceEndpointSecurityClient`** à l'application de sécurité gérée par **`tccd`**, afin que `tccutil` n'efface pas ses permissions, ce qui l'empêcherait de s'exécuter.<sup>[[3]](#references)</sup>

## Références

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - Internals des System Extension](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
