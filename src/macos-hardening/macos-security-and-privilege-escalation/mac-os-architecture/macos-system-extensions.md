# Extensions système macOS

{{#include ../../../banners/hacktricks-training.md}}

## Extensions système / Endpoint Security Framework

Contrairement aux **Kernel Extensions**, les **System Extensions s’exécutent dans l’espace utilisateur** plutôt que dans l’espace kernel, ce qui réduit le risque de crash du système dû à un dysfonctionnement de l’extension.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Il existe trois types d’extensions système : les extensions **DriverKit**, les extensions **Network** et les extensions **Endpoint Security**.

### **Extensions DriverKit**

DriverKit est un remplacement des extensions kernel qui **fournissent la prise en charge du matériel**. Il permet aux drivers de périphériques (tels que les drivers USB, Serial, NIC et HID) de s’exécuter dans l’espace utilisateur plutôt que dans l’espace kernel. Le framework DriverKit inclut des **versions dans l’espace utilisateur de certaines classes I/O Kit**, et le kernel transfère les événements I/O Kit normaux vers l’espace utilisateur, offrant ainsi un environnement plus sûr pour l’exécution de ces drivers.<sup>[2]</sup>

### **Network Extensions**

Les Network Extensions permettent de personnaliser les comportements réseau. Il existe plusieurs types de Network Extensions :

- **App Proxy** : utilisé pour créer un client VPN qui implémente un protocole VPN personnalisé orienté flux. Cela signifie qu’il gère le trafic réseau en fonction des connexions (ou flux), plutôt que des paquets individuels.
- **Packet Tunnel** : utilisé pour créer un client VPN qui implémente un protocole VPN personnalisé orienté paquets. Cela signifie qu’il gère le trafic réseau en fonction des paquets individuels.
- **Filter Data** : utilisé pour filtrer les « flux » réseau. Il peut surveiller ou modifier les données réseau au niveau des flux.
- **Filter Packet** : utilisé pour filtrer les paquets réseau individuels. Il peut surveiller ou modifier les données réseau au niveau des paquets.
- **DNS Proxy** : utilisé pour créer un fournisseur DNS personnalisé. Il peut être utilisé pour surveiller ou modifier les requêtes et les réponses DNS.<sup>[2]</sup>

## Endpoint Security Framework

Endpoint Security est un framework fourni par Apple dans macOS qui offre un ensemble d’APIs pour la sécurité du système. Il est destiné aux **fournisseurs de solutions de sécurité et aux développeurs qui créent des produits capables de surveiller et de contrôler l’activité du système** afin d’identifier et de prévenir les activités malveillantes.

Ce framework fournit une **collection d’APIs permettant de surveiller et de contrôler l’activité du système**, comme les exécutions de processus, les événements du système de fichiers, ainsi que les événements réseau et kernel.

Le cœur de ce framework est implémenté dans le kernel, sous la forme d’une Kernel Extension (KEXT) située dans **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[2]</sup> Cette KEXT est composée de plusieurs éléments clés :

- **EndpointSecurityDriver** : agit comme le « point d’entrée » de l’extension kernel. Il constitue le principal point d’interaction entre l’OS et le framework Endpoint Security.
- **EndpointSecurityEventManager** : ce composant est chargé d’implémenter les kernel hooks. Les kernel hooks permettent au framework de surveiller les événements système en interceptant les system calls.
- **EndpointSecurityClientManager** : gère la communication avec les clients de l’espace utilisateur, en gardant la trace des clients connectés qui doivent recevoir les notifications d’événements.
- **EndpointSecurityMessageManager** : envoie les messages et les notifications d’événements aux clients de l’espace utilisateur.

Les événements que le framework Endpoint Security peut surveiller sont répartis dans les catégories suivantes :

- Événements liés aux fichiers
- Événements liés aux processus
- Événements liés aux sockets
- Événements kernel (comme le chargement/déchargement d’une extension kernel ou l’ouverture d’un périphérique I/O Kit)

### Architecture du Endpoint Security Framework

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

La **communication dans l’espace utilisateur** avec le framework Endpoint Security s’effectue via la classe IOUserClient. Deux sous-classes différentes sont utilisées, selon le type d’appelant :

- **EndpointSecurityDriverClient** : nécessite l’entitlement `com.apple.private.endpoint-security.manager`, qui est uniquement détenu par le processus système `endpointsecurityd`.
- **EndpointSecurityExternalClient** : nécessite l’entitlement `com.apple.developer.endpoint-security.client`. Il est généralement utilisé par les logiciels de sécurité tiers qui doivent interagir avec le framework Endpoint Security.<sup>[1]</sup>

Les Endpoint Security Extensions : **`libEndpointSecurity.dylib`** est la bibliothèque C que les extensions système utilisent pour communiquer avec le kernel. Cette bibliothèque utilise I/O Kit (`IOKit`) pour communiquer avec la KEXT Endpoint Security.<sup>[2]</sup>

**`endpointsecurityd`** est un daemon système essentiel impliqué dans la gestion et le lancement des extensions système Endpoint Security, en particulier pendant le processus de démarrage précoce. **Seules les extensions système** marquées avec **`NSEndpointSecurityEarlyBoot`** dans leur fichier `Info.plist` bénéficient de ce traitement au démarrage précoce.<sup>[2]</sup>

Un autre daemon système, **`sysextd`**, **valide les extensions système** et les déplace vers les emplacements système appropriés. Il demande ensuite au daemon concerné de charger l’extension. Le **`SystemExtensions.framework`** est responsable de l’activation et de la désactivation des extensions système.<sup>[2]</sup>

## Contourner ESF

ESF est utilisé par des outils de sécurité qui tenteront de détecter un red teamer ; toute information sur la manière d’éviter cette détection est donc intéressante.

### CVE-2021-30965

Le problème est que l’application de sécurité doit disposer des **permissions Full Disk Access**. Ainsi, si un attaquant pouvait les supprimer, il pourrait empêcher le logiciel de s’exécuter :<sup>[3]</sup>
```bash
tccutil reset All
```
Pour **plus d'informations** sur ce bypass et les bypass associés, consultez la présentation [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Finalement, ce problème a été corrigé en accordant la nouvelle permission **`kTCCServiceEndpointSecurityClient`** à l'application de sécurité gérée par **`tccd`**, afin que `tccutil` n'efface pas ses permissions, ce qui l'empêcherait de s'exécuter.<sup>[3]</sup>

## Références

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
