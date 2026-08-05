# Kernel et extensions système de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Kernel XNU

Le **cœur de macOS est XNU**, ce qui signifie « X is Not Unix ». Ce kernel est fondamentalement composé du **microkernel Mach** (qui sera abordé plus loin), **ainsi que** d’éléments issus de Berkeley Software Distribution (**BSD**). XNU fournit également une plateforme pour les **drivers kernel via un système appelé I/O Kit**. Le kernel XNU fait partie du projet open source Darwin, ce qui signifie que **son code source est librement accessible**.

Du point de vue d’un chercheur en sécurité ou d’un développeur Unix, **macOS** peut sembler assez **similaire** à un système **FreeBSD** doté d’une interface graphique élégante et de nombreuses applications personnalisées. La plupart des applications développées pour BSD se compileront et s’exécuteront sur macOS sans nécessiter de modifications, car les outils en ligne de commande familiers aux utilisateurs Unix sont tous présents dans macOS. Cependant, puisque le kernel XNU intègre Mach, il existe des différences importantes entre un système traditionnel de type Unix et macOS, et ces différences peuvent provoquer des problèmes potentiels ou fournir des avantages uniques.

Version open source de XNU : [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach est un **microkernel** conçu pour être **compatible avec UNIX**. L’un de ses principaux principes de conception était de **réduire au minimum** la quantité de **code** exécutée dans l’espace **kernel**, et de permettre à la place à de nombreuses fonctions typiques du kernel, comme le système de fichiers, le réseau et les entrées/sorties, de **s’exécuter comme des tâches au niveau utilisateur**.

Dans XNU, Mach est **responsable de nombreuses opérations critiques de bas niveau** généralement prises en charge par un kernel, comme l’ordonnancement du processeur, le multitâche et la gestion de la mémoire virtuelle.

### BSD

Le **kernel** XNU **intègre** également une quantité importante de code dérivé du projet **FreeBSD**. Ce code **s’exécute au sein du kernel avec Mach**, dans le même espace d’adressage. Cependant, le code FreeBSD présent dans XNU peut différer considérablement du code FreeBSD original, car des modifications ont été nécessaires pour assurer sa compatibilité avec Mach. FreeBSD contribue à de nombreuses opérations du kernel, notamment :

- Gestion des processus
- Gestion des signaux
- Mécanismes de sécurité de base, notamment la gestion des utilisateurs et des groupes
- Infrastructure des appels système
- Stack TCP/IP et sockets
- Firewall et filtrage des paquets

Comprendre l’interaction entre BSD et Mach peut être complexe en raison de leurs cadres conceptuels différents. Par exemple, BSD utilise les processus comme unité d’exécution fondamentale, tandis que Mach fonctionne à partir de threads. Cette divergence est résolue dans XNU en **associant chaque processus BSD à une tâche Mach** contenant exactement un thread Mach. Lorsque l’appel système fork() de BSD est utilisé, le code BSD présent dans le kernel utilise des fonctions Mach pour créer une tâche et une structure de thread.

De plus, **Mach et BSD possèdent chacun des modèles de sécurité différents** : le modèle de sécurité de **Mach** repose sur les **droits d’accès aux ports**, tandis que celui de BSD repose sur la **propriété des processus**. Les disparités entre ces deux modèles ont parfois entraîné des vulnérabilités d’élévation de privilèges locale. En plus des appels système classiques, il existe également des **traps Mach permettant aux programmes de l’espace utilisateur d’interagir avec le kernel**. Tous ces éléments forment ensemble l’architecture hybride et multifacette du kernel de macOS.

### I/O Kit - Drivers

L’I/O Kit est un **framework de drivers de périphériques** open source et orienté objet du kernel XNU, qui gère les **drivers de périphériques chargés dynamiquement**. Il permet d’ajouter à la volée du code modulaire au kernel, afin de prendre en charge différents types de matériel.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocesseurs dans l’architecture de macOS

Les plateformes Apple s’appuient sur plusieurs coprocesseurs afin de décharger les opérations sensibles à la latence des cœurs principaux et d’isoler les fonctions critiques pour la sécurité.

- **Secure Enclave Processor (SEP)** : cœur ARM dédié disposant de son propre microkernel et de sa propre chaîne de démarrage sécurisé, fonctionnant généralement au niveau **EL3/secure world**. L’interaction s’effectue via des drivers mailbox de macOS au niveau EL1.
- Surface d’attaque : mises à jour du firmware du SEP et daemons de l’espace utilisateur (`seputil`, `securityd`) qui servent de proxy aux requêtes.
- Impact d’une compromission : leak de clés à long terme, contournement du contrôle biométrique et rupture des protections FileVault ou Apple Pay.
- **System Management Controller (SMC)** : exécute un firmware propriétaire sur un microcontrôleur situé en dehors des niveaux d’exception ARM. macOS (EL1) y accède via des user clients de l’I/O Kit.
- Surface d’attaque : messages de distribution électrique USB-C, interfaces de gestion des ventilateurs et de la batterie, ainsi que les chemins de mise à jour du firmware.
- Impact d’une compromission : contournement des limites thermiques, injection de fausses données de capteurs, coupure de l’alimentation ou implantation de backdoors persistantes dans la NVRAM.
- **Puce de sécurité T1/T2** : exécute bridgeOS (dérivé de watchOS), principalement aux niveaux EL1/EL3, sur ses propres cœurs ARM. macOS communique via des canaux de type PCIe/USB gérés par IOKit.
- Surface d’attaque : chemins DFU/restauration, endpoints IPC exposés par des services comme `tccd`, et pipelines multimédias reliés au T2.
- Impact d’une compromission : désactivation du démarrage sécurisé, déchiffrement du contenu du SSD, détournement du contrôle de la caméra et du microphone, ou émulation d’entrées HID pour une persistence furtive.
- **Display Coprocessor (DCP)** : exécute un firmware au niveau EL1 dans un espace d’adressage isolé protégé par DART (l’IOMMU d’Apple).
- Surface d’attaque : interfaces `DCPAVService`, buffers de descripteurs partagés et analyse des images firmware.
- Impact d’une compromission : injection d’images arbitraires, espionnage des framebuffers ou blocage du pipeline d’affichage pour provoquer un DoS.
- **Apple Neural Engine (ANE)** : exécute du microcode sur un cluster ML dédié (sans niveaux EL ARM). macOS planifie les tâches via `ANECompilerService` et IOKit.
- Surface d’attaque : binaires de modèles compilés (`.ane`), APIs Core ML alimentant des kernels personnalisés et chargeurs de firmware.
- Impact d’une compromission : modification ou exfiltration de modèles ML, leak de données audio/visuelles traitées ou sabotage de l’inférence on-device.
- **GPU AGX** : le firmware s’exécute sur des cœurs GPU personnalisés avec un scheduler ; EL0 soumet des commandes Metal qu’EL1 valide.
- Surface d’attaque : compilateur de shaders Metal, APIs de mappage des buffers partagés et interfaces ioctl `com.apple.AGXFirmware`.
- Impact d’une compromission : accès DMA à la mémoire système, sandbox escapes via les drivers GPU ou implantation persistante dans le firmware.
- **Apple Video Encoder (AVE)** : le firmware s’exécute sur le Media Engine dans une sandbox de type EL1. macOS interagit via VideoToolbox et `AppleAVE2`.
- Surface d’attaque : bitstreams de codecs, ensembles de paramètres, buffers fournis par l’utilisateur et blobs de mise à jour du firmware.
- Impact d’une compromission : leak d’images non compressées, contournement des DRM ou obtention de code execution avec accès aux moteurs DMA.
- **Image Signal Processor (ISP)** : exécute un firmware sécurisé dans le cluster Media Engine ; les drivers caméra de macOS fonctionnent au niveau EL1.
- Surface d’attaque : HAL caméra, descripteurs de trames RAW, queues de configuration de l’ISP et mises à jour du firmware.
- Impact d’une compromission : capture furtive des flux caméra RAW, désactivation des indicateurs de confidentialité ou injection d’images falsifiées.
- **Cœurs matriciels AMX** : fonctionnent comme des unités coprocesseurs exposées aux niveaux EL0/EL1 via de nouvelles instructions.
- Surface d’attaque : virtualisation par le kernel de l’état AMX (`thread_set_state`, changements de contexte) et génération de code dans l’espace utilisateur.
- Impact d’une compromission : leak des registres tile d’autres processus, fingerprinting des workloads ou élévation via une corruption de la mémoire du kernel.

Les versions modernes de macOS traitent ces coprocesseurs comme des composants de confiance dans la chaîne de confiance. Le firmware du SEP, du SMC et du T2 est signé par Apple, et les protocoles de handshake (souvent implémentés via des mailbox ou des familles I/O Kit) incluent des vérifications challenge-response afin que seul un firmware authentifié puisse traiter les requêtes.

### IPC - Communication interprocessus

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## Extensions du kernel de macOS

macOS est **très restrictif quant au chargement des extensions du kernel** (.kext), en raison des privilèges élevés avec lesquels ce code s’exécute. En réalité, par défaut, cela est pratiquement impossible (sauf si un bypass est trouvé).

Dans la page suivante, vous pouvez également voir comment récupérer le `.kext` que macOS charge dans son **kernelcache** :

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### Extensions système de macOS

Au lieu d’utiliser des extensions du kernel, macOS a créé les System Extensions, qui offrent des APIs au niveau utilisateur pour interagir avec le kernel. Ainsi, les développeurs peuvent éviter d’utiliser des extensions du kernel.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes et RSR (Rapid Security Response)

- **Cryptex** signifie **CRYPTographically-sealed EXtension**. Il s’agit d’une image disque scellée (conteneur) utilisée par Apple pour héberger des parties de l’OS (frameworks, bibliothèques partagées, applications) plus susceptibles de changer entre les mises à jour majeures de l’OS.
- Sur macOS et iOS, les composants placés dans des cryptexes peuvent être **patchés ou remplacés** via RSR sans resceller l’intégralité du volume système.
- Les cryptexes résident sur le volume **Preboot**, avec le firmware de démarrage, et sont greffés au système de fichiers de l’OS au runtime.
- Le chargement du contenu d’un cryptex implique une validation : le système vérifie les seals des fichiers, les manifests et les root hashes, puis monte ou « greffe » le contenu du cryptex afin que les applications utilisent au runtime les versions du cryptex lorsqu’elles existent.
- Dans les logs de démarrage, le chargement des cryptexes a lieu après l’initialisation du kernel, mais avant le démarrage complet des services système.


#### Rapid Security Response (RSR)

- **RSR** est le mécanisme d’Apple permettant de distribuer des **security patches entre les mises à jour régulières de l’OS**. Il cible le contenu des cryptexes afin de mettre à jour les parties vulnérables (par exemple les bibliothèques et frameworks) sans modifier le volume système principal.
- Lors de l’application d’une mise à jour RSR, l’appareil demande au serveur de signature d’Apple un **manifest Cryptex1 Image4**. Ce manifest est lié cryptographiquement à l’appareil et au nouveau contenu du cryptex.
- Le ticket de démarrage AP existant du système de base **n’est pas modifié** par la RSR. Le patch s’applique de manière additive par-dessus l’OS de base scellé.
- Sur macOS, certains composants patchés (par exemple Safari) deviennent actifs dès que l’application est relancée ; un redémarrage complet du système n’est pas toujours nécessaire.
- Les RSR sont **amovibles** : chacune fournit à la fois un patch et un « antipatch » permettant de revenir à la version de l’OS de base. Lors de la suppression, le contenu du cryptex est restauré.
- Les mises à jour RSR sont généralement beaucoup plus petites que les mises à jour complètes de l’OS et nécessitent un niveau de batterie moins élevé pour être installées.


## Références

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
