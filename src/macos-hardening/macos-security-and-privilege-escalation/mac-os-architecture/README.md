# Architecture de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Noyau XNU

Le **noyau de macOS est XNU**, qui signifie "X is Not Unix". Ce noyau est fondamentalement composé du **micro-noyau Mach** (qui sera discuté plus tard), **et** d'éléments de Berkeley Software Distribution (**BSD**). XNU fournit également une plateforme pour **les pilotes de noyau via un système appelé I/O Kit**. Le noyau XNU fait partie du projet open source Darwin, ce qui signifie que **son code source est librement accessible**.

Du point de vue d'un chercheur en sécurité ou d'un développeur Unix, **macOS** peut sembler assez **similaire** à un système **FreeBSD** avec une interface graphique élégante et une multitude d'applications personnalisées. La plupart des applications développées pour BSD se compileront et s'exécuteront sur macOS sans nécessiter de modifications, car les outils en ligne de commande familiers aux utilisateurs Unix sont tous présents dans macOS. Cependant, parce que le noyau XNU incorpore Mach, il existe des différences significatives entre un système de type Unix traditionnel et macOS, et ces différences pourraient causer des problèmes potentiels ou offrir des avantages uniques.

Version open source de XNU : [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach est un **micro-noyau** conçu pour être **compatible UNIX**. L'un de ses principes de conception clés était de **minimiser** la quantité de **code** s'exécutant dans l'espace **noyau** et de permettre à de nombreuses fonctions typiques du noyau, telles que le système de fichiers, le réseau et l'I/O, de **s'exécuter en tant que tâches de niveau utilisateur**.

Dans XNU, Mach est **responsable de nombreuses opérations critiques de bas niveau** qu'un noyau gère généralement, telles que la planification des processeurs, le multitâche et la gestion de la mémoire virtuelle.

### BSD

Le **noyau** XNU **incorpore également** une quantité significative de code dérivé du projet **FreeBSD**. Ce code **s'exécute comme partie du noyau avec Mach**, dans le même espace d'adresses. Cependant, le code FreeBSD au sein de XNU peut différer considérablement du code FreeBSD original car des modifications étaient nécessaires pour garantir sa compatibilité avec Mach. FreeBSD contribue à de nombreuses opérations du noyau, y compris :

- Gestion des processus
- Gestion des signaux
- Mécanismes de sécurité de base, y compris la gestion des utilisateurs et des groupes
- Infrastructure d'appels système
- Pile TCP/IP et sockets
- Pare-feu et filtrage de paquets

Comprendre l'interaction entre BSD et Mach peut être complexe, en raison de leurs différents cadres conceptuels. Par exemple, BSD utilise des processus comme son unité d'exécution fondamentale, tandis que Mach fonctionne sur la base de threads. Cette divergence est réconciliée dans XNU en **associant chaque processus BSD à une tâche Mach** qui contient exactement un thread Mach. Lorsque l'appel système fork() de BSD est utilisé, le code BSD au sein du noyau utilise des fonctions Mach pour créer une tâche et une structure de thread.

De plus, **Mach et BSD maintiennent chacun des modèles de sécurité différents** : le modèle de sécurité de **Mach** est basé sur les **droits de port**, tandis que le modèle de sécurité de BSD fonctionne sur la base de **la propriété des processus**. Les disparités entre ces deux modèles ont parfois entraîné des vulnérabilités d'escalade de privilèges locales. En plus des appels système typiques, il existe également des **traps Mach qui permettent aux programmes en espace utilisateur d'interagir avec le noyau**. Ces différents éléments forment ensemble l'architecture hybride et multifacette du noyau macOS.

### I/O Kit - Pilotes

L'I/O Kit est un cadre de **pilotes de périphériques** open-source et orienté objet dans le noyau XNU, gérant **les pilotes de périphériques chargés dynamiquement**. Il permet d'ajouter du code modulaire au noyau à la volée, prenant en charge un matériel diversifié.

{{#ref}}
macos-iokit.md
{{#endref}}

### IPC - Communication Inter-Processus

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## Extensions du Noyau macOS

macOS est **très restrictif pour charger des Extensions de Noyau** (.kext) en raison des privilèges élevés avec lesquels le code s'exécutera. En fait, par défaut, il est pratiquement impossible (à moins qu'un contournement ne soit trouvé).

Sur la page suivante, vous pouvez également voir comment récupérer le `.kext` que macOS charge dans son **kernelcache** :

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### Extensions Système macOS

Au lieu d'utiliser des Extensions de Noyau, macOS a créé les Extensions Système, qui offrent des API de niveau utilisateur pour interagir avec le noyau. De cette manière, les développeurs peuvent éviter d'utiliser des extensions de noyau.

{{#ref}}
macos-system-extensions.md
{{#endref}}

## Références

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
