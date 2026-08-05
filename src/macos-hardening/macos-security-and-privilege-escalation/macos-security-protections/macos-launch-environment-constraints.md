# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Les launch constraints dans macOS ont été introduites pour renforcer la sécurité en **régulant comment, par qui et depuis où un processus peut être lancé**. Introduites dans macOS Ventura, elles fournissent un framework qui catégorise **chaque binaire système dans différentes catégories de contraintes**, lesquelles sont définies dans le **trust cache**, une liste contenant les binaires système et leurs hash respectifs​. Ces contraintes s’appliquent à chaque binaire exécutable du système et comprennent un ensemble de **règles** définissant les conditions requises pour **lancer un binaire donné**. Ces règles incluent les self constraints auxquelles un binaire doit satisfaire, les parent constraints que son processus parent doit respecter, ainsi que les responsible constraints auxquelles doivent se conformer les autres entités concernées​.

Ce mécanisme s’étend aux apps tierces avec les **Environment Constraints**, à partir de macOS Sonoma, permettant aux développeurs de protéger leurs apps en spécifiant un **ensemble de clés et de valeurs pour les environment constraints.**

Vous définissez les **launch environment and library constraints** dans des dictionnaires de contraintes que vous enregistrez soit dans des fichiers de liste de propriétés de **`launchd`**, soit dans des fichiers de **liste de propriétés séparés** que vous utilisez lors de la signature du code.

Il existe 4 types de contraintes :

- **Self Constraints** : Contraintes appliquées au binaire **en cours d’exécution**.
- **Parent Process** : Contraintes appliquées au **parent du processus** (par exemple **`launchd`** exécutant un service XP)
- **Responsible Constraints** : Contraintes appliquées au **processus appelant le service** dans une communication XPC
- **Library load constraints** : Utilisez les library load constraints pour décrire sélectivement le code pouvant être chargé

Ainsi, lorsqu’un processus tente de lancer un autre processus — en appelant `execve(_:_:_:)` ou `posix_spawn(_:_:_:_:_:_:)` — le système d’exploitation vérifie que le fichier **exécutable** **satisfait sa propre self constraint**. Il vérifie également que l’exécutable du **processus** **parent** **satisfait la parent constraint** de l’exécutable, et que l’exécutable du **processus** **responsable** **satisfait la responsible process constraint** de l’exécutable. Si l’une de ces launch constraints n’est pas satisfaite, le système d’exploitation n’exécute pas le programme.

Lors du chargement d’une library, si une partie quelconque de la **library constraint n’est pas satisfaite**, votre processus ne charge pas la library.

## Catégories de LC

Une LC est composée de **facts** et d’**opérations logiques** (and, or...) qui combinent ces facts.

Les[ **facts qu’une LC peut utiliser sont documentés**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Par exemple :

- is-init-proc: Valeur booléenne indiquant si l’exécutable doit être le processus d’initialisation du système d’exploitation (`launchd`).
- is-sip-protected: Valeur booléenne indiquant si l’exécutable doit être un fichier protégé par System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Valeur booléenne indiquant si le système d’exploitation a chargé l’exécutable depuis un volume APFS autorisé et authentifié.
- `on-authorized-authapfs-volume`: Valeur booléenne indiquant si le système d’exploitation a chargé l’exécutable depuis un volume APFS autorisé et authentifié.
- Volume Cryptexes
- `on-system-volume:`Valeur booléenne indiquant si le système d’exploitation a chargé l’exécutable depuis le volume système actuellement démarré.
- À l’intérieur de /System...
- ...

Lorsqu’un binaire Apple est signé, il **l’assigne à une catégorie de LC** dans le **trust cache**.

- Les [**catégories de LC d’iOS 16** ont été [**reversed et documentées ici**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[6]</sup>
- Les [**catégories de LC actuelles (macOS 14** - Somona) ont été reversed et leurs [**descriptions sont disponibles ici**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[7]</sup>

Par exemple, la catégorie 1 est :<sup>[7]</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Doit se trouver dans le volume System ou Cryptexes.
- `launch-type == 1`: Doit être un service système (plist dans LaunchDaemons).
- `validation-category == 1`: Un exécutable du système d’exploitation.
- `is-init-proc`: Launchd

### Reversing des catégories LC

Vous trouverez davantage d’informations [**à ce sujet ici**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), mais en résumé, elles sont définies dans **AMFI (AppleMobileFileIntegrity)**. Vous devez donc télécharger le Kernel Development Kit pour obtenir le **KEXT**. Les symboles commençant par **`kConstraintCategory`** sont les plus intéressants. En les extrayant, vous obtiendrez un flux encodé en DER (ASN.1), que vous devrez décoder avec [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) ou avec la bibliothèque python-asn1 et son script `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), qui vous fourniront une chaîne plus compréhensible.<sup>[3]</sup>

## Contraintes d’environnement

Il s’agit des Launch Constraints configurées dans les **applications tierces**. Le développeur peut sélectionner les **facts** et les **opérandes logiques à utiliser** dans son application afin d’en restreindre l’accès.

Il est possible d’énumérer les contraintes d’environnement d’une application avec :
```bash
codesign -d -vvvv app.app
```
## Caches de confiance

Dans **macOS**, il existe quelques caches de confiance :

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

Et dans iOS, il semble se trouver dans **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Sur macOS exécuté sur des appareils Apple Silicon, si un binaire signé par Apple ne se trouve pas dans le cache de confiance, AMFI refusera de le charger.

### Énumération des caches de confiance

Les fichiers de cache de confiance précédents sont au format **IMG4** et **IM4P**, IM4P étant la section payload d’un format IMG4.

Vous pouvez utiliser [**pyimg4**](https://github.com/m1stadev/PyIMG4) pour extraire le payload des bases de données :
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
(Une autre option consiste à utiliser l'outil [**img4tool**](https://github.com/tihmstar/img4tool), qui fonctionnera même sur M1, même si la release est ancienne et pour x86_64 si vous l'installez aux emplacements appropriés).

Vous pouvez maintenant utiliser l'outil [**trustcache**](https://github.com/CRKatri/trustcache) pour obtenir les informations dans un format lisible :
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
Le trust cache suit la structure suivante ; la catégorie **LC** se trouve dans la 4e colonne.
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Ensuite, vous pouvez utiliser un script tel que [**celui-ci**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) pour extraire les données.

À partir de ces données, vous pouvez vérifier les applications avec une **launch constraints value de `0`**, qui sont celles qui ne sont pas contraintes ([**voir ici**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) pour connaître la signification de chaque valeur).<sup>[6]</sup>

## Mitigations des attaques

Les Launch Constraints auraient permis de mitiger plusieurs anciennes attaques en **s'assurant que le processus ne serait pas exécuté dans des conditions inattendues :** par exemple depuis des emplacements inattendus ou en étant invoqué par un processus parent inattendu (si seul launchd devrait le lancer).

De plus, les Launch Constraints **mitigent également les downgrade attacks.**

Cependant, elles **ne mitigent pas les abus XPC courants**, les injections de code **Electron** ou les **dylib injections** sans library validation (sauf si les team IDs pouvant charger des bibliothèques sont connus).<sup>[3]</sup>

### Protection des XPC Daemons

Dans la release Sonoma, un point notable concerne la **configuration de responsabilité** du service XPC du daemon. Le service XPC est responsable de lui-même, contrairement au client qui se connecte, qui serait responsable. Cela est documenté dans le rapport de feedback FB13206884. Cette configuration peut sembler imparfaite, car elle permet certaines interactions avec le service XPC :

- **Lancement du service XPC** : Si l'on considère qu'il s'agit d'un bug, cette configuration ne permet pas d'initier le service XPC via du code d'attaquant.
- **Connexion à un service actif** : Si le service XPC est déjà en cours d'exécution (éventuellement activé par son application d'origine), rien n'empêche de s'y connecter.

Bien qu'implémenter des contraintes sur le service XPC puisse être bénéfique en **réduisant la fenêtre des attaques potentielles**, cela ne traite pas le problème principal. Garantir la sécurité du service XPC nécessite fondamentalement de **valider efficacement le client qui se connecte**. Il s'agit de la seule méthode pour renforcer la sécurité du service. Il convient également de noter que la configuration de responsabilité mentionnée est actuellement opérationnelle, ce qui pourrait ne pas correspondre à la conception prévue.<sup>[3]</sup>

### Protection Electron

Même s'il est requis que l'application soit **ouverte par LaunchService** (dans les contraintes des processus parents), cela peut être réalisé en utilisant **`open`** (qui peut définir des variables d'environnement) ou l'API **Launch Services** (où les variables d'environnement peuvent être indiquées).<sup>[3]</sup>

### CVE-2025-43253 - Remplacement des contraintes intégrées au moment du spawn

Les launch constraints (officiellement **lightweight code requirements**, *LWCR*) sont appliquées par la **AMFI MAC policy**. `posix_spawn` permet à un appelant de transmettre un blob arbitraire à une MAC policy via **`posix_spawnattr_setmacpolicyinfo_np()`**, et AMFI acceptait un dictionnaire LWCR fourni par l'appelant via ce chemin. Le bug venait du fait que les **contraintes fournies par l'attaquant remplaçaient celles intégrées au binaire** au lieu d'être vérifiées en plus de celles-ci :

- Construire un dictionnaire de launch constraints minimal (voire vide).
- Définir la **constraint category à `127`**, une valeur qu'AMFI autorise dans les spawn attributes, mais **n'applique pas** — elle journalise uniquement `Launch Constraint Violation (not enforcing)` au lieu de bloquer l'exécution.
- Le transmettre via les spawn attributes : le processus se lance alors dans un contexte que ses véritables contraintes self/parent auraient interdit.

Après le correctif, **les contraintes intégrées et celles fournies sont toutes deux validées**, de sorte que le dictionnaire fourni ne peut plus affaiblir les contraintes intégrées.<sup>[2]</sup>

> [!TIP]
> Voici la forme générale à rechercher lors de l'audit de l'application des contraintes : une API qui permet à une entrée non fiable de *fournir* une policy est généralement intéressante lorsque le moteur de policy traite la valeur fournie comme un remplacement plutôt que comme une exigence supplémentaire.

## Références

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Why won't a system app or command tool run? Launch constraints and trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protect your Mac app with environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description of the Launch Constraints introduced in iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
