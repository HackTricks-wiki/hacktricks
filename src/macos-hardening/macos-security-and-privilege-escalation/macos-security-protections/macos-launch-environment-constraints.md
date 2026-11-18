# Contraintes de lancement/d’environnement macOS et Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Les contraintes de lancement ont été introduites dans macOS pour renforcer la sécurité en **réglementant comment, par qui et depuis où un processus peut être lancé**. Introduites avec macOS Ventura, elles fournissent un cadre qui classe **chaque binaire système dans une catégorie de contraintes distincte**, définie dans le **Trust Cache**, une liste contenant les binaires système et leurs hachages respectifs. Ces contraintes s’appliquent à chaque binaire exécutable du système et comprennent un ensemble de **règles** définissant les exigences nécessaires au **lancement d’un binaire donné**. Elles incluent les contraintes propres que doit respecter un binaire, les contraintes du parent que doit respecter son processus parent et les contraintes du processus responsable que doivent respecter les autres entités concernées.<sup>[[1]](#references)[[4]](#references)</sup>

À partir de macOS Sonoma, le mécanisme s’étend aux applications tierces grâce aux **contraintes d’environnement**, permettant aux développeurs de protéger leurs applications en spécifiant un **ensemble de clés et de valeurs pour les contraintes d’environnement**.<sup>[[5]](#references)</sup>

Vous définissez les **contraintes d’environnement de lancement et de bibliothèque** dans des dictionnaires de contraintes que vous enregistrez dans des **fichiers de liste de propriétés `launchd`**, ou dans des fichiers de **liste de propriétés distincts** que vous utilisez pour la signature du code.<sup>[[5]](#references)</sup>

Il existe 4 types de contraintes :

- **Contraintes propres** : contraintes appliquées au binaire **en cours d’exécution**.
- **Processus parent** : contraintes appliquées au **parent du processus** (par exemple, **`launchd`** exécutant un service XP)
- **Contraintes du processus responsable** : contraintes appliquées au **processus qui appelle le service** dans une communication XPC
- **Contraintes de chargement de bibliothèque** : utilisez-les pour décrire de façon sélective le code qui peut être chargé

Ainsi, lorsqu’un processus tente de lancer un autre processus — en appelant `execve(_:_:_:)` ou `posix_spawn(_:_:_:_:_:_:)` — le système d’exploitation vérifie que le fichier **exécutable** **respecte** sa **propre contrainte**. Il vérifie également que l’exécutable du **processus parent** **respecte la contrainte parent** de l’exécutable, et que l’exécutable du **processus responsable** **respecte la contrainte du processus responsable** de l’exécutable. Si l’une de ces contraintes de lancement n’est pas respectée, le système d’exploitation n’exécute pas le programme.

Si une partie de la **contrainte de bibliothèque n’est pas respectée** lors du chargement d’une bibliothèque, votre processus **ne charge pas** cette bibliothèque.

## Catégories LC

Une LC est composée de **faits** et d’**opérations logiques** (et, ou...) qui combinent ces faits.

Les[ **faits utilisables par une LC sont documentés**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Par exemple :

- is-init-proc: valeur booléenne indiquant si l’exécutable doit être le processus d’initialisation du système d’exploitation (`launchd`).
- is-sip-protected: valeur booléenne indiquant si l’exécutable doit être un fichier protégé par System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Valeur booléenne indiquant si le système d’exploitation a chargé l’exécutable depuis un volume APFS autorisé et authentifié.
- `on-authorized-authapfs-volume`: valeur booléenne indiquant si le système d’exploitation a chargé l’exécutable depuis un volume APFS autorisé et authentifié.
  - Volume Cryptexes
- `on-system-volume:` Valeur booléenne indiquant si le système d’exploitation a chargé l’exécutable depuis le volume système actuellement démarré.
  - Dans /System...
- ...

Lorsqu’un binaire Apple est signé, il **l’associe à une catégorie LC** dans le **Trust Cache**.

- Les **catégories LC d’iOS 16** ont été [**rétro-ingéniérées et documentées ici**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Les **catégories LC actuelles (macOS 14** - Somona) ont été rétro-ingéniérées et leurs [**descriptions sont disponibles ici**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Par exemple, la catégorie 1 est :<sup>[[7]](#references)</sup>

```
Category 1:
        Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
        Parent Constraint: is-init-proc
```

- `(on-authorized-authapfs-volume || on-system-volume)`: Doit se trouver sur le volume System ou Cryptexes.
- `launch-type == 1`: Doit être un service système (plist dans LaunchDaemons).
- `validation-category == 1`: Un exécutable du système d’exploitation.
- `is-init-proc`: Launchd

### Reverse engineering des catégories LC

Vous trouverez davantage d’informations [**à ce sujet ici**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), mais en résumé, elles sont définies dans **AMFI (AppleMobileFileIntegrity)**. Vous devez donc télécharger le Kernel Development Kit pour obtenir le **KEXT**. Les symboles commençant par **`kConstraintCategory`** sont les plus **intéressants**. En les extrayant, vous obtiendrez un flux encodé en DER (ASN.1), que vous devrez décoder avec [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) ou la bibliothèque python-asn1 et son script `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), qui vous donnera une chaîne plus facile à comprendre.<sup>[[3]](#references)[[8]](#references)</sup>

## Contraintes d’environnement

Il s’agit des Launch Constraints configurées dans les **applications tierces**. Le développeur peut choisir les **faits** et les **opérandes logiques à utiliser** dans son application pour en restreindre l’accès.

Il est possible d’énumérer les contraintes d’environnement d’une application avec :

```bash
codesign -d -vvvv app.app
```

## Trust Caches

Dans **macOS**, il existe quelques trust caches :

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

Et dans iOS, il semble se trouver dans **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Sur macOS exécuté sur des appareils Apple Silicon, si un binaire signé par Apple ne figure pas dans le trust cache, AMFI refusera de le charger.

### Énumération des Trust Caches

Les fichiers trust cache précédents sont au format **IMG4** et **IM4P**, IM4P étant la section de charge utile d’un fichier au format IMG4.

Vous pouvez utiliser [**pyimg4**](https://github.com/m1stadev/PyIMG4) pour extraire la charge utile des bases de données :

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

(Une autre option consiste à utiliser l’outil [**img4tool**](https://github.com/tihmstar/img4tool), qui fonctionne même sur M1 malgré son ancienneté, ainsi que sur x86_64 si vous l’installez aux emplacements appropriés).

Vous pouvez maintenant utiliser l’outil [**trustcache**](https://github.com/CRKatri/trustcache) pour obtenir les informations dans un format lisible :

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

Le trust cache suit la structure suivante, donc **la catégorie LC est la 4e colonne**.

```c
struct trust_cache_entry2 {
	uint8_t cdhash[CS_CDHASH_LEN];
	uint8_t hash_type;
	uint8_t flags;
	uint8_t constraintCategory;
	uint8_t reserved0;
} __attribute__((__packed__));
```

Ensuite, vous pourriez utiliser un script tel que [**celui-ci**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) pour extraire les données.

À partir de ces données, vous pouvez repérer les apps dont la **valeur de launch constraints est `0`** : ce sont celles qui ne sont soumises à aucune contrainte ([**consultez cette page**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) pour connaître la signification de chaque valeur).<sup>[[6]](#references)</sup>

## Atténuation des attaques

Les Launch Constraints auraient permis d’atténuer plusieurs anciennes attaques en **s’assurant que le processus ne soit pas exécuté dans des conditions inattendues** : par exemple, depuis des emplacements inattendus ou à la demande d’un processus parent inattendu (si seul launchd est censé le lancer).

De plus, les Launch Constraints **atténuent également les attaques par downgrade**.

Cependant, elles **n’atténuent pas les abus courants de XPC**, les injections de code **Electron** ni les **injections de dylib** sans validation de bibliothèque (sauf si les team IDs autorisés à charger des bibliothèques sont connus).<sup>[[3]](#references)</sup>

### Protection des daemons XPC

Dans la version Sonoma, un point notable concerne la **configuration de responsabilité** du service XPC du daemon. Le service XPC est responsable de lui-même, contrairement au client qui s’y connecte. Ce comportement est documenté dans le rapport de feedback FB13206884. Cette configuration peut sembler imparfaite, car elle autorise certaines interactions avec le service XPC :

- **Lancement du service XPC** : même si l’on considère cela comme un bug, cette configuration ne permet pas de lancer le service XPC depuis du code d’attaquant.
- **Connexion à un service actif** : si le service XPC est déjà en cours d’exécution (peut-être activé par son application d’origine), rien n’empêche de s’y connecter.

La mise en place de contraintes sur le service XPC pourrait être utile pour **réduire la fenêtre d’exposition aux attaques potentielles**, mais elle ne résout pas le problème principal. Pour assurer la sécurité du service XPC, il faut fondamentalement **valider efficacement le client qui se connecte**. C’est la seule façon de renforcer la sécurité du service. Il convient également de noter que la configuration de responsabilité mentionnée est actuellement en vigueur, ce qui pourrait ne pas correspondre à la conception prévue.<sup>[[3]](#references)</sup>

### Protection d’Electron

Même si l’application doit être **ouverte par LaunchService** (dans les contraintes des processus parents), cela peut se faire avec **`open`** (qui peut définir des variables d’environnement) ou avec l’**API Launch Services** (qui permet d’indiquer des variables d’environnement).<sup>[[3]](#references)</sup>

Pour en savoir plus sur le mécanisme MACF général qui sous-tend les attributs de spawn propres aux politiques, consultez [les attributs de spawn propres aux politiques MACF](macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input).

### CVE-2025-43253 - Remplacement des contraintes intégrées au moment du spawn

Les launch constraints (officiellement appelées **lightweight code requirements**, *LWCR*) sont appliquées par la **politique MAC AMFI**. `posix_spawn` permet à un appelant de transmettre un blob arbitraire à une politique MAC via **`posix_spawnattr_setmacpolicyinfo_np()`**, et AMFI acceptait par ce biais un dictionnaire LWCR fourni par l’appelant. Le bug venait du fait que **les contraintes fournies par l’attaquant remplaçaient celles intégrées au binaire**, au lieu d’être vérifiées en plus de celles-ci :

- Construire un dictionnaire de launch constraints minimal (même vide).
- Définir la **catégorie de contrainte sur `127`**, une valeur qu’AMFI autorise dans les attributs de spawn, mais qu’il **n’applique pas** : il consigne uniquement `Launch Constraint Violation (not enforcing)` au lieu de bloquer l’exécution.
- Le transmettre via les attributs de spawn ; le processus est alors lancé dans un contexte que ses véritables contraintes propres/parentales auraient interdit.

Depuis le correctif, **les contraintes intégrées et celles fournies** sont toutes deux validées ; le dictionnaire fourni ne peut donc plus affaiblir les contraintes intégrées.<sup>[[2]](#references)</sup>

> [!TIP]
> Voici la forme générale à rechercher lors d’un audit de l’application des contraintes : une API qui permet à une entrée non fiable de *fournir* une politique mérite généralement qu’on s’y intéresse lorsque le moteur de politiques traite la valeur fournie comme un remplacement plutôt que comme une exigence supplémentaire.



## References

- [1] [Objective by the Sea #OBTS v6.0, jour 2 (diffusion en direct)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253 : contournement des Launch Constraints sur macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Analyse approfondie des Launch and Environment Constraints - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Pourquoi une app ou un outil en ligne de commande système ne se lance-t-il pas ? Launch constraints et caches de confiance - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protégez votre app Mac avec les contraintes d’environnement - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description des Launch Constraints introduites dans iOS 16 (gist de LinusHenze)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [Launch Constraints de macOS Sonoma (14) (gist de theevilbit)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Au-delà des bons vieux LaunchAgents - à lire ici](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)
{{#include ../../../banners/hacktricks-training.md}}
