# Abus des processus macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base sur les processus

Un processus est une instance d’un exécutable en cours d’exécution. Toutefois, les processus n’exécutent pas de code : ce sont les threads qui le font. Par conséquent, **les processus ne sont que des conteneurs pour les threads en cours d’exécution** ; ils fournissent la mémoire, les descripteurs, les ports, les permissions...

Traditionnellement, les processus étaient démarrés à l’intérieur d’autres processus (sauf PID 1) en appelant **`fork`**, qui créait une copie exacte du processus courant. Le **processus enfant** appelait ensuite généralement **`execve`** pour charger le nouvel exécutable et l’exécuter. Puis **`vfork`** a été introduit pour accélérer ce processus en évitant toute copie de mémoire.\
Ensuite, **`posix_spawn`** a été introduit pour combiner **`vfork`** et **`execve`** en un seul appel et accepter des flags :

- `POSIX_SPAWN_RESETIDS` : réinitialiser les identifiants effectifs en utilisant les identifiants réels
- `POSIX_SPAWN_SETPGROUP` : définir l’appartenance au groupe de processus
- `POSUX_SPAWN_SETSIGDEF` : définir le comportement par défaut des signaux
- `POSIX_SPAWN_SETSIGMASK` : définir le masque de signaux
- `POSIX_SPAWN_SETEXEC` : exécuter dans le même processus (comme `execve`, avec plus d’options)
- `POSIX_SPAWN_START_SUSPENDED` : démarrer en étant suspendu
- `_POSIX_SPAWN_DISABLE_ASLR` : démarrer sans ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` utiliser l’allocateur Nano de libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` autoriser `rwx` sur les segments de données
- `POSIX_SPAWN_CLOEXEC_DEFAULT` : fermer par défaut tous les descripteurs de fichiers lors de exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` randomiser les bits de poids fort du décalage ASLR

De plus, `posix_spawn` accepte des paramètres **`posix_spawnattr`** qui contrôlent certains aspects du processus créé, ainsi que des entrées **`posix_spawn_file_actions`** qui modifient les descripteurs de fichiers.

Lorsqu’un processus meurt, il envoie le **code de retour au processus parent** (si le parent est mort, le nouveau parent est PID 1) avec le signal `SIGCHLD`. Le parent doit récupérer cette valeur en appelant `wait4()` ou `waitid()`. En attendant, l’enfant reste dans un état zombie : il est toujours répertorié, mais ne consomme pas de ressources.

### PID

Les PID (identifiants de processus) identifient un processus unique. Dans XNU, les **PID** sont des nombres de **64 bits** qui augmentent de façon monotone et **ne rebouclent jamais** (afin d’éviter les abus).

### Groupes de processus, sessions et coalitions

Les **processus** peuvent être regroupés pour faciliter leur gestion. Par exemple, les commandes d’un script shell appartiennent au même groupe de processus, ce qui permet de leur **envoyer un signal simultanément**, par exemple avec kill.\
Il est également possible de **regrouper des processus dans des sessions**. Lorsqu’un processus démarre une session (`setsid(2)`), ses processus enfants sont intégrés à cette session, sauf s’ils démarrent leur propre session.

Une coalition est une autre manière de regrouper les processus dans Darwin. Rejoindre une coalition permet à un processus d’accéder à des ressources partagées, de partager un ledger ou d’être soumis à Jetsam. Les coalitions ont différents rôles : Leader, service XPC, Extension.

### Identifiants et personae

Chaque processus détient des **identifiants** qui **définissent ses privilèges** dans le système. Chaque processus possède un `uid` principal et un `gid` principal (bien qu’il puisse appartenir à plusieurs groupes).\
Il est également possible de modifier l’ID utilisateur et l’ID de groupe si le binaire possède le bit `setuid/setgid`.\
Il existe plusieurs fonctions pour **définir de nouveaux uid/gid**.

L’appel système **`persona`** fournit un ensemble **alternatif** d’**identifiants**. Adopter une persona revient à adopter simultanément son uid, son gid et ses appartenances aux groupes. Dans le [**code source**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), il est possible de trouver la structure :

```c
struct kpersona_info { uint32_t persona_info_version;
    uid_t    persona_id; /* overlaps with UID */
    int      persona_type;
    gid_t    persona_gid;
    uint32_t persona_ngroups;
    gid_t    persona_groups[NGROUPS];
    uid_t    persona_gmuid;
    char     persona_name[MAXLOGNAME + 1];

    /* TODO: MAC policies?! */
}
```

## Informations de base sur les threads

1. **Threads POSIX (pthreads) :** macOS prend en charge les threads POSIX (`pthreads`), qui font partie d’une API standard de gestion des threads pour C/C++. L’implémentation de pthreads dans macOS se trouve dans `/usr/lib/system/libsystem_pthread.dylib`, qui provient du projet `libpthread` disponible publiquement. Cette bibliothèque fournit les fonctions nécessaires à la création et à la gestion des threads.
2. **Création de threads :** La fonction `pthread_create()` sert à créer de nouveaux threads. En interne, elle appelle `bsdthread_create()`, un appel système de bas niveau propre au noyau XNU (le noyau sur lequel repose macOS). Cet appel système prend différents indicateurs dérivés de `pthread_attr` (attributs), qui définissent le comportement du thread, notamment les politiques d’ordonnancement et la taille de la pile.
   - **Taille de pile par défaut :** La taille de pile par défaut des nouveaux threads est de 512 KB. Elle suffit pour les opérations courantes, mais peut être ajustée à l’aide des attributs du thread si davantage ou moins d’espace est nécessaire.
3. **Initialisation des threads :** La fonction `__pthread_init()` joue un rôle essentiel lors de la configuration des threads. Elle utilise l’argument `env[]` pour analyser les variables d’environnement, qui peuvent contenir des informations sur l’emplacement et la taille de la pile.

#### Terminaison des threads dans macOS

1. **Sortie des threads :** Les threads sont généralement terminés par un appel à `pthread_exit()`. Cette fonction permet à un thread de se terminer proprement, en effectuant le nettoyage nécessaire et en renvoyant une valeur aux threads qui le rejoignent.
2. **Nettoyage des threads :** Lors de l’appel à `pthread_exit()`, la fonction `pthread_terminate()` est invoquée pour supprimer toutes les structures associées au thread. Elle désalloue les ports de thread Mach (Mach est le sous-système de communication du noyau XNU) et appelle `bsdthread_terminate`, un appel système qui supprime les structures du noyau associées au thread.

#### Mécanismes de synchronisation

Pour gérer l’accès aux ressources partagées et éviter les conditions de concurrence, macOS fournit plusieurs primitives de synchronisation. Elles sont essentielles dans les environnements multithreads pour garantir l’intégrité des données et la stabilité du système :

1. **Mutex :**
   - **Mutex standard (signature : 0x4D555458) :** Mutex standard occupant 60 octets (56 octets pour le mutex et 4 octets pour la signature).
   - **Mutex rapide (signature : 0x4d55545A) :** Similaire au mutex standard, mais optimisé pour des opérations plus rapides ; il occupe également 60 octets.
2. **Variables de condition :**
   - Utilisées pour attendre que certaines conditions soient remplies ; elles occupent 44 octets (40 octets plus une signature de 4 octets).
   - **Attributs de variable de condition (signature : 0x434e4441) :** Attributs de configuration des variables de condition, occupant 12 octets.
3. **Variable once (signature : 0x4f4e4345) :**
   - Garantit qu’un code d’initialisation est exécuté une seule fois. Elle occupe 12 octets.
4. **Verrous en lecture-écriture :**
   - Permettent plusieurs lecteurs ou un seul rédacteur à la fois, facilitant ainsi l’accès efficace aux données partagées.
   - **Verrou en lecture-écriture (signature : 0x52574c4b) :** Occupe 196 octets.
   - **Attributs de verrou en lecture-écriture (signature : 0x52574c41) :** Attributs des verrous en lecture-écriture, occupant 20 octets.

> [!TIP]
> Les 4 derniers octets de ces objets servent à détecter les débordements.

### Variables locales au thread (TLV)

Les **variables locales au thread (TLV)** dans le contexte des fichiers Mach-O (le format des exécutables dans macOS) servent à déclarer des variables propres à **chaque thread** d’une application multithread. Ainsi, chaque thread possède sa propre instance de la variable, ce qui permet d’éviter les conflits et de préserver l’intégrité des données sans avoir besoin de mécanismes de synchronisation explicites comme les mutex.

En C et dans les langages apparentés, vous pouvez déclarer une variable locale au thread avec le mot-clé **`__thread`**. Voici comment cela fonctionne dans votre exemple :

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Cet extrait définit `tlv_var` comme une variable locale au thread. Chaque thread exécutant ce code aura son propre `tlv_var`, et les modifications apportées à `tlv_var` par un thread n’affecteront pas la variable des autres threads.

Dans le binaire Mach-O, les données liées aux variables locales au thread sont organisées dans des sections spécifiques :

- **`__DATA.__thread_vars`** : cette section contient les métadonnées des variables locales au thread, comme leur type et leur état d’initialisation.
- **`__DATA.__thread_bss`** : cette section est utilisée pour les variables locales au thread qui ne sont pas explicitement initialisées. Elle fait partie de la mémoire réservée aux données initialisées à zéro.

Mach-O fournit également une API spécifique appelée **`tlv_atexit`** pour gérer les variables locales au thread lorsqu’un thread se termine. Cette API permet d’**enregistrer des destructeurs** — des fonctions spéciales qui nettoient les données locales au thread lorsque celui-ci se termine.

### Priorités des threads

Pour comprendre les priorités des threads, il faut examiner comment le système d’exploitation décide quels threads exécuter et à quel moment. Cette décision dépend du niveau de priorité attribué à chaque thread. Dans macOS et les systèmes de type Unix, cela repose sur des concepts tels que `nice`, `renice` et les classes Quality of Service (QoS).

#### Nice et Renice

1. **Nice :**
   - La valeur `nice` d’un processus est un nombre qui influe sur sa priorité. Chaque processus a une valeur `nice` comprise entre -20 (priorité la plus élevée) et 19 (priorité la plus basse). La valeur `nice` par défaut à la création d’un processus est généralement 0.
   - Une valeur `nice` plus faible (proche de -20) rend un processus plus « égoïste » et lui accorde davantage de temps CPU qu’aux processus ayant une valeur `nice` plus élevée.
2. **Renice :**
   - `renice` est une commande permettant de modifier la valeur `nice` d’un processus en cours d’exécution. Elle permet d’ajuster dynamiquement la priorité des processus, en augmentant ou en réduisant le temps CPU qui leur est alloué selon leur nouvelle valeur `nice`.
   - Par exemple, si un processus a temporairement besoin de davantage de ressources CPU, vous pouvez réduire sa valeur `nice` avec `renice`.

#### Classes Quality of Service (QoS)

Les classes QoS constituent une approche plus moderne de la gestion des priorités des threads, notamment dans les systèmes comme macOS qui prennent en charge **Grand Central Dispatch (GCD)**. Elles permettent aux développeurs de **classer** le travail selon différents niveaux d’importance ou d’urgence. macOS gère automatiquement la priorité des threads en fonction de ces classes QoS :

1. **User Interactive :**
   - Cette classe concerne les tâches qui interagissent actuellement avec l’utilisateur ou qui doivent produire un résultat immédiat pour offrir une bonne expérience utilisateur. Ces tâches bénéficient de la priorité la plus élevée afin de préserver la réactivité de l’interface (par exemple, les animations ou la gestion des événements).
2. **User Initiated :**
   - Cette classe concerne les tâches lancées par l’utilisateur, dont il attend un résultat immédiat, comme l’ouverture d’un document ou le clic sur un bouton nécessitant des calculs. Leur priorité est élevée, mais inférieure à celle de la classe User Interactive.
3. **Utility :**
   - Ces tâches sont longues et affichent généralement un indicateur de progression (par exemple, le téléchargement de fichiers ou l’importation de données). Leur priorité est inférieure à celle des tâches lancées par l’utilisateur et elles n’ont pas besoin de se terminer immédiatement.
4. **Background :**
   - Cette classe concerne les tâches exécutées en arrière-plan et invisibles pour l’utilisateur, comme l’indexation, la synchronisation ou les sauvegardes. Elles ont la priorité la plus faible et leur impact sur les performances du système est minimal.

Avec les classes QoS, les développeurs n’ont pas besoin de gérer les valeurs de priorité exactes : ils peuvent se concentrer sur la nature de la tâche, et le système optimise en conséquence les ressources CPU.

Il existe également différentes **politiques d’ordonnancement des threads**, qui permettent de définir un ensemble de paramètres d’ordonnancement pris en compte par l’ordonnanceur. Cela peut se faire avec `thread_policy_[set/get]`. Cette possibilité peut être utile dans les attaques par race condition.

## Abus des processus macOS

macOS fournit de nombreux mécanismes permettant aux **processus d’interagir, de communiquer et de partager des données**. Bien que ces mécanismes soient indispensables au fonctionnement normal du système, les attaquants peuvent les détourner pour effectuer de l’injection, exécuter du code ou accéder à des données.

### Library Injection

Library Injection est une technique par laquelle un attaquant **force un processus à charger une bibliothèque malveillante**. Une fois injectée, la bibliothèque s’exécute dans le contexte du processus cible et donne à l’attaquant les mêmes autorisations et le même accès que ceux du processus.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking consiste à **intercepter des appels de fonctions** ou des messages dans un code logiciel. En accrochant des fonctions, un attaquant peut **modifier le comportement** d’un processus, observer des données sensibles ou même prendre le contrôle du flux d’exécution.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Cette page traite des métadonnées d’unwind ARM64, des contraintes PAC d’arm64e et des chaînes d’appels synthétiques.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) désigne les différentes méthodes permettant à des processus distincts de **partager et d’échanger des données**. Bien que l’IPC soit essentiel à de nombreuses applications légitimes, il peut aussi être détourné pour contourner l’isolation des processus, divulguer des informations sensibles ou effectuer des actions non autorisées.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Les applications Electron exécutées avec certaines variables d’environnement peuvent être vulnérables à l’injection de processus :


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Il est possible d’utiliser les options `--load-extension` et `--use-fake-ui-for-media-stream` pour effectuer une **attaque man in the browser** permettant de voler les frappes au clavier, le trafic et les cookies, ou encore d’injecter des scripts dans des pages… :


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Les fichiers NIB **définissent les éléments d’interface utilisateur (UI)** d’une application et leurs interactions. Ils peuvent toutefois **exécuter des commandes arbitraires**, et **Gatekeeper n’empêche pas** une application déjà exécutée de l’être à nouveau si un **fichier NIB est modifié**. Ils peuvent donc servir à faire exécuter des commandes arbitraires par des programmes arbitraires :


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Il est possible d’injecter des options JVM via **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ou **`JDK_JAVA_OPTIONS`** et de charger un agent Java ou natif avant le démarrage de l’application.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** précharge du JavaScript contrôlé par l’attaquant avec `--require` (fichier) ou `--import data:text/javascript,…` (sans fichier, Node ≥ 20.6) ; **`NODE_REPL_EXTERNAL_MODULE`** charge un module dans un REPL interactif, et **`ELECTRON_RUN_AS_NODE`** réactive toutes ces possibilités sur les binaires Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Il est possible d’injecter du code dans des applications .NET avec **`DOTNET_STARTUP_HOOKS`** avant `Main`, ou en détournant la fonctionnalité de débogage .NET lorsque ses prérequis sont réunis.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash non interactif lit **`BASH_ENV`** ; les shells POSIX interactifs lisent **`ENV`** ; zsh lit **`$ZDOTDIR/.zshenv`** ; et fish lit sa configuration dans **`XDG_CONFIG_HOME`** ou **`XDG_DATA_DIRS`**. Chacun peut exécuter un fichier de démarrage contrôlé avant la commande prévue. Bash exécute également une substitution de commande placée dans **`PS4`** lorsque xtrace est activé (par exemple, via **`SHELLOPTS=xtrace`** hérité) :

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Lancer `/bin/zsh -s` demande au shell de lire un programme depuis l’entrée standard. Ainsi, un téléchargeur qui copie un document structuré non fiable dans l’entrée standard du processus enfant sans l’analyser au préalable transforme l’ensemble du document en code source du shell. Un loader observé transmettait ligne par ligne, par un tube anonyme, un fichier iCalendar public. Les métadonnées du calendrier échouaient comme commandes, mais zsh continuait jusqu’à atteindre des lignes exécutables placées après `DESCRIPTION:`. Ces lignes téléchargeaient et lançaient le bundle d’application suivant. Le type de contenu attendu du fichier et l’hébergement de confiance ne rendaient pas cette opération sûre : le risque venait du fait de transmettre ses octets à un interpréteur.<sup>[[5]](#references)</sup>

Les étapes connexes sont présentées dans [les overlays Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper et la quarantaine](../macos-security-protections/macos-gatekeeper.md) et [les emplacements de démarrage automatique de macOS](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** ou **`PHP_INI_SCAN_DIR`** peut charger une configuration PHP contrôlée dont **`auto_prepend_file`** s’exécute avant le script cible.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

L’interpréteur Lua autonome exécute du code ou un `@file` défini par **`LUA_INIT`** (ou sa variante propre à la version) avant de traiter le script cible.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** et **`R_PROFILE`** redirigent vers des profils de démarrage contenant du code R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, associés à un chemin de bibliothèque R, peuvent aussi charger automatiquement un package installé.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** redirige vers le dépôt dont le fichier `config/startup.jl` est exécuté automatiquement.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** ou **`ERL_ZFLAGS`** peuvent injecter une expression Erlang VM **`-eval`** sans fichier payload ; les workloads Elixir lancent souvent la même VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** et **`OCTAVE_VERSION_INITFILE`** redirigent vers des scripts de démarrage Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` est une application .NET multiplateforme ; plusieurs variables d’environnement permettent donc une exécution avant la commande : **`XDG_CONFIG_HOME`** redirige vers les scripts de profil exécutés au démarrage, **`PSModulePath`** permet de détourner le chargement automatique des modules (un fichier `.psm1` placé à cet effet s’exécute à l’importation et peut masquer des cmdlets intégrées), et les variables .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** et **`DOTNET_STARTUP_HOOKS`** chargent le code de l’attaquant dans le processus avant `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Consultez les différentes options permettant à un script Perl d’exécuter du code arbitraire dans les conditions suivantes :


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Il est également possible de détourner les variables d’environnement Ruby (**`RUBYOPT`**, **`RUBYLIB`**) pour faire exécuter du code arbitraire par des scripts arbitraires :


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

La chaîne de la bibliothèque standard **`PYTHONWARNINGS`** et **`BROWSER`** peut exécuter une commande lors de l’analyse des filtres d’avertissement. Une autre méthode, basée sur un fichier, consiste à placer `sitecustomize.py` sur **`PYTHONPATH`** afin que l’initialisation normale de `site` l’importe avant le script cible. **`PYTHONBREAKPOINT`** exécute un callable/module choisi lorsque le code atteint `breakpoint()`. Les variables réservées au mode interactif, telles que **`PYTHONSTARTUP`**, ont un champ d’application plus limité.

Notez que les exécutables compilés avec **`pyinstaller`** n’utilisent pas ces variables d’environnement, même s’ils s’exécutent avec un Python embarqué.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (et son alternative `EXINIT`) est exécutée comme commandes Ex lors d’un démarrage normal. Ainsi, `:!cmd` / `:call system(...)` permettent l’exécution de code lorsqu’une victime ouvre Vim/Neovim dans un environnement contrôlé :

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Par ailleurs, Homebrew installe souvent Python sous `/opt/homebrew`, où les membres du groupe local `admin` peuvent parfois remplacer le lanceur. Il s’agit d’un détournement de binaire accessible en écriture, et non d’une injection par variable d’environnement ; vérifiez la propriété et les ACL avant de conclure que cette faille est exploitable.


## Détection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) est une application open source reposant sur **EndpointSecurity** qui détecte et bloque l’injection de processus. C’est une bonne référence pour savoir quels signaux sont observables via Endpoint Security, car elle déclenche des alertes pour :<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Les variables d’environnement d’injection** lors de l’exécution d’un processus : `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` et `ELECTRON_RUN_AS_NODE`.
- Les appels à **`task_for_pid`** — un processus demande le port de tâche d’un autre processus, condition préalable à son injection.
- **Les arguments de débogage Electron** — `--inspect`, `--inspect-brk` et `--remote-debugging-port`, qui démarrent une application Electron en mode débogage et permettent à quiconque de s’y connecter et d’y exécuter du code.<sup>[[3]](#references)</sup>
- **La création de liens symboliques ou physiques entre différents niveaux de privilèges** — le procédé classique qui consiste à « créer un lien en tant qu’utilisateur normal et à le faire pointer vers un emplacement privilégié ». Notez que **les liens symboliques peuvent déclencher une alerte, mais pas être bloqués** : EndpointSecurity n’expose pas la destination du lien avant sa création.

### Appels effectués par d’autres processus

Dans [**cet article de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), vous trouverez comment utiliser la fonction **`task_name_for_pid`** pour obtenir des informations sur d’autres **processus qui injectent du code dans un processus**, puis recueillir des informations sur ces autres processus.<sup>[[4]](#references)</sup>

Notez que pour appeler cette fonction, vous devez avoir le **même uid** que celui du processus ou être **root** (elle renvoie des informations sur le processus, mais ne permet pas d’y injecter du code).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — détection open source de l’injection de processus macOS (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Pourquoi les applications Electron ne peuvent pas stocker vos secrets de manière confidentielle : l’option --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Détection des modifications de tâches](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Une nouvelle version du stealer macOS MacSync cible les passionnés de crypto et les développeurs](https://securelist.com/macsync-new-version/121383/)
