# Abus des processus macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base sur les processus

Un processus est une instance d’un exécutable en cours d’exécution. Toutefois, les processus n’exécutent pas de code : ce sont les threads qui le font. Par conséquent, **les processus sont simplement des conteneurs pour les threads en cours d’exécution**, qui fournissent la mémoire, les descripteurs, les ports, les permissions...

Traditionnellement, les processus étaient démarrés à partir d’autres processus (à l’exception du PID 1) en appelant **`fork`**, qui créait une copie exacte du processus courant. Ensuite, le **processus enfant** appelait généralement **`execve`** pour charger le nouvel exécutable et l’exécuter. Puis **`vfork`** a été introduit pour accélérer ce processus sans copier la mémoire.\
Ensuite, **`posix_spawn`** a été introduit pour combiner **`vfork`** et **`execve`** en un seul appel et accepter des flags :

- `POSIX_SPAWN_RESETIDS` : Réinitialiser les identifiants effectifs aux identifiants réels
- `POSIX_SPAWN_SETPGROUP` : Définir l’appartenance au groupe de processus
- `POSUX_SPAWN_SETSIGDEF` : Définir le comportement par défaut des signaux
- `POSIX_SPAWN_SETSIGMASK` : Définir le masque des signaux
- `POSIX_SPAWN_SETEXEC` : Exécuter dans le même processus (comme `execve`, avec davantage d’options)
- `POSIX_SPAWN_START_SUSPENDED` : Démarrer en état suspendu
- `_POSIX_SPAWN_DISABLE_ASLR` : Démarrer sans ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Utiliser l’allocateur Nano de libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Autoriser `rwx` sur les segments de données
- `POSIX_SPAWN_CLOEXEC_DEFAULT` : Fermer par défaut tous les descripteurs de fichiers lors de exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiser les bits de poids fort du décalage ASLR

De plus, `posix_spawn` accepte les paramètres **`posix_spawnattr`**, qui contrôlent certains aspects du processus créé, ainsi que les entrées **`posix_spawn_file_actions`**, qui modifient les descripteurs de fichiers.

Lorsqu’un processus meurt, il envoie son **code de retour au processus parent** (si le parent est mort, le nouveau parent est le PID 1) avec le signal `SIGCHLD`. Le parent doit récupérer cette valeur en appelant `wait4()` ou `waitid()`. Jusque-là, l’enfant reste dans un état zombie : il est toujours répertorié, mais ne consomme pas de ressources.

### PIDs

Les PIDs (identifiants de processus) identifient un processus unique. Dans XNU, les **PIDs** sont des entiers de **64 bits** qui augmentent de façon monotone et **ne reviennent jamais à zéro** (pour éviter les abus).

### Groupes de processus, sessions et coalitions

Les **processus** peuvent être regroupés pour en faciliter la gestion. Par exemple, les commandes d’un script shell appartiennent au même groupe de processus, ce qui permet de leur **envoyer des signaux ensemble**, par exemple avec kill.\
Il est également possible de **regrouper les processus dans des sessions**. Lorsqu’un processus démarre une session (`setsid(2)`), les processus enfants sont intégrés à cette session, sauf s’ils démarrent leur propre session.

Les coalitions sont un autre moyen de regrouper les processus dans Darwin. Un processus qui rejoint une coalition peut accéder aux ressources du pool, partager un ledger ou être soumis à Jetsam. Les coalitions ont différents rôles : Leader, service XPC, Extension.

### Identifiants et personae

Chaque processus possède des **identifiants** qui **déterminent ses privilèges** dans le système. Chaque processus possède un `uid` principal et un `gid` principal (bien qu’il puisse appartenir à plusieurs groupes).\
Il est également possible de changer l’identifiant d’utilisateur et de groupe si le binaire possède le bit `setuid/setgid`.\
Il existe plusieurs fonctions permettant de **définir de nouveaux uids/gids**.

L’appel système **`persona`** fournit un ensemble **alternatif** d’**identifiants**. Adopter une persona revient à prendre simultanément son uid, son gid et ses appartenances aux groupes. Dans le [**code source**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), on peut trouver la structure :

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

1. **Threads POSIX (pthreads) :** macOS prend en charge les threads POSIX (`pthreads`), qui font partie d’une API standard de gestion des threads pour C/C++. L’implémentation des pthreads dans macOS se trouve dans `/usr/lib/system/libsystem_pthread.dylib`, qui provient du projet `libpthread` accessible au public. Cette bibliothèque fournit les fonctions nécessaires pour créer et gérer des threads.
2. **Création de threads :** La fonction `pthread_create()` sert à créer de nouveaux threads. En interne, cette fonction appelle `bsdthread_create()`, un appel système de bas niveau propre au noyau XNU (le noyau sur lequel repose macOS). Cet appel système prend différents indicateurs dérivés de `pthread_attr` (attributs), qui définissent le comportement des threads, notamment les politiques d’ordonnancement et la taille de la pile.
   - **Taille de pile par défaut :** La taille de pile par défaut des nouveaux threads est de 512 Ko, ce qui suffit pour les opérations courantes. Elle peut toutefois être ajustée via les attributs du thread si davantage ou moins d’espace est nécessaire.
3. **Initialisation des threads :** La fonction `__pthread_init()` joue un rôle essentiel lors de la configuration des threads. Elle utilise l’argument `env[]` pour analyser les variables d’environnement, qui peuvent inclure des informations sur l’emplacement et la taille de la pile.

#### Terminaison des threads dans macOS

1. **Arrêt des threads :** Les threads sont généralement arrêtés en appelant `pthread_exit()`. Cette fonction permet à un thread de se terminer proprement, d’effectuer le nettoyage nécessaire et de renvoyer une valeur aux threads qui attendent sa fin.
2. **Nettoyage des threads :** Lors de l’appel à `pthread_exit()`, la fonction `pthread_terminate()` est invoquée pour supprimer toutes les structures associées au thread. Elle désalloue les ports de thread Mach (Mach est le sous-système de communication du noyau XNU) et appelle `bsdthread_terminate`, un appel système qui supprime les structures du noyau associées au thread.

#### Mécanismes de synchronisation

Pour gérer l’accès aux ressources partagées et éviter les conditions de concurrence, macOS fournit plusieurs primitives de synchronisation. Elles sont essentielles dans les environnements multithreads pour garantir l’intégrité des données et la stabilité du système :

1. **Mutex :**
   - **Mutex standard (signature : 0x4D555458) :** Mutex standard occupant 60 octets (56 octets pour le mutex et 4 octets pour la signature).
   - **Mutex rapide (signature : 0x4d55545A) :** Semblable à un mutex standard, mais optimisé pour des opérations plus rapides ; il occupe également 60 octets.
2. **Variables de condition :**
   - Utilisées pour attendre que certaines conditions soient réunies ; elles occupent 44 octets (40 octets plus une signature de 4 octets).
   - **Attributs de variable de condition (signature : 0x434e4441) :** Attributs de configuration des variables de condition, occupant 12 octets.
3. **Variable Once (signature : 0x4f4e4345) :**
   - Garantit qu’un bloc de code d’initialisation ne s’exécute qu’une seule fois. Elle occupe 12 octets.
4. **Verrous de lecture-écriture :**
   - Permettent plusieurs lecteurs ou un seul rédacteur à la fois, facilitant ainsi l’accès efficace aux données partagées.
   - **Verrou de lecture-écriture (signature : 0x52574c4b) :** Occupe 196 octets.
   - **Attributs de verrou de lecture-écriture (signature : 0x52574c41) :** Attributs des verrous de lecture-écriture, occupant 20 octets.

> [!TIP]
> Les 4 derniers octets de ces objets servent à détecter les débordements.

### Variables locales aux threads (TLV)

Les **variables locales aux threads (TLV)** dans les fichiers Mach-O (le format des exécutables dans macOS) servent à déclarer des variables propres à **chaque thread** d’une application multithread. Ainsi, chaque thread dispose de sa propre instance de la variable, ce qui permet d’éviter les conflits et de préserver l’intégrité des données sans recourir à des mécanismes de synchronisation explicites tels que les mutex.

En C et dans les langages apparentés, vous pouvez déclarer une variable locale à un thread avec le mot-clé **`__thread`**. Voici comment cela fonctionne dans votre exemple :

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Cet extrait définit `tlv_var` comme une variable locale au thread. Chaque thread qui exécute ce code aura son propre `tlv_var`, et les modifications apportées par un thread à `tlv_var` n'affecteront pas celui d'un autre thread.

Dans le binaire Mach-O, les données liées aux variables locales aux threads sont organisées dans des sections spécifiques :

- **`__DATA.__thread_vars`** : cette section contient les métadonnées des variables locales aux threads, comme leurs types et leur état d'initialisation.
- **`__DATA.__thread_bss`** : cette section est utilisée pour les variables locales aux threads qui ne sont pas explicitement initialisées. Elle correspond à une zone mémoire réservée aux données initialisées à zéro.

Mach-O fournit également une API spécifique, **`tlv_atexit`**, pour gérer les variables locales aux threads lorsqu'un thread se termine. Cette API permet d'**enregistrer des destructeurs** — des fonctions spéciales qui nettoient les données locales au thread à la fin de celui-ci.

### Priorités des threads

Pour comprendre les priorités des threads, il faut examiner comment le système d'exploitation décide quels threads exécuter et à quel moment. Cette décision dépend du niveau de priorité attribué à chaque thread. Dans macOS et les systèmes de type Unix, cette gestion repose sur des concepts comme `nice`, `renice` et les classes Quality of Service (QoS).

#### Nice et renice

1. **Nice :**
   - La valeur `nice` d'un processus est un nombre qui influe sur sa priorité. Chaque processus a une valeur `nice` comprise entre -20 (priorité la plus élevée) et 19 (priorité la plus basse). La valeur `nice` par défaut à la création d'un processus est généralement 0.
   - Une valeur `nice` plus faible (plus proche de -20) rend un processus plus « égoïste » : il obtient davantage de temps CPU que les processus dont la valeur `nice` est plus élevée.
2. **Renice :**
   - `renice` est une commande qui permet de modifier la valeur `nice` d'un processus déjà en cours d'exécution. Elle permet d'ajuster dynamiquement la priorité des processus et donc leur allocation de temps CPU, en fonction de leur nouvelle valeur `nice`.
   - Par exemple, si un processus a temporairement besoin de davantage de ressources CPU, vous pouvez réduire sa valeur `nice` avec `renice`.

#### Classes Quality of Service (QoS)

Les classes QoS constituent une approche plus moderne de la gestion des priorités des threads, notamment dans les systèmes comme macOS qui prennent en charge **Grand Central Dispatch (GCD)**. Elles permettent aux développeurs de **classer** les tâches selon leur importance ou leur urgence. macOS gère automatiquement la priorité des threads en fonction de ces classes QoS :

1. **User Interactive :**
   - Cette classe concerne les tâches qui interagissent avec l'utilisateur ou qui doivent fournir un résultat immédiatement pour garantir une bonne expérience utilisateur. Elles bénéficient de la priorité la plus élevée afin de préserver la réactivité de l'interface (par exemple, les animations ou la gestion des événements).
2. **User Initiated :**
   - Cette classe concerne les tâches lancées par l'utilisateur, dont il attend un résultat immédiat, comme l'ouverture d'un document ou le clic sur un bouton qui nécessite des calculs. Leur priorité est élevée, mais inférieure à celle des tâches User Interactive.
3. **Utility :**
   - Ces tâches sont longues et affichent généralement un indicateur de progression (par exemple, le téléchargement de fichiers ou l'importation de données). Leur priorité est inférieure à celle des tâches lancées par l'utilisateur et elles n'ont pas besoin de se terminer immédiatement.
4. **Background :**
   - Cette classe concerne les tâches exécutées en arrière-plan et invisibles pour l'utilisateur, comme l'indexation, la synchronisation ou les sauvegardes. Elles ont la priorité la plus faible et un impact minimal sur les performances du système.

Avec les classes QoS, les développeurs n'ont pas besoin de gérer les valeurs de priorité exactes : ils peuvent se concentrer sur la nature de la tâche, et le système optimise les ressources CPU en conséquence.

Il existe également différentes **politiques de planification des threads** qui définissent un ensemble de paramètres pris en compte par le planificateur. Cela peut se faire avec `thread_policy_[set/get]`. Ces politiques peuvent être utiles dans les attaques par race condition.

## Abus de processus macOS

macOS fournit de nombreux mécanismes permettant aux **processus d'interagir, de communiquer et de partager des données**. Bien qu'ils soient essentiels au fonctionnement normal du système, les attaquants peuvent les détourner pour effectuer de l'injection, exécuter du code ou accéder à des données.

### Library Injection

Library Injection est une technique par laquelle un attaquant **force un processus à charger une bibliothèque malveillante**. Une fois injectée, la bibliothèque s'exécute dans le contexte du processus ciblé et donne à l'attaquant les mêmes autorisations et accès que ce processus.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking consiste à **intercepter des appels de fonction** ou des messages dans le code d'un logiciel. En hookant des fonctions, un attaquant peut **modifier le comportement** d'un processus, observer des données sensibles, voire prendre le contrôle du flux d'exécution.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Cette page traite des métadonnées de déroulement de pile ARM64, des contraintes PAC d'arm64e et des chaînes d'appels synthétiques.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) désigne les différentes méthodes permettant à des processus distincts de **partager et d'échanger des données**. Bien que l'IPC soit essentiel à de nombreuses applications légitimes, il peut aussi être détourné pour contourner l'isolation des processus, provoquer le leak d'informations sensibles ou effectuer des actions non autorisées.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Les applications Electron lancées avec certaines variables d'environnement peuvent être vulnérables à l'injection de processus :


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Il est possible d'utiliser les flags `--load-extension` et `--use-fake-ui-for-media-stream` pour effectuer une **attaque man in the browser**, qui permet de voler les frappes clavier, le trafic et les cookies, d'injecter des scripts dans les pages, etc. :


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Les fichiers NIB **définissent les éléments d'interface utilisateur (UI)** et leurs interactions au sein d'une application. Cependant, ils peuvent **exécuter des commandes arbitraires**, et **Gatekeeper n'empêche pas** la relance d'une application déjà exécutée si un **fichier NIB est modifié**. Ils peuvent donc servir à faire exécuter des commandes arbitraires par des programmes arbitraires :


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Il est possible d'injecter des options JVM via **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ou **`JDK_JAVA_OPTIONS`**, et de charger un agent Java ou natif avant le démarrage de l'application.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** précharge le JavaScript de l'attaquant via `--require` (fichier) ou `--import data:text/javascript,…` (sans fichier, Node ≥ 20.6) ; **`NODE_REPL_EXTERNAL_MODULE`** charge un module dans un REPL interactif, et **`ELECTRON_RUN_AS_NODE`** réactive toutes ces possibilités dans les binaires Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Il est possible d'injecter du code dans des applications .NET via **`DOTNET_STARTUP_HOOKS`**, avant `Main`, ou en détournant les fonctionnalités de débogage .NET lorsque les prérequis sont réunis.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash non interactif lit **`BASH_ENV`** ; les shells POSIX interactifs lisent **`ENV`** ; zsh lit **`$ZDOTDIR/.zshenv`** ; et fish lit les fichiers de configuration sous **`XDG_CONFIG_HOME`** ou **`XDG_DATA_DIRS`**. Chacun peut exécuter un fichier de démarrage contrôlé avant la commande prévue. Bash exécute également une substitution de commande placée dans **`PS4`** chaque fois que xtrace est activé (par exemple, via **`SHELLOPTS=xtrace`** hérité) :

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

Lancer `/bin/zsh -s` fait lire au shell un programme depuis l'entrée standard. Ainsi, un téléchargeur qui copie un document structuré non fiable vers l'entrée standard du processus enfant sans l'analyser au préalable transforme le document entier en code source shell. Un loader observé transmettait un fichier iCalendar public ligne par ligne via un pipe anonyme. Les métadonnées du calendrier échouaient en tant que commandes, mais zsh continuait jusqu'à atteindre des lignes exécutables placées après `DESCRIPTION:`. Ces lignes téléchargeaient et lançaient le bundle d'application suivant. Le type de contenu attendu du document et la fiabilité de l'hébergement ne rendaient pas cette opération sûre ; le risque venait du fait que ses octets étaient transmis à un interpréteur.<sup>[[5]](#references)</sup>

Les étapes connexes sont abordées dans [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) et [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** ou **`PHP_INI_SCAN_DIR`** peuvent charger une configuration PHP contrôlée dont **`auto_prepend_file`** s'exécute avant le script cible.

[Injection au démarrage via la configuration PHP et `auto_prepend_file`](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

L'interpréteur Lua autonome exécute du code ou un `@file` défini dans **`LUA_INIT`** (ou sa variante propre à la version) avant de traiter le script cible.

[Injection au démarrage Lua via `LUA_INIT` (fichier et code inline)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** et **`R_PROFILE`** redirigent vers des profils de démarrage contenant du code R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, associés à un chemin de bibliothèque R, peuvent à la place charger automatiquement un package installé.

[Profils de démarrage R et chargement de packages](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** redirige vers le dépôt dont le fichier `config/startup.jl` est exécuté automatiquement.

[Injection Julia via `JULIA_DEPOT_PATH` et `startup.jl`](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** ou **`ERL_ZFLAGS`** peuvent injecter une expression Erlang VM **`-eval`** sans nécessiter de fichier payload ; les applications Elixir démarrent souvent la même VM.

[Injection via les flags de la VM Erlang/Elixir](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** et **`OCTAVE_VERSION_INITFILE`** redirigent vers les scripts de démarrage Octave.

[Injection via les fichiers de démarrage GNU Octave](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` est une application .NET multiplateforme ; plusieurs variables d'environnement permettent donc d'exécuter du code avant la commande : **`XDG_CONFIG_HOME`** redirige vers les scripts de profil exécutés au démarrage, **`PSModulePath`** détourne le chargement automatique des modules (un fichier `.psm1` placé à cet endroit s'exécute à l'importation et peut masquer des cmdlets intégrées), et les variables .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** et **`DOTNET_STARTUP_HOOKS`** chargent le code de l'attaquant dans le processus avant `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Consultez les différentes options permettant à un script Perl d'exécuter du code arbitraire dans :


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Il est également possible de détourner les variables d'environnement de Ruby (**`RUBYOPT`**, **`RUBYLIB`**) pour faire exécuter du code arbitraire par des scripts arbitraires :


[Options du loader Ruby `RUBYOPT`/`RUBYLIB`](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

La chaîne **`PYTHONWARNINGS`** et **`BROWSER`** de la bibliothèque standard peut exécuter une commande lors de l'analyse des filtres d'avertissement. Une autre méthode, reposant sur un fichier, consiste à placer `sitecustomize.py` dans **`PYTHONPATH`** afin que l'initialisation normale de `site` l'importe avant le script cible. **`PYTHONBREAKPOINT`** exécute une fonction ou un module choisi lorsque le code atteint `breakpoint()`.

Avec CPython 3.13 et versions ultérieures, **`PYTHONINSPECT`** peut également exécuter un fichier **`PYTHONSTARTUP`** après un script, lorsque son PyREPL démarre dans un terminal.<sup>[[6]](#references)</sup>

Notez que les exécutables compilés avec **`pyinstaller`** n'utilisent pas ces variables d'environnement, même s'ils s'exécutent avec un Python embarqué.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (et son fallback `EXINIT`) sont exécutés comme des commandes Ex lors d'un démarrage normal ; `:!cmd` / `:call system(...)` permettent donc d'exécuter du code lorsqu'une victime ouvre Vim/Neovim dans un environnement contrôlé :

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Par ailleurs, Homebrew installe souvent Python sous `/opt/homebrew`, où les membres du groupe `admin` local peuvent parfois remplacer le lanceur. Il s'agit d'un détournement de binaire accessible en écriture, et non d'une injection par variable d'environnement ; vérifiez le propriétaire et les ACL avant de considérer la vulnérabilité comme exploitable.


## Détection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) est une application open source basée sur **EndpointSecurity** qui détecte et bloque l'injection de processus. C'est une bonne référence pour connaître les signaux observables via Endpoint Security, car elle génère des alertes sur :<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Les variables d'environnement d'injection** lors de l'exécution d'un processus : `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` et `ELECTRON_RUN_AS_NODE`.
- **Les appels à `task_for_pid`** — un processus demande le port de tâche d'un autre, condition préalable à l'injection dans celui-ci.
- **Les arguments de débogage Electron** — `--inspect`, `--inspect-brk` et `--remote-debugging-port`, qui démarrent une application Electron en mode débogage et permettent à quiconque de s'y connecter et d'y exécuter du code.<sup>[[3]](#references)</sup>
- **La création de symlinks/hardlinks entre différents niveaux de privilèges** — la technique classique qui consiste à « créer un lien en tant qu'utilisateur normal, puis à le faire pointer vers un emplacement privilégié ». Notez que **les symlinks peuvent déclencher une alerte, mais pas être bloqués** : EndpointSecurity ne permet pas d'obtenir la destination du lien avant sa création.

### Appels effectués par d'autres processus

Dans [**cet article de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), vous trouverez comment utiliser la fonction **`task_name_for_pid`** pour obtenir des informations sur d'autres **processus qui injectent du code dans un processus**, puis sur ce processus tiers.<sup>[[4]](#references)</sup>

Notez que pour appeler cette fonction, vous devez avoir le **même uid** que celui du processus ou être **root** (et elle renvoie des informations sur le processus, mais ne permet pas d'y injecter du code).



## References

- [1] [Shield — détection open source de l'injection de processus macOS (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Pourquoi les applications Electron ne peuvent pas conserver vos secrets de manière confidentielle : l'option --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Détecter les modifications de tâches](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Une nouvelle version du voleur macOS MacSync cible les passionnés de crypto et les développeurs](https://securelist.com/macsync-new-version/121383/)
- [6] [Ligne de commande et environnement Python — `PYTHONINSPECT`](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONINSPECT)
{{#include ../../../banners/hacktricks-training.md}}
