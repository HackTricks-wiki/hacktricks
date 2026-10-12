# Abus des processus macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base sur les processus

Un processus est une instance d’un exécutable en cours d’exécution. Cependant, les processus n’exécutent pas de code : ce sont les threads qui le font. Par conséquent, **les processus ne sont que des conteneurs pour les threads en cours d’exécution**, fournissant la mémoire, les descripteurs, les ports, les permissions...

Traditionnellement, les processus étaient démarrés depuis d’autres processus (à l’exception du PID 1) en appelant **`fork`**, qui créait une copie exacte du processus courant. Le **processus enfant** appelait ensuite généralement **`execve`** pour charger le nouvel exécutable et l’exécuter. Puis **`vfork`** a été introduit pour accélérer ce processus sans copie de mémoire.\
Ensuite, **`posix_spawn`** a été introduit pour combiner **`vfork`** et **`execve`** en un seul appel et accepter des flags :

- `POSIX_SPAWN_RESETIDS` : réinitialiser les identifiants effectifs aux identifiants réels
- `POSIX_SPAWN_SETPGROUP` : définir l’appartenance au groupe de processus
- `POSUX_SPAWN_SETSIGDEF` : définir le comportement par défaut des signaux
- `POSIX_SPAWN_SETSIGMASK` : définir le masque de signaux
- `POSIX_SPAWN_SETEXEC` : effectuer un Exec dans le même processus (comme `execve`, avec plus d’options)
- `POSIX_SPAWN_START_SUSPENDED` : démarrer en état suspendu
- `_POSIX_SPAWN_DISABLE_ASLR` : démarrer sans ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` utiliser l’allocateur Nano de libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` autoriser `rwx` sur les segments de données
- `POSIX_SPAWN_CLOEXEC_DEFAULT` : fermer par défaut tous les descripteurs de fichiers lors de exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` randomiser les bits de poids fort du décalage ASLR

De plus, `posix_spawn` accepte des paramètres **`posix_spawnattr`** qui contrôlent certains aspects du processus démarré, ainsi que des entrées **`posix_spawn_file_actions`** qui modifient les descripteurs de fichiers.

Lorsqu’un processus meurt, il envoie le **code de retour au processus parent** (si le parent est mort, le nouveau parent est le PID 1) avec le signal `SIGCHLD`. Le parent doit récupérer cette valeur en appelant `wait4()` ou `waitid()`. Jusque-là, l’enfant reste dans un état zombie : il est toujours répertorié, mais ne consomme pas de ressources.

### PIDs

Les PIDs, ou identifiants de processus, identifient un processus unique. Dans XNU, les **PIDs** font **64 bits**, augmentent de façon monotone et **ne reviennent jamais à zéro** (afin d’éviter les abus).

### Groupes de processus, sessions et coalitions

Les **processus** peuvent être réunis en **groupes** pour en faciliter la gestion. Par exemple, les commandes d’un script shell appartiennent au même groupe de processus, ce qui permet de **leur envoyer un signal simultanément**, par exemple avec kill.\
Il est également possible de **regrouper des processus dans des sessions**. Lorsqu’un processus démarre une session (`setsid(2)`), ses processus enfants sont placés dans cette session, sauf s’ils démarrent leur propre session.

Une coalition est un autre moyen de regrouper des processus dans Darwin. Un processus qui rejoint une coalition peut accéder aux ressources du pool, partager un registre ou être soumis à Jetsam. Les coalitions ont différents rôles : Leader, service XPC, Extension.

### Identifiants et personae

Chaque processus détient des **identifiants** qui **définissent ses privilèges** dans le système. Chaque processus possède un `uid` principal et un `gid` principal (bien qu’il puisse appartenir à plusieurs groupes).\
Il est également possible de changer l’identifiant d’utilisateur et de groupe si le binaire possède le bit `setuid/setgid`.\
Il existe plusieurs fonctions pour **définir de nouveaux uids/gids**.

L’appel système **`persona`** fournit un jeu **alternatif** d’**identifiants**. Adopter une persona revient à adopter simultanément son uid, son gid et ses appartenances aux groupes. Dans le [**code source**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), il est possible de trouver la structure :

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

1. **POSIX Threads (pthreads) :** macOS prend en charge les threads POSIX (`pthreads`), qui font partie d’une API standard de gestion des threads pour C/C++. L’implémentation de pthreads dans macOS se trouve dans `/usr/lib/system/libsystem_pthread.dylib` et provient du projet `libpthread`, disponible publiquement. Cette bibliothèque fournit les fonctions nécessaires pour créer et gérer des threads.
2. **Création de threads :** La fonction `pthread_create()` sert à créer de nouveaux threads. En interne, elle appelle `bsdthread_create()`, un appel système de niveau inférieur propre au noyau XNU (le noyau sur lequel macOS est basé). Cet appel système prend différents indicateurs issus de `pthread_attr` (attributs), qui définissent le comportement du thread, notamment les politiques d’ordonnancement et la taille de la pile.
   - **Taille de pile par défaut :** La taille de pile par défaut des nouveaux threads est de 512 Ko. Elle suffit pour les opérations courantes, mais peut être ajustée via les attributs du thread si davantage ou moins d’espace est nécessaire.
3. **Initialisation des threads :** La fonction `__pthread_init()` joue un rôle essentiel dans la configuration d’un thread. Elle utilise l’argument `env[]` pour analyser les variables d’environnement, qui peuvent inclure des informations sur l’emplacement et la taille de la pile.

#### Terminaison des threads dans macOS

1. **Sortie des threads :** Les threads sont généralement terminés en appelant `pthread_exit()`. Cette fonction permet à un thread de se terminer proprement, en effectuant le nettoyage nécessaire et en renvoyant une valeur de retour aux threads qui le rejoignent.
2. **Nettoyage des threads :** Lors de l’appel à `pthread_exit()`, la fonction `pthread_terminate()` est invoquée pour supprimer toutes les structures associées au thread. Elle désalloue les ports de thread Mach (Mach est le sous-système de communication du noyau XNU) et appelle `bsdthread_terminate`, un appel système qui supprime les structures du noyau associées au thread.

#### Mécanismes de synchronisation

Pour gérer l’accès aux ressources partagées et éviter les conditions de concurrence, macOS fournit plusieurs primitives de synchronisation. Elles sont essentielles dans les environnements multithreads afin de garantir l’intégrité des données et la stabilité du système :

1. **Mutex :**
   - **Mutex ordinaire (signature : 0x4D555458) :** mutex standard occupant 60 octets (56 octets pour le mutex et 4 octets pour la signature).
   - **Mutex rapide (signature : 0x4d55545A) :** similaire à un mutex ordinaire, mais optimisé pour des opérations plus rapides ; il occupe également 60 octets.
2. **Variables de condition :**
   - Utilisées pour attendre que certaines conditions soient réunies. Elles occupent 44 octets (40 octets plus une signature de 4 octets).
   - **Attributs des variables de condition (signature : 0x434e4441) :** attributs de configuration des variables de condition, occupant 12 octets.
3. **Variable once (signature : 0x4f4e4345) :**
   - Garantit qu’un bloc de code d’initialisation est exécuté une seule fois. Elle occupe 12 octets.
4. **Verrous de lecture-écriture :**
   - Permettent plusieurs lecteurs ou un seul rédacteur à la fois, pour un accès efficace aux données partagées.
   - **Verrou de lecture-écriture (signature : 0x52574c4b) :** occupe 196 octets.
   - **Attributs des verrous de lecture-écriture (signature : 0x52574c41) :** attributs des verrous de lecture-écriture, occupant 20 octets.

> [!TIP]
> Les 4 derniers octets de ces objets servent à détecter les débordements.

### Variables locales aux threads (TLV)

Les **variables locales aux threads (TLV)** dans les fichiers Mach-O (le format des exécutables sous macOS) servent à déclarer des variables propres à **chaque thread** d’une application multithread. Ainsi, chaque thread dispose de sa propre instance de variable, ce qui évite les conflits et préserve l’intégrité des données sans nécessiter de mécanismes de synchronisation explicites comme les mutex.

En C et dans les langages apparentés, vous pouvez déclarer une variable locale à un thread à l’aide du mot-clé **`__thread`**. Voici comment cela fonctionne dans votre exemple :

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Cet extrait définit `tlv_var` comme une variable thread-local. Chaque thread exécutant ce code possède sa propre variable `tlv_var`, et les modifications apportées par un thread à `tlv_var` n’affectent pas la variable `tlv_var` d’un autre thread.

Dans le binaire Mach-O, les données liées aux variables thread-local sont organisées dans des sections spécifiques :

- **`__DATA.__thread_vars`** : Cette section contient les métadonnées des variables thread-local, telles que leur type et leur état d’initialisation.
- **`__DATA.__thread_bss`** : Cette section est utilisée pour les variables thread-local qui ne sont pas explicitement initialisées. Elle fait partie de la mémoire réservée aux données initialisées à zéro.

Mach-O fournit également une API spécifique, **`tlv_atexit`**, pour gérer les variables thread-local à la fin d’un thread. Cette API permet d’**enregistrer des destructeurs** — des fonctions spéciales qui nettoient les données thread-local lorsqu’un thread se termine.

### Priorités des threads

Pour comprendre les priorités des threads, il faut examiner comment le système d’exploitation décide quels threads exécuter et à quel moment. Cette décision dépend du niveau de priorité attribué à chaque thread. Dans macOS et les systèmes de type Unix, cela repose sur des concepts tels que `nice`, `renice` et les classes Quality of Service (QoS).

#### Nice et Renice

1. **Nice :**
   - La valeur `nice` d’un processus est un nombre qui influe sur sa priorité. Chaque processus a une valeur `nice` comprise entre -20 (priorité la plus élevée) et 19 (priorité la plus basse). La valeur `nice` par défaut à la création d’un processus est généralement 0.
   - Une valeur `nice` plus basse (proche de -20) rend un processus plus « égoïste » et lui accorde davantage de temps CPU par rapport aux processus ayant une valeur `nice` plus élevée.
2. **Renice :**
   - `renice` est une commande qui permet de modifier la valeur `nice` d’un processus déjà en cours d’exécution. Elle permet d’ajuster dynamiquement la priorité des processus et le temps CPU qui leur est alloué en fonction de leur nouvelle valeur `nice`.
   - Par exemple, si un processus a temporairement besoin de davantage de ressources CPU, vous pouvez réduire sa valeur `nice` avec `renice`.

#### Classes Quality of Service (QoS)

Les classes QoS constituent une approche plus moderne de la gestion des priorités des threads, notamment dans les systèmes comme macOS qui prennent en charge **Grand Central Dispatch (GCD)**. Elles permettent aux développeurs de **classer** les tâches selon leur importance ou leur urgence. macOS gère automatiquement la priorité des threads en fonction de ces classes QoS :

1. **User Interactive :**
   - Cette classe concerne les tâches qui interagissent avec l’utilisateur ou nécessitent des résultats immédiats pour garantir une bonne expérience. Ces tâches bénéficient de la priorité la plus élevée afin de préserver la réactivité de l’interface (par exemple, les animations ou le traitement des événements).
2. **User Initiated :**
   - Cette classe concerne les tâches lancées par l’utilisateur, dont il attend des résultats immédiats, comme l’ouverture d’un document ou un clic sur un bouton nécessitant des calculs. Leur priorité est élevée, mais inférieure à celle de la classe User Interactive.
3. **Utility :**
   - Ces tâches sont de longue durée et affichent généralement un indicateur de progression (par exemple, le téléchargement de fichiers ou l’importation de données). Leur priorité est inférieure à celle des tâches lancées par l’utilisateur, et elles n’ont pas besoin de se terminer immédiatement.
4. **Background :**
   - Cette classe concerne les tâches exécutées en arrière-plan et invisibles pour l’utilisateur, comme l’indexation, la synchronisation ou les sauvegardes. Elles ont la priorité la plus basse et un impact minimal sur les performances du système.

Grâce aux classes QoS, les développeurs n’ont pas besoin de gérer les valeurs de priorité exactes : ils peuvent se concentrer sur la nature de la tâche, et le système optimise les ressources CPU en conséquence.

Il existe également différentes **politiques d’ordonnancement des threads** qui permettent de spécifier un ensemble de paramètres d’ordonnancement pris en compte par l’ordonnanceur. Cela peut se faire avec `thread_policy_[set/get]`. Cette fonctionnalité peut être utile dans les attaques par race condition.

## Abus des processus macOS

macOS fournit de nombreux mécanismes permettant aux **processus d’interagir, de communiquer et de partager des données**. Bien que ces mécanismes soient essentiels au fonctionnement normal du système, les attaquants peuvent les détourner pour réaliser de l’injection, de l’exécution de code ou de l’accès aux données.

### Injection de bibliothèques

L’injection de bibliothèques est une technique par laquelle un attaquant **force un processus à charger une bibliothèque malveillante**. Une fois injectée, la bibliothèque s’exécute dans le contexte du processus cible et donne à l’attaquant les mêmes autorisations et le même accès que ce processus.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Le Function Hooking consiste à **intercepter des appels de fonction** ou des messages dans un logiciel. En hookant des fonctions, un attaquant peut **modifier le comportement** d’un processus, observer des données sensibles ou même prendre le contrôle du flux d’exécution.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Usurpation de la pile d’appels ARM64/ARM64e

Cette page traite des métadonnées de déroulement de pile ARM64, des contraintes PAC d’arm64e et des chaînes d’appels synthétiques.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Communication interprocessus

La communication interprocessus (IPC) désigne les différentes méthodes permettant à des processus distincts de **partager et d’échanger des données**. Bien que l’IPC soit essentiel à de nombreuses applications légitimes, il peut aussi être détourné pour contourner l’isolation des processus, divulguer des informations sensibles ou effectuer des actions non autorisées.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Injection dans les applications Electron

Les applications Electron exécutées avec certaines variables d’environnement peuvent être vulnérables à l’injection de processus :


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Injection dans Chromium

Il est possible d’utiliser les flags `--load-extension` et `--use-fake-ui-for-media-stream` pour réaliser une **attaque man in the browser**, permettant de voler des frappes au clavier, du trafic et des cookies, et d’injecter des scripts dans des pages :


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Les fichiers NIB **définissent les éléments d’interface utilisateur (UI)** et leurs interactions au sein d’une application. Cependant, ils peuvent **exécuter des commandes arbitraires**, et **Gatekeeper n’empêche pas** une application déjà exécutée de l’être à nouveau si un **fichier NIB est modifié**. Ils peuvent donc servir à faire exécuter des commandes arbitraires par des programmes :


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Injection dans les applications Java

Il est possible d’injecter des options JVM via **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ou **`JDK_JAVA_OPTIONS`**, puis de charger un agent Java ou natif avant le démarrage de l’application.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Injection dans Node.js

**`NODE_OPTIONS`** précharge du JavaScript contrôlé par l’attaquant avec `--require` (fichier) ou `--import data:text/javascript,…` (sans fichier, Node ≥ 20.6) ; **`NODE_REPL_EXTERNAL_MODULE`** charge un module dans un REPL interactif, et **`ELECTRON_RUN_AS_NODE`** réactive tout cela sur les binaires Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### Injection dans les applications .Net

Il est possible d’injecter du code dans des applications .NET via **`DOTNET_STARTUP_HOOKS`** avant `Main`, ou en détournant la fonctionnalité de débogage .NET lorsque ses prérequis sont présents.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Injection dans les shells

Bash non interactif lit **`BASH_ENV`** ; les shells POSIX interactifs lisent **`ENV`** ; zsh lit **`$ZDOTDIR/.zshenv`** ; et fish lit les fichiers de configuration situés sous **`XDG_CONFIG_HOME`** ou **`XDG_DATA_DIRS`**. Chacun peut exécuter un fichier de démarrage contrôlé avant la commande prévue. Bash exécute également une substitution de commande placée dans **`PS4`** lorsque xtrace est activé (par exemple, via **`SHELLOPTS=xtrace`** hérité) :

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Injection PHP

**`PHPRC`** ou **`PHP_INI_SCAN_DIR`** peut charger une configuration PHP contrôlée dont **`auto_prepend_file`** s’exécute avant le script cible.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Injection Lua

L’interpréteur Lua autonome exécute du code ou un `@file` défini dans **`LUA_INIT`** (ou sa variante propre à la version) avant de traiter le script cible.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### Injection R

**`R_PROFILE_USER`** et **`R_PROFILE`** redirigent vers des profils de démarrage contenant du code R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, associés à un chemin de bibliothèque R, peuvent aussi charger automatiquement un package installé.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Injection Julia

**`JULIA_DEPOT_PATH`** redirige vers le dépôt dont le fichier `config/startup.jl` est exécuté automatiquement.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Injection Erlang et Elixir

**`ERL_AFLAGS`**, **`ERL_FLAGS`** ou **`ERL_ZFLAGS`** peuvent injecter une expression Erlang VM **`-eval`** sans nécessiter de fichier payload ; les applications Elixir démarrent généralement la même VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### Injection GNU Octave

**`OCTAVE_SITE_INITFILE`** et **`OCTAVE_VERSION_INITFILE`** redirigent vers des scripts de démarrage Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### Injection PowerShell

`pwsh` est une application .NET multiplateforme ; plusieurs variables d’environnement permettent donc l’exécution de code avant la commande : **`XDG_CONFIG_HOME`** redirige les scripts de profil exécutés au démarrage, **`PSModulePath`** détourne le chargement automatique des modules (un fichier `.psm1` placé à cet endroit s’exécute à l’importation et peut masquer des cmdlets intégrées), et les variables .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** et **`DOTNET_STARTUP_HOOKS`** chargent le code de l’attaquant dans le processus avant `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Injection Perl

Consultez les différentes options permettant à un script Perl d’exécuter du code arbitraire dans :


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Injection Ruby

Il est également possible de détourner les variables d’environnement Ruby (**`RUBYOPT`**, **`RUBYLIB`**) pour faire exécuter du code arbitraire par des scripts :


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Injection Python

La chaîne **`PYTHONWARNINGS`** et **`BROWSER`** de la bibliothèque standard peut exécuter une commande lors de l’analyse des filtres d’avertissement. Une autre méthode, reposant sur un fichier, consiste à placer `sitecustomize.py` dans **`PYTHONPATH`** afin que l’initialisation normale de `site` l’importe avant le script cible. **`PYTHONBREAKPOINT`** exécute une fonction ou un module choisi lorsque le code atteint `breakpoint()`. Les variables réservées au mode interactif, comme **`PYTHONSTARTUP`**, ont un champ d’application plus limité.

Notez que les exécutables compilés avec **`pyinstaller`** n’utilisent pas ces variables d’environnement, même s’ils s’exécutent avec un Python intégré.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Injection Vim/Neovim

**`VIMINIT`** (et sa solution de repli `EXINIT`) sont exécutés comme des commandes Ex au démarrage normal. Ainsi, `:!cmd` / `:call system(...)` permettent l’exécution de code lorsqu’une victime ouvre Vim/Neovim avec un environnement contrôlé :

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Par ailleurs, Homebrew installe souvent Python sous `/opt/homebrew`, où les membres du groupe local `admin` peuvent être en mesure de remplacer le lanceur. Il s’agit d’un détournement de binaire modifiable, et non d’une injection par variable d’environnement ; vérifiez la propriété et les ACL avant de considérer le problème comme exploitable.


## Détection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) est une application open source basée sur **EndpointSecurity** qui détecte et bloque l’injection de processus. Elle constitue une bonne référence sur les signaux observables via Endpoint Security, car elle déclenche des alertes sur :<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Les variables d’environnement d’injection** lors de l’exécution d’un processus : `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` et `ELECTRON_RUN_AS_NODE`.
- **Les appels à `task_for_pid`** — un processus demande le port de tâche d’un autre processus, préalable à son injection.
- **Les arguments de débogage Electron** — `--inspect`, `--inspect-brk` et `--remote-debugging-port`, qui démarrent une application Electron en mode débogage et permettent à quiconque de s’y attacher et d’y exécuter du code.<sup>[[3]](#references)</sup>
- **La création de symlinks/hardlinks entre différents niveaux de privilèges** — la technique classique qui consiste à « créer un lien en tant qu’utilisateur normal et le faire pointer vers un emplacement privilégié ». Notez que **les symlinks peuvent déclencher une alerte, mais pas être bloqués** : EndpointSecurity n’expose pas la destination du lien avant sa création.

### Appels effectués par d’autres processus

Dans [**cet article de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), vous trouverez comment utiliser la fonction **`task_name_for_pid`** pour obtenir des informations sur d’autres **processus injectant du code dans un processus**, puis obtenir des informations sur ces processus.<sup>[[4]](#references)</sup>

Notez que pour appeler cette fonction, vous devez avoir le **même uid** que celui du processus ou être **root** (elle renvoie des informations sur le processus, mais ne permet pas d’y injecter du code).

## References

- [1] [Shield — détection open source de l’injection de processus macOS (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Pourquoi les applications Electron ne peuvent pas conserver vos secrets de manière confidentielle : option --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Détecter les modifications de tâches](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
