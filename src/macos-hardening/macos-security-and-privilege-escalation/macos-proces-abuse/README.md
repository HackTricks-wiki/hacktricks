# Abus des processus macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base sur les processus

Un processus est une instance d’un exécutable en cours d’exécution. Cependant, les processus n’exécutent pas de code : ce sont les threads qui le font. Par conséquent, **les processus sont simplement des conteneurs pour les threads en cours d’exécution**, qui fournissent la mémoire, les descripteurs, les ports, les permissions...

Traditionnellement, les processus étaient lancés depuis d’autres processus (à l’exception du PID 1) en appelant **`fork`**, qui créait une copie exacte du processus courant. Ensuite, le **processus enfant** appelait généralement **`execve`** pour charger le nouvel exécutable et l’exécuter. Puis **`vfork`** a été introduit pour accélérer ce processus sans copier la mémoire.\
Ensuite, **`posix_spawn`** a été introduit. Il combine **`vfork`** et **`execve`** en un seul appel et accepte des flags :

- `POSIX_SPAWN_RESETIDS` : réinitialiser les identifiants effectifs avec les identifiants réels
- `POSIX_SPAWN_SETPGROUP` : définir l’appartenance au groupe de processus
- `POSUX_SPAWN_SETSIGDEF` : définir le comportement par défaut des signaux
- `POSIX_SPAWN_SETSIGMASK` : définir le masque de signaux
- `POSIX_SPAWN_SETEXEC` : exécuter dans le même processus (comme `execve`, avec plus d’options)
- `POSIX_SPAWN_START_SUSPENDED` : démarrer en état suspendu
- `_POSIX_SPAWN_DISABLE_ASLR` : démarrer sans ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` utiliser l’allocateur Nano de libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` autoriser `rwx` sur les segments de données
- `POSIX_SPAWN_CLOEXEC_DEFAULT` : fermer par défaut tous les descripteurs de fichiers lors de exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` randomiser les bits de poids fort du décalage ASLR

De plus, `posix_spawn` accepte des paramètres **`posix_spawnattr`** qui contrôlent certains aspects du processus lancé, ainsi que des entrées **`posix_spawn_file_actions`** qui modifient les descripteurs de fichiers.

Lorsqu’un processus se termine, il envoie son **code de retour au processus parent** (si le parent est mort, le nouveau parent est le PID 1) avec le signal `SIGCHLD`. Le parent doit récupérer cette valeur en appelant `wait4()` ou `waitid()`. En attendant, l’enfant reste dans un état zombie : il est toujours répertorié, mais ne consomme pas de ressources.

### PIDs

Les PID (identifiants de processus) identifient un processus unique. Dans XNU, les **PID** sont des entiers de **64 bits** qui augmentent de façon monotone et **ne reviennent jamais à zéro** (afin d’éviter les abus).

### Groupes de processus, sessions et coalitions

Les **processus** peuvent être répartis en **groupes** pour faciliter leur gestion. Par exemple, les commandes d’un script shell appartiennent au même groupe de processus, ce qui permet de **leur envoyer un signal simultanément**, par exemple à l’aide de kill.\
Il est également possible de **regrouper les processus dans des sessions**. Lorsqu’un processus démarre une session (`setsid(2)`), ses processus enfants sont placés dans cette session, sauf s’ils démarrent leur propre session.

Une coalition est un autre moyen de regrouper les processus dans Darwin. Un processus qui rejoint une coalition peut accéder à des ressources du pool, partager un ledger ou être soumis à Jetsam. Les coalitions ont différents rôles : leader, service XPC, extension.

### Identifiants et personae

Chaque processus détient des **identifiants** qui **déterminent ses privilèges** dans le système. Chaque processus possède un `uid` principal et un `gid` principal (bien qu’il puisse appartenir à plusieurs groupes).\
Il est également possible de modifier l’identifiant de l’utilisateur et du groupe si le binaire possède le bit `setuid/setgid`.\
Il existe plusieurs fonctions pour **définir de nouveaux uid/gid**.

L’appel système **`persona`** fournit un ensemble **alternatif** d’**identifiants**. Adopter une persona revient à adopter simultanément son uid, son gid et ses appartenances à des groupes. Dans le [**code source**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), il est possible de trouver la structure :

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

1. **POSIX Threads (pthreads) :** macOS prend en charge les threads POSIX (`pthreads`), qui font partie d’une API standard de gestion des threads pour C/C++. L’implémentation de pthreads dans macOS se trouve dans `/usr/lib/system/libsystem_pthread.dylib`, qui provient du projet `libpthread` accessible au public. Cette bibliothèque fournit les fonctions nécessaires pour créer et gérer des threads.
2. **Création de threads :** La fonction `pthread_create()` sert à créer de nouveaux threads. En interne, elle appelle `bsdthread_create()`, un appel système de plus bas niveau propre au kernel XNU (le kernel sur lequel macOS repose). Cet appel système prend différents indicateurs dérivés de `pthread_attr` (attributs) qui définissent le comportement du thread, notamment les politiques d’ordonnancement et la taille de la stack.
   - **Taille de stack par défaut :** La taille de stack par défaut des nouveaux threads est de 512 KB, ce qui suffit pour les opérations courantes, mais peut être ajusté à l’aide des attributs du thread si davantage ou moins d’espace est nécessaire.
3. **Initialisation des threads :** La fonction `__pthread_init()` est essentielle lors de la configuration d’un thread ; elle utilise l’argument `env[]` pour analyser les variables d’environnement, qui peuvent contenir des informations sur l’emplacement et la taille de la stack.

#### Terminaison des threads dans macOS

1. **Arrêt des threads :** Les threads sont généralement terminés en appelant `pthread_exit()`. Cette fonction permet à un thread de se terminer proprement, d’effectuer le nettoyage nécessaire et de transmettre une valeur de retour aux threads qui le rejoignent.
2. **Nettoyage des threads :** Lors de l’appel à `pthread_exit()`, la fonction `pthread_terminate()` est invoquée pour supprimer toutes les structures associées au thread. Elle désalloue les ports de thread Mach (Mach est le sous-système de communication du kernel XNU) et appelle `bsdthread_terminate`, un syscall qui supprime les structures du kernel associées au thread.

#### Mécanismes de synchronisation

Pour gérer l’accès aux ressources partagées et éviter les conditions de course, macOS fournit plusieurs primitives de synchronisation. Elles sont essentielles dans les environnements multithreads afin de garantir l’intégrité des données et la stabilité du système :

1. **Mutex :**
   - **Mutex standard (signature : 0x4D555458) :** Mutex standard de 60 octets (56 octets pour le mutex et 4 octets pour la signature).
   - **Mutex rapide (signature : 0x4d55545A) :** Similaire à un mutex standard, mais optimisé pour des opérations plus rapides ; il mesure également 60 octets.
2. **Variables de condition :**
   - Utilisées pour attendre que certaines conditions se produisent ; elles mesurent 44 octets (40 octets plus une signature de 4 octets).
   - **Attributs des variables de condition (signature : 0x434e4441) :** Attributs de configuration des variables de condition, d’une taille de 12 octets.
3. **Variable once (signature : 0x4f4e4345) :**
   - Garantit qu’un bloc de code d’initialisation n’est exécuté qu’une seule fois. Sa taille est de 12 octets.
4. **Verrous en lecture-écriture :**
   - Permettent plusieurs lecteurs ou un seul rédacteur à la fois, facilitant un accès efficace aux données partagées.
   - **Verrou en lecture-écriture (signature : 0x52574c4b) :** Taille de 196 octets.
   - **Attributs des verrous en lecture-écriture (signature : 0x52574c41) :** Attributs des verrous en lecture-écriture, d’une taille de 20 octets.

> [!TIP]
> Les 4 derniers octets de ces objets servent à détecter les débordements.

### Variables locales aux threads (TLV)

Les **variables locales aux threads (TLV)** dans le contexte des fichiers Mach-O (le format des exécutables dans macOS) servent à déclarer des variables propres à **chaque thread** d’une application multithread. Ainsi, chaque thread possède sa propre instance d’une variable, ce qui permet d’éviter les conflits et de préserver l’intégrité des données sans recourir à des mécanismes de synchronisation explicites comme les mutex.

En C et dans les langages apparentés, vous pouvez déclarer une variable locale à un thread à l’aide du mot-clé **`__thread`**. Voici comment cela fonctionne dans votre exemple :

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Cet extrait définit `tlv_var` comme une variable locale au thread. Chaque thread qui exécute ce code possède sa propre variable `tlv_var`, et les modifications apportées à `tlv_var` par un thread n’affectent pas la variable `tlv_var` d’un autre thread.

Dans le binaire Mach-O, les données liées aux variables locales au thread sont organisées dans des sections spécifiques :

- **`__DATA.__thread_vars`** : cette section contient les métadonnées des variables locales au thread, comme leur type et leur état d’initialisation.
- **`__DATA.__thread_bss`** : cette section est utilisée pour les variables locales au thread qui ne sont pas explicitement initialisées. Elle correspond à une zone mémoire réservée aux données initialisées à zéro.

Mach-O fournit également une API spécifique, **`tlv_atexit`**, pour gérer les variables locales au thread lorsqu’un thread se termine. Cette API permet d’**enregistrer des destructeurs** — des fonctions spéciales qui nettoient les données locales au thread à la fin de celui-ci.

### Priorités des threads

Pour comprendre les priorités des threads, il faut examiner comment le système d’exploitation décide quels threads exécuter et à quel moment. Cette décision dépend du niveau de priorité attribué à chaque thread. Dans macOS et les systèmes de type Unix, cela fait appel à des notions comme `nice`, `renice` et les classes Quality of Service (QoS).

#### Nice et Renice

1. **Nice :**
   - La valeur `nice` d’un processus est un nombre qui influe sur sa priorité. Chaque processus possède une valeur `nice` comprise entre -20 (priorité la plus élevée) et 19 (priorité la plus faible). La valeur `nice` par défaut à la création d’un processus est généralement 0.
   - Une valeur `nice` plus faible (proche de -20) rend un processus plus « égoïste » et lui accorde davantage de temps CPU qu’aux processus dont la valeur `nice` est plus élevée.
2. **Renice :**
   - `renice` est une commande qui permet de modifier la valeur `nice` d’un processus déjà en cours d’exécution. Elle permet d’ajuster dynamiquement la priorité des processus, et donc leur temps CPU, en fonction de leur nouvelle valeur `nice`.
   - Par exemple, si un processus a temporairement besoin de davantage de ressources CPU, vous pouvez diminuer sa valeur `nice` avec `renice`.

#### Classes Quality of Service (QoS)

Les classes QoS constituent une approche plus moderne de la gestion des priorités des threads, notamment dans les systèmes comme macOS qui prennent en charge **Grand Central Dispatch (GCD)**. Elles permettent aux développeurs de **classer** les tâches selon leur importance ou leur urgence. macOS gère automatiquement les priorités des threads en fonction de ces classes QoS :

1. **User Interactive :**
   - Cette classe concerne les tâches qui interagissent avec l’utilisateur ou qui doivent fournir un résultat immédiat pour garantir une bonne expérience utilisateur. Ces tâches bénéficient de la priorité la plus élevée afin de maintenir la réactivité de l’interface (par exemple, les animations ou la gestion des événements).
2. **User Initiated :**
   - Cette classe concerne les tâches lancées par l’utilisateur pour lesquelles il attend un résultat immédiat, comme l’ouverture d’un document ou le clic sur un bouton qui déclenche des calculs. Leur priorité est élevée, mais inférieure à celle des tâches User Interactive.
3. **Utility :**
   - Ces tâches sont longues et affichent généralement un indicateur de progression (par exemple, le téléchargement de fichiers ou l’importation de données). Leur priorité est inférieure à celle des tâches lancées par l’utilisateur, et elles n’ont pas besoin de se terminer immédiatement.
4. **Background :**
   - Cette classe concerne les tâches exécutées en arrière-plan et invisibles pour l’utilisateur, comme l’indexation, la synchronisation ou les sauvegardes. Elles ont la priorité la plus faible et un impact minimal sur les performances du système.

Grâce aux classes QoS, les développeurs n’ont pas besoin de gérer les valeurs de priorité exactes : ils peuvent se concentrer sur la nature de la tâche, et le système optimise les ressources CPU en conséquence.

Il existe également différentes **politiques d’ordonnancement des threads**, qui permettent de définir des paramètres d’ordonnancement pris en compte par l’ordonnanceur. Cela peut se faire avec `thread_policy_[set/get]`. Cette fonctionnalité peut être utile dans les attaques par condition de concurrence.

## Abus des processus macOS

macOS propose de nombreux mécanismes permettant aux **processus d’interagir, de communiquer et de partager des données**. Bien qu’ils soient essentiels au fonctionnement normal du système, les attaquants peuvent en abuser pour injecter du code, en exécuter ou accéder à des données.

### Library Injection

Library Injection est une technique par laquelle un attaquant **force un processus à charger une bibliothèque malveillante**. Une fois injectée, la bibliothèque s’exécute dans le contexte du processus cible, ce qui donne à l’attaquant les mêmes permissions et le même accès que ce processus.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking consiste à **intercepter des appels de fonction** ou des messages dans un logiciel. En hookant des fonctions, un attaquant peut **modifier le comportement** d’un processus, observer des données sensibles, voire prendre le contrôle du flux d’exécution.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Usurpation de pile d’appels ARM64/ARM64e

Cette page traite des métadonnées d’unwinding ARM64, des contraintes PAC d’arm64e et des chaînes d’appels synthétiques.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Communication interprocessus

La communication interprocessus (IPC) désigne les différentes méthodes permettant à des processus distincts de **partager et d’échanger des données**. Bien que l’IPC soit essentiel à de nombreuses applications légitimes, il peut aussi être détourné pour contourner l’isolation des processus, provoquer une fuite d’informations sensibles ou effectuer des actions non autorisées.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Injection dans les applications Electron

Les applications Electron exécutées avec des variables d’environnement spécifiques peuvent être vulnérables à l’injection de processus :


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Injection dans Chromium

Il est possible d’utiliser les options `--load-extension` et `--use-fake-ui-for-media-stream` pour réaliser une **attaque man in the browser** permettant de voler les frappes clavier, le trafic et les cookies, ou d’injecter des scripts dans les pages… :


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Les fichiers NIB **définissent les éléments d’interface utilisateur (UI)** et leurs interactions au sein d’une application. Cependant, ils peuvent **exécuter des commandes arbitraires**, et **Gatekeeper n’empêche pas** le lancement d’une application déjà exécutée si un **fichier NIB est modifié**. Ils peuvent donc servir à faire exécuter des commandes arbitraires par des programmes arbitraires :


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Injection dans les applications Java

Il est possible d’injecter des options JVM via **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ou **`JDK_JAVA_OPTIONS`**, et de charger un agent Java ou natif avant le démarrage de l’application.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Injection dans Node.js

**`NODE_OPTIONS`** précharge du JavaScript contrôlé par l’attaquant via `--require` (fichier) ou `--import data:text/javascript,…` (sans fichier, Node ≥ 20.6). **`NODE_REPL_EXTERNAL_MODULE`** charge un module dans un REPL interactif, et **`ELECTRON_RUN_AS_NODE`** réactive ces mécanismes dans les binaires Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### Injection dans les applications .Net

Il est possible d’injecter du code dans des applications .NET via **`DOTNET_STARTUP_HOOKS`**, avant `Main`, ou en détournant les fonctionnalités de débogage de .NET lorsque les prérequis sont réunis.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Injection dans les shells

Bash non interactif lit **`BASH_ENV`** ; les shells POSIX interactifs lisent **`ENV`** ; zsh lit **`$ZDOTDIR/.zshenv`** ; et fish lit sa configuration sous **`XDG_CONFIG_HOME`** ou **`XDG_DATA_DIRS`**. Chacun peut exécuter un fichier de démarrage contrôlé avant la commande prévue. Bash exécute également une substitution de commande placée dans **`PS4`** chaque fois que xtrace est activé (par exemple, via **`SHELLOPTS=xtrace`** hérité) :

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Insertion furtive de commandes via stdin du shell

Lancer `/bin/zsh -s` fait lire au shell un programme depuis l’entrée standard. Par conséquent, si un téléchargeur copie un document structuré non fiable dans l’entrée standard du processus enfant sans l’analyser au préalable, il transforme tout le document en code source du shell. Un chargeur observé a transmis, ligne par ligne via un tube anonyme, un fichier iCalendar public. Les métadonnées du calendrier ont échoué en tant que commandes, mais zsh a poursuivi son exécution jusqu’aux lignes exécutables placées après `DESCRIPTION:`. Ces lignes téléchargeaient et lançaient le bundle d’application suivant. Le type de contenu attendu du document et l’hébergement de confiance ne suffisaient pas à rendre cette pratique sûre : le risque venait du fait de transmettre ses octets à un interpréteur.<sup>[[5]](#references)</sup>

Les étapes associées sont abordées dans [les overlays Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper et la quarantaine](../macos-security-protections/macos-gatekeeper.md) et [les emplacements de démarrage automatique de macOS](../../macos-auto-start-locations.md).

### Injection dans PHP

**`PHPRC`** ou **`PHP_INI_SCAN_DIR`** peuvent charger une configuration PHP contrôlée dont **`auto_prepend_file`** est exécuté avant le script cible.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Injection dans Lua

L’interpréteur Lua autonome exécute du code ou un `@file` défini par **`LUA_INIT`** (ou sa variante spécifique à la version) avant de traiter le script cible.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### Injection dans R

**`R_PROFILE_USER`** et **`R_PROFILE`** redirigent vers des profils de démarrage contenant du code R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, associés à un chemin de bibliothèque R, peuvent aussi charger automatiquement un package installé.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Injection dans Julia

**`JULIA_DEPOT_PATH`** redirige vers le dépôt dont le fichier `config/startup.jl` est exécuté automatiquement.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Injection dans Erlang et Elixir

**`ERL_AFLAGS`**, **`ERL_FLAGS`** ou **`ERL_ZFLAGS`** peuvent injecter une expression Erlang **`-eval`** sans nécessiter de fichier de payload ; les applications Elixir démarrent généralement la même VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### Injection dans GNU Octave

**`OCTAVE_SITE_INITFILE`** et **`OCTAVE_VERSION_INITFILE`** redirigent vers des scripts de démarrage Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### Injection dans PowerShell

`pwsh` est une application .NET multiplateforme. Plusieurs variables d’environnement permettent donc l’exécution avant la commande : **`XDG_CONFIG_HOME`** redirige les scripts de profil exécutés au démarrage, **`PSModulePath`** détourne le chargement automatique des modules (un fichier `.psm1` placé à cet effet s’exécute lors de l’importation et peut masquer les cmdlets intégrées), et les variables .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** et **`DOTNET_STARTUP_HOOKS`** chargent le code de l’attaquant dans le processus avant `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Injection dans Perl

Consultez les différentes options permettant à un script Perl d’exécuter du code arbitraire dans :


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Injection dans Ruby

Il est également possible d’abuser des variables d’environnement de Ruby (**`RUBYOPT`**, **`RUBYLIB`**) pour faire exécuter du code arbitraire par des scripts arbitraires :


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Injection dans Python

La chaîne formée par **`PYTHONWARNINGS`** et **`BROWSER`** de la bibliothèque standard peut exécuter une commande lors de l’analyse des filtres d’avertissement. Une autre méthode, reposant sur un fichier, consiste à placer `sitecustomize.py` sur **`PYTHONPATH`** afin que l’initialisation normale de `site` l’importe avant le script cible. **`PYTHONBREAKPOINT`** exécute une fonction ou un module choisi lorsque le code atteint `breakpoint()`. Les variables réservées au mode interactif, comme **`PYTHONSTARTUP`**, ont un champ d’application plus limité.

Notez que les exécutables compilés avec **`pyinstaller`** n’utilisent pas ces variables d’environnement, même s’ils s’exécutent avec un interpréteur Python intégré.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Injection dans Vim/Neovim

**`VIMINIT`** (et sa solution de repli `EXINIT`) est exécuté comme des commandes Ex lors d’un démarrage normal. Ainsi, `:!cmd` / `:call system(...)` permet l’exécution de code lorsqu’une victime ouvre Vim/Neovim avec un environnement contrôlé :

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Par ailleurs, Homebrew installe généralement Python sous `/opt/homebrew`, où les membres du groupe local `admin` peuvent parfois remplacer le lanceur. Il s’agit d’un détournement de binaire accessible en écriture, et non d’une injection par variable d’environnement ; vérifiez le propriétaire et les ACL avant de considérer cette faille comme exploitable.


## Détection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) est une application open source basée sur **EndpointSecurity** qui détecte et bloque l’injection de processus. C’est une bonne référence pour savoir quels signaux sont observables via Endpoint Security, car elle émet des alertes sur :<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Les variables d’environnement d’injection** lors de l’exécution d’un processus : `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` et `ELECTRON_RUN_AS_NODE`.
- **Les appels à `task_for_pid`** — lorsqu’un processus demande le port de tâche d’un autre processus, prérequis à son injection.
- **Les arguments de débogage d’Electron** — `--inspect`, `--inspect-brk` et `--remote-debugging-port`, qui démarrent une application Electron en mode débogage et permettent à quiconque de s’y connecter et d’y exécuter du code.<sup>[[3]](#references)</sup>
- **La création de liens symboliques ou physiques entre différents niveaux de privilèges** — la méthode classique consistant à « créer un lien en tant qu’utilisateur normal et le faire pointer vers un emplacement privilégié ». Notez que **les liens symboliques peuvent déclencher une alerte, mais pas être bloqués** : EndpointSecurity n’expose pas la destination du lien avant sa création.

### Appels effectués par d’autres processus

Dans [**cet article de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), vous trouverez comment utiliser la fonction **`task_name_for_pid`** pour obtenir des informations sur d’autres **processus qui injectent du code dans un processus**, puis sur ce processus lui-même.<sup>[[4]](#references)</sup>

Notez que pour appeler cette fonction, vous devez avoir **le même UID** que le processus ou être **root** (elle renvoie des informations sur le processus, mais ne permet pas d’y injecter du code).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — détection open source de l’injection de processus macOS (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Pourquoi les applications Electron ne peuvent pas conserver vos secrets de manière confidentielle : option --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Détecter les modifications de tâches](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Une nouvelle version du voleur macOS MacSync cible les passionnés de cryptomonnaies et les développeurs](https://securelist.com/macsync-new-version/121383/)
