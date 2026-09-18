# Abus des processus macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base sur les processus

Un processus est une instance d'un exécutable en cours d'exécution. Cependant, les processus n'exécutent pas de code, ce sont les threads qui s'en chargent. Par conséquent, **les processus sont simplement des conteneurs pour les threads en cours d'exécution**, fournissant la mémoire, les descripteurs, les ports, les permissions...

Traditionnellement, les processus étaient démarrés au sein d'autres processus (à l'exception du PID 1) en appelant **`fork`**, qui créait une copie exacte du processus actuel. Le **processus enfant** appelait ensuite généralement **`execve`** pour charger le nouvel exécutable et l'exécuter. Ensuite, **`vfork`** a été introduit pour accélérer ce processus sans effectuer de copie de mémoire.\
Puis **`posix_spawn`** a été introduit, combinant **`vfork`** et **`execve`** en un seul appel et acceptant des flags :

- `POSIX_SPAWN_RESETIDS`: Réinitialiser les identifiants effectifs aux identifiants réels
- `POSIX_SPAWN_SETPGROUP`: Définir l'appartenance au groupe de processus
- `POSUX_SPAWN_SETSIGDEF`: Définir le comportement par défaut des signaux
- `POSIX_SPAWN_SETSIGMASK`: Définir le masque de signaux
- `POSIX_SPAWN_SETEXEC`: Exécuter dans le même processus (comme `execve` avec davantage d'options)
- `POSIX_SPAWN_START_SUSPENDED`: Démarrer en état suspendu
- `_POSIX_SPAWN_DISABLE_ASLR`: Démarrer sans ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Utiliser l'allocateur Nano de libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Autoriser `rwx` sur les segments de données
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Fermer toutes les descriptions de fichiers lors de exec(2) par défaut
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiser les bits de poids fort du slide ASLR

De plus, `posix_spawn` accepte les paramètres **`posix_spawnattr`**, qui contrôlent certains aspects du processus créé, ainsi que les entrées **`posix_spawn_file_actions`**, qui modifient les descripteurs de fichiers.

Lorsqu'un processus se termine, il envoie le **code de retour au processus parent** (si le parent est terminé, le nouveau parent est le PID 1) avec le signal `SIGCHLD`. Le parent doit récupérer cette valeur en appelant `wait4()` ou `waitid()`. Jusqu'à cela, l'enfant reste dans un état zombie : il est toujours listé, mais ne consomme pas de ressources.

### PIDs

Les PIDs, ou identifiants de processus, identifient un processus unique. Dans XNU, les **PIDs** font **64 bits**, augmentent de manière monotone et ne reviennent **jamais à zéro** (afin d'éviter les abus).

### Groupes de processus, sessions et coalitions

Les **processus** peuvent être regroupés pour faciliter leur gestion. Par exemple, les commandes d'un script shell appartiennent au même groupe de processus, ce qui permet de les **signaler ensemble**, par exemple avec kill.\
Il est également possible de **regrouper les processus dans des sessions**. Lorsqu'un processus démarre une session (`setsid(2)`), les processus enfants sont placés dans cette session, sauf s'ils démarrent leur propre session.

La coalition est une autre manière de regrouper les processus dans Darwin. Rejoindre une coalition permet à un processus d'accéder à des ressources partagées, de partager un ledger ou d'être soumis à Jetsam. Les coalitions ont différents rôles : Leader, service XPC, Extension.

### Identifiants et personae

Chaque processus possède des **identifiants** qui **déterminent ses privilèges** dans le système. Chaque processus possède un `uid` principal et un `gid` principal (bien qu'il puisse appartenir à plusieurs groupes).\
Il est également possible de modifier l'identifiant utilisateur et l'identifiant de groupe si le binaire possède le bit `setuid/setgid`.\
Il existe plusieurs fonctions permettant de **définir de nouveaux uids/gids**.

L'appel système **`persona`** fournit un ensemble **alternatif d'identifiants**. Adopter une persona revient à adopter simultanément son uid, son gid et ses appartenances aux groupes. Dans le [**code source**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), il est possible de trouver la structure :
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

1. **POSIX Threads (pthreads) :** macOS prend en charge les threads POSIX (`pthreads`), qui font partie d’une API standard de gestion des threads pour C/C++. L’implémentation de pthreads dans macOS se trouve dans `/usr/lib/system/libsystem_pthread.dylib`, qui provient du projet `libpthread` disponible publiquement. Cette bibliothèque fournit les fonctions nécessaires pour créer et gérer des threads.
2. **Création de threads :** La fonction `pthread_create()` est utilisée pour créer de nouveaux threads. En interne, cette fonction appelle `bsdthread_create()`, un appel système de niveau inférieur propre au kernel XNU (le kernel sur lequel macOS est basé). Cet appel système utilise différents flags dérivés de `pthread_attr` (attributs), qui définissent le comportement du thread, notamment les politiques de scheduling et la taille de la stack.
- **Taille de stack par défaut :** La taille de stack par défaut des nouveaux threads est de 512 Ko, ce qui est suffisant pour les opérations classiques, mais elle peut être ajustée via les attributs du thread si davantage ou moins d’espace est nécessaire.
3. **Initialisation des threads :** La fonction `__pthread_init()` joue un rôle essentiel lors de la configuration du thread, en utilisant l’argument `env[]` pour analyser les variables d’environnement pouvant contenir des informations sur l’emplacement et la taille de la stack.

#### Terminaison des threads dans macOS

1. **Quitter les threads :** Les threads sont généralement terminés en appelant `pthread_exit()`. Cette fonction permet à un thread de se terminer proprement, d’effectuer le nettoyage nécessaire et d’envoyer une valeur de retour aux threads qui l’attendent avec join.
2. **Nettoyage des threads :** Lors de l’appel à `pthread_exit()`, la fonction `pthread_terminate()` est invoquée. Elle gère la suppression de toutes les structures associées au thread. Elle désalloue les ports de thread Mach (Mach est le sous-système de communication du kernel XNU) et appelle `bsdthread_terminate`, un syscall qui supprime les structures de niveau kernel associées au thread.

#### Mécanismes de synchronisation

Pour gérer l’accès aux ressources partagées et éviter les race conditions, macOS fournit plusieurs primitives de synchronisation. Elles sont essentielles dans les environnements multithread afin de garantir l’intégrité des données et la stabilité du système :

1. **Mutex :**
- **Mutex standard (Signature : 0x4D555458) :** Mutex standard avec une empreinte mémoire de 60 octets (56 octets pour le mutex et 4 octets pour la signature).
- **Mutex rapide (Signature : 0x4d55545A) :** Similaire à un mutex standard, mais optimisé pour des opérations plus rapides, avec également une taille de 60 octets.
2. **Variables de condition :**
- Utilisées pour attendre que certaines conditions se produisent, avec une taille de 44 octets (40 octets plus une signature de 4 octets).
- **Attributs des variables de condition (Signature : 0x434e4441) :** Attributs de configuration pour les variables de condition, d’une taille de 12 octets.
3. **Variable Once (Signature : 0x4f4e4345) :**
- Garantit qu’un code d’initialisation donné n’est exécuté qu’une seule fois. Sa taille est de 12 octets.
4. **Verrous Read-Write :**
- Permettent plusieurs lecteurs ou un seul writer à la fois, facilitant ainsi l’accès efficace aux données partagées.
- **Verrou Read Write (Signature : 0x52574c4b) :** D’une taille de 196 octets.
- **Attributs du verrou Read Write (Signature : 0x52574c41) :** Attributs des verrous Read-Write, d’une taille de 20 octets.

> [!TIP]
> Les 4 derniers octets de ces objets servent à détecter les overflows.

### Variables locales aux threads (TLV)

Les **Thread Local Variables (TLV)** dans le contexte des fichiers Mach-O (le format des exécutables dans macOS) servent à déclarer des variables propres à **chaque thread** dans une application multithread. Cela garantit que chaque thread dispose de sa propre instance distincte d’une variable, offrant ainsi un moyen d’éviter les conflits et de préserver l’intégrité des données sans avoir besoin de mécanismes de synchronisation explicites tels que les mutex.

En C et dans les langages associés, vous pouvez déclarer une variable thread-local à l’aide du mot-clé **`__thread`**. Voici comment cela fonctionne dans votre exemple :
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Cet extrait définit `tlv_var` comme une variable locale au thread. Chaque thread exécutant ce code possède sa propre `tlv_var`, et les modifications apportées par un thread à `tlv_var` n'affectent pas la variable `tlv_var` d'un autre thread.

Dans le binaire Mach-O, les données associées aux variables locales au thread sont organisées dans des sections spécifiques :

- **`__DATA.__thread_vars`** : cette section contient les métadonnées relatives aux variables locales au thread, comme leur type et leur état d'initialisation.
- **`__DATA.__thread_bss`** : cette section est utilisée pour les variables locales au thread qui ne sont pas explicitement initialisées. Elle fait partie de la mémoire réservée aux données initialisées à zéro.

Mach-O fournit également une API spécifique appelée **`tlv_atexit`** pour gérer les variables locales au thread lorsqu'un thread se termine. Cette API permet d'**enregistrer des destructeurs** : des fonctions spéciales qui nettoient les données locales au thread lorsqu'un thread se termine.

### Priorités des threads

Comprendre les priorités des threads implique d'examiner comment le système d'exploitation décide quels threads exécuter et à quel moment. Cette décision est influencée par le niveau de priorité attribué à chaque thread. Dans macOS et les systèmes de type Unix, cela s'effectue à l'aide de concepts comme `nice`, `renice` et les classes de Quality of Service (QoS).

#### Nice et Renice

1. **Nice :**
- La valeur `nice` d'un processus est un nombre qui affecte sa priorité. Chaque processus possède une valeur nice comprise entre -20 (priorité la plus élevée) et 19 (priorité la plus basse). La valeur nice par défaut lors de la création d'un processus est généralement 0.
- Une valeur nice plus faible (plus proche de -20) rend un processus plus « égoïste », en lui accordant davantage de temps CPU qu'aux autres processus ayant des valeurs nice plus élevées.
2. **Renice :**
- `renice` est une commande utilisée pour modifier la valeur nice d'un processus déjà en cours d'exécution. Elle peut être utilisée pour ajuster dynamiquement la priorité des processus, en augmentant ou en diminuant le temps CPU qui leur est alloué selon les nouvelles valeurs nice.
- Par exemple, si un processus a temporairement besoin de davantage de ressources CPU, vous pouvez diminuer sa valeur nice à l'aide de `renice`.

#### Classes de Quality of Service (QoS)

Les classes QoS constituent une approche plus moderne de la gestion des priorités des threads, notamment dans les systèmes comme macOS qui prennent en charge **Grand Central Dispatch (GCD)**. Les classes QoS permettent aux développeurs de **catégoriser** le travail selon différents niveaux, en fonction de son importance ou de son urgence. macOS gère automatiquement la priorisation des threads en fonction de ces classes QoS :

1. **User Interactive :**
- Cette classe concerne les tâches qui interagissent actuellement avec l'utilisateur ou qui nécessitent des résultats immédiats afin d'offrir une bonne expérience utilisateur. Ces tâches reçoivent la priorité la plus élevée pour maintenir la réactivité de l'interface (par exemple, les animations ou la gestion des événements).
2. **User Initiated :**
- Ces tâches sont lancées par l'utilisateur, qui attend des résultats immédiats, comme l'ouverture d'un document ou un clic sur un bouton nécessitant des calculs. Elles ont une priorité élevée, mais inférieure à celle de User Interactive.
3. **Utility :**
- Ces tâches s'exécutent sur une longue durée et affichent généralement un indicateur de progression (par exemple, le téléchargement de fichiers ou l'importation de données). Leur priorité est inférieure à celle des tâches initiées par l'utilisateur et elles n'ont pas besoin de se terminer immédiatement.
4. **Background :**
- Cette classe concerne les tâches qui s'exécutent en arrière-plan et qui ne sont pas visibles par l'utilisateur. Il peut s'agir de tâches d'indexation, de synchronisation ou de sauvegarde. Elles ont la priorité la plus faible et un impact minimal sur les performances du système.

Grâce aux classes QoS, les développeurs n'ont pas besoin de gérer les valeurs exactes de priorité et peuvent plutôt se concentrer sur la nature de la tâche ; le système optimise alors les ressources CPU en conséquence.

De plus, il existe différentes **politiques de planification des threads** qui permettent de spécifier un ensemble de paramètres de planification pris en compte par le scheduler. Cela peut être effectué avec `thread_policy_[set/get]`. Cette fonctionnalité peut être utile dans les attaques par race condition.

## Abus des processus macOS

macOS fournit de nombreux mécanismes permettant aux **processus d'interagir, de communiquer et de partager des données**. Bien que ces mécanismes soient essentiels au fonctionnement normal du système, les attaquants peuvent les détourner pour effectuer de l'injection, de l'exécution de code ou de l'accès aux données.

### Library Injection

Library Injection est une technique par laquelle un attaquant **force un processus à charger une bibliothèque malveillante**. Une fois injectée, la bibliothèque s'exécute dans le contexte du processus cible, ce qui donne à l'attaquant les mêmes permissions et le même accès que ceux du processus.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking consiste à **intercepter des appels de fonctions** ou des messages au sein d'un code logiciel. En hookant des fonctions, un attaquant peut **modifier le comportement** d'un processus, observer des données sensibles ou même prendre le contrôle du flux d'exécution.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) désigne les différentes méthodes permettant à des processus distincts de **partager et d'échanger des données**. Bien que l'IPC soit fondamentale pour de nombreuses applications légitimes, elle peut également être détournée pour contourner l'isolation des processus, provoquer un leak d'informations sensibles ou effectuer des actions non autorisées.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Les applications Electron exécutées avec certaines variables d'environnement peuvent être vulnérables à l'injection de processus :


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Il est possible d'utiliser les flags `--load-extension` et `--use-fake-ui-for-media-stream` pour effectuer une **attaque man in the browser**, permettant de voler les frappes clavier, le trafic, les cookies, d'injecter des scripts dans les pages, etc. :


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Les fichiers NIB **définissent les éléments de l'interface utilisateur (UI)** et leurs interactions au sein d'une application. Cependant, ils peuvent **exécuter des commandes arbitraires** et **Gatekeeper n'empêche pas** une application déjà exécutée de l'être à nouveau si un **fichier NIB est modifié**. Ils peuvent donc être utilisés pour faire exécuter des commandes arbitraires à des programmes arbitraires :


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Il est possible d'injecter des options JVM via **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ou **`JDK_JAVA_OPTIONS`**, et de charger un agent Java ou natif avant le démarrage de l'application.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** précharge du JavaScript contrôlé par l'attaquant via `--require` (fichier) ou `--import data:text/javascript,…` (sans fichier, Node ≥ 20.6) ; **`NODE_REPL_EXTERNAL_MODULE`** charge un module dans un REPL interactif, et **`ELECTRON_RUN_AS_NODE`** réactive toutes ces fonctionnalités sur les binaires Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Il est possible d'injecter du code dans les applications .NET via **`DOTNET_STARTUP_HOOKS`** avant `Main`, ou en détournant la fonctionnalité de debugging de .NET lorsque ses prérequis sont présents.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash non interactif lit **`BASH_ENV`** ; les shells POSIX interactifs lisent **`ENV`** ; zsh lit **`$ZDOTDIR/.zshenv`** ; et fish lit sa configuration sous **`XDG_CONFIG_HOME`** ou **`XDG_DATA_DIRS`**. Chacun peut exécuter un fichier de démarrage contrôlé avant la commande prévue. Bash exécute également une substitution de commande placée dans **`PS4`** lorsque xtrace est activé (par exemple, via **`SHELLOPTS=xtrace`** hérité) :

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** ou **`PHP_INI_SCAN_DIR`** peuvent charger une configuration PHP contrôlée dont **`auto_prepend_file`** s'exécute avant le script cible.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

L'interpréteur Lua autonome exécute du code ou un `@file` provenant de **`LUA_INIT`** (ou de sa variante spécifique à la version) avant de traiter le script cible.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** et **`R_PROFILE`** redirigent vers des profils de démarrage contenant du code R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, associés à un chemin de bibliothèque R, peuvent également charger automatiquement un package installé.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** redirige vers le depot dont `config/startup.jl` est automatiquement exécuté.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** ou **`ERL_ZFLAGS`** peuvent injecter une expression Erlang **`-eval`** dans la VM Erlang sans nécessiter de fichier de payload ; les workloads Elixir démarrent généralement la même VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** et **`OCTAVE_VERSION_INITFILE`** redirigent vers les scripts de démarrage d'Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` est une application .NET multiplateforme ; plusieurs variables d'environnement permettent donc une exécution avant la commande : **`XDG_CONFIG_HOME`** redirige vers les scripts de profil exécutés au démarrage, **`PSModulePath`** détourne le chargement automatique des modules (un fichier `.psm1` implanté s'exécute lors de l'importation et peut masquer les cmdlets intégrées), et les variables .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** et **`DOTNET_STARTUP_HOOKS`** chargent du code contrôlé par l'attaquant dans le processus avant `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Vérifiez les différentes options permettant à un script Perl d'exécuter du code arbitraire dans :

{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Il est également possible de détourner les variables d'environnement Ruby (**`RUBYOPT`**, **`RUBYLIB`**) pour faire exécuter du code arbitraire à des scripts arbitraires :


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

La chaîne de la bibliothèque standard **`PYTHONWARNINGS`** et **`BROWSER`** peut exécuter une commande lors de l'analyse des filtres d'avertissement. Une alternative basée sur un fichier place `sitecustomize.py` dans **`PYTHONPATH`**, afin que l'initialisation normale de `site` l'importe avant le script cible. **`PYTHONBREAKPOINT`** exécute un callable/module choisi lorsque le code atteint `breakpoint()`. Les variables réservées au mode interactif, comme **`PYTHONSTARTUP`**, ont une applicabilité plus limitée.

Notez que les exécutables compilés avec **`pyinstaller`** n'utiliseront pas ces variables d'environnement, même s'ils s'exécutent avec un Python intégré.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (et sa solution de repli **`EXINIT`**) est exécuté sous forme de commandes Ex lors d'un démarrage normal ; `:!cmd` / `:call system(...)` permettent donc l'exécution de code lorsqu'une victime ouvre Vim/Neovim avec un environnement contrôlé :

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Par ailleurs, Homebrew installe généralement Python sous `/opt/homebrew`, où les membres du groupe local `admin` peuvent être en mesure de remplacer le launcher. Il s'agit d'un détournement de binaire accessible en écriture plutôt que d'une injection par variable d'environnement ; vérifiez la propriété et les ACL avant de considérer ce scénario comme exploitable.


## Détection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) est une application open source basée sur **EndpointSecurity** qui détecte et bloque l'injection de processus. Elle constitue une bonne référence pour déterminer quels signaux sont observables via Endpoint Security, puisqu'elle génère des alertes sur :<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Variables d'environnement d'injection** lors de l'exécution d'un processus : `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` et `ELECTRON_RUN_AS_NODE`.
- Les appels **`task_for_pid`** — un processus demande le task port d'un autre processus, ce qui constitue le prérequis pour l'injecter.
- Les **arguments de debugging Electron** — `--inspect`, `--inspect-brk` et `--remote-debugging-port`, qui démarrent une application Electron en mode debugging et permettent à n'importe qui de s'y attacher et d'y exécuter du code.<sup>[[3]](#references)</sup>
- La **création de symlinks/hardlinks entre différents niveaux de privilèges** — la primitive classique consistant à « créer un lien en tant qu'utilisateur normal et le faire pointer vers un emplacement privilégié ». Notez que les **symlinks peuvent déclencher une alerte, mais pas être bloqués** : EndpointSecurity n'expose pas la destination du lien avant sa création.

### Appels effectués par d'autres processus

Dans [**cet article de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), vous trouverez comment utiliser la fonction **`task_name_for_pid`** pour obtenir des informations sur d'autres **processus injectant du code dans un processus**, puis obtenir des informations sur cet autre processus.<sup>[[4]](#references)</sup>

Notez que pour appeler cette fonction, vous devez avoir **le même uid** que celui utilisé pour exécuter le processus, ou être **root** (et elle renvoie des informations sur le processus, pas un moyen d'y injecter du code).

## References

- [1] [Shield — détection open source de l'injection de processus macOS (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Pourquoi les applications Electron ne peuvent pas conserver vos secrets de manière confidentielle : option --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Détection des modifications de tâches](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
