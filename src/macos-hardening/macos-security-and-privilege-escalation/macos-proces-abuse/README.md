# Abus des processus macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base sur les processus

Un processus est une instance d'un exécutable en cours d'exécution. Cependant, les processus n'exécutent pas de code, ce sont les threads qui s'en chargent. Par conséquent, **les processus sont simplement des conteneurs pour les threads en cours d'exécution**, fournissant la mémoire, les descripteurs, les ports, les permissions...

Traditionnellement, les processus étaient démarrés au sein d'autres processus (à l'exception du PID 1) en appelant **`fork`**, ce qui créait une copie exacte du processus actuel. Ensuite, le **processus fils** appelait généralement **`execve`** pour charger le nouvel exécutable et l'exécuter. Puis **`vfork`** a été introduit pour accélérer ce processus sans effectuer de copie de la mémoire.\
Ensuite, **`posix_spawn`** a été introduit, combinant **`vfork`** et **`execve`** en un seul appel et acceptant des flags :

- `POSIX_SPAWN_RESETIDS`: Réinitialiser les identifiants effectifs aux identifiants réels
- `POSIX_SPAWN_SETPGROUP`: Définir l'appartenance au groupe de processus
- `POSUX_SPAWN_SETSIGDEF`: Définir le comportement par défaut des signaux
- `POSIX_SPAWN_SETSIGMASK`: Définir le masque de signaux
- `POSIX_SPAWN_SETEXEC`: Exécuter dans le même processus (comme `execve` avec davantage d'options)
- `POSIX_SPAWN_START_SUSPENDED`: Démarrer en étant suspendu
- `_POSIX_SPAWN_DISABLE_ASLR`: Démarrer sans ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Utiliser l'allocateur Nano de libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Autoriser `rwx` sur les segments de données
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Fermer toutes les descriptions de fichiers lors de exec(2) par défaut
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiser les bits de poids fort du slide ASLR

De plus, `posix_spawn` accepte des paramètres **`posix_spawnattr`** qui contrôlent certains aspects du processus créé, ainsi que des entrées **`posix_spawn_file_actions`** qui modifient les descripteurs de fichiers.

Lorsqu'un processus meurt, il envoie le **code de retour au processus parent** (si le parent est mort, le nouveau parent est le PID 1) avec le signal `SIGCHLD`. Le parent doit récupérer cette valeur en appelant `wait4()` ou `waitid()` et, jusqu'à ce que cela se produise, le processus fils reste dans un état zombie où il est toujours listé, mais ne consomme pas de ressources.

### PIDs

Les PIDs, ou identifiants de processus, identifient un processus unique. Dans XNU, les **PIDs** sont des valeurs de **64 bits** qui augmentent de manière monotone et **ne rebouclent jamais** (afin d'éviter les abus).

### Groupes de processus, sessions et coalitions

Les **processus** peuvent être placés dans des **groupes** afin de faciliter leur gestion. Par exemple, les commandes d'un script shell appartiennent au même groupe de processus, ce qui permet de leur **envoyer un signal ensemble**, en utilisant par exemple kill.\
Il est également possible de **regrouper les processus dans des sessions**. Lorsqu'un processus démarre une session (`setsid(2)`), les processus fils sont placés dans cette session, sauf s'ils démarrent leur propre session.

Une coalition est une autre manière de regrouper les processus dans Darwin. Lorsqu'un processus rejoint une coalition, cela lui permet d'accéder à des ressources partagées, de partager un ledger ou d'être soumis à Jetsam. Les coalitions ont différents rôles : Leader, XPC service, Extension.

### Credentials et personae

Chaque processus possède des **credentials** qui **identifient ses privilèges** dans le système. Chaque processus possède un `uid` primaire et un `gid` primaire (bien qu'il puisse appartenir à plusieurs groupes).\
Il est également possible de modifier l'identifiant de l'utilisateur et du groupe si le binaire possède le bit `setuid/setgid`.\
Il existe plusieurs fonctions permettant de **définir de nouveaux uids/gids**.

Le syscall **`persona`** fournit un ensemble **alternatif** de **credentials**. Adopter une persona implique d'assumer simultanément son uid, son gid et ses appartenances aux groupes. Dans le [**code source**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), il est possible de trouver la structure :
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
## Informations de base sur les Threads

1. **Threads POSIX (pthreads) :** macOS prend en charge les threads POSIX (`pthreads`), qui font partie d’une API standard de gestion des threads pour C/C++. L’implémentation des pthreads dans macOS se trouve dans `/usr/lib/system/libsystem_pthread.dylib`, qui provient du projet `libpthread` disponible publiquement. Cette bibliothèque fournit les fonctions nécessaires pour créer et gérer les threads.
2. **Création de Threads :** La fonction `pthread_create()` est utilisée pour créer de nouveaux threads. En interne, cette fonction appelle `bsdthread_create()`, qui est un appel système de niveau inférieur spécifique au kernel XNU (le kernel sur lequel macOS est basé). Cet appel système prend différents flags dérivés de `pthread_attr` (attributs) qui spécifient le comportement du thread, notamment les politiques de scheduling et la taille de la stack.
- **Taille de stack par défaut :** La taille de stack par défaut des nouveaux threads est de 512 KB, ce qui est suffisant pour les opérations habituelles, mais peut être ajusté via les attributs du thread si davantage ou moins d’espace est nécessaire.
3. **Initialisation du Thread :** La fonction `__pthread_init()` joue un rôle essentiel lors de la configuration du thread, en utilisant l’argument `env[]` pour analyser les variables d’environnement pouvant contenir des informations sur l’emplacement et la taille de la stack.

#### Terminaison des Threads dans macOS

1. **Sortie des Threads :** Les threads sont généralement terminés en appelant `pthread_exit()`. Cette fonction permet à un thread de se terminer proprement, d’effectuer le nettoyage nécessaire et d’envoyer une valeur de retour aux threads qui attendent sa terminaison.
2. **Nettoyage du Thread :** Lors de l’appel à `pthread_exit()`, la fonction `pthread_terminate()` est invoquée. Elle gère la suppression de toutes les structures associées au thread. Elle désalloue les ports de threads Mach (Mach est le sous-système de communication du kernel XNU) et appelle `bsdthread_terminate`, un syscall qui supprime les structures de niveau kernel associées au thread.

#### Mécanismes de Synchronisation

Pour gérer l’accès aux ressources partagées et éviter les race conditions, macOS fournit plusieurs primitives de synchronisation. Elles sont essentielles dans les environnements multi-threads afin de garantir l’intégrité des données et la stabilité du système :

1. **Mutex :**
- **Mutex standard (Signature : 0x4D555458) :** Mutex standard avec une empreinte mémoire de 60 octets (56 octets pour le mutex et 4 octets pour la signature).
- **Mutex rapide (Signature : 0x4d55545A) :** Similaire à un mutex standard, mais optimisé pour des opérations plus rapides, avec également une taille de 60 octets.
2. **Variables de condition :**
- Utilisées pour attendre que certaines conditions se produisent, avec une taille de 44 octets (40 octets plus une signature de 4 octets).
- **Attributs des variables de condition (Signature : 0x434e4441) :** Attributs de configuration des variables de condition, d’une taille de 12 octets.
3. **Variable Once (Signature : 0x4f4e4345) :**
- Garantit qu’un code d’initialisation n’est exécuté qu’une seule fois. Sa taille est de 12 octets.
4. **Verrous Read-Write :**
- Permettent plusieurs lecteurs ou un seul writer à la fois, facilitant un accès efficace aux données partagées.
- **Read Write Lock (Signature : 0x52574c4b) :** D’une taille de 196 octets.
- **Attributs des Read Write Locks (Signature : 0x52574c41) :** Attributs des verrous Read-Write, d’une taille de 20 octets.

> [!TIP]
> Les 4 derniers octets de ces objets sont utilisés pour détecter les overflows.

### Variables Thread Local (TLV)

Les **Variables Thread Local (TLV)** dans le contexte des fichiers Mach-O (le format des exécutables dans macOS) servent à déclarer des variables spécifiques à **chaque thread** dans une application multi-threads. Cela garantit que chaque thread dispose de sa propre instance distincte d’une variable, offrant ainsi un moyen d’éviter les conflits et de préserver l’intégrité des données sans avoir besoin de mécanismes de synchronisation explicites tels que les mutex.

En C et dans les langages apparentés, vous pouvez déclarer une variable Thread Local à l’aide du mot-clé **`__thread`**. Voici comment cela fonctionne dans votre exemple :
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Cet extrait définit `tlv_var` comme une variable thread-local. Chaque thread exécutant ce code possède son propre `tlv_var`, et les modifications apportées par un thread à `tlv_var` n'affecteront pas le `tlv_var` d'un autre thread.

Dans le binaire Mach-O, les données relatives aux variables thread-local sont organisées dans des sections spécifiques :

- **`__DATA.__thread_vars`** : cette section contient les métadonnées des variables thread-local, notamment leur type et leur état d'initialisation.
- **`__DATA.__thread_bss`** : cette section est utilisée pour les variables thread-local qui ne sont pas initialisées explicitement. Elle fait partie de la mémoire réservée aux données initialisées à zéro.

Mach-O fournit également une API spécifique appelée **`tlv_atexit`** pour gérer les variables thread-local lorsqu'un thread se termine. Cette API permet d'**enregistrer des destructeurs** — des fonctions spéciales qui nettoient les données thread-local lorsqu'un thread se termine.

### Threading Priorities

Comprendre les priorités des threads implique d'examiner comment le système d'exploitation décide quels threads exécuter et à quel moment. Cette décision est influencée par le niveau de priorité attribué à chaque thread. Dans macOS et les systèmes de type Unix, cela est géré à l'aide de concepts tels que `nice`, `renice` et les classes Quality of Service (QoS).

#### Nice et Renice

1. **Nice:**
- La valeur `nice` d'un processus est un nombre qui affecte sa priorité. Chaque processus possède une valeur `nice` comprise entre -20 (priorité la plus élevée) et 19 (priorité la plus faible). La valeur `nice` par défaut lors de la création d'un processus est généralement 0.
- Une valeur `nice` plus faible (proche de -20) rend un processus plus « égoïste », en lui accordant davantage de temps CPU par rapport aux autres processus ayant des valeurs `nice` plus élevées.
2. **Renice:**
- `renice` est une commande utilisée pour modifier la valeur `nice` d'un processus déjà en cours d'exécution. Elle permet d'ajuster dynamiquement la priorité des processus, en augmentant ou en réduisant le temps CPU qui leur est attribué selon les nouvelles valeurs `nice`.
- Par exemple, si un processus a temporairement besoin de davantage de ressources CPU, vous pouvez réduire sa valeur `nice` à l'aide de `renice`.

#### Quality of Service (QoS) Classes

Les classes QoS constituent une approche plus moderne de la gestion des priorités des threads, notamment dans les systèmes tels que macOS qui prennent en charge **Grand Central Dispatch (GCD)**. Les classes QoS permettent aux développeurs de **catégoriser** le travail selon différents niveaux d'importance ou d'urgence. macOS gère automatiquement la priorisation des threads en fonction de ces classes QoS :

1. **User Interactive:**
- Cette classe concerne les tâches qui interagissent actuellement avec l'utilisateur ou qui nécessitent des résultats immédiats afin d'offrir une bonne expérience utilisateur. Ces tâches bénéficient de la priorité la plus élevée afin de maintenir la réactivité de l'interface (par exemple, les animations ou la gestion des événements).
2. **User Initiated:**
- Il s'agit des tâches lancées par l'utilisateur pour lesquelles celui-ci attend des résultats immédiats, comme l'ouverture d'un document ou un clic sur un bouton nécessitant des calculs. Elles ont une priorité élevée, mais inférieure à celle de User Interactive.
3. **Utility:**
- Ces tâches sont longues et affichent généralement un indicateur de progression (par exemple, le téléchargement de fichiers ou l'importation de données). Leur priorité est inférieure à celle des tâches initiées par l'utilisateur et elles n'ont pas besoin de se terminer immédiatement.
4. **Background:**
- Cette classe concerne les tâches exécutées en arrière-plan et invisibles pour l'utilisateur. Il peut s'agir de l'indexation, de la synchronisation ou des sauvegardes. Elles ont la priorité la plus faible et un impact minimal sur les performances du système.

Avec les classes QoS, les développeurs n'ont pas besoin de gérer les valeurs exactes de priorité ; ils peuvent plutôt se concentrer sur la nature de la tâche, tandis que le système optimise les ressources CPU en conséquence.

De plus, il existe différentes **thread scheduling policies** qui permettent de spécifier un ensemble de paramètres de planification pris en compte par le scheduler. Cela peut être effectué avec `thread_policy_[set/get]`. Cela peut être utile dans les attaques par race condition.

## macOS Process Abuse

macOS fournit de nombreux mécanismes permettant aux **processus d'interagir, de communiquer et de partager des données**. Bien que ces mécanismes soient essentiels au fonctionnement normal du système, les attaquants peuvent les exploiter pour effectuer de l'injection, de l'exécution de code ou de l'accès aux données.

### Library Injection

Library Injection est une technique par laquelle un attaquant **force un processus à charger une bibliothèque malveillante**. Une fois injectée, la bibliothèque s'exécute dans le contexte du processus cible, donnant à l'attaquant les mêmes permissions et le même accès que ce processus.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking consiste à **intercepter les appels de fonctions** ou les messages au sein d'un code logiciel. En hookant des fonctions, un attaquant peut **modifier le comportement** d'un processus, observer des données sensibles ou même prendre le contrôle du flux d'exécution.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) désigne les différentes méthodes par lesquelles des processus distincts **partagent et échangent des données**. Bien que l'IPC soit fondamentale pour de nombreuses applications légitimes, elle peut également être détournée afin de contourner l'isolation des processus, de provoquer un leak d'informations sensibles ou d'effectuer des actions non autorisées.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Les applications Electron exécutées avec certaines variables d'environnement peuvent être vulnérables à l'injection de processus :


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Il est possible d'utiliser les flags `--load-extension` et `--use-fake-ui-for-media-stream` pour effectuer une **man in the browser attack**, permettant de voler les frappes clavier et le trafic, de récupérer les cookies, d'injecter des scripts dans les pages, etc. :


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Les fichiers NIB **définissent les éléments d'interface utilisateur (UI)** et leurs interactions au sein d'une application. Cependant, ils peuvent **exécuter des commandes arbitraires** et **Gatekeeper n'empêche pas** une application déjà exécutée de s'exécuter à nouveau si un **fichier NIB est modifié**. Ils pourraient donc être utilisés pour faire exécuter des commandes arbitraires par des programmes arbitraires :


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Il est possible d'injecter des options JVM via **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** ou **`JDK_JAVA_OPTIONS`**, et de charger un agent Java ou natif avant le démarrage de l'application.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Il est possible d'injecter du code dans les applications .NET via **`DOTNET_STARTUP_HOOKS`** avant `Main`, ou d'abuser de la fonctionnalité de debugging de .NET lorsque ses prérequis sont présents.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash non interactif lit **`BASH_ENV`** ; zsh lit **`$ZDOTDIR/.zshenv`** ; et fish lit les fichiers de configuration situés sous **`XDG_CONFIG_HOME`** ou **`XDG_DATA_DIRS`**. Chacun peut exécuter un fichier de démarrage contrôlé avant la commande prévue :

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** ou **`PHP_INI_SCAN_DIR`** peuvent charger une configuration PHP contrôlée dont **`auto_prepend_file`** s'exécute avant le script cible.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

L'interpréteur Lua autonome exécute du code ou un fichier `@file` depuis **`LUA_INIT`** (ou sa variante spécifique à la version) avant de traiter le script cible.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** et **`R_PROFILE`** redirigent vers des profils de démarrage contenant du code R. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**, associés à un chemin de bibliothèque R, peuvent à la place charger automatiquement un package installé.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** redirige vers le depot dont le fichier `config/startup.jl` est exécuté automatiquement.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** ou **`ERL_ZFLAGS`** peuvent injecter une expression Erlang **`-eval`** sans nécessiter de fichier payload ; les workloads Elixir démarrent généralement la même VM.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** et **`OCTAVE_VERSION_INITFILE`** redirigent vers les scripts de démarrage d'Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

Sur macOS et Linux, **`XDG_CONFIG_HOME`** peut rediriger vers les profils utilisateur PowerShell qui s'exécutent au démarrage de `pwsh`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Consultez les différentes options permettant à un script Perl d'exécuter du code arbitraire dans :

{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Il est également possible d'abuser des variables d'environnement de Ruby pour faire exécuter du code arbitraire par des scripts arbitraires :

{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

La chaîne de la bibliothèque standard reposant sur **`PYTHONWARNINGS`** et **`BROWSER`** peut exécuter une commande pendant l'analyse des filtres d'avertissement. Une alternative basée sur un fichier place `sitecustomize.py` dans **`PYTHONPATH`**, afin que l'initialisation normale de `site` l'importe avant le script cible. Les variables réservées au mode interactif, telles que **`PYTHONSTARTUP`**, ont un champ d'application plus limité.

Notez que les exécutables compilés avec **`pyinstaller`** n'utiliseront pas ces variables d'environnement, même s'ils s'exécutent avec un Python embarqué.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

Par ailleurs, Homebrew installe généralement Python sous `/opt/homebrew`, où les membres du groupe local `admin` peuvent parfois remplacer le launcher. Il s'agit d'un détournement de binaire accessible en écriture plutôt que d'une injection par variable d'environnement ; vérifiez la propriété et les ACL avant de considérer cela comme exploitable.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) est une application open source basée sur **EndpointSecurity** qui détecte et bloque l'injection de processus. Elle constitue une bonne référence pour identifier les signaux observables via Endpoint Security, car elle génère des alertes pour :<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Les variables d'environnement d'injection** lors de l'exécution d'un processus : `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` et `ELECTRON_RUN_AS_NODE`.
- Les appels **`task_for_pid`** — un processus demandant le task port d'un autre processus, ce qui constitue le prérequis pour l'injecter.
- **Les arguments de debugging Electron** — `--inspect`, `--inspect-brk` et `--remote-debugging-port`, qui démarrent une application Electron en mode debugging et permettent à n'importe qui de s'y attacher et d'y exécuter du code.<sup>[[3]](#references)</sup>
- **La création de symlinks/hardlinks entre différents niveaux de privilèges** — la primitive classique consistant à « créer un lien en tant qu'utilisateur normal et à le faire pointer vers un emplacement privilégié ». Notez que **les symlinks peuvent déclencher une alerte, mais pas être bloqués** : EndpointSecurity n'expose pas la destination du lien avant sa création.

### Calls made by other processes

Dans [**cet article de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), vous trouverez comment utiliser la fonction **`task_name_for_pid`** pour obtenir des informations sur d'autres **processus injectant du code dans un processus**, puis obtenir des informations sur cet autre processus.<sup>[[4]](#references)</sup>

Notez que pour appeler cette fonction, vous devez avoir **le même uid** que celui utilisé pour exécuter le processus, ou être **root** (et elle renvoie des informations sur le processus, pas un moyen d'y injecter du code).

## References

- [1] [Shield — détection open source de l'injection de processus macOS (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Pourquoi les applications Electron ne peuvent pas conserver vos secrets de manière confidentielle : option --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Détection des modifications de tâches](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
