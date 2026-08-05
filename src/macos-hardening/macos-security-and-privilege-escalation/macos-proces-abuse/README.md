# Abus des processus macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base sur les processus

Un processus est une instance d'un exécutable en cours d'exécution. Cependant, les processus n'exécutent pas de code : ce sont les threads qui s'en chargent. Par conséquent, **les processus sont simplement des conteneurs pour les threads en cours d'exécution**, fournissant la mémoire, les descripteurs, les ports, les permissions...

Traditionnellement, les processus étaient démarrés au sein d'autres processus (à l'exception du PID 1) en appelant **`fork`**, qui créait une copie exacte du processus actuel. Ensuite, le **processus enfant** appelait généralement **`execve`** pour charger le nouvel exécutable et l'exécuter. Puis **`vfork`** a été introduit afin d'accélérer ce processus sans effectuer de copie de la mémoire.\
Ensuite, **`posix_spawn`** a été introduit pour combiner **`vfork`** et **`execve`** en un seul appel et accepter des flags :

- `POSIX_SPAWN_RESETIDS`: Réinitialiser les identifiants effectifs aux identifiants réels
- `POSIX_SPAWN_SETPGROUP`: Définir l'appartenance au groupe de processus
- `POSUX_SPAWN_SETSIGDEF`: Définir le comportement par défaut des signaux
- `POSIX_SPAWN_SETSIGMASK`: Définir le masque de signaux
- `POSIX_SPAWN_SETEXEC`: Exécuter dans le même processus (comme `execve`, avec davantage d'options)
- `POSIX_SPAWN_START_SUSPENDED`: Démarrer en état suspendu
- `_POSIX_SPAWN_DISABLE_ASLR`: Démarrer sans ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Utiliser l'allocateur Nano de libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Autoriser `rwx` sur les segments de données
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Fermer par défaut toutes les descriptions de fichiers lors de exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiser les bits de poids fort du slide ASLR

De plus, `posix_spawn` permet de spécifier un tableau de **`posix_spawnattr`** qui contrôle certains aspects du processus créé, ainsi que des **`posix_spawn_file_actions`** pour modifier l'état des descripteurs.

Lorsqu'un processus meurt, il envoie le **code de retour au processus parent** (si le parent est mort, le nouveau parent est le PID 1) avec le signal `SIGCHLD`. Le parent doit récupérer cette valeur en appelant `wait4()` ou `waitid()` ; jusqu'à ce que cela se produise, l'enfant reste dans un état zombie, où il est toujours listé mais ne consomme pas de ressources.

### PIDs

Les PIDs, ou identifiants de processus, identifient un processus unique. Dans XNU, les **PIDs** ont une taille de **64 bits**, augmentent de manière monotone et **ne reviennent jamais à zéro** (afin d'éviter les abus).

### Groupes de processus, sessions et coalitions

Les **processus** peuvent être regroupés afin de faciliter leur gestion. Par exemple, les commandes d'un shell script appartiennent au même groupe de processus, ce qui permet de leur **envoyer un signal simultanément**, par exemple avec kill.\
Il est également possible de **regrouper des processus dans des sessions**. Lorsqu'un processus démarre une session (`setsid(2)`), les processus enfants sont placés dans cette session, sauf s'ils démarrent leur propre session.

Une coalition est une autre manière de regrouper des processus dans Darwin. Rejoindre une coalition permet à un processus d'accéder à des ressources partagées, de partager un ledger ou de subir Jetsam. Les coalitions ont différents rôles : Leader, XPC service, Extension.

### Identifiants et personae

Chaque processus possède des **identifiants** qui **déterminent ses privilèges** dans le système. Chaque processus possède un `uid` primaire et un `gid` primaire (bien qu'il puisse appartenir à plusieurs groupes).\
Il est également possible de modifier l'identifiant utilisateur et l'identifiant de groupe si le binaire possède le bit `setuid/setgid`.\
Plusieurs fonctions permettent de **définir de nouveaux uids/gids**.

L'appel système **`persona`** fournit un ensemble **alternatif** d'**identifiants**. Adopter une persona signifie adopter simultanément son uid, son gid et ses appartenances à des groupes. Dans le [**code source**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), il est possible de trouver la structure :
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

1. **POSIX Threads (pthreads) :** macOS prend en charge les threads POSIX (`pthreads`), qui font partie d’une API standard de gestion des threads pour C/C++. L’implémentation de pthreads dans macOS se trouve dans `/usr/lib/system/libsystem_pthread.dylib`, qui provient du projet `libpthread` disponible publiquement. Cette bibliothèque fournit les fonctions nécessaires pour créer et gérer les threads.
2. **Création de threads :** La fonction `pthread_create()` est utilisée pour créer de nouveaux threads. En interne, cette fonction appelle `bsdthread_create()`, un appel système de niveau inférieur spécifique au kernel XNU (le kernel sur lequel macOS est basé). Cet appel système accepte différents flags dérivés de `pthread_attr` (attributs), qui spécifient le comportement du thread, notamment les politiques de scheduling et la taille de la stack.
- **Taille de stack par défaut :** La taille de stack par défaut des nouveaux threads est de 512 KB, ce qui est suffisant pour les opérations courantes, mais peut être ajusté via les attributs du thread si davantage ou moins d’espace est nécessaire.
3. **Initialisation des threads :** La fonction `__pthread_init()` est essentielle lors de la configuration d’un thread. Elle utilise l’argument `env[]` pour analyser les variables d’environnement, qui peuvent contenir des informations sur l’emplacement et la taille de la stack.

#### Terminaison des threads dans macOS

1. **Quitter un thread :** Les threads sont généralement terminés en appelant `pthread_exit()`. Cette fonction permet à un thread de se terminer proprement, d’effectuer le nettoyage nécessaire et d’envoyer une valeur de retour aux threads qui l’attendent avec join.
2. **Nettoyage du thread :** Lors de l’appel à `pthread_exit()`, la fonction `pthread_terminate()` est invoquée. Elle gère la suppression de toutes les structures associées au thread. Elle désalloue les ports de thread Mach (Mach est le sous-système de communication du kernel XNU) et appelle `bsdthread_terminate`, un syscall qui supprime les structures de niveau kernel associées au thread.

#### Mécanismes de synchronisation

Pour gérer l’accès aux ressources partagées et éviter les conditions de concurrence, macOS fournit plusieurs primitives de synchronisation. Elles sont essentielles dans les environnements multi-thread pour garantir l’intégrité des données et la stabilité du système :

1. **Mutex :**
- **Mutex standard (Signature : 0x4D555458) :** Mutex standard avec une empreinte mémoire de 60 octets (56 octets pour le mutex et 4 octets pour la signature).
- **Mutex rapide (Signature : 0x4d55545A) :** Similaire à un mutex standard, mais optimisé pour des opérations plus rapides, avec également une taille de 60 octets.
2. **Variables de condition :**
- Utilisées pour attendre que certaines conditions se produisent, avec une taille de 44 octets (40 octets plus une signature de 4 octets).
- **Attributs de variable de condition (Signature : 0x434e4441) :** Attributs de configuration pour les variables de condition, d’une taille de 12 octets.
3. **Variable Once (Signature : 0x4f4e4345) :**
- Garantit qu’un morceau de code d’initialisation ne soit exécuté qu’une seule fois. Sa taille est de 12 octets.
4. **Verrous Read-Write :**
- Permettent plusieurs lecteurs ou un seul writer à la fois, facilitant un accès efficace aux données partagées.
- **Read Write Lock (Signature : 0x52574c4b) :** D’une taille de 196 octets.
- **Attributs Read Write Lock (Signature : 0x52574c41) :** Attributs des verrous read-write, d’une taille de 20 octets.

> [!TIP]
> Les 4 derniers octets de ces objets sont utilisés pour détecter les débordements.

### Variables locales aux threads (TLV)

Les **Thread Local Variables (TLV)** dans le contexte des fichiers Mach-O (le format des exécutables sous macOS) servent à déclarer des variables spécifiques à **chaque thread** dans une application multi-thread. Ainsi, chaque thread possède sa propre instance distincte d’une variable, ce qui permet d’éviter les conflits et de préserver l’intégrité des données sans nécessiter de mécanismes de synchronisation explicites tels que les mutex.

En C et dans les langages associés, vous pouvez déclarer une variable locale à un thread à l’aide du mot-clé **`__thread`**. Voici comment cela fonctionne dans votre exemple :
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Cet extrait définit `tlv_var` comme une variable thread-local. Chaque thread exécutant ce code possède son propre `tlv_var`, et les modifications apportées par un thread à `tlv_var` n'affectent pas le `tlv_var` d'un autre thread.

Dans le binaire Mach-O, les données associées aux variables thread-local sont organisées dans des sections spécifiques :

- **`__DATA.__thread_vars`** : cette section contient les métadonnées relatives aux variables thread-local, comme leur type et leur état d'initialisation.
- **`__DATA.__thread_bss`** : cette section est utilisée pour les variables thread-local qui ne sont pas explicitement initialisées. Elle fait partie de la mémoire réservée aux données initialisées à zéro.

Mach-O fournit également une API spécifique appelée **`tlv_atexit`** pour gérer les variables thread-local lorsqu'un thread se termine. Cette API permet d'**enregistrer des destructeurs** — des fonctions spéciales qui nettoient les données thread-local lorsqu'un thread se termine.

### Priorités des threads

Comprendre les priorités des threads implique d'examiner comment le système d'exploitation décide quels threads exécuter et à quel moment. Cette décision est influencée par le niveau de priorité attribué à chaque thread. Dans macOS et les systèmes de type Unix, cela repose sur des concepts comme `nice`, `renice` et les classes Quality of Service (QoS).

#### Nice et Renice

1. **Nice :**
- La valeur `nice` d'un processus est un nombre qui affecte sa priorité. Chaque processus possède une valeur nice comprise entre -20 (priorité la plus élevée) et 19 (priorité la plus faible). La valeur nice par défaut lors de la création d'un processus est généralement 0.
- Une valeur nice plus faible (proche de -20) rend un processus plus « égoïste », en lui accordant davantage de temps CPU qu'aux autres processus ayant des valeurs nice plus élevées.
2. **Renice :**
- `renice` est une commande utilisée pour modifier la valeur nice d'un processus déjà en cours d'exécution. Elle permet d'ajuster dynamiquement la priorité des processus, en augmentant ou en réduisant le temps CPU qui leur est alloué selon les nouvelles valeurs nice.
- Par exemple, si un processus a temporairement besoin de davantage de ressources CPU, vous pouvez réduire sa valeur nice à l'aide de `renice`.

#### Classes Quality of Service (QoS)

Les classes QoS constituent une approche plus moderne de la gestion des priorités des threads, notamment dans les systèmes comme macOS qui prennent en charge **Grand Central Dispatch (GCD)**. Les classes QoS permettent aux développeurs de **catégoriser** le travail selon différents niveaux, en fonction de son importance ou de son urgence. macOS gère automatiquement la priorité des threads en fonction de ces classes QoS :

1. **User Interactive :**
- Cette classe est destinée aux tâches qui interagissent actuellement avec l'utilisateur ou qui nécessitent des résultats immédiats afin d'offrir une bonne expérience utilisateur. Ces tâches reçoivent la priorité la plus élevée afin de maintenir la réactivité de l'interface (par exemple, les animations ou la gestion des événements).
2. **User Initiated :**
- Il s'agit des tâches lancées par l'utilisateur pour lesquelles celui-ci attend des résultats immédiats, comme l'ouverture d'un document ou le clic sur un bouton nécessitant des calculs. Elles ont une priorité élevée, mais inférieure à celle de User Interactive.
3. **Utility :**
- Ces tâches s'exécutent sur une longue durée et affichent généralement un indicateur de progression (par exemple, le téléchargement de fichiers ou l'importation de données). Leur priorité est inférieure à celle des tâches initiées par l'utilisateur et elles n'ont pas besoin de se terminer immédiatement.
4. **Background :**
- Cette classe est destinée aux tâches exécutées en arrière-plan et invisibles pour l'utilisateur. Il peut s'agir de tâches telles que l'indexation, la synchronisation ou les sauvegardes. Elles ont la priorité la plus faible et un impact minimal sur les performances du système.

Grâce aux classes QoS, les développeurs n'ont pas besoin de gérer des valeurs de priorité exactes : ils peuvent plutôt se concentrer sur la nature de la tâche, tandis que le système optimise les ressources CPU en conséquence.

En outre, il existe différentes **politiques de planification des threads** qui permettent de définir un ensemble de paramètres de planification pris en compte par le planificateur. Cela peut être réalisé à l'aide de `thread_policy_[set/get]`. Cela peut être utile dans les attaques par conditions de concurrence.

## Abus des processus macOS

MacOS, comme tout autre système d'exploitation, fournit différentes méthodes et mécanismes permettant aux **processus d'interagir, de communiquer et de partager des données**. Bien que ces techniques soient essentielles au fonctionnement efficace du système, elles peuvent également être exploitées par des acteurs malveillants pour **effectuer des activités malveillantes**.

### Injection de bibliothèques

L'injection de bibliothèques est une technique par laquelle un attaquant **force un processus à charger une bibliothèque malveillante**. Une fois injectée, la bibliothèque s'exécute dans le contexte du processus ciblé, donnant à l'attaquant les mêmes permissions et le même accès que ce processus.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Le Function Hooking consiste à **intercepter des appels de fonctions** ou des messages au sein d'un code logiciel. En hookant des fonctions, un attaquant peut **modifier le comportement** d'un processus, observer des données sensibles, voire prendre le contrôle du flux d'exécution.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Communication interprocessus

La communication interprocessus (IPC) désigne les différentes méthodes permettant à des processus distincts de **partager et d'échanger des données**. Bien que l'IPC soit fondamentale pour de nombreuses applications légitimes, elle peut également être utilisée abusivement pour contourner l'isolation des processus, effectuer un leak d'informations sensibles ou réaliser des actions non autorisées.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Injection dans les applications Electron

Les applications Electron exécutées avec certaines variables d'environnement peuvent être vulnérables à l'injection de processus :


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Injection Chromium

Il est possible d'utiliser les flags `--load-extension` et `--use-fake-ui-for-media-stream` pour effectuer une **attaque man in the browser**, permettant de voler les frappes clavier et le trafic, de récupérer les cookies, d'injecter des scripts dans les pages, etc. :


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Les fichiers NIB **définissent les éléments d'interface utilisateur (UI)** et leurs interactions au sein d'une application. Cependant, ils peuvent **exécuter des commandes arbitraires** et **Gatekeeper n'empêche pas** une application déjà exécutée de s'exécuter si un **fichier NIB est modifié**. Ils pourraient donc être utilisés pour faire exécuter des commandes arbitraires à des programmes arbitraires :


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Injection dans les applications Java

Il est possible d'abuser de certaines fonctionnalités de Java (comme la variable d'environnement **`_JAVA_OPTS`**) pour faire exécuter du **code/des commandes arbitraires** à une application Java.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Injection dans les applications .Net

Il est possible d'injecter du code dans les applications .Net en **abusant de la fonctionnalité de debugging de .Net** (qui n'est pas protégée par les mécanismes de protection de macOS tels que le runtime hardening).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Injection Perl

Consultez différentes options permettant de faire exécuter du code arbitraire à un script Perl dans :


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Injection Ruby

Il est également possible d'abuser des variables d'environnement Ruby pour faire exécuter du code arbitraire à des scripts arbitraires :


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Injection Python

Si la variable d'environnement **`PYTHONINSPECT`** est définie, le processus Python bascule vers une CLI Python une fois son exécution terminée. Il est également possible d'utiliser **`PYTHONSTARTUP`** pour indiquer un script Python à exécuter au début d'une session interactive.\
Cependant, notez que le script **`PYTHONSTARTUP`** ne sera pas exécuté lorsque **`PYTHONINSPECT`** crée la session interactive.

D'autres variables d'environnement telles que **`PYTHONPATH`** et **`PYTHONHOME`** peuvent également être utiles pour faire exécuter du code arbitraire à une commande Python.

Notez que les exécutables compilés avec **`pyinstaller`** n'utiliseront pas ces variables d'environnement, même s'ils s'exécutent avec un Python intégré.

> [!CAUTION]
> Dans l'ensemble, je n'ai pas trouvé de moyen de faire exécuter du code arbitraire à Python en abusant des variables d'environnement.\
> Cependant, la plupart des utilisateurs installent Python avec **Hombrew**, qui installe Python dans un **emplacement accessible en écriture** pour l'utilisateur administrateur par défaut. Vous pouvez le détourner avec quelque chose comme :
>
> ```bash
> mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
> cat > /opt/homebrew/bin/python3 <<EOF
> #!/bin/bash
> # Extra hijack code
> /opt/homebrew/bin/python3.old "$@"
> EOF
> chmod +x /opt/homebrew/bin/python3
> ```
>
> Même **root** exécutera ce code lors de l'exécution de Python.


## Détection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) est une application open source basée sur **EndpointSecurity** qui détecte et bloque l'injection de processus. Il s'agit d'une bonne référence pour déterminer quels signaux sont réellement observables depuis ES, puisqu'elle génère des alertes sur :<sup>[[1]](#references)</sup>

- Les **variables d'environnement d'injection** lors de l'exécution d'un processus : `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` et `ELECTRON_RUN_AS_NODE`.
- Les appels **`task_for_pid`** — lorsqu'un processus demande le port de tâche d'un autre processus, ce qui constitue le prérequis pour l'injection dans celui-ci.
- Les **arguments de debugging Electron** — `--inspect`, `--inspect-brk` et `--remote-debugging-port`, qui démarrent une application Electron en mode debugging et permettent à n'importe qui de s'y connecter et d'y exécuter du code.
- La **création de liens symboliques/liens physiques entre différents niveaux de privilèges** — la primitive classique consistant à « créer un lien en tant qu'utilisateur normal et à le faire pointer vers un emplacement privilégié ». Notez que les **liens symboliques peuvent générer des alertes, mais pas être bloqués** : EndpointSecurity n'expose pas la destination du lien avant sa création.

### Appels effectués par d'autres processus

Dans [**cet article de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), vous trouverez comment utiliser la fonction **`task_name_for_pid`** pour obtenir des informations sur d'autres **processus injectant du code dans un processus**, puis obtenir des informations sur cet autre processus.<sup>[[4]](#references)</sup>

Notez que pour appeler cette fonction, vous devez avoir **le même uid** que celui utilisé pour exécuter le processus ou être **root** (et elle renvoie des informations sur le processus, mais ne permet pas d'y injecter du code).

## Références

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
