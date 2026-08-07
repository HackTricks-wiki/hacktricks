# Abuse des processus macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base sur les processus

Un processus est une instance d'un exécutable en cours d'exécution. Cependant, les processus n'exécutent pas le code, ce sont les threads qui s'en chargent. Par conséquent, **les processus sont simplement des conteneurs pour les threads en cours d'exécution**, fournissant la mémoire, les descripteurs, les ports, les permissions...

Traditionnellement, les processus étaient démarrés au sein d'autres processus (à l'exception du PID 1) en appelant **`fork`**, ce qui créait une copie exacte du processus actuel. Le **processus enfant** appelait ensuite généralement **`execve`** pour charger le nouvel exécutable et l'exécuter. Ensuite, **`vfork`** a été introduit afin d'accélérer ce processus sans copie de mémoire.\
Puis **`posix_spawn`** a été introduit, combinant **`vfork`** et **`execve`** en un seul appel et acceptant des flags :

- `POSIX_SPAWN_RESETIDS`: Réinitialiser les identifiants effectifs avec les identifiants réels
- `POSIX_SPAWN_SETPGROUP`: Définir l'appartenance au groupe de processus
- `POSUX_SPAWN_SETSIGDEF`: Définir le comportement par défaut des signaux
- `POSIX_SPAWN_SETSIGMASK`: Définir le masque des signaux
- `POSIX_SPAWN_SETEXEC`: Exécuter dans le même processus (comme `execve` avec davantage d'options)
- `POSIX_SPAWN_START_SUSPENDED`: Démarrer en état suspendu
- `_POSIX_SPAWN_DISABLE_ASLR`: Démarrer sans ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Utiliser l'allocateur Nano de libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Autoriser `rwx` sur les segments de données
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Fermer par défaut tous les descripteurs de fichiers lors de exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiser les bits de poids fort du décalage ASLR

De plus, `posix_spawn` permet de spécifier un tableau de **`posix_spawnattr`** qui contrôle certains aspects du processus créé, ainsi que des **`posix_spawn_file_actions`** pour modifier l'état des descripteurs.

Lorsqu'un processus meurt, il envoie le **code de retour au processus parent** (si le parent est mort, le nouveau parent est le PID 1) avec le signal `SIGCHLD`. Le parent doit récupérer cette valeur en appelant `wait4()` ou `waitid()` et, jusqu'à ce que cela se produise, l'enfant reste dans un état zombie : il est toujours listé, mais ne consomme pas de ressources.

### PIDs

Les PIDs, ou identifiants de processus, identifient un processus unique. Dans XNU, les **PIDs** ont une taille de **64 bits**, augmentent de manière monotone et **ne débordent jamais** (afin d'éviter les abus).

### Groupes de processus, sessions et Coalations

Les **processus** peuvent être insérés dans des **groupes** afin de faciliter leur gestion. Par exemple, les commandes d'un script shell appartiennent au même groupe de processus, ce qui permet de les **signaler ensemble**, par exemple avec kill.\
Il est également possible de **regrouper les processus dans des sessions**. Lorsqu'un processus démarre une session (`setsid(2)`), les processus enfants sont placés dans cette session, sauf s'ils démarrent leur propre session.

Coalition est une autre manière de regrouper les processus dans Darwin. Rejoindre une coalition permet à un processus d'accéder à des ressources communes, de partager un ledger ou d'être soumis à Jetsam. Les Coalations ont différents rôles : Leader, XPC service, Extension.

### Credentials et Personae

Chaque processus possède des **credentials** qui **identifient ses privilèges** dans le système. Chaque processus possède un `uid` principal et un `gid` principal (même s'il peut appartenir à plusieurs groupes).\
Il est également possible de modifier l'identifiant utilisateur et l'identifiant de groupe si le binaire possède le bit `setuid/setgid`.\
Il existe plusieurs fonctions permettant de **définir de nouveaux uids/gids**.

Le syscall **`persona`** fournit un ensemble **alternatif** de **credentials**. Adopter une persona implique d'assumer simultanément son uid, son gid et ses appartenances aux groupes. Dans le [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), il est possible de trouver la structure :
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

1. **POSIX Threads (pthreads) :** macOS prend en charge les threads POSIX (`pthreads`), qui font partie d’une API standard de gestion des threads pour le C/C++. L’implémentation de pthreads dans macOS se trouve dans `/usr/lib/system/libsystem_pthread.dylib`, qui provient du projet `libpthread` disponible publiquement. Cette bibliothèque fournit les fonctions nécessaires pour créer et gérer les threads.
2. **Création des threads :** La fonction `pthread_create()` est utilisée pour créer de nouveaux threads. En interne, cette fonction appelle `bsdthread_create()`, un appel système de niveau inférieur spécifique au kernel XNU (le kernel sur lequel macOS est basé). Cet appel système accepte différents flags dérivés de `pthread_attr` (attributs), qui spécifient le comportement du thread, notamment les politiques de scheduling et la taille de la stack.
- **Taille de stack par défaut :** La taille de stack par défaut des nouveaux threads est de 512 KB, ce qui est suffisant pour les opérations courantes, mais peut être ajusté via les attributs du thread si davantage ou moins d’espace est nécessaire.
3. **Initialisation des threads :** La fonction `__pthread_init()` est essentielle lors de la configuration du thread. Elle utilise l’argument `env[]` pour analyser les variables d’environnement, qui peuvent notamment contenir des informations sur l’emplacement et la taille de la stack.

#### Terminaison des threads dans macOS

1. **Quitter les threads :** Les threads sont généralement terminés en appelant `pthread_exit()`. Cette fonction permet à un thread de se terminer proprement, d’effectuer le nettoyage nécessaire et d’envoyer une valeur de retour aux threads qui l’attendent avec `join`.
2. **Nettoyage des threads :** Lors de l’appel à `pthread_exit()`, la fonction `pthread_terminate()` est invoquée. Elle gère la suppression de toutes les structures associées au thread. Elle désalloue les ports de threads Mach (Mach est le sous-système de communication du kernel XNU) et appelle `bsdthread_terminate`, un syscall qui supprime les structures de niveau kernel associées au thread.

#### Mécanismes de synchronisation

Pour gérer l’accès aux ressources partagées et éviter les race conditions, macOS fournit plusieurs primitives de synchronisation. Elles sont essentielles dans les environnements multi-threads afin de garantir l’intégrité des données et la stabilité du système :

1. **Mutex :**
- **Mutex standard (Signature : 0x4D555458) :** Mutex standard avec une empreinte mémoire de 60 octets (56 octets pour le mutex et 4 octets pour la signature).
- **Mutex rapide (Signature : 0x4d55545A) :** Similaire à un mutex standard, mais optimisé pour des opérations plus rapides, avec également une taille de 60 octets.
2. **Variables de condition :**
- Utilisées pour attendre que certaines conditions se produisent, avec une taille de 44 octets (40 octets plus une signature de 4 octets).
- **Attributs des variables de condition (Signature : 0x434e4441) :** Attributs de configuration des variables de condition, d’une taille de 12 octets.
3. **Variable Once (Signature : 0x4f4e4345) :**
- Garantit qu’un code d’initialisation n’est exécuté qu’une seule fois. Sa taille est de 12 octets.
4. **Read-Write Locks :**
- Permettent plusieurs lecteurs ou un seul writer à la fois, facilitant l’accès efficace aux données partagées.
- **Read Write Lock (Signature : 0x52574c4b) :** D’une taille de 196 octets.
- **Attributs des Read Write Locks (Signature : 0x52574c41) :** Attributs des read-write locks, d’une taille de 20 octets.

> [!TIP]
> Les 4 derniers octets de ces objets sont utilisés pour détecter les overflows.

### Variables locales aux threads (TLV)

Les **Variables locales aux threads (TLV)** dans le contexte des fichiers Mach-O (le format des exécutables macOS) servent à déclarer des variables propres à **chaque thread** dans une application multi-threads. Cela garantit que chaque thread possède sa propre instance distincte d’une variable, offrant ainsi un moyen d’éviter les conflits et de préserver l’intégrité des données sans nécessiter de mécanismes explicites de synchronisation tels que les mutexes.

En C et dans les langages associés, vous pouvez déclarer une variable locale à un thread à l’aide du mot-clé **`__thread`**. Voici son fonctionnement dans votre exemple :
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Cet extrait définit `tlv_var` comme une variable locale au thread. Chaque thread exécutant ce code dispose de sa propre `tlv_var`, et les modifications effectuées par un thread sur `tlv_var` n'affecteront pas la variable `tlv_var` d'un autre thread.

Dans le binaire Mach-O, les données associées aux variables locales aux threads sont organisées dans des sections spécifiques :

- **`__DATA.__thread_vars`** : cette section contient les métadonnées relatives aux variables locales aux threads, comme leur type et leur état d'initialisation.
- **`__DATA.__thread_bss`** : cette section est utilisée pour les variables locales aux threads qui ne sont pas explicitement initialisées. Elle fait partie de la mémoire réservée aux données initialisées à zéro.

Mach-O fournit également une API spécifique appelée **`tlv_atexit`** pour gérer les variables locales aux threads lorsqu'un thread se termine. Cette API permet d'**enregistrer des destructeurs** — des fonctions spéciales qui nettoient les données locales au thread lorsqu'un thread se termine.

### Priorités des threads

Comprendre les priorités des threads implique d'examiner comment le système d'exploitation décide quels threads exécuter et à quel moment. Cette décision est influencée par le niveau de priorité attribué à chaque thread. Dans macOS et les systèmes de type Unix, cela est géré à l'aide de concepts tels que `nice`, `renice` et les classes Quality of Service (QoS).

#### Nice et Renice

1. **Nice :**
- La valeur `nice` d'un processus est un nombre qui affecte sa priorité. Chaque processus possède une valeur nice comprise entre -20 (priorité la plus élevée) et 19 (priorité la plus faible). La valeur nice par défaut lors de la création d'un processus est généralement 0.
- Une valeur nice plus faible (plus proche de -20) rend un processus plus « égoïste », en lui accordant davantage de temps CPU par rapport aux autres processus ayant des valeurs nice plus élevées.
2. **Renice :**
- `renice` est une commande utilisée pour modifier la valeur nice d'un processus déjà en cours d'exécution. Elle peut être utilisée pour ajuster dynamiquement la priorité des processus, en augmentant ou en diminuant la part de temps CPU qui leur est allouée selon les nouvelles valeurs nice.
- Par exemple, si un processus a temporairement besoin de davantage de ressources CPU, vous pouvez réduire sa valeur nice à l'aide de `renice`.

#### Classes Quality of Service (QoS)

Les classes QoS constituent une approche plus moderne de la gestion des priorités des threads, notamment dans les systèmes comme macOS qui prennent en charge **Grand Central Dispatch (GCD)**. Les classes QoS permettent aux développeurs de **catégoriser** le travail selon différents niveaux, en fonction de son importance ou de son urgence. macOS gère automatiquement la priorisation des threads selon ces classes QoS :

1. **User Interactive :**
- Cette classe concerne les tâches qui interagissent actuellement avec l'utilisateur ou qui nécessitent des résultats immédiats afin d'offrir une bonne expérience utilisateur. Ces tâches reçoivent la priorité la plus élevée afin de maintenir la réactivité de l'interface (par exemple, les animations ou la gestion des événements).
2. **User Initiated :**
- Il s'agit des tâches initiées par l'utilisateur pour lesquelles celui-ci attend des résultats immédiats, comme l'ouverture d'un document ou un clic sur un bouton nécessitant des calculs. Elles ont une priorité élevée, mais inférieure à celle de User Interactive.
3. **Utility :**
- Ces tâches s'exécutent sur une longue durée et affichent généralement un indicateur de progression (par exemple, le téléchargement de fichiers ou l'importation de données). Leur priorité est inférieure à celle des tâches initiées par l'utilisateur et elles n'ont pas besoin de se terminer immédiatement.
4. **Background :**
- Cette classe concerne les tâches qui s'exécutent en arrière-plan et ne sont pas visibles par l'utilisateur. Il peut s'agir de tâches telles que l'indexation, la synchronisation ou les sauvegardes. Elles ont la priorité la plus faible et un impact minimal sur les performances du système.

Grâce aux classes QoS, les développeurs n'ont pas besoin de gérer des valeurs de priorité précises : ils peuvent se concentrer sur la nature de la tâche, tandis que le système optimise les ressources CPU en conséquence.

En outre, il existe différentes **politiques de planification des threads** qui permettent de spécifier un ensemble de paramètres de planification pris en compte par le scheduler. Cela peut être effectué à l'aide de `thread_policy_[set/get]`. Cela peut être utile dans les attaques par race condition.

## Abus des processus MacOS

MacOS, comme tout autre système d'exploitation, fournit différentes méthodes et mécanismes permettant aux **processus d'interagir, de communiquer et de partager des données**. Bien que ces techniques soient essentielles au fonctionnement efficace du système, elles peuvent également être détournées par des threat actors pour **mener des activités malveillantes**.

### Library Injection

Library Injection est une technique par laquelle un attaquant **force un processus à charger une bibliothèque malveillante**. Une fois injectée, la bibliothèque s'exécute dans le contexte du processus ciblé, donnant à l'attaquant les mêmes permissions et le même accès que ceux du processus.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking consiste à **intercepter des appels de fonction** ou des messages au sein d'un code logiciel. En hookant des fonctions, un attaquant peut **modifier le comportement** d'un processus, observer des données sensibles ou même prendre le contrôle du flux d'exécution.


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

Il est possible d'utiliser les flags `--load-extension` et `--use-fake-ui-for-media-stream` pour effectuer une **man in the browser attack**, permettant de voler les frappes clavier et le trafic, de récupérer les cookies, d'injecter des scripts dans les pages, etc. :


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Les fichiers NIB **définissent les éléments de l'interface utilisateur (UI)** et leurs interactions au sein d'une application. Cependant, ils peuvent **exécuter des commandes arbitraires** et **Gatekeeper n'empêche pas** une application déjà exécutée de s'exécuter à nouveau si un **fichier NIB est modifié**. Ils pourraient donc être utilisés pour faire exécuter des commandes arbitraires par des programmes arbitraires :


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Il est possible de détourner certaines fonctionnalités de java (comme la variable d'environnement **`_JAVA_OPTS`**) afin de faire exécuter du **code/des commandes arbitraires** par une application java.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

Il est possible d'injecter du code dans des applications .Net en **détournant la fonctionnalité de debugging de .Net** (qui n'est pas protégée par les mécanismes de protection de macOS tels que runtime hardening).


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Consultez différentes options permettant à un script Perl d'exécuter du code arbitraire dans :


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Il est également possible de détourner les variables d'environnement de ruby afin que des scripts arbitraires exécutent du code arbitraire :


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Si la variable d'environnement **`PYTHONINSPECT`** est définie, le processus python passera à une cli python une fois son exécution terminée. Il est également possible d'utiliser **`PYTHONSTARTUP`** pour indiquer un script python à exécuter au début d'une session interactive.\
Cependant, notez que le script **`PYTHONSTARTUP`** ne sera pas exécuté lorsque **`PYTHONINSPECT`** crée la session interactive.

D'autres variables d'environnement telles que **`PYTHONPATH`** et **`PYTHONHOME`** peuvent également être utiles pour faire exécuter du code arbitraire à une commande python.

Notez que les exécutables compilés avec **`pyinstaller`** n'utiliseront pas ces variables d'environnement, même s'ils s'exécutent avec un python embarqué.

> [!CAUTION]
> Globalement, je n'ai pas trouvé de moyen de faire exécuter du code arbitraire à python en détournant les variables d'environnement.\
> Cependant, la plupart des utilisateurs installent pyhton avec **Hombrew**, qui installe pyhton dans un **emplacement accessible en écriture** pour l'utilisateur admin par défaut. Vous pouvez le hijack avec quelque chose comme :
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
> Même **root** exécutera ce code lorsqu'il lancera python.


## Détection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) est une application open source basée sur **EndpointSecurity** qui détecte et bloque l'injection de processus. Il s'agit d'une bonne référence pour déterminer quels signaux sont réellement observables depuis ES, car elle génère des alertes sur :<sup>[[1]](#references)[[2]](#references)</sup>

- Les **variables d'environnement d'injection** lors de l'exécution d'un processus : `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` et `ELECTRON_RUN_AS_NODE`.
- Les appels **`task_for_pid`** — lorsqu'un processus demande le task port d'un autre processus, ce qui constitue le prérequis pour l'injection dans celui-ci.
- Les **arguments de debugging Electron** — `--inspect`, `--inspect-brk` et `--remote-debugging-port`, qui démarrent une application Electron en mode debug et permettent à n'importe qui de s'y attacher et d'y exécuter du code.<sup>[[3]](#references)</sup>
- La **création de symlinks/hardlinks entre différents niveaux de privilèges** — la primitive classique consistant à « créer un lien en tant qu'utilisateur normal et le faire pointer vers un emplacement privilégié ». Notez que les **symlinks peuvent générer des alertes, mais ne peuvent pas être bloqués** : EndpointSecurity n'expose pas la destination du lien avant sa création.

### Appels effectués par d'autres processus

Dans [**cet article de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), vous trouverez comment utiliser la fonction **`task_name_for_pid`** pour obtenir des informations sur les autres **processus injectant du code dans un processus**, puis obtenir des informations sur cet autre processus.<sup>[[4]](#references)</sup>

Notez que pour appeler cette fonction, vous devez avoir **le même uid** que celui utilisé pour exécuter le processus, ou être **root** (et elle renvoie des informations sur le processus, pas un moyen d'y injecter du code).

## Références

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications)

{{#include ../../../banners/hacktricks-training.md}}
