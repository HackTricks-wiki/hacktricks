# Méthodologie de fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing : couverture vs sémantique

Dans le **mutational grammar fuzzing**, les entrées sont mutées tout en restant **valides selon la grammaire**. En mode guidé par la couverture, seuls les échantillons qui déclenchent une **nouvelle couverture** sont enregistrés comme seeds du corpus. Pour les **cibles linguistiques** (analyseurs, interpréteurs, moteurs), cela peut passer à côté de bugs qui nécessitent des **chaînes sémantiques/de flux de données**, où la sortie d’une construction devient l’entrée d’une autre.<sup>[[1]](#references)</sup>

**Mode d’échec :** le fuzzer trouve des seeds qui exercent individuellement `document()` et `generate-id()` (ou des primitives similaires), mais **ne préserve pas le flux de données enchaîné** ; l’échantillon « plus proche du bug » est donc écarté, car il n’apporte pas de nouvelle couverture. Avec **au moins 3 étapes dépendantes**, les recombinaisons aléatoires deviennent coûteuses et le retour de couverture ne guide pas la recherche.<sup>[[1]](#references)</sup>

**Conséquence :** pour les grammaires fortement dépendantes, envisagez **d’hybrider les phases de mutation et de génération** ou d’orienter la génération vers des motifs de **chaînage de fonctions** (et pas uniquement vers la couverture).<sup>[[1]](#references)</sup>

## Pièges liés à la diversité du corpus

La mutation guidée par la couverture est **gloutonne** : un échantillon apportant une nouvelle couverture est enregistré immédiatement, et conserve souvent de grandes régions inchangées. Avec le temps, les corpus se remplissent de **quasi-doublons** présentant une faible diversité structurelle. Une minimisation agressive peut supprimer du contexte utile ; un compromis pratique consiste donc à effectuer une **minimisation tenant compte de la grammaire**, qui **s’arrête après un seuil minimal de tokens** (réduire le bruit tout en conservant suffisamment de structure environnante pour faciliter les mutations).<sup>[[1]](#references)</sup>

Une règle pratique pour le corpus en mutational fuzzing : **préférer un petit ensemble de seeds structurellement différentes qui maximisent la couverture** plutôt qu’une grande quantité de quasi-doublons. En pratique, cela signifie généralement ce qui suit.<sup>[[1]](#references)[[3]](#references)</sup>

- Commencez par des **échantillons réels** (corpus publics, données collectées par crawling, trafic capturé, ensembles de fichiers provenant de l’écosystème ciblé).
- Réduisez-les au moyen d’une **minimisation du corpus fondée sur la couverture**, plutôt que de conserver chaque échantillon valide.
- Gardez des seeds **suffisamment petites** pour que les mutations portent sur des champs pertinents, au lieu de consacrer la plupart des cycles à des octets sans intérêt.
- Relancez la minimisation du corpus après toute modification importante du harness ou de l’instrumentation, car le « meilleur » corpus change lorsque la portée du code accessible évolue.

## Mutation tenant compte des comparaisons pour les valeurs magiques

Les fuzzers plafonnent souvent non pas à cause de la syntaxe, mais en raison de **comparaisons strictes** : octets magiques, vérifications de longueur, chaînes d’énumération, sommes de contrôle ou valeurs de dispatch de l’analyseur protégées par `memcmp`, des tables `switch` ou des comparaisons en cascade. La mutation purement aléatoire gaspille des cycles à essayer de deviner ces valeurs octet par octet.

Pour ces cibles, utilisez le **traçage des comparaisons** (par exemple les workflows AFL++ `CMPLOG` ou de type Redqueen) afin que le fuzzer puisse observer les opérandes des comparaisons échouées et orienter les mutations vers des valeurs qui les satisfont.<sup>[[3]](#references)</sup>

```bash
./configure --cc=afl-clang-fast
make
cp ./target ./target.afl

make clean
AFL_LLVM_CMPLOG=1 ./configure --cc=afl-clang-fast
make
cp ./target ./target.cmplog

afl-fuzz -i in -o out -c ./target.cmplog -- ./target.afl @@
```

**Notes pratiques :**

- C’est particulièrement utile lorsque la cible verrouille la logique avancée derrière des **signatures de fichier**, des **verbes de protocole**, des **étiquettes de type** ou des **bits de fonctionnalités dépendants de la version**.
- Combinez cette approche avec des **dictionnaires** extraits d’échantillons réels, de spécifications de protocole ou de journaux de débogage. Un petit dictionnaire contenant des jetons de grammaire, des noms de blocs, des verbes et des délimiteurs est souvent plus utile qu’une énorme liste de mots générique.
- Si la cible effectue de nombreux contrôles séquentiels, résolvez d’abord les premières comparaisons « magic », puis réduisez à nouveau le corpus obtenu afin que les étapes suivantes commencent avec des préfixes déjà valides.

## Fuzzer les API de fichiers qui dissimulent un langage de noms de fichiers

Un paramètre nommé `filename`, `path` ou `URL` peut être un point d’entrée d’interpréteur plutôt qu’une simple recherche de fichier. Par exemple, la syntaxe CFITSIO Extended Filename Syntax (EFS) évalue des sélecteurs entre crochets, des expressions de lignes/pixels, des colonnes calculées, des histogrammes et des transformations avant de renvoyer l’objet ouvert ; certaines formes créent également des copies temporaires. Lors de la cartographie de la surface d’attaque, classez chaque API d’ouverture/importation comme **chemin littéral** ou **chemin interprété**, puis fuzzez le point d’entrée de production réellement appelé par les applications.<sup>[[20]](#references)[[22]](#references)</sup>

Pour les primitives SSRF, de copie de fichiers et de gestionnaire de protocole qui en résultent — ainsi que pour des API de chemin littéral plus sûres — consultez [Les mini-langages de noms de fichiers comme primitives SSRF/de fichiers](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Séparer l’objet sous-jacent du programme fuzzé

Lorsque la grammaire se trouve dans un suffixe de nom de fichier, modifier uniquement les octets du fichier référencé ne permet pas de tester l’analyseur. Un petit harness peut plutôt lire un testcase sous forme de chaîne et la transmettre à l’API d’ouverture interprétée ; la campagne CFITSIO a atteint la plupart des analyseurs et évaluateurs EFS en appelant `fits_open_file()` en lecture seule. Gardez des fichiers sous-jacents valides disponibles séparément afin que les mutations puissent cibler le langage des sélecteurs/expressions au lieu de casser constamment le chemin de base.<sup>[[22]](#references)</sup>

Utilisez des seeds qui atteignent chacun une famille de grammaire différente, puis constituez un dictionnaire compact à partir de la spécification et du code source du lexer/analyseur. Si la couverture stagne tandis que les entrées échouent systématiquement dans le même chemin d’erreur syntaxique, conservez les préfixes valides et ajoutez des délimiteurs, des opérateurs, des mots-clés, des noms de fonctions et des noms de champs représentatifs, au lieu d’augmenter uniquement la durée des mutations aléatoires.<sup>[[22]](#references)</sup>

Exécutez le harness avec le dictionnaire de grammaire, par exemple :<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Contenir les effets secondaires du harness « read-only »

Un flag de bibliothèque en lecture seule ne garantit pas un testcase sans effets secondaires : le langage des noms de fichiers peut réécrire l’entrée, créer des fichiers de sortie ou matérialiser des objets temporaires. La campagne CFITSIO a d’abord détruit des fichiers seed et laissé des fichiers inattendus sur le système de fichiers ; un nettoyage et une isolation étaient donc nécessaires.<sup>[[22]](#references)</sup>

- Attribuez à chaque worker un répertoire de travail jetable et un répertoire temporaire privé.
- Exposez des copies des fichiers de référence ; ne laissez jamais la cible modifier l’unique copie du corpus.
- Désactivez l’accès réseau, sauf si les backends distants sont la cible visée, et limitez les chemins accessibles en écriture à l’aide d’un conteneur, d’un espace de noms de montage ou d’un sandbox équivalent.
- Réinitialisez le répertoire après chaque exécution ou lot de workers, et traitez toute modification inattendue du système de fichiers comme un résultat supplémentaire.

### Boucle crash-to-patch-to-fuzz

Regroupez les crashes avant de les corriger afin que des milliers d’artefacts ne deviennent pas autant de tâches de correction. Lors de l’évaluation CFITSIO, AFLTriage a réduit l’ensemble initial de crashes à quelques causes racines ; l’avis de sécurité qui en a résulté décrit plusieurs défaillances distinctes, notamment des vérifications incorrectes de la taille de destination, des pointeurs périmés après `realloc()`, des erreurs arithmétiques et des chemins de nettoyage dangereux du parser.<sup>[[21]](#references)[[22]](#references)</sup>

1. Réduisez un input représentatif de chaque groupe et reproduisez-le avec AddressSanitizer.
2. Consignez l’accès exact à l’origine de la défaillance, son emplacement dans le code source, l’historique d’allocation/libération et l’état du parser qui a rendu l’invariant faux.
3. Appliquez un patch candidat de portée limitée et recompilez avec la même instrumentation de couverture et de sanitizer.
4. Rejouez le reproducteur d’origine **et chaque input de son groupe** ; activez également la détection des leaks, car une correction liée à la sécurité mémoire peut briser la gestion de la propriété sur un chemin d’erreur.
5. Exécutez les tests fonctionnels avec de vrais fichiers, puis reprenez à partir de la queue accumulée (ou réimportez cette queue si le moteur exige un nouveau répertoire de sortie après la modification du binaire).
6. Répétez : la suppression du premier crash superficiel permet souvent aux seeds existants d’atteindre un état plus profond du parser.

Un LLM peut accélérer l’étape 2 et rédiger une ébauche pour l’étape 3 s’il reçoit l’input qui provoque le crash, le rapport du sanitizer, le harness et le code source pertinent, mais son patch reste non fiable. Ce sont le rejeu avec le sanitizer et les contrôles de régression — et non l’explication du modèle — qui déterminent si la correction est acceptée.<sup>[[22]](#references)</sup>

## Des retours plus riches lorsque la couverture des edges confond différents chemins

La couverture normale des edges ne permet pas de distinguer deux exécutions qui traversent le même helper depuis des callers différents ou empruntent des combinaisons de branches différentes au sein d’une fonction. C’est important dans les decoders partagés, les dispatchers de protocoles et les helpers d’interpréteur, où la **route** vers un edge détermine l’état actif. Suivre naïvement chaque contexte d’appel est également risqué : la carte de couverture et la queue peuvent exploser. Les recherches sur le fuzzing sensible au contexte recommandent donc d’affiner uniquement les contextes prometteurs, plutôt que de rendre sensible au contexte l’ensemble du graphe d’appels.<sup>[[14]](#references)</sup>

Les versions récentes d’AFL++ proposent une **couverture des chemins par fonction Ball-Larus**, en complément de la couverture normale des edges. Cette méthode attribue une feature à chaque chemin acyclique traversant une fonction ; les back-edges des boucles sont supprimés, si bien que ce retour distingue les combinaisons de branches, mais **pas le nombre d’itérations des boucles**. Commencez par le niveau souple `1`, puis appliquez les modes plus stricts au code suspect des parsers et machines à états, car le nombre de chemins peut croître de façon exponentielle.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Pour un helper appelé depuis de nombreux emplacements sensibles du point de vue de la sécurité, le mode LTO peut combiner chaque chemin de fonction avec son site d’appel immédiat :<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LTO_CALLER=1
export AFL_LLVM_LTO_PATH=1
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

**Conseils pour les campagnes :** appliquez prudemment une instrumentation plus riche et surveillez son coût en couverture de carte/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Exécutez en parallèle une instance ordinaire avec couverture des arêtes ; un feedback plus riche n’est utile que si le coût supplémentaire en queue/carte ne réduit pas trop le nombre d’exécutions par seconde.
- Utilisez `AFL_LLVM_ALLOWLIST` pour limiter l’instrumentation des chemins/appelants lorsque de grandes bibliothèques riches en templates ou du code utilitaire générique dominent la carte.
- Les fonctions présentant un nombre excessif de chemins acycliques peuvent être ignorées par AFL++ ; les avertissements à la compilation indiquent que la cible nécessite une allowlist ou un niveau moins strict.
- La couverture par appelant + chemin ne prend en charge qu’un seul niveau d’appelant. Ne la combinez pas avec des piles de contexte plus profondes.
- Les ID de chemin peuvent changer d’une version majeure de LLVM à l’autre. Gardez une toolchain fixe pour toute la campagne et ne synchronisez pas des corpus basés sur PATH comme si leurs ID de fonctionnalités étaient stables entre les builds.
- Ce feedback complète `CMPLOG` : le traçage des comparaisons détermine **quelle valeur franchit une garde**, tandis que le feedback de chemin/appelant préserve **le parcours et la combinaison de branches qui y ont mené**.

## Fuzzing avec état : les séquences sont des seeds

Pour les **protocoles**, les **workflows authentifiés** et les **parseurs à plusieurs étapes**, l’unité intéressante est souvent une **séquence de messages** plutôt qu’un blob unique. Concaténer toute la transcription dans un seul fichier et la muter à l’aveugle est généralement inefficace, car le fuzzer mute chaque étape de la même manière, même si seul le message ultérieur atteint l’état fragile.<sup>[[4]](#references)</sup>

Une approche plus efficace consiste à traiter la **séquence elle-même comme seed** et à utiliser un **état observable** (codes de réponse, états du protocole, phases du parseur, types des objets renvoyés) comme feedback supplémentaire.<sup>[[4]](#references)</sup>

- Gardez les **messages préfixes valides** stables et concentrez les mutations sur le message qui **déclenche la transition**.
- Mettez en cache les identifiants et les valeurs générées par le serveur dans les réponses précédentes lorsque l’étape suivante en dépend.
- Préférez les mutations/splicings par message à la mutation de toute la transcription sérialisée comme un blob opaque.
- Si le protocole expose des codes de réponse significatifs, utilisez-les comme **oracle d’état peu coûteux** afin de prioriser les séquences qui progressent davantage.

C’est pour la même raison que les bugs authentifiés, les transitions cachées ou les bugs de parseur qui ne se produisent « qu’après le handshake » échappent souvent au fuzzing classique de fichiers : le fuzzer doit préserver **l’ordre, l’état et les dépendances**, et pas seulement la structure.<sup>[[4]](#references)</sup>

### Android Binder : fuzzing de pilote multi-client

Une couverture élevée des arêtes peut tout de même passer à côté de bugs du pilote IPC, car la couverture ne décrit pas **la propriété des objets, les compteurs de références, les messages en attente, l’ordre du nettoyage ou les interleavings entre threads**. La page [internals de l’IPC Android Binder](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) présente le modèle d’objets du pilote ; cet exemple porte sur le harness du fuzzer. Android Binder est un modèle utile : atteindre à la fois les chemins d’allocation et de libération ne suffit pas si le fuzzer ne peut pas faire opérer plusieurs processus sur le même objet du noyau dans l’ordre requis.<sup>[[15]](#references)</sup>

#### Modéliser le protocole, pas des buffers `ioctl` isolés

Représentez un cas de test comme une grammaire ordonnée composée de **l’identité du client + l’opération + des arguments structurés**. Le fuzzer Binder LKL utilise protobuf et `libprotobuf-mutator`, avec un client gestionnaire de contexte persistant et deux clients ordinaires. Un harness sémantique préserve alors les relations que la mutation aveugle d’octets détruirait.<sup>[[15]](#references)</sup>

- Mettez en cache les valeurs renvoyées par les opérations précédentes. Par exemple, `BC_FREE_BUFFER` doit réutiliser un pointeur vers un buffer de transaction renvoyé par un `ioctl` antérieur.
- Générez des réponses par défaut valides afin que les transactions synchrones puissent se terminer et que les opérations ultérieures restent accessibles.
- Rejetez les transitions impossibles, comme les transactions vers soi-même ou plusieurs transactions en attente vers la même cible.
- Conservez l’état d’initialisation singleton hors de la réinitialisation par entrée. Binder n’autorise qu’un seul enregistrement `BINDER_SET_CONTEXT_MGR` par démarrage ; détruire puis recréer ce client à répétition rendrait les entrées ultérieures invalides.

Un modèle utile pour provoquer une course de durée de vie consiste à faire transférer un objet par un client, à lancer le nettoyage d’un thread ou d’un processus, puis à faire libérer simultanément le buffer de transaction par le client destinataire. Dans l’exemple CVE-2020-0423, le transfert d’un `BINDER_TYPE_WEAK_BINDER`, suivi d’un `BINDER_THREAD_EXIT` entrant en course avec `BC_FREE_BUFFER`, pouvait libérer un `binder_work` intégré alors que le chemin de nettoyage du thread sortant l’utilisait encore.<sup>[[15]](#references)</sup>

#### Réintroduire des interleavings contrôlés dans un noyau en espace utilisateur

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) lie le code réel du noyau dans un harness en espace utilisateur et expose son interface système via `lkl_syscall`. Cela facilite la coordination de l’état protobuf, de la couverture et de KASAN au sein d’un même processus. Toutefois, LKL exécute normalement un appel système sans qu’un autre thread du noyau ne l’interrompe. Pour les campagnes de course, insérez des points d’appel à `schedule()` autour de verrous/déverrouillages et de limites de durée de vie sélectionnés, puis laissez le harness choisir au hasard le prochain client à chaque yield. Limitez ces points aux endroits ciblés, car chacun d’eux multiplie l’espace de recherche des ordonnancements. Le scheduler aléatoire décrit par les chercheurs **ne fait pas** partie du fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Construire et rejouer des seeds de régression sérialisées

Le harness upstream fixe une version compatible de `libprotobuf-mutator`, active l’instrumentation de fuzzing LKL et KASAN avec `LKL_FUZZING=1`, et active `CONFIG_MMU` pour Binder avec `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Après avoir extrait une révision délibérément vulnérable ou appliqué les correctifs de rollback documentés en amont, un seed sérialisé peut reproduire toute la transition d’état multi-client sans avoir à la reconstruire dans une preuve de concept C ad hoc :<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Considérez le use-after-free détecté par KASAN comme la confirmation que le seed a atteint le chemin de durée de vie vulnérable. Cela ne démontre **pas** les primitives ultérieures nécessaires à l’exécution de code dans le kernel ou à l’élévation de privilèges.<sup>[[16]](#references)</sup>

## Astuce de diversité sur une seule machine (style Jackalope)

Une méthode pratique pour combiner la **nouveauté générative** et la **réutilisation de la couverture** consiste à **redémarrer des workers de courte durée** face à un serveur persistant. Chaque worker démarre avec un corpus vide, se synchronise après `T` secondes, s’exécute pendant encore `T` secondes sur le corpus combiné, se synchronise à nouveau, puis se termine. Cela produit des **structures inédites à chaque génération**, tout en tirant parti de la couverture accumulée.<sup>[[1]](#references)[[2]](#references)</sup>

**Serveur :**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Workers séquentiels (boucle d’exemple) :**

<details>
<summary>Boucle de redémarrage du worker Jackalope</summary>

```python
import subprocess
import time

T = 3600

while True:
  subprocess.run(["rm", "-rf", "workerout"])
  p = subprocess.Popen([
      "/path/to/fuzzer",
      "-grammar", "grammar.txt",
      "-instrumentation", "sancov",
      "-in", "empty",
      "-out", "workerout",
      "-t", "1000",
      "-delivery", "shmem",
      "-iterations", "10000",
      "-mute_child",
      "-nthreads", "6",
      "-server", "127.0.0.1:8337",
      "-server_update_interval", str(T),
      "--", "./harness", "-m", "@@",
  ])
  time.sleep(T * 2)
  p.kill()
```

</details>

**Remarques :**

- `-in empty` force un **corpus vierge** à chaque génération.
- `-server_update_interval T` permet de simuler une **synchronisation différée** (nouveauté d’abord, réutilisation ensuite).
- En mode grammar fuzzing, la **synchronisation initiale avec le serveur est ignorée par défaut** (pas besoin de `-skip_initial_server_sync`).
- La valeur optimale de `T` **dépend de la cible** ; le mieux est généralement de changer de stratégie une fois que le worker a trouvé la plupart des couvertures « faciles ».

## Snapshot Fuzzing pour les cibles difficiles à instrumenter

Lorsque le code que vous voulez tester n’est accessible qu’**après une longue phase de préparation** (démarrage d’une VM, connexion, réception d’un paquet, analyse d’un conteneur, initialisation d’un service), le **snapshot fuzzing** constitue une solution de rechange utile : capturez l’état du processus ou de la VM une fois prêt, injectez chaque cas de test dans le chemin d’entrée de la cible, exécutez jusqu’au crash ou au timeout, puis restaurez le snapshot. Cette méthode évite de répéter l’initialisation ou les préfixes du protocole et est utile pour les **services réseau**, le **firmware**, les **surfaces d’attaque post-authentification** et les **cibles binaires uniquement**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Exécutez la cible jusqu’à ce que l’état intéressant soit prêt.
2. Prenez un snapshot de la **mémoire + des registres** à ce stade.
3. Pour chaque cas de test, écrivez directement l’entrée modifiée dans le tampon pertinent du processus ou de la machine invitée.
4. Exécutez jusqu’au crash/timeout/réinitialisation.
5. Restaurez le snapshot ; pour les cibles VM, ne restaurez que les **pages modifiées** si cette fonctionnalité est prise en charge, puis recommencez.

Placez le snapshot aussi près que possible de la première étape coûteuse d’analyse ou de dispatch, par exemple après un `recv`/`read` ou une étape de désérialisation de paquet, et consignez le tampon d’entrée utilisé par la cible. Cette démarche suit le principe de placement adaptatif, qui consiste à déplacer le snapshot plus loin dans le traitement de l’entrée afin d’éviter de répéter les opérations.<sup>[[11]](#references)</sup>

## Exploration des conditions de concurrence du noyau Linux avec MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) transforme les conditions de concurrence sensibles au timing dans le noyau Linux en séquences reproductibles d’accès mémoire. Il peut énumérer automatiquement les exécutions **A-B-A** dans deux contextes ou permettre à un analyste d’imposer des contraintes d’ordre dans une interface terminal/GUI. Il s’agit d’un outil de recherche expérimental, et non d’un fuzzer de concurrence complet : il nécessite actuellement LLVM 23+ et le noyau modifié du projet, les outils en ligne de commande prennent en charge deux threads de test et la couche de fuzzing en espace utilisateur proposée n’est pas implémentée.<sup>[[17]](#references)[[18]](#references)</sup>

### Collecter les points de communication entre contextes

Compilez le noyau instrumenté avec les callbacks KASAN outline et la prise en charge des enregistrements mémoire KCOV modifiée. Le README du projet recommande également de désactiver l’optimisation des appels entre frères afin de conserver des piles d’appels exploitables.<sup>[[17]](#references)[[18]](#references)</sup>

```text
CONFIG_KASAN=y
CONFIG_KASAN_OUTLINE=y
CONFIG_KCOV=y
CONFIG_KCOV_EXT_RECORDS=y
CONFIG_KCOV_MEMORY=y
CONFIG_KALLSYMS_ALL=y
CONFIG_DEBUG_INFO_DWARF5=y
CONFIG_PREEMPT=y
CONFIG_RANDOMIZE_BASE=n
```

```bash
export KCFLAGS="-fno-optimize-sibling-calls -mllvm -sanitizer-coverage-prune-blocks=false"
```

Le mode outline de KASAN (`asan-instrumentation-with-call-threshold=0`) convertit les accès instrumentés en appels à des fonctions auxiliaires. Les patches du noyau MAccConc désactivent `asan-opt-same-temp` afin que les accès consécutifs ne soient pas fusionnés ; désactivez également l’optimisation `asan-opt-globals` lorsque les data races sur les variables globales doivent être visibles. KCOV transmet les enregistrements ainsi obtenus à l’espace utilisateur. Comparez les accès provenant de contextes d’exécution différents et conservez les paires dont les plages d’octets se chevauchent et dont au moins un côté effectue une écriture ; modélisez `kfree()` comme une écriture afin que les transitions de durée de vie deviennent elles aussi des candidates.<sup>[[17]](#references)</sup>

Pour les tâches qui se poursuivent hors de la tâche initiale, comme le traitement de paquets ou les callbacks RCU, le sous-système doit propager un handle de couverture distante KCOV. La couverture distante KCOV en amont est activée explicitement et n’est pas automatiquement disponible pour les tâches d’arrière-plan arbitraires ; l’absence de propagation peut donc rendre invisible une interaction réelle.<sup>[[17]](#references)[[19]](#references)</sup>

### Identifier le même accès dynamique à chaque exécution

Ne rejouez pas à partir d’une adresse de tas concrète, qui peut changer après chaque allocation, ni uniquement à partir d’une adresse d’instruction, qui est ambiguë dans des fonctions auxiliaires telles que `memcpy()` et `spin_lock()`. MAccConc utilise une **trace de pile augmentée par des compteurs** : chaque frame identifie un callee ainsi que son nombre d’invocations dans l’appelant, et le dernier élément identifie l’instruction d’accès mémoire. Les enregistrements d’entrée et de sortie de fonction de SanitizerCoverage permettent à l’espace utilisateur de reconstruire cet identifiant dynamique, qui reste stable malgré les changements d’adresse et les variations de flux de contrôle sans rapport.<sup>[[17]](#references)</sup>

### Convertir les paires candidates en ordonnancements imposés

L’ioctl `KCOV_SET_DI` modifié associe un identifiant d’accès augmenté par des compteurs à une action sur un indicateur partagé.<sup>[[17]](#references)</sup>

| Action | Sémantique |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Définir l’indicateur *N* immédiatement avant l’accès sélectionné. |
| `DI_STACK_WAIT` | Avant l’accès sélectionné, attendre activement que l’indicateur *N* soit défini ou que la limite configurée soit atteinte. |
| `DI_STACK_WAKE_POST` | Définir l’indicateur *N* immédiatement après l’accès sélectionné. |

Pour imposer une contrainte partielle **A précède B**, associez `DI_STACK_WAKE_POST` à A et `DI_STACK_WAIT` à B en utilisant le même indicateur. Pour un ordonnancement entièrement défini entre deux contextes, bloquez d’abord B, puis faites en sorte que A réveille B et attende au premier point de transfert ; B effectue l’opération inverse au point de transfert suivant. Cette dernière méthode agit comme un changement de contexte déterministe et est utilisée par l’explorateur automatique A-B-A.<sup>[[17]](#references)</sup>

Une campagne minimale consiste à compiler le cas de test à quatre hooks (`test_setup`, les deux fonctions de thread et `test_end`) en bibliothèque partagée, à collecter une trace sans contraintes, puis à énumérer les candidates A-B-A ou à ajouter des contraintes manuelles autour des accès suspects.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interprétez les timeouts séparément des réordonnancements réussis : l’ordre demandé peut être impossible si un verrou ou une dépendance d’initialisation/publication empêche le second contexte d’atteindre son point d’injection. Gardez également à l’esprit les angles morts de KASAN : les accès directs à la pile ne sont généralement pas interceptés, sauf s’ils risquent de dépasser les limites, les variables globales sont omises avec l’optimisation par défaut, et les compilateurs actuels ne peuvent pas émettre simultanément des hooks ASAN et TSAN. Enfin, le prototype perd son buffer KCOV lorsqu’un invité panique ; préservez donc une console/un oracle de crash indépendant.<sup>[[17]](#references)</sup>

Pour le fuzzing guidé par la concurrence à venir, enregistrez des résumés des accès mémoire par entrée ou par syscall, associez les opérations qui formeraient des points de communication entre contextes, puis explorez uniquement ces combinaisons. Les snapshots de VM stabilisent l’état global et les adresses ; sans snapshots, les métadonnées des sites d’allocation peuvent permettre d’abstraire les objets entre les exécutions. Il s’agit d’une extension proposée, et non d’une fonctionnalité des outils userspace actuels de MAccConc.<sup>[[17]](#references)</sup>

## Introspection du harness : repérer tôt les fuzzers superficiels

Lorsqu’une campagne stagne, le problème vient souvent non pas du mutateur, mais du **harness**. Utilisez l’**introspection de l’accessibilité/de la couverture** pour repérer les fonctions statiquement accessibles depuis votre cible de fuzzing, mais rarement ou jamais couvertes dynamiquement. Ces fonctions signalent généralement l’un de trois problèmes.<sup>[[12]](#references)</sup>

- Le harness entre dans la cible trop tard ou trop tôt.
- Le corpus de seeds ne contient pas toute une famille de fonctionnalités.
- La cible a réellement besoin d’un **deuxième harness** plutôt que d’un unique harness surdimensionné « qui fait tout ».

Si vous utilisez des workflows de type OSS-Fuzz / ClusterFuzz, Fuzz Introspector peut comparer l’accessibilité statique à la couverture à l’exécution et générer des rapports à partir d’une exécution chronométrée ou d’un corpus public.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Utilisez le rapport pour décider s'il faut ajouter un nouveau harness pour un chemin de parser non testé, étoffer le corpus pour une fonctionnalité spécifique ou diviser un harness monolithique en points d'entrée plus petits.

## Sélection des cibles de fuzzing et triage des mutations à partir du graphe

Si vous disposez déjà de **résultats d'analyse statique**, de **survivants du mutation testing** et de **rapports de couverture**, ne les triez pas comme des listes indépendantes. Commencez par construire un **graphe d'appels**, annotez ses nœuds avec la **complexité cyclomatique**, l'**accessibilité depuis des points d'entrée/des entrées non fiables** et tout résultat externe, puis posez des questions sur le graphe.<sup>[[5]](#references)[[6]](#references)</sup>

- Quelles fonctions à forte complexité sont accessibles depuis des entrées non fiables ?
- Quels survivants du mutation testing se trouvent sur des chemins reliant les parsers/handlers au code critique pour la sécurité ?
- Quelles fonctions sont des goulots d'étranglement architecturaux avec un **rayon d'impact** inhabituellement élevé ?

Cette approche fait généralement ressortir de meilleures cibles de fuzzing que le simple fait de choisir celles qui ont la « couverture la plus faible ». Un parser/décodeur à **forte complexité**, dont l'**accessibilité externe est confirmée**, constitue un meilleur candidat pour un harness qu'un utilitaire interne isolé, peu couvert mais sans chemin contrôlé par un attaquant.

### Workflow de triage pratique

1. Construisez un **graphe de code** à partir de la base de code et extrayez les métriques de complexité et de branchement pour chaque fonction.
2. Recensez les **points d'entrée** qui acceptent des données contrôlées par un attaquant : handlers de requêtes, décodeurs, importateurs, parsers de protocoles, lecteurs CLI/de fichiers.
3. Exécutez des requêtes de chemin depuis ces points d'entrée vers les fonctions candidates afin de distinguer la surface d'attaque accessible du code mort ou réservé à un usage interne.
4. Donnez la priorité aux nœuds qui combinent :
   - une **complexité cyclomatique** élevée
   - une **accessibilité confirmée depuis des entrées non fiables**
   - un **rayon d'impact** élevé ou de nombreux dépendants en aval
   - des éléments corroborants, tels que des résultats **SARIF**, des notes d'audit ou des survivants du mutation testing
5. Rédigez d'abord des harnesses ciblés pour les nœuds les mieux classés, en particulier les **parsers/codecs** comme les décodeurs hex/Base64/IP/de messages.

### Survivants du mutation testing : équivalents ou exploitables

Le mutation testing produit souvent une liste de survivants bruitée. Avant de considérer chaque survivant comme une faille de sécurité, posez-vous les questions suivantes à l'aide du graphe :

- La fonction mutée est-elle accessible depuis un point d'entrée contrôlé par un attaquant ?
- Tous les chemins d'appel sont-ils soumis à des invariants plus stricts que le contrôle muté ?
- Le nœud se trouve-t-il dans du code mort, une logique de formatage uniquement ou un chemin arithmétique/parser à fort impact ?

Les survivants qui restent inaccessibles ou sont structurellement contraints sont souvent des **mutants équivalents**. Ceux qui restent **accessibles** et touchent aux **conditions limites**, aux **chemins de dépassement/carry** ou à l'**arithmétique/au parsing critiques pour la sécurité** doivent être transformés en :

- nouveaux fuzz harnesses
- tests directs de propriétés/invariants
- vecteurs ciblés de cas limites

### Reporter les résultats externes sur le graphe

Si votre pipeline SAST exporte des résultats **SARIF**, projetez-les sur les nœuds du graphe à partir du **fichier + plage de lignes**, puis utilisez le graphe pour élargir l'analyse de l'impact.<sup>[[6]](#references)</sup>

- calculez le **rayon d'impact** de la fonction signalée
- vérifiez si le résultat se trouve sur un chemin depuis un point d'entrée
- regroupez les résultats proches qui convergent vers le même goulot d'étranglement

C'est utile pour décider s'il faut consacrer du temps au fuzzing d'une fonction donnée : un nœud **accessible**, **complexe** et présentant déjà des **résultats SAST** est souvent une meilleure cible qu'un nœud simplement complexe sans chemin accessible à un attaquant.

Exemple de workflow avec Trailmark.<sup>[[6]](#references)</sup>

```bash
uv pip install trailmark
trailmark analyze --complexity 10 path/to/project
```

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("path/to/project", language="c")
engine.preanalysis()
engine.complexity_hotspots(10)
engine.paths_between("handle_request", "parse_ipv6")
```

L’élément essentiel est l’intersection : **complexité x exposition x impact**. Utilisez le graphique pour choisir les cibles de fuzzing offrant la plus grande valeur attendue en matière de sécurité, puis utilisez les survivants aux mutations pour déterminer quelles limites et quels invariants votre harness doit mettre à l’épreuve.<sup>[[5]](#references)</sup>

## Fuzzing Go avec gosentry : moteur plus puissant, entrées typées et vérifications différentielles

Si une cible Go dispose déjà d’un harness natif `testing.F`, une mise à niveau pratique consiste à exécuter le même harness avec [gosentry](https://github.com/trailofbits/gosentry), une toolchain Go forkée qui conserve `go test -fuzz`, mais remplace le backend par **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

This est utile lorsque le fuzzer Go natif cale sur des **comparaisons difficiles**, des **entrées typées** ou des **formats complexes à analyser**. La méthodologie reste la même :

- Continuez à utiliser `f.Add(...)` pour les seeds et `f.Fuzz(...)` pour le callback.
- Réutilisez le même harness, mais exécutez-le avec le binaire `go` de gosentry plutôt qu’avec la toolchain standard.
- Traitez la campagne obtenue comme une exécution normale guidée par la couverture, mais avec l’ordonnancement et la mutation de LibAFL, ainsi que de meilleurs détecteurs auxiliaires.

### Transformer les échecs silencieux en résultats de fuzzing

Un problème récurrent lors des évaluations Go est que les comportements dangereux ne provoquent souvent **pas** de crash par défaut. Avec gosentry, vous pouvez transformer plusieurs catégories d’états « mauvais, mais silencieux » en résultats.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` pour faire en sorte que certains chemins de journalisation ou d’erreur se comportent comme des crashs (utile pour les chemins de code de type `log.Fatal` qui, autrement, se contentent de journaliser et de continuer).
- `--catch-races=true` pour rejouer les nouvelles entrées découvertes dans la queue avec le détecteur de race Go.
- `--catch-leaks=true` pour rejouer les nouvelles entrées de la queue avec `goleak` et s’arrêter en cas de fuite de goroutine.
- La gestion des blocages de LibAFL pour conserver les **boucles infinies / entrées très lentes** comme résultats de fuzzing, au lieu de les laisser disparaître comme de simples timeouts.
- Des contrôles intégrés de dépassement arithmétique activés par défaut, ainsi que des contrôles facultatifs de troncature via une instrumentation de type go-panikint.

C’est particulièrement utile pour les cibles où l’impact sur la sécurité est un **échec d’analyse syntaxique sans panic**, un **bug de concurrence** ou un **blocage causant uniquement un DoS**, plutôt qu’une corruption de mémoire.

### Fuzzing tenant compte des structures pour les API Go typées

Le fuzzing Go natif attend principalement des valeurs scalaires telles que `[]byte`, `string` et des nombres. Si le code testé consomme des objets typés, gosentry peut fuzz-er directement des **valeurs composites** (structures, slices, tableaux, pointeurs), tout en continuant à muter les octets sous-jacents.<sup>[[7]](#references)[[8]](#references)</sup>

```go
type Input struct {
    Data []byte
    S    string
    N    int
}

func FuzzStructInput(f *testing.F) {
    f.Add(Input{Data: []byte("hello"), S: "world", N: 42})
    f.Fuzz(func(t *testing.T, in Input) {
        Process(in)
    })
}
```

Utilisez ceci lors de la création d’un faux format filaire : le fait de l’utiliser uniquement pour le fuzzing masquerait les bugs logiques derrière du code d’analyse propre au harness. Pour les campagnes différentielles ou basées sur une grammaire, gardez l’entrée du harness sous la forme d’un seul `[]byte` ou `string` et effectuez l’analyse dans le callback.

### Fuzzing basé sur une grammaire pour les analyseurs syntaxiques et les entrées de protocole

Pour les analyseurs syntaxiques, les formats et les langages d’entrée, gosentry peut exécuter le **fuzzing par grammaire Nautilus** avec LibAFL. La grammaire est un tableau JSON de règles de production, et le harness devrait généralement accepter un seul argument `[]byte` ou `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Notes méthodologiques :

- Utilisez le mode grammaire lorsque les mutations au niveau des octets échouent principalement lors des premières vérifications syntaxiques.
- Concentrez la grammaire sur le **sous-ensemble du langage/protocole pertinent pour la sécurité**, au lieu de modéliser la spécification complète.
- Utilisez de grandes valeurs limites dans les terminaux/non-terminaux pour mettre à l’épreuve les limites des entiers, des longueurs et des machines à états.
- Le mode grammaire garantit que les entrées respectent la grammaire, mais la cible reçoit toujours des **octets/chaînes** : l’analyse et les vérifications sémantiques restent dans le code soumis au harness.

### Fuzzing différentiel : comparer les implémentations, pas seulement les plantages

Une approche efficace dans les écosystèmes Go consiste à faire du **fuzzing différentiel basé sur une grammaire** : générer des entrées structurées valides et les transmettre à deux analyseurs, clients ou moteurs de transition d’état.<sup>[[7]](#references)[[8]](#references)</sup>

```go
f.Fuzz(func(t *testing.T, data []byte) {
    gotA, errA := ParseA(data)
    gotB, errB := ParseB(data)
    if (errA == nil) != (errB == nil) {
        t.Fatalf("parser disagreement: A=%v B=%v", errA, errB)
    }
    _ = gotA
    _ = gotB
})
```

Considérez les éléments suivants comme des résultats :

- une implémentation panique tandis que l’autre rejette proprement
- des divergences entre les entrées acceptées et rejetées
- des arbres syntaxiques ou des objets décodés différents
- des transitions d’état, des nonces, des soldes ou des racines d’état divergents

C’est un moyen pratique de repérer les **divergences de consensus**, les **ambiguïtés d’analyse syntaxique** et les **écarts entre les spécifications et les implémentations**, souvent ignorés par le fuzzing axé uniquement sur les plantages.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Réutiliser le corpus de campagne pour générer un rapport de couverture

Après une campagne, rejouez le corpus de la file d’attente sauvegardé afin de générer un rapport de couverture Go, sans avoir à exporter manuellement un corpus distinct.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Exécutez la commande depuis le **même package** et avec la **même cible `-fuzz`** afin que gosentry résolve le bon état de campagne mis en cache.



## References

- [1] [Fuzzing par grammaire mutationnelle](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Le fuzzing AFL++ en profondeur](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet, cinq ans plus tard : le fuzzing de protocoles guidé par la couverture](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark transforme le code en graphes](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Le fuzzing Go ne disposait que de la moitié des outils. Nous avons forké la chaîne d’outils pour y remédier.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer : un fuzzer greybox rapide pour les protocoles réseau à état utilisant des snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Pas de grammaire, pas de problème : vers le fuzzing du noyau Linux sans descriptions des appels système](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy : fuzzing efficace avec des snapshots adaptatifs et modifiables](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentation LLVM d’AFL++ : couverture des chemins et des appelants](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing prédictif sensible au contexte](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Android Offensive Security - Fuzzing de Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer LKL pour Android Binder - documentation sur la compilation et les graines de régression](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc : exploration des conditions de concurrence du noyau Linux avec des entrelacements contrôlés des accès mémoire](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV : couverture de code pour le fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Syntaxe des noms de fichiers étendus CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Avis de sécurité Doyensec : CFITSIO, quatrième trimestre 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing de la syntaxe des noms de fichiers étendus CFITSIO : 16 vulnérabilités de sécurité mémoire et triage assisté par Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
{{#include ../banners/hacktricks-training.md}}
