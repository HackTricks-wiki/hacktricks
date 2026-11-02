# Méthodologie de fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing : coverage vs. sémantique

Dans le **mutational grammar fuzzing**, les entrées sont mutées tout en restant **valides selon la grammaire**. En mode guidé par la coverage, seuls les échantillons qui déclenchent une **nouvelle coverage** sont enregistrés comme seeds du corpus. Pour les **cibles de langage** (parseurs, interpréteurs, moteurs), cela peut faire manquer des bugs qui nécessitent des **chaînes sémantiques/de flux de données**, où la sortie d’une construction devient l’entrée d’une autre.<sup>[[1]](#references)</sup>

**Mode d’échec :** le fuzzer trouve des seeds qui exercent individuellement `document()` et `generate-id()` (ou des primitives similaires), mais **ne préserve pas le flux de données enchaîné** ; l’échantillon « plus proche du bug » est donc écarté, car il n’apporte pas de nouvelle coverage. Avec **au moins 3 étapes dépendantes**, la recombinaison aléatoire devient coûteuse et le feedback de coverage ne guide pas la recherche.<sup>[[1]](#references)</sup>

**Conséquence :** pour les grammaires à fortes dépendances, envisagez **d’hybrider les phases mutationnelle et générative** ou d’orienter la génération vers des motifs d’**enchaînement de fonctions** (et pas seulement vers la coverage).<sup>[[1]](#references)</sup>

## Pièges liés à la diversité du corpus

La mutation guidée par la coverage est **gloutonne** : un échantillon apportant une nouvelle coverage est immédiatement enregistré, en conservant souvent de grandes régions inchangées. Avec le temps, les corpus deviennent des **quasi-doublons**, avec une faible diversité structurelle. Une minimisation agressive peut supprimer du contexte utile. Un compromis pratique consiste donc à effectuer une **minimisation tenant compte de la grammaire**, qui **s’arrête après un nombre minimal de tokens** (réduire le bruit tout en conservant suffisamment de structure environnante pour faciliter les mutations).<sup>[[1]](#references)</sup>

Une règle pratique pour le corpus en fuzzing mutationnel consiste à **privilégier un petit ensemble de seeds structurellement différentes qui maximisent la coverage**, plutôt qu’une grande collection de quasi-doublons. En pratique, cela implique généralement les points suivants.<sup>[[1]](#references)[[3]](#references)</sup>

- Partez d’**échantillons réels** (corpus publics, crawling, trafic capturé, ensembles de fichiers issus de l’écosystème cible).
- Réduisez-les avec une **minimisation du corpus basée sur la coverage**, plutôt que de conserver chaque échantillon valide.
- Gardez des seeds **suffisamment petites** pour que les mutations ciblent des champs pertinents, au lieu de consacrer la plupart des cycles à des octets sans intérêt.
- Relancez la minimisation du corpus après les changements majeurs du harness ou de l’instrumentation, car le « meilleur » corpus évolue lorsque la couverture du code accessible change.

## Mutation tenant compte des comparaisons pour les valeurs magiques

Une raison courante pour laquelle les fuzzers plafonnent n’est pas la syntaxe, mais les **comparaisons strictes** : octets magiques, vérifications de longueur, chaînes d’énumération, sommes de contrôle ou valeurs de dispatch du parseur protégées par `memcmp`, des tables `switch` ou des comparaisons en cascade. La mutation purement aléatoire gaspille des cycles à tenter de deviner ces valeurs octet par octet.

Pour ces cibles, utilisez le **traçage des comparaisons** (par exemple, les workflows de type AFL++ `CMPLOG` / Redqueen) afin que le fuzzer puisse observer les opérandes des comparaisons échouées et orienter les mutations vers des valeurs qui les satisfont.<sup>[[3]](#references)</sup>

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

- Cette technique est particulièrement utile lorsque la cible masque une logique complexe derrière des **signatures de fichiers**, des **verbes de protocole**, des **étiquettes de type** ou des **bits de fonctionnalités dépendant de la version**.
- Associez-la à des **dictionnaires** extraits d’échantillons réels, de spécifications de protocoles ou de journaux de débogage. Un petit dictionnaire contenant des tokens de grammaire, des noms de blocs, des verbes et des délimiteurs est souvent plus utile qu’une énorme liste de mots générique.
- Si la cible effectue de nombreuses vérifications séquentielles, résolvez d’abord les premières comparaisons « magic », puis minimisez à nouveau le corpus obtenu afin que les étapes suivantes partent de préfixes déjà valides.

## Fuzzing des API de fichiers qui masquent un langage de noms de fichiers

Un paramètre nommé `filename`, `path` ou `URL` peut être un point d’entrée d’interpréteur plutôt qu’une simple recherche de fichier. Par exemple, la syntaxe de nom de fichier étendue (EFS) de CFITSIO évalue les sélecteurs entre crochets, les expressions de lignes/pixels, les colonnes calculées, les histogrammes et les transformations avant de renvoyer l’objet ouvert ; certaines formes créent également des copies temporaires. Lors de la cartographie de la surface d’attaque, classez chaque API d’ouverture/importation comme **chemin littéral** ou **chemin interprété**, puis fuzziez le point d’entrée de production réellement appelé par les applications.<sup>[[20]](#references)[[22]](#references)</sup>

Pour les primitives SSRF, de copie de fichiers et de gestionnaires de protocoles qui en résultent — ainsi que pour des API de chemin littéral plus sûres — voir [Les mini-langages de noms de fichiers comme primitives SSRF/de fichiers](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Séparer l’objet de référence du programme fuzzé

Lorsque la grammaire se trouve dans un suffixe de nom de fichier, modifier uniquement les octets du fichier référencé ne permet pas d’atteindre l’analyseur. Un petit banc de test peut plutôt lire un cas de test sous forme de chaîne et le transmettre à l’API d’ouverture interprétée ; la campagne CFITSIO a atteint la plupart des analyseurs et évaluateurs EFS en appelant `fits_open_file()` en mode lecture seule. Gardez des fichiers de référence valides disponibles séparément afin que les mutations ciblent le langage des sélecteurs/expressions, plutôt que de rendre continuellement invalide le chemin de base.<sup>[[22]](#references)</sup>

Utilisez des graines qui atteignent chacune une famille de grammaires différente, puis créez un dictionnaire compact à partir de la spécification et du code source de l’analyseur lexical/de l’analyseur syntaxique. Si la couverture plafonne tandis que les entrées échouent régulièrement dans le même chemin d’erreur syntaxique, conservez les préfixes valides et ajoutez des délimiteurs, opérateurs, mots-clés, noms de fonctions et noms de champs représentatifs, plutôt que d’augmenter simplement la durée des mutations aléatoires.<sup>[[22]](#references)</sup>

Exécutez le banc de test avec le dictionnaire de grammaire, par exemple :<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Contenir les effets secondaires du harness « read-only »

Un indicateur de bibliothèque « read-only » ne garantit pas un testcase sans effets secondaires : le langage des noms de fichiers peut réécrire l’entrée, créer des fichiers de sortie ou matérialiser des objets temporaires. La campagne CFITSIO a d’abord détruit des fichiers seed et laissé des fichiers inattendus sur le système de fichiers ; un nettoyage et une isolation se sont donc avérés nécessaires.<sup>[[22]](#references)</sup>

- Attribuez à chaque worker un répertoire de travail jetable et un répertoire temporaire privé.
- Exposez des copies des fichiers canoniques utilisés comme support ; ne laissez jamais la cible modifier l’unique copie du corpus.
- Désactivez l’accès réseau, sauf si les backends distants sont la cible visée, et limitez les chemins inscriptibles au moyen d’un conteneur, d’un espace de noms de montage ou d’un sandbox équivalent.
- Réinitialisez le répertoire après chaque exécution ou lot de workers et traitez toute modification inattendue du système de fichiers comme un résultat supplémentaire.

### Boucle crash-to-patch-to-fuzz

Regroupez les crashes avant de corriger le code afin que des milliers d’artefacts ne deviennent pas des milliers de tâches de patch. Lors de l’évaluation de CFITSIO, AFLTriage a réduit l’ensemble initial de crashes à quelques causes racines ; l’avis qui en a résulté décrit des défaillances distinctes, notamment des vérifications incorrectes de la taille de destination, des pointeurs obsolètes après `realloc()`, des erreurs arithmétiques et des chemins de nettoyage du parser non sécurisés.<sup>[[21]](#references)[[22]](#references)</sup>

1. Réduisez un input représentatif de chaque cluster et reproduisez-le avec AddressSanitizer.
2. Consignez l’accès exact à l’origine de la défaillance, son emplacement dans le code source, l’historique des allocations/libérations et l’état du parser qui a rendu l’invariant faux.
3. Appliquez un patch candidat de portée limitée et recompilez avec la même instrumentation de couverture et de sanitizer.
4. Rejouez le reproducer d’origine **et chaque input de son cluster** ; activez également la détection des leaks, car un correctif de sûreté mémoire peut rompre la gestion de la propriété sur un chemin d’erreur.
5. Exécutez les tests fonctionnels avec de vrais fichiers, puis reprenez à partir de la queue accumulée (ou réimportez cette queue si le moteur exige un nouveau répertoire de sortie après la modification du binaire).
6. Répétez : la suppression du premier crash superficiel permet souvent aux seeds existants d’atteindre un état plus profond du parser.

Un LLM peut accélérer l’étape 2 et proposer une ébauche pour l’étape 3 s’il reçoit l’input qui provoque le crash, le rapport du sanitizer, le harness et le code source pertinent, mais son patch reste non fiable. Ce sont le rejeu avec le sanitizer et les contrôles de régression — et non l’explication du modèle — qui déterminent si la correction est acceptée.<sup>[[22]](#references)</sup>

## Comment obtenir un feedback plus riche lorsque la couverture des arêtes confond différents chemins

La couverture normale des arêtes ne permet pas de distinguer deux exécutions qui passent par le même helper depuis des callers différents ou prennent différentes combinaisons de branches dans une fonction. C’est important dans les decoders partagés, les dispatchers de protocoles et les helpers d’interpréteurs, où la **route** vers une arête détermine l’état actif. Suivre naïvement chaque contexte d’appel est également risqué : la carte de couverture et la queue peuvent exploser. Les recherches sur le fuzzing sensible au contexte recommandent donc d’affiner uniquement les contextes prometteurs, plutôt que de rendre sensible au contexte l’ensemble du graphe d’appels.<sup>[[14]](#references)</sup>

Les versions récentes d’AFL++ proposent la **couverture des chemins par fonction de Ball-Larus**, en plus de la couverture normale des arêtes. Chaque chemin acyclique dans une fonction reçoit une feature ; les back-edges de boucle sont supprimées. Ce feedback distingue donc les combinaisons de branches, mais **pas le nombre d’itérations des boucles**. Commencez avec le niveau souple `1`, puis limitez les modes plus stricts au code suspect des parsers/machines à états, car le nombre de chemins peut croître de façon exponentielle.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Pour un helper appelé depuis de nombreux endroits sensibles du point de vue de la sécurité, le mode LTO peut combiner chaque chemin de fonction avec son site d’appel immédiat :<sup>[[13]](#references)</sup>

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

**Conseil pour la campagne :** appliquez le feedback enrichi avec prudence et surveillez son coût en couverture de la map et de la queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Exécutez en parallèle une instance ordinaire avec edge coverage ; le feedback enrichi n’est utile que si le coût supplémentaire en queue/map ne réduit pas trop le nombre d’exécutions par seconde.
- Utilisez `AFL_LLVM_ALLOWLIST` pour limiter l’instrumentation path/caller lorsque les grandes bibliothèques riches en templates ou le code utilitaire générique dominent la map.
- Les fonctions comportant un nombre excessif de chemins acycliques peuvent être ignorées par AFL++ ; les avertissements lors de la compilation indiquent que la cible nécessite une allowlist ou un niveau moins strict.
- Caller + path coverage ne prend en charge qu’un seul niveau de caller. Ne la combinez pas avec des piles de contexte plus profondes.
- Les Path IDs peuvent changer d’une version majeure de LLVM à l’autre. Gardez la toolchain fixe pendant une campagne et ne synchronisez pas des corpus basés sur PATH comme si leurs feature IDs étaient stables d’une build à l’autre.
- Ce feedback complète `CMPLOG` : le tracing des comparaisons résout **quelle valeur passe un guard**, tandis que le feedback path/caller préserve **quel itinéraire et quelle combinaison de branches y ont mené**.

## Fuzzing avec état : les séquences sont des seeds

Pour les **protocoles**, les **workflows authentifiés** et les **parseurs à plusieurs étapes**, l’unité intéressante n’est souvent pas un blob isolé, mais une **séquence de messages**. Concaténer toute la transcription dans un seul fichier et la muter à l’aveugle est généralement inefficace, car le fuzzer mute toutes les étapes de la même façon, même si seul le message ultérieur atteint l’état fragile.<sup>[[4]](#references)</sup>

Une approche plus efficace consiste à traiter la **séquence elle-même comme le seed** et à utiliser l’**état observable** (codes de réponse, états du protocole, phases du parseur, types des objets renvoyés) comme feedback supplémentaire.<sup>[[4]](#references)</sup>

- Gardez stables les **messages de préfixe valides** et concentrez les mutations sur le message qui **déclenche la transition**.
- Mettez en cache les identifiants et les valeurs générées par le serveur dans les réponses précédentes lorsque l’étape suivante en dépend.
- Préférez les mutations et le splicing par message à la mutation de toute la transcription sérialisée comme un blob opaque.
- Si le protocole expose des codes de réponse pertinents, utilisez-les comme **oracle d’état peu coûteux** pour prioriser les séquences qui progressent davantage.

C’est pour la même raison que les bugs authentifiés, les transitions cachées ou les bugs de parseur qui ne surviennent « qu’après le handshake » échappent souvent au fuzzing classique de fichiers : le fuzzer doit préserver **l’ordre, l’état et les dépendances**, et pas seulement la structure.<sup>[[4]](#references)</sup>

### Android Binder : fuzzing d’un driver multi-client

Une edge coverage élevée peut quand même manquer des bugs de driver IPC, car la couverture ne décrit pas **la propriété des objets, les compteurs de références, les messages en attente, l’ordre du nettoyage ou les entrelacements de threads**. La page [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) décrit le modèle d’objets du driver ; cet exemple porte sur le harness du fuzzer. Android Binder constitue un modèle utile : atteindre à la fois les chemins d’allocation et de libération ne suffit pas si le fuzzer ne peut pas faire agir plusieurs processus sur le même objet du noyau dans l’ordre requis.<sup>[[15]](#references)</sup>

#### Modélisez le protocole, pas des buffers `ioctl` isolés

Représentez un cas de test comme une grammaire ordonnée composée de **l’identité du client + l’opération + des arguments structurés**. Le fuzzer Binder LKL utilise protobuf et `libprotobuf-mutator`, avec un client gestionnaire de contexte persistant et deux clients ordinaires. Un harness sémantique préserve alors les relations que des mutations aveugles d’octets détruiraient.<sup>[[15]](#references)</sup>

- Mettez en cache les valeurs renvoyées par les opérations précédentes. Par exemple, `BC_FREE_BUFFER` doit réutiliser un pointeur de buffer de transaction renvoyé par un `ioctl` précédent.
- Générez des réponses par défaut valides afin que les transactions synchrones puissent se terminer et que les opérations ultérieures restent accessibles.
- Rejetez les transitions impossibles, comme les transactions vers soi-même ou plusieurs transactions en attente vers la même cible.
- Gardez l’état d’initialisation singleton en dehors de la réinitialisation par entrée. Binder n’autorise qu’un seul enregistrement `BINDER_SET_CONTEXT_MGR` par démarrage ; détruire puis recréer ce client à répétition rendrait les entrées suivantes invalides.

Un modèle utile de race sur la durée de vie consiste à faire transférer un objet par un client, à démarrer le nettoyage d’un thread ou d’un processus, puis à faire libérer simultanément le buffer de transaction par le client destinataire. Dans l’exemple CVE-2020-0423, un transfert `BINDER_TYPE_WEAK_BINDER` suivi d’un `BINDER_THREAD_EXIT` en compétition avec `BC_FREE_BUFFER` pouvait libérer un `binder_work` intégré alors que le chemin de nettoyage du thread en cours de sortie l’utilisait encore.<sup>[[15]](#references)</sup>

#### Réintroduisez des entrelacements contrôlés dans un noyau en espace utilisateur

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) lie le code réel du noyau à un harness en espace utilisateur et expose son interface syscall via `lkl_syscall`. Cela facilite la coordination du protobuf, de la couverture et de KASAN dans un même processus. Toutefois, LKL exécute normalement un syscall sans qu’un autre thread du noyau ne l’interrompe. Pour les campagnes de race, insérez des points `schedule()` autour de frontières ciblées de verrouillage/déverrouillage et de durée de vie, puis laissez le harness choisir aléatoirement le prochain client à chaque yield. Limitez ces points à des emplacements ciblés, car chacun multiplie l’espace de recherche de l’ordonnancement. L’ordonnanceur aléatoire décrit par les chercheurs ne fait **pas** partie du fuzzer Binder en amont.<sup>[[15]](#references)</sup>

#### Construisez et rejouez des seeds de régression sérialisés

Le harness en amont fixe une version compatible de `libprotobuf-mutator`, active l’instrumentation de fuzzing LKL et KASAN avec `LKL_FUZZING=1`, et active `CONFIG_MMU` pour Binder avec `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Après avoir récupéré une révision délibérément vulnérable ou appliqué les correctifs de rollback documentés en amont, une graine sérialisée peut reproduire toute la transition d’état multi-client sans avoir à la reconstruire dans une preuve de concept C ad hoc :<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Considérez le use-after-free détecté par KASAN comme la confirmation que le seed a atteint le chemin de durée de vie vulnérable. Cela ne démontre **pas** la présence des primitives ultérieures nécessaires à l’exécution de code dans le kernel ou à l’escalade de privilèges.<sup>[[16]](#references)</sup>

## Astuce de diversité sur une seule machine (à la manière de Jackalope)

Une méthode pratique pour combiner la **nouveauté générative** et la **réutilisation de la couverture** consiste à **redémarrer des workers de courte durée** face à un serveur persistant. Chaque worker démarre avec un corpus vide, se synchronise après `T` secondes, s’exécute pendant encore `T` secondes sur le corpus combiné, se synchronise à nouveau, puis s’arrête. Cela produit des **structures inédites à chaque génération**, tout en tirant parti de la couverture accumulée.<sup>[[1]](#references)[[2]](#references)</sup>

**Serveur :**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Workers séquentiels (exemple de boucle) :**

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
- `-server_update_interval T` approxime une **synchronisation différée** (nouveauté d’abord, réutilisation ensuite).
- En mode grammar fuzzing, la **synchronisation initiale avec le serveur est ignorée par défaut** (pas besoin de `-skip_initial_server_sync`).
- La valeur optimale de `T` **dépend de la cible** ; il est généralement préférable de changer de valeur lorsque le worker a trouvé la plupart des éléments de couverture « faciles ».

## Snapshot Fuzzing pour les cibles difficiles à instrumenter

Lorsque le code que vous voulez tester n’est accessible qu’**après une longue phase de préparation** (démarrage d’une VM, connexion, réception d’un paquet, analyse d’un conteneur, initialisation d’un service), une alternative utile est le **snapshot fuzzing** : capturer l’état du processus ou de la VM prêt, injecter chaque cas de test dans le chemin d’entrée de la cible, exécuter jusqu’à un crash ou un timeout, puis restaurer le snapshot. Cela évite de répéter l’initialisation ou les préfixes de protocole et est utile pour les **services réseau**, le **firmware**, les **surfaces d’attaque post-authentification** et les **cibles binaires uniquement**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Exécutez la cible jusqu’à ce que l’état intéressant soit prêt.
2. Prenez un snapshot de la **mémoire + des registres** à ce stade.
3. Pour chaque cas de test, écrivez directement l’entrée mutée dans le tampon pertinent du processus ou de la machine invitée.
4. Exécutez jusqu’à un crash, un timeout ou une réinitialisation.
5. Restaurez le snapshot ; pour les cibles VM, ne restaurez que les **pages modifiées** si cette fonctionnalité est prise en charge, puis recommencez.

Placez le snapshot aussi près que possible de la première étape coûteuse d’analyse ou de dispatch, par exemple après un `recv`/`read` ou une étape de désérialisation de paquet, et identifiez le tampon d’entrée utilisé par la cible. Cela applique le principe de placement adaptatif, qui consiste à déplacer le snapshot plus profondément dans le traitement de l’entrée pour éviter de répéter des opérations.<sup>[[11]](#references)</sup>

## Exploration des race conditions du noyau Linux avec MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) transforme les race conditions sensibles au timing dans le noyau Linux en séquences d’accès mémoire reproductibles. Il peut énumérer automatiquement des exécutions **A-B-A** dans deux contextes ou permettre à un analyste d’imposer des contraintes d’ordre dans une interface terminal/GUI. Il s’agit d’un outil de recherche expérimental, et non d’un fuzzer de concurrence complet : il nécessite actuellement LLVM 23+ et le noyau modifié du projet, les outils en ligne de commande prennent en charge deux threads de test, et la couche de fuzzing en espace utilisateur proposée n’est pas implémentée.<sup>[[17]](#references)[[18]](#references)</sup>

### Collecter les points de communication entre contextes

Compilez le noyau instrumenté avec les callbacks outline de KASAN et la prise en charge des enregistrements mémoire KCOV modifiée. Le README du projet recommande également de désactiver l’optimisation des appels entre frères afin que les piles d’appels restent exploitables.<sup>[[17]](#references)[[18]](#references)</sup>

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

Le mode outline de KASAN (`asan-instrumentation-with-call-threshold=0`) convertit les accès instrumentés en appels à des fonctions auxiliaires. Les patches du noyau MAccConc désactivent `asan-opt-same-temp` afin que les accès consécutifs ne soient pas fusionnés ; désactivez également l’optimisation `asan-opt-globals` lorsque les races sur les variables globales doivent être visibles. KCOV transmet les enregistrements ainsi obtenus à l’espace utilisateur. Comparez les accès issus de contextes d’exécution différents et conservez les paires dont les plages d’octets se chevauchent et dont au moins un côté effectue une écriture ; modélisez `kfree()` comme une écriture afin que les transitions de durée de vie soient également prises en compte.<sup>[[17]](#references)</sup>

Pour les tâches qui se poursuivent en dehors de la tâche initiatrice, comme le traitement des paquets ou les callbacks RCU, le sous-système doit propager un handle de couverture distante KCOV. La couverture distante KCOV en amont est opt-in et n’est pas automatiquement disponible pour les tâches arbitraires en arrière-plan ; l’absence de propagation peut donc rendre une interaction réelle invisible.<sup>[[17]](#references)[[19]](#references)</sup>

### Identifier le même accès dynamique à chaque exécution

Ne rejouez pas l’exécution à partir d’une adresse concrète du tas, qui peut changer après chaque allocation, ni uniquement à partir d’une adresse d’instruction, qui est ambiguë dans des fonctions auxiliaires comme `memcpy()` et `spin_lock()`. MAccConc utilise une **trace de pile augmentée par des compteurs** : chaque frame identifie un callee ainsi que son nombre d’invocations dans son caller, et le dernier élément identifie l’instruction d’accès mémoire. Les enregistrements d’entrée et de sortie de fonction de SanitizerCoverage permettent à l’espace utilisateur de reconstruire cet identifiant dynamique, qui reste stable malgré les changements d’adresse et le bruit lié à des flux de contrôle sans rapport.<sup>[[17]](#references)</sup>

### Convertir les paires candidates en ordonnancements forcés

L’ioctl `KCOV_SET_DI` ajouté par le patch associe un identifiant d’accès augmenté par des compteurs à une action sur un indicateur partagé.<sup>[[17]](#references)</sup>

| Action | Sémantique |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Définir l’indicateur *N* immédiatement avant l’accès sélectionné. |
| `DI_STACK_WAIT` | Avant l’accès sélectionné, attendre en boucle que l’indicateur *N* soit défini ou que la limite configurée soit atteinte. |
| `DI_STACK_WAKE_POST` | Définir l’indicateur *N* immédiatement après l’accès sélectionné. |

Pour une contrainte partielle **A-happens-before-B**, associez `DI_STACK_WAKE_POST` à A et `DI_STACK_WAIT` à B, en utilisant le même indicateur. Pour un ordonnancement entièrement spécifié entre deux contextes, bloquez B au départ, puis faites réveiller B par A et attendez au premier point de transfert ; B effectue l’opération inverse au transfert suivant. Cette dernière méthode se comporte comme un changement de contexte déterministe et est utilisée par l’explorateur automatique A-B-A.<sup>[[17]](#references)</sup>

Une campagne minimale consiste à compiler le cas de test à quatre hooks (`test_setup`, les deux fonctions de thread et `test_end`) sous forme de bibliothèque partagée, à recueillir une trace sans contraintes, puis à énumérer les candidats A-B-A ou à ajouter des contraintes manuelles autour des accès suspects.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interprétez les délais d’attente séparément des réordonnancements réussis : l’ordre demandé peut être impossible parce qu’un verrou ou une dépendance d’initialisation/publication empêche le second contexte d’atteindre son point d’injection. Gardez aussi à l’esprit les angles morts de KASAN : les accès directs à la pile ne sont généralement pas instrumentés, sauf s’ils risquent de dépasser les limites, les variables globales sont omises avec l’optimisation par défaut, et les compilateurs actuels ne peuvent pas émettre simultanément les hooks ASAN et TSAN. Enfin, le prototype perd son tampon KCOV lorsque le système invité panique ; préservez donc une console/un oracle de crash indépendant.<sup>[[17]](#references)</sup>

Pour le fuzzing guidé par la concurrence à l’avenir, enregistrez des résumés des accès mémoire par entrée ou par appel système, associez les opérations qui constitueraient des points de communication entre contextes, puis explorez uniquement ces combinaisons. Les instantanés de VM stabilisent l’état global et les adresses ; sans instantanés, les métadonnées des sites d’allocation peuvent permettre d’abstraire les objets d’une exécution à l’autre. Il s’agit d’une extension proposée, et non d’une fonctionnalité des outils userspace actuels de MAccConc.<sup>[[17]](#references)</sup>

## Introspection du harness : repérer rapidement les fuzzers superficiels

Lorsqu’une campagne stagne, le problème vient souvent non pas du mutator, mais du **harness**. Utilisez l’**introspection de l’accessibilité et de la couverture** pour repérer les fonctions qui sont statiquement accessibles depuis votre cible de fuzzing, mais rarement ou jamais couvertes dynamiquement. Ces fonctions révèlent généralement l’un de ces trois problèmes.<sup>[[12]](#references)</sup>

- Le harness entre dans la cible trop tôt ou trop tard.
- Le corpus de seeds ne contient pas toute une famille de fonctionnalités.
- La cible a réellement besoin d’un **second harness**, plutôt que d’un unique harness surdimensionné censé « tout faire ».

Si vous utilisez des workflows de type OSS-Fuzz / ClusterFuzz, Fuzz Introspector peut comparer l’accessibilité statique à la couverture d’exécution et générer des rapports à partir d’une exécution chronométrée ou d’un corpus public.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Utilisez le rapport pour décider s’il faut ajouter un nouveau harness pour un chemin de parser non testé, étendre le corpus pour une fonctionnalité particulière ou diviser un harness monolithique en points d’entrée plus petits.

## Sélection des cibles de fuzzing basée sur le graphe et triage des mutations

Si vous disposez déjà de **résultats d’analyse statique**, de **mutants survivants aux tests de mutation** et de **rapports de couverture**, ne les triez pas comme des listes indépendantes. Construisez d’abord un **graphe d’appels**, annotez les nœuds avec leur **complexité cyclomatique**, leur **accessibilité depuis les points d’entrée et les entrées non fiables**, ainsi que tout résultat externe, puis posez des questions sur le graphe.<sup>[[5]](#references)[[6]](#references)</sup>

- Quelles fonctions à forte complexité sont accessibles depuis des entrées non fiables ?
- Quels mutants survivants se trouvent sur des chemins allant des parsers/gestionnaires au code critique pour la sécurité ?
- Quelles fonctions sont des points de congestion architecturaux avec un **rayon d’impact** inhabituellement important ?

Cette méthode fait généralement ressortir de meilleures cibles de fuzzing que le seul critère de « couverture la plus faible ». Un parser/décodeur à **forte complexité** et dont l’**accessibilité externe** est confirmée constitue un meilleur candidat pour un harness qu’un helper interne isolé, peu couvert mais sans chemin contrôlé par un attaquant.

### Processus pratique de triage

1. Construisez un **graphe du code** à partir de la base de code et extrayez les métriques de complexité et de branches pour chaque fonction.
2. Répertoriez les **points d’entrée** qui acceptent des entrées contrôlées par un attaquant : gestionnaires de requêtes, décodeurs, importateurs, parsers de protocoles, lecteurs de CLI/fichiers.
3. Exécutez des requêtes de chemin depuis ces points d’entrée vers les fonctions candidates pour distinguer la surface d’attaque accessible du code mort ou uniquement interne.
4. Priorisez les nœuds qui réunissent :
   - une **complexité cyclomatique** élevée
   - une **accessibilité confirmée depuis des entrées non fiables**
   - un **rayon d’impact** élevé ou de nombreuses dépendances en aval
   - des éléments corroborants, tels que des résultats **SARIF**, des notes d’audit ou des mutants survivants
5. Écrivez d’abord des harness ciblés pour les nœuds les mieux classés, en particulier les **parsers/codecs**, tels que les décodeurs hex/Base64/IP/de messages.

### Mutants survivants : équivalents ou exploitables

Les tests de mutation produisent souvent une liste de mutants survivants bruitée. Avant de considérer chaque mutant survivant comme une faille de sécurité, utilisez le graphe pour vous poser les questions suivantes :

- La fonction modifiée est-elle accessible depuis un point d’entrée contrôlé par un attaquant ?
- Tous les chemins d’appel sont-ils soumis à des invariants plus stricts que le contrôle modifié ?
- Le nœud se trouve-t-il dans du code mort, une logique de formatage uniquement ou un chemin arithmétique/parser à fort impact ?

Les mutants survivants qui restent inaccessibles ou structurellement contraints sont souvent des **mutants équivalents**. Ceux qui restent **accessibles** et touchent aux **conditions limites**, aux **chemins de débordement/propagation de retenue** ou à l’**arithmétique/analyse syntaxique critique pour la sécurité** devraient être ajoutés à :

- de nouveaux harness de fuzzing
- des tests directs de propriétés/invariants
- des vecteurs ciblés de cas limites

### Reporter les résultats externes sur le graphe

Si votre pipeline SAST exporte du **SARIF**, reportez les résultats sur les nœuds du graphe à l’aide du **fichier et de la plage de lignes**, puis utilisez le graphe pour étendre l’analyse de leur impact.<sup>[[6]](#references)</sup>

- calculez le **rayon d’impact** de la fonction signalée
- vérifiez si le résultat se trouve sur un chemin depuis un point d’entrée
- regroupez les résultats proches qui convergent vers le même point de congestion

Cette méthode est utile pour décider s’il faut consacrer du temps de fuzzing à une fonction précise : un nœud **accessible**, **complexe** et déjà signalé par le **SAST** constitue souvent une meilleure cible qu’un nœud simplement complexe, sans chemin contrôlé par un attaquant.

Exemple de processus avec Trailmark.<sup>[[6]](#references)</sup>

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

La méthodologie essentielle repose sur l’intersection : **complexité x exposition x impact**. Utilisez le graphique pour choisir les cibles de fuzzing présentant la plus grande valeur attendue en matière de sécurité, puis servez-vous des mutations qui passent les filtres pour déterminer quelles frontières et quels invariants votre harness doit mettre à l’épreuve.<sup>[[5]](#references)</sup>

## Fuzzing différentiel des encodages de clés cryptographiques

Partez de clés sérialisées valides ou de vecteurs de test standard. Modifiez les champs encodés sans altérer la longueur ni la structure nécessaires pour atteindre les chemins d’importation et d’opération, puis soumettez les mêmes octets à des implémentations indépendantes. Comparez leur acceptation et les erreurs. Les signatures et textes chiffrés aléatoires nécessitent des oracles de correction, et non une comparaison octet par octet : vérifiez les signatures ou comparez les secrets partagés après un aller-retour encapsulation/décapsulation. Les vecteurs de test établissent la conformité pour des cas connus ; les mutations différentielles sondent les encodages malformés qui vont au-delà de ces cas.<sup>[[23]](#references)[[26]](#references)</sup>

Pour ces formats de clés, utilisez des oracles spécifiques au format :<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Clés de signature étendues ML-DSA :** modifiez les coefficients `s1` ou `s2` empaquetés pour qu’ils sortent de `[-η, η]`, tout en gardant la clé analysable. Vérifiez si l’importation ou la signature est rejetée, et si une éventuelle signature obtenue est vérifiée. Les différences d’acceptation ne constituent pas, à elles seules, des violations des normes, car FIPS 204 n’impose pas de vérifications supplémentaires des clés privées. Voir le [mécanisme de fuite conditionnelle](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Paires de clés ML-KEM :** distinguez les vérifications requises de la clé d’encapsulation et de l’entrée de décapsulation de la vérification facultative de cohérence de paire (PCT) lors de l’importation d’une paire. Effectuez une encapsulation avec la clé publique, une décapsulation avec la clé privée, puis comparez les secrets partagés ; une discordance peut compromettre les communications chiffrées, même si chaque clé passe individuellement les vérifications d’entrée. Vérifiez si l’API valide les entrées lors de l’opération ou via un appel distinct ; libcrux expose `validate_public_key(pk)` et `validate_private_key(sk, ct)`, qui ne remplacent pas une PCT.
- **Clés brutes XMSS/XMSSMT :** testez les allers-retours de sérialisation des clés de **signature et de vérification** pour différents jeux de paramètres, et pas seulement les opérations avec des clés en mémoire. XMSS et XMSSMT ont des espaces de noms OID de quatre octets distincts ; un analyseur qui se base uniquement sur l’OID et essaie XMSS en premier peut mal classer une clé XMSSMT ayant un OID identique et rejeter son importation. L’analyseur RustCrypto signalé illustre un échec d’interopérabilité et de disponibilité, pas une falsification de signature.

## Fuzzing Go avec gosentry : moteur plus puissant, entrées typées et vérifications différentielles

Si une cible Go dispose déjà d’un harness natif `testing.F`, une manière pratique de la faire évoluer consiste à exécuter ce même harness avec [gosentry](https://github.com/trailofbits/gosentry), une chaîne d’outils Go forkée qui conserve `go test -fuzz`, mais remplace le backend par **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

C'est utile lorsque le fuzzer Go natif bloque sur des **comparaisons difficiles**, des **entrées typées** ou des **formats nécessitant beaucoup de parsing**. La méthodologie reste la même :

- Continuez à utiliser `f.Add(...)` pour les seeds et `f.Fuzz(...)` pour le callback.
- Réutilisez le même harness, mais exécutez-le avec le binaire `go` de gosentry au lieu de la toolchain standard.
- Traitez la campagne obtenue comme une exécution normale guidée par la couverture, mais avec le scheduling et la mutation de LibAFL, ainsi que de meilleurs détecteurs.

### Transformer les échecs silencieux en findings

Un problème récurrent lors des évaluations Go est que les comportements dangereux ne provoquent souvent **pas** de crash par défaut. Avec gosentry, vous pouvez transformer plusieurs catégories d'états « mauvais mais silencieux » en findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` pour faire en sorte que certains chemins de journalisation/d'erreur se comportent comme des crashes (utile pour les chemins de code de type `log.Fatal` qui, autrement, ne font que journaliser et continuer).
- `--catch-races=true` pour rejouer les nouvelles entrées découvertes dans la file avec le race detector de Go.
- `--catch-leaks=true` pour rejouer les nouvelles entrées de la file avec `goleak` et s'arrêter en cas de fuite de goroutine.
- La gestion des hangs de LibAFL pour conserver les **boucles infinies / entrées très lentes** comme findings du fuzzing, plutôt que de les laisser disparaître comme des timeouts.
- Vérifications intégrées des dépassements arithmétiques activées par défaut, ainsi que des vérifications facultatives de troncature via une instrumentation de type go-panikint.

Cela est particulièrement utile pour les cibles où l'impact sur la sécurité est un **échec de parser sans panic**, un **bug de concurrence** ou un **hang provoquant uniquement un DoS**, plutôt qu'une corruption mémoire.

### Fuzzing tenant compte des structs pour les API Go typées

Le fuzzing Go natif attend principalement des scalaires comme `[]byte`, `string` et des nombres. Si le code testé consomme des objets typés, gosentry peut fuzz directement des **valeurs composites** (structs, slices, arrays, pointeurs) tout en mutant les octets sous-jacents.<sup>[[7]](#references)[[8]](#references)</sup>

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

Utilisez cette approche lorsque la création d’un faux format binaire uniquement pour le fuzzing risque de masquer des bugs logiques derrière du code d’analyse réservé au harness. Pour les campagnes différentielles ou basées sur une grammaire, gardez l’entrée du harness sous la forme d’un seul `[]byte` ou `string` et effectuez l’analyse dans le callback.

### Fuzzing basé sur une grammaire pour les parseurs et les entrées de protocole

Pour les parseurs, les formats et les langages d’entrée, gosentry peut exécuter du **fuzzing par grammaire Nautilus** sur LibAFL. La grammaire est un tableau JSON de règles de production, et le harness devrait généralement prendre un seul argument `[]byte` ou `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Notes méthodologiques :

- Utilisez le mode grammaire lorsque les mutations au niveau des octets échouent généralement lors des premières vérifications syntaxiques.
- Limitez la grammaire au **sous-ensemble du langage/protocole pertinent pour la sécurité**, au lieu de modéliser toute la spécification.
- Utilisez de grandes valeurs limites dans les terminaux/non-terminaux pour solliciter les limites des entiers, des longueurs et des machines à états.
- Le mode grammaire garantit que les entrées respectent la grammaire, mais la cible reçoit toujours des **octets/chaînes** : l’analyse et les vérifications sémantiques restent dans le code soumis au fuzzing.

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

C’est une méthode pratique pour détecter les **divergences de consensus**, les **ambiguïtés d’analyse syntaxique** et les **écarts entre les spécifications et les implémentations**, que le fuzzing visant uniquement les plantages ne révèle souvent pas.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Réutiliser le corpus de la campagne pour générer un rapport de couverture

Après une campagne, rejouez le corpus de la file sauvegardée pour générer un rapport de couverture Go, sans exporter manuellement un corpus distinct.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Exécutez la commande depuis le **même package** et avec la même cible `-fuzz` afin que gosentry résolve le bon état de campagne mis en cache.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [Fuzzing par grammaire mutationnelle](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing AFL++ en profondeur](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinq ans plus tard : le fuzzing de protocoles guidé par la couverture](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark transforme le code en graphes](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Le fuzzing Go ne disposait que de la moitié des outils. Nous avons forké la toolchain pour y remédier.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer : un fuzzer greybox rapide pour les protocoles réseau à état utilisant des snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Pas de grammaire, pas de problème : vers le fuzzing du noyau Linux sans descriptions des appels système](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy : un fuzzing efficace grâce à des snapshots adaptatifs et modifiables](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentation LLVM d’AFL++ : couverture des chemins et des appelants](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing prédictif sensible au contexte](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Android Offensive Security - Fuzzing de Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer LKL pour Android Binder - documentation de compilation et de seed de régression](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc : exploration des conditions de concurrence dans le noyau Linux avec des entrelacements contrôlés des accès mémoire](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV : couverture de code pour le fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Syntaxe des noms de fichiers étendus de CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Avis de sécurité Doyensec : CFITSIO T4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing de la syntaxe des noms de fichiers étendus de CFITSIO : 16 vulnérabilités de sécurité mémoire et triage assisté par Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Fuzzing différentiel pour la cryptographie](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203 : norme pour un mécanisme d’encapsulation de clés basé sur les réseaux euclidiens modulaires](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Bug d’analyse de l’OID XMSSMT - issue RustCrypto #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [État des implémentations de la cryptographie post-quantique](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
