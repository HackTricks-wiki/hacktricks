# Méthodologie de fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing mutationnel basé sur une grammaire : couverture et sémantique

Dans le **fuzzing mutationnel basé sur une grammaire**, les entrées sont modifiées tout en restant **valides selon la grammaire**. En mode guidé par la couverture, seuls les échantillons qui déclenchent une **nouvelle couverture** sont enregistrés comme seeds du corpus. Pour les **cibles liées aux langages** (parseurs, interpréteurs, moteurs), cette méthode peut manquer des bugs qui nécessitent des **chaînes sémantiques/de flux de données**, où la sortie d’une construction devient l’entrée d’une autre.<sup>[[1]](#references)</sup>

**Mode d’échec :** le fuzzer trouve des seeds qui exercent individuellement `document()` et `generate-id()` (ou des primitives similaires), mais **ne préserve pas le flux de données en chaîne**. L’échantillon « plus proche du bug » est alors écarté, car il n’ajoute pas de couverture. Avec **3 étapes dépendantes ou plus**, les recombinaisons aléatoires deviennent coûteuses et le retour de couverture ne guide pas la recherche.<sup>[[1]](#references)</sup>

**Conséquence :** pour les grammaires comportant de nombreuses dépendances, envisagez de **combiner des phases mutationnelles et génératives**, ou d’orienter la génération vers des motifs d’**enchaînement de fonctions** (et pas seulement vers la couverture).<sup>[[1]](#references)</sup>

## Pièges liés à la diversité du corpus

La mutation guidée par la couverture est **gloutonne** : un échantillon qui apporte une nouvelle couverture est enregistré immédiatement, souvent en conservant de grandes régions inchangées. Avec le temps, les corpus deviennent des **quasi-doublons** présentant une faible diversité structurelle. Une minimisation agressive peut supprimer du contexte utile. Un compromis pratique consiste donc à effectuer une **minimisation tenant compte de la grammaire**, qui **s’arrête après un nombre minimal de tokens** (pour réduire le bruit tout en conservant suffisamment de structure environnante pour faciliter les mutations).<sup>[[1]](#references)</sup>

Une règle pratique pour le corpus en fuzzing mutationnel : **préférer un petit ensemble de seeds structurellement différents qui maximisent la couverture** à une grande quantité de quasi-doublons. En pratique, cela signifie généralement ce qui suit.<sup>[[1]](#references)[[3]](#references)</sup>

- Commencez par des **échantillons du monde réel** (corpus publics, données collectées par crawling, trafic capturé, ensembles de fichiers issus de l’écosystème cible).
- Réduisez-les à l’aide d’une **minimisation du corpus basée sur la couverture**, plutôt que de conserver chaque échantillon valide.
- Gardez des seeds **assez petits** pour que les mutations portent sur des champs pertinents, au lieu de consacrer la plupart des cycles à des octets sans intérêt.
- Relancez la minimisation du corpus après toute modification majeure du harness ou de l’instrumentation, car le « meilleur » corpus change lorsque les chemins accessibles changent.

## Mutation tenant compte des comparaisons pour les valeurs magiques

Les fuzzers plafonnent souvent non pas à cause de la syntaxe, mais à cause de **comparaisons strictes** : octets magiques, vérifications de longueur, chaînes d’énumération, sommes de contrôle ou valeurs de dispatch du parseur, protégés par `memcmp`, des tables `switch` ou des comparaisons en cascade. La mutation purement aléatoire gaspille des cycles à essayer de deviner ces valeurs octet par octet.

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

- Cette technique est particulièrement utile lorsque la cible protège une logique complexe derrière des **signatures de fichiers**, des **verbes de protocole**, des **balises de type** ou des **bits de fonctionnalité dépendants de la version**.
- Associez-la à des **dictionnaires** extraits d’échantillons réels, de spécifications de protocole ou de journaux de débogage. Un petit dictionnaire contenant des tokens de grammaire, des noms de blocs, des verbes et des délimiteurs est souvent plus utile qu’une énorme liste de mots générique.
- Si la cible effectue de nombreuses vérifications séquentielles, résolvez d’abord les comparaisons « magiques » les plus précoces, puis réduisez à nouveau le corpus obtenu afin que les étapes suivantes partent de préfixes déjà valides.

## Retour d'information plus riche lorsque la couverture des arêtes confond différents chemins

La couverture normale des arêtes ne permet pas de distinguer deux exécutions qui traversent le même helper depuis différents appelants ou suivent différentes combinaisons de branches à l’intérieur d’une fonction. C’est important dans les décodeurs partagés, les répartiteurs de protocoles et les helpers d’interpréteur, où le **chemin** menant à une arête détermine l’état actif. Suivre naïvement chaque contexte d’appel est également risqué : la carte de couverture et la file d’attente peuvent exploser. Les recherches sur le fuzzing sensible au contexte recommandent donc d’affiner uniquement les contextes prometteurs, plutôt que de rendre tout le graphe d’appels sensible au contexte.<sup>[[14]](#references)</sup>

Les versions récentes d’AFL++ proposent la **couverture des chemins par fonction Ball-Larus**, en plus de la couverture normale des arêtes. Elle attribue une caractéristique à chaque chemin acyclique traversant une fonction ; les arêtes de retour des boucles sont supprimées, de sorte que ce retour d'information distingue les combinaisons de branches, mais **pas le nombre d’itérations des boucles**. Commencez avec le niveau souple `1`, puis limitez les modes plus stricts au code suspect des analyseurs syntaxiques et des machines à états, car le nombre de chemins peut croître de façon exponentielle.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Pour un helper appelé depuis de nombreux sites pertinents pour la sécurité, le mode LTO peut combiner chaque chemin de fonction avec son site d'appel immédiat :<sup>[[13]](#references)</sup>

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

**Conseils pour la campagne :** appliquez le feedback enrichi avec prudence et surveillez son coût en couverture de la map et en taille de la queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Exécutez en parallèle une instance ordinaire à edge coverage ; le feedback enrichi n’est utile que si le coût supplémentaire en queue/map ne réduit pas trop le nombre d’exécutions par seconde.
- Utilisez `AFL_LLVM_ALLOWLIST` pour limiter l’instrumentation des chemins et des appelants lorsque de grandes bibliothèques riches en templates ou du code utilitaire générique dominent la map.
- Les fonctions comportant trop de chemins acycliques peuvent être ignorées par AFL++ ; les avertissements lors de la compilation indiquent que la cible nécessite une allowlist ou un niveau moins strict.
- La couverture des appelants et des chemins ne prend en charge qu’un seul niveau d’appelant. Ne la combinez pas avec des piles de contexte plus profondes.
- Les identifiants de chemin peuvent changer d’une version majeure de LLVM à l’autre. Gardez la toolchain fixe pendant une campagne et ne synchronisez pas les corpus basés sur PATH comme si leurs identifiants de caractéristiques étaient stables d’une compilation à l’autre.
- Ce feedback complète `CMPLOG` : la trace des comparaisons permet de déterminer **quelle valeur franchit une garde**, tandis que le feedback des chemins et des appelants préserve **quel itinéraire et quelle combinaison de branches y ont mené**.

## Fuzzing avec état : les séquences sont des seeds

Pour les **protocoles**, les **workflows authentifiés** et les **parseurs à plusieurs étapes**, l’unité intéressante n’est souvent pas un blob isolé, mais une **séquence de messages**. Concaténer toute la transcription dans un seul fichier et la muter à l’aveugle est généralement inefficace, car le fuzzer mute chaque étape de la même façon, même lorsque seul le message ultérieur atteint l’état fragile.<sup>[[4]](#references)</sup>

Une approche plus efficace consiste à traiter la **séquence elle-même comme seed** et à utiliser un **état observable** (codes de réponse, états du protocole, phases du parseur, types des objets renvoyés) comme feedback supplémentaire.<sup>[[4]](#references)</sup>

- Gardez les **messages de préfixe valides** stables et concentrez les mutations sur le message qui **déclenche la transition**.
- Mettez en cache les identifiants et les valeurs générés par le serveur dans les réponses précédentes lorsque l’étape suivante en dépend.
- Privilégiez la mutation et le splicing par message plutôt que la mutation de toute la transcription sérialisée comme un blob opaque.
- Si le protocole expose des codes de réponse significatifs, utilisez-les comme **oracle d’état peu coûteux** pour prioriser les séquences qui progressent davantage.

C’est aussi pourquoi les bugs authentifiés, les transitions cachées ou les bugs de parseur « uniquement après le handshake » échappent souvent au fuzzing classique de fichiers : le fuzzer doit préserver **l’ordre, l’état et les dépendances**, pas seulement la structure.<sup>[[4]](#references)</sup>

### Android Binder : fuzzing d’un pilote multi-client

Une couverture élevée des branches peut malgré tout manquer des bugs du pilote IPC, car la couverture ne décrit pas **la propriété des objets, les compteurs de références, les messages en attente, l’ordre du nettoyage ou l’entrelacement des threads**. La page [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) présente le modèle d’objets du pilote ; cet exemple porte sur le harness du fuzzer. Android Binder est un bon modèle : atteindre les chemins d’allocation et de libération ne suffit pas si le fuzzer ne peut pas faire opérer plusieurs processus sur le même objet du noyau dans l’ordre requis.<sup>[[15]](#references)</sup>

#### Modéliser le protocole, pas des buffers `ioctl` isolés

Représentez un cas de test sous la forme d’une grammaire ordonnée composée d’une **identité de client + une opération + des arguments structurés**. Le fuzzer Binder LKL utilise protobuf et `libprotobuf-mutator`, avec un client gestionnaire de contexte persistant et deux clients ordinaires. Un harness sémantique préserve ainsi les relations que la mutation aveugle d’octets détruirait.<sup>[[15]](#references)</sup>

- Mettez en cache les valeurs renvoyées par les opérations précédentes. Par exemple, `BC_FREE_BUFFER` doit réutiliser un pointeur de buffer de transaction renvoyé par un `ioctl` précédent.
- Générez des réponses par défaut valides pour que les transactions synchrones puissent aboutir et que les opérations suivantes restent accessibles.
- Rejetez les transitions impossibles, telles que les transactions vers soi-même ou plusieurs transactions en attente vers la même cible.
- Gardez l’état d’initialisation singleton en dehors de la réinitialisation par entrée. Binder n’autorise qu’un seul enregistrement `BINDER_SET_CONTEXT_MGR` par démarrage ; détruire et recréer ce client à répétition invaliderait donc les entrées suivantes.

Un modèle utile de course de durée de vie consiste à faire transférer un objet par un client, à démarrer le nettoyage d’un thread ou d’un processus, puis à faire libérer simultanément au client récepteur le buffer de transaction. Dans l’exemple CVE-2020-0423, le transfert d’un `BINDER_TYPE_WEAK_BINDER`, suivi d’un `BINDER_THREAD_EXIT` en course avec `BC_FREE_BUFFER`, pouvait libérer un `binder_work` intégré alors que le chemin de nettoyage du thread en cours de sortie l’utilisait encore.<sup>[[15]](#references)</sup>

#### Réintroduire des entrelacements contrôlés dans un noyau en espace utilisateur

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) lie le code réel du noyau dans un harness en espace utilisateur et expose son interface d’appels système via `lkl_syscall`. Cela facilite la coordination de l’état protobuf, de la couverture et de KASAN dans un même processus. Cependant, LKL exécute normalement un appel système sans interruption par un autre thread du noyau. Pour les campagnes de recherche de courses, insérez des points `schedule()` autour de frontières sélectionnées entre verrous et déverrouillages, ainsi que de durée de vie, puis laissez le harness choisir aléatoirement le prochain client à chaque yield. Ciblez précisément ces points, car chacun multiplie l’espace de recherche de l’ordonnancement. L’ordonnanceur aléatoire décrit par les chercheurs **ne fait pas** partie du fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Compiler et rejouer des seeds de régression sérialisées

Le harness upstream utilise une version compatible de `libprotobuf-mutator`, active l’instrumentation de fuzzing LKL et KASAN avec `LKL_FUZZING=1`, et active `CONFIG_MMU` pour Binder avec `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Après avoir récupéré une révision délibérément vulnérable ou appliqué les correctifs de rollback documentés en amont, une graine sérialisée peut reproduire toute la transition d’état multi-client sans avoir à la reconstruire dans un proof of concept C ad hoc :<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Traitez le use-after-free KASAN obtenu comme la confirmation que le seed a atteint le chemin de durée de vie vulnérable. Cela ne démontre **pas** la présence des primitives ultérieures nécessaires à l’exécution de code dans le kernel ou à l’escalade de privilèges.<sup>[[16]](#references)</sup>

## Astuce de diversité sur une seule machine (style Jackalope)

Une méthode pratique pour combiner la **nouveauté générative** et la **réutilisation de la couverture** consiste à **redémarrer des workers de courte durée** face à un serveur persistant. Chaque worker démarre avec un corpus vide, se synchronise après `T` secondes, s’exécute pendant encore `T` secondes avec le corpus combiné, se synchronise à nouveau, puis s’arrête. On obtient ainsi des **structures inédites à chaque génération**, tout en tirant parti de la couverture accumulée.<sup>[[1]](#references)[[2]](#references)</sup>

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
- La valeur optimale de `T` dépend de la **cible** ; il est généralement préférable de changer de stratégie une fois que le worker a trouvé la majeure partie de la couverture « facile ».

## Snapshot Fuzzing pour les cibles difficiles à instrumenter

Lorsque le code à tester n’est accessible qu’après une longue phase de préparation (démarrage d’une VM, connexion, réception d’un paquet, analyse d’un conteneur, initialisation d’un service), le **snapshot fuzzing** est une alternative utile : capturer l’état prêt du processus ou de la VM, injecter chaque cas de test dans le chemin d’entrée de la cible, exécuter jusqu’à un crash ou un timeout, puis restaurer le snapshot. Cela évite de répéter l’initialisation ou les préfixes de protocole et est utile pour les **services réseau**, les **firmwares**, les **surfaces d’attaque post-authentification** et les **cibles binaires uniquement**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Exécutez la cible jusqu’à ce que l’état intéressant soit prêt.
2. Prenez un snapshot de la **mémoire et des registres** à ce stade.
3. Pour chaque cas de test, écrivez directement l’entrée mutée dans le tampon pertinent du processus ou du système invité.
4. Exécutez jusqu’à un crash, un timeout ou une réinitialisation.
5. Restaurez le snapshot ; pour les cibles VM, ne restaurez que les **pages modifiées** si cette option est prise en charge, puis recommencez.

Placez le snapshot aussi près que possible de la première étape coûteuse d’analyse ou de dispatch, par exemple après un `recv`/`read` ou la désérialisation d’un paquet, et consignez le tampon d’entrée utilisé par la cible. Cela suit le principe de placement adaptatif, qui consiste à déplacer le snapshot plus loin dans le traitement de l’entrée pour éviter de répéter du travail.<sup>[[11]](#references)</sup>

## Exploration des race conditions du noyau Linux avec MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) transforme les race conditions sensibles au timing du noyau Linux en séquences reproductibles d’accès mémoire. Il peut énumérer automatiquement des exécutions **A-B-A** à deux contextes ou permettre à un analyste d’imposer des contraintes d’ordre dans une interface utilisateur en terminal ou graphique. Il s’agit d’un outil de recherche expérimental, et non d’un fuzzer de concurrence complet : il nécessite actuellement LLVM 23+ et le noyau modifié du projet, les outils en ligne de commande prennent en charge deux threads de test, et la couche de fuzzing en espace utilisateur proposée n’est pas implémentée.<sup>[[17]](#references)[[18]](#references)</sup>

### Collecter les points de communication entre contextes

Compilez le noyau instrumenté avec les callbacks KASAN outline et la prise en charge modifiée de KCOV pour l’enregistrement des accès mémoire. Le README du projet recommande également de désactiver l’optimisation des appels entre frères afin de conserver des piles d’appels exploitables.<sup>[[17]](#references)[[18]](#references)</sup>

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

Le mode outline de KASAN (`asan-instrumentation-with-call-threshold=0`) convertit les accès instrumentés en appels à des fonctions auxiliaires. Les correctifs du noyau MAccConc désactivent `asan-opt-same-temp` afin que les accès consécutifs ne soient pas fusionnés ; désactivez également l’optimisation `asan-opt-globals` lorsque les races sur les variables globales doivent être visibles. KCOV transmet les enregistrements ainsi obtenus à l’espace utilisateur. Comparez les accès provenant de différents contextes d’exécution et conservez les paires dont les plages d’octets se chevauchent et dont au moins un côté effectue une écriture ; modélisez `kfree()` comme une écriture afin que les transitions de durée de vie soient également prises en compte.<sup>[[17]](#references)</sup>

Pour les tâches qui se poursuivent hors de la tâche initiatrice, comme le traitement des paquets ou les callbacks RCU, le sous-système doit propager un handle de couverture distante KCOV. La couverture distante KCOV en amont est activée sur demande et n’est pas automatiquement disponible pour tout travail en arrière-plan ; l’absence de propagation peut donc rendre invisible une interaction réelle.<sup>[[17]](#references)[[19]](#references)</sup>

### Identifier le même accès dynamique à chaque exécution

Ne rejouez pas à partir d’une adresse concrète du heap, qui peut changer après chaque allocation, ni uniquement à partir d’une adresse d’instruction, qui est ambiguë dans des fonctions auxiliaires comme `memcpy()` et `spin_lock()`. MAccConc utilise une **trace de pile enrichie de compteurs** : chaque frame identifie une fonction appelée et son nombre d’invocations dans la fonction appelante, et le dernier élément identifie l’instruction d’accès mémoire. Les enregistrements d’entrée et de sortie de fonction de SanitizerCoverage permettent à l’espace utilisateur de reconstruire cet identifiant dynamique, qui reste stable malgré les changements d’adresse et le bruit dû à des chemins de contrôle sans rapport.<sup>[[17]](#references)</sup>

### Convertir les paires candidates en ordonnancements forcés

L’ioctl `KCOV_SET_DI` modifié associe un identifiant d’accès enrichi de compteurs à une action sur un indicateur partagé.<sup>[[17]](#references)</sup>

| Action | Sémantique |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Définir l’indicateur *N* immédiatement avant l’accès sélectionné. |
| `DI_STACK_WAIT` | Avant l’accès sélectionné, attendre en boucle que l’indicateur *N* soit défini ou que la limite configurée soit atteinte. |
| `DI_STACK_WAKE_POST` | Définir l’indicateur *N* immédiatement après l’accès sélectionné. |

Pour une contrainte partielle **A arrive-avant B**, associez `DI_STACK_WAKE_POST` à A et `DI_STACK_WAIT` à B en utilisant le même indicateur. Pour un ordonnancement entièrement spécifié entre deux contextes, bloquez B au départ, puis faites en sorte que A réveille B et attende au premier point de transfert ; B effectue l’opération inverse au transfert suivant. Cette approche équivaut à un changement de contexte déterministe et est utilisée par l’explorateur automatique A-B-A.<sup>[[17]](#references)</sup>

Une campagne minimale consiste à compiler le cas de test à quatre hooks (`test_setup`, les deux fonctions de thread et `test_end`) sous forme de bibliothèque partagée, à collecter une trace sans contraintes, puis à énumérer les candidats A-B-A ou à ajouter des contraintes manuelles autour des accès suspects.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interprétez séparément les délais d’expiration et les réordonnancements réussis : l’ordre demandé peut être impossible parce qu’un verrou ou une dépendance d’initialisation/publication empêche le second contexte d’atteindre son point d’injection. Gardez également à l’esprit les angles morts de KASAN : les accès directs à la pile ne sont généralement pas instrumentés, sauf s’ils risquent de dépasser les limites ; les variables globales sont omises avec l’optimisation par défaut ; et les compilateurs actuels ne peuvent pas émettre simultanément des hooks ASAN et TSAN. Enfin, le prototype perd son buffer KCOV quand une machine virtuelle invitée panique ; conservez donc une console/oracle de crash indépendant.<sup>[[17]](#references)</sup>

Pour le fuzzing guidé par la concurrence à venir, enregistrez des résumés des accès mémoire par entrée ou par appel système, associez les opérations qui formeraient des points de communication entre contextes, puis explorez uniquement ces combinaisons. Les snapshots de VM stabilisent l’état global et les adresses ; sans snapshots, les métadonnées des sites d’allocation peuvent servir à abstraire les objets entre les exécutions. Il s’agit d’une extension proposée, pas d’une fonctionnalité des outils userspace actuels de MAccConc.<sup>[[17]](#references)</sup>

## Introspection du harness : repérer rapidement les fuzzers superficiels

Lorsqu’une campagne stagne, le problème vient souvent non pas du mutator, mais du **harness**. Utilisez l’**introspection de l’accessibilité/de la couverture** pour repérer les fonctions statiquement accessibles depuis votre cible de fuzzing, mais rarement ou jamais couvertes dynamiquement. Ces fonctions signalent généralement l’un des trois problèmes suivants.<sup>[[12]](#references)</sup>

- Le harness entre dans la cible trop tôt ou trop tard.
- Le corpus de seeds ne contient pas toute une famille de fonctionnalités.
- La cible a réellement besoin d’un **second harness** plutôt que d’un seul harness surdimensionné qui « fait tout ».

Si vous utilisez des workflows de type OSS-Fuzz / ClusterFuzz, Fuzz Introspector peut comparer l’accessibilité statique à la couverture à l’exécution et générer des rapports à partir d’une exécution chronométrée ou d’un corpus public.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Utilisez le rapport pour décider s’il faut ajouter un nouveau harness pour un chemin d’analyseur non testé, étoffer le corpus pour une fonctionnalité précise ou diviser un harness monolithique en plusieurs points d’entrée.

## Sélection des cibles de fuzzing par graphe et triage des mutations

Si vous disposez déjà de **résultats d’analyse statique**, de **survivants aux tests de mutation** et de **rapports de couverture**, ne les triez pas comme des listes indépendantes. Commencez par construire un **graphe d’appels**, annotez ses nœuds avec la **complexité cyclomatique**, leur **accessibilité depuis un point d’entrée/des données non fiables** et tout résultat externe, puis posez des questions sur le graphe.<sup>[[5]](#references)[[6]](#references)</sup>

- Quelles fonctions à forte complexité sont accessibles depuis des données non fiables ?
- Quels survivants aux mutations se trouvent sur des chemins reliant les analyseurs/gestionnaires au code critique pour la sécurité ?
- Quelles fonctions sont des points de congestion architecturaux avec un **rayon d’impact** inhabituellement élevé ?

Cette approche permet généralement de trouver de meilleures cibles de fuzzing que le simple critère de « couverture la plus faible ». Un analyseur/décodeur à **forte complexité**, dont l’**accessibilité externe est confirmée**, est un meilleur candidat pour un harness qu’un utilitaire interne isolé, peu couvert mais sans chemin contrôlé par un attaquant.

### Procédure pratique de triage

1. Construisez un **graphe de code** à partir de la base de code et extrayez les métriques de complexité/de branchement de chaque fonction.
2. Recensez les **points d’entrée** qui acceptent des données contrôlées par un attaquant : gestionnaires de requêtes, décodeurs, outils d’importation, analyseurs de protocoles, lecteurs CLI/de fichiers.
3. Lancez des **requêtes de chemin** depuis ces points d’entrée vers les fonctions candidates afin de distinguer la surface d’attaque accessible du code mort/accessible uniquement en interne.
4. Donnez la priorité aux nœuds qui combinent :
   - une forte **complexité cyclomatique**
   - une **accessibilité depuis des données non fiables** confirmée
   - un **rayon d’impact** élevé ou de nombreux éléments dépendants en aval
   - des éléments corroborants, tels que des résultats **SARIF**, des notes d’audit ou des survivants aux mutations
5. Écrivez d’abord des harnesses ciblés pour les nœuds les mieux notés, en particulier les **analyseurs/codecs** comme les décodeurs hex/Base64/IP/de messages.

### Survivants aux mutations : équivalents ou exploitables

Les tests de mutation produisent souvent une liste de survivants bruitée. Avant de considérer chaque survivant comme une faille de sécurité, utilisez le graphe pour poser les questions suivantes :

- La fonction mutée est-elle accessible depuis un point d’entrée contrôlé par un attaquant ?
- Tous les chemins d’appel sont-ils soumis à des invariants plus stricts que la vérification mutée ?
- Le nœud se trouve-t-il dans du code mort, une logique de mise en forme uniquement ou un chemin de calcul/analyseur à fort impact ?

Les survivants qui restent inaccessibles ou sont contraints par la structure sont souvent des **mutants équivalents**. Ceux qui restent **accessibles** et concernent des **cas limites**, des **chemins de dépassement/carry** ou des **calculs/analyses critiques pour la sécurité** devraient être ajoutés à :

- de nouveaux harnesses de fuzzing
- des tests directs de propriétés/invariants
- des jeux de vecteurs ciblant les cas limites

### Reporter les résultats externes sur le graphe

Si votre pipeline SAST exporte du **SARIF**, reportez les résultats sur les nœuds du graphe à l’aide du **fichier et de la plage de lignes**, puis utilisez le graphe pour étendre l’analyse de leur impact.<sup>[[6]](#references)</sup>

- calculez le **rayon d’impact** de la fonction signalée
- vérifiez si le résultat se trouve sur un chemin partant d’un point d’entrée
- regroupez les résultats proches qui convergent vers le même point de congestion

Cette méthode est utile pour décider s’il faut consacrer du temps au fuzzing d’une fonction précise : un nœud **accessible**, **complexe** et présentant déjà des **résultats SAST** constitue souvent une meilleure cible qu’un nœud simplement complexe sans chemin accessible à un attaquant.

Exemple de procédure avec Trailmark.<sup>[[6]](#references)</sup>

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

L’essentiel de la méthodologie réside dans l’intersection : **complexité x exposition x impact**. Utilisez le graphique pour choisir les cibles de fuzzing offrant la meilleure valeur attendue en matière de sécurité, puis servez-vous des mutations qui survivent pour déterminer quelles frontières et quels invariants votre harness doit mettre à l’épreuve.<sup>[[5]](#references)</sup>

## Fuzzing Go avec gosentry : moteur renforcé, entrées typées et vérifications différentielles

Si une cible Go dispose déjà d’un harness natif `testing.F`, une amélioration pratique consiste à exécuter ce même harness avec [gosentry](https://github.com/trailofbits/gosentry), une toolchain Go forkée qui conserve `go test -fuzz`, mais remplace le backend par **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Cela est utile lorsque le fuzzer Go natif bloque sur des **comparaisons difficiles**, des **entrées typées** ou des **formats fortement dépendants d’un parseur**. La méthodologie reste la même :

- Continuez à utiliser `f.Add(...)` pour les seeds et `f.Fuzz(...)` pour le callback.
- Réutilisez le même harness, mais exécutez-le avec le binaire `go` de gosentry plutôt qu’avec la toolchain standard.
- Traitez la campagne obtenue comme une exécution normale guidée par la couverture, mais avec le scheduling et la mutation de LibAFL, ainsi que de meilleurs détecteurs associés.

### Transformer les échecs silencieux en résultats de fuzzing

Dans les audits Go, un problème récurrent est que les comportements dangereux ne provoquent souvent **pas** de crash par défaut. Avec gosentry, vous pouvez transformer plusieurs catégories d’états « problématiques mais silencieux » en résultats.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` pour faire traiter certains chemins de journalisation/d’erreur comme des crashes (utile pour les chemins de code de type `log.Fatal` qui, autrement, se contentent de journaliser et de continuer).
- `--catch-races=true` pour rejouer les entrées récemment découvertes dans la file avec le détecteur de race de Go.
- `--catch-leaks=true` pour rejouer les nouvelles entrées de la file avec `goleak` et s’arrêter en cas de fuite de goroutine.
- La gestion des blocages de LibAFL pour conserver les **boucles infinies / entrées très lentes** comme résultats de fuzzing au lieu de les laisser disparaître en tant que timeouts.
- Des vérifications intégrées du dépassement arithmétique par défaut, ainsi que des vérifications facultatives de troncature via une instrumentation de type go-panikint.

C’est particulièrement utile pour les cibles dont l’impact sur la sécurité prend la forme d’un échec de parseur sans panic, d’un bug de concurrence ou d’un blocage provoquant uniquement un DoS, plutôt que d’une corruption mémoire.

### Fuzzing tenant compte des structs pour les API Go typées

Le fuzzing Go natif attend principalement des scalaires comme `[]byte`, `string` et des nombres. Si le code testé consomme des objets typés, gosentry peut fuzz **directement des valeurs composites** (structs, slices, arrays, pointeurs), tout en mutant les octets sous-jacents.<sup>[[7]](#references)[[8]](#references)</sup>

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

Utiliser ce format wire factice uniquement pour le fuzzing masquerait des bugs logiques derrière du code d’analyse propre au harness. Pour les campagnes différentielles ou basées sur une grammaire, gardez l’entrée du harness sous la forme d’un unique `[]byte` ou `string` et effectuez l’analyse dans le callback.

### Fuzzing basé sur une grammaire pour les parseurs et les entrées de protocole

Pour les parseurs, les formats et les langages d’entrée, gosentry peut exécuter le fuzzing par grammaire **Nautilus** avec LibAFL. La grammaire est un tableau JSON de règles de production, et le harness devrait généralement prendre un unique argument `[]byte` ou `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Notes méthodologiques :

- Utilisez le mode grammaire lorsque les mutations au niveau des octets échouent généralement lors des premières vérifications syntaxiques.
- Limitez la grammaire au **sous-ensemble du langage/protocole pertinent pour la sécurité**, au lieu de modéliser toute la spécification.
- Utilisez de grandes valeurs limites dans les terminaux/non-terminaux pour mettre à l’épreuve les limites des entiers, des longueurs et des machines à états.
- Le mode grammaire garantit que les entrées sont valides selon la grammaire, mais la cible reçoit toujours des **octets/chaînes** : l’analyse syntaxique et les vérifications sémantiques restent dans le code exécuté par le harness.

### Differential fuzzing : comparer les implémentations, pas seulement les plantages

Une approche efficace dans les écosystèmes Go est le **differential fuzzing basé sur une grammaire** : générer des entrées structurées valides et les transmettre à deux parseurs, clients ou moteurs de transition d’état.<sup>[[7]](#references)[[8]](#references)</sup>

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

Considérez comme des anomalies :

- une implémentation panique tandis que l’autre rejette proprement
- des divergences entre les entrées acceptées et rejetées
- des arbres d’analyse ou des objets décodés différents
- des transitions d’état, des nonces, des soldes ou des racines d’état divergents

C’est une méthode pratique pour détecter les **divergences de consensus**, les **ambiguïtés de parseur** et les **écarts entre spécification et implémentation** que le fuzzing visant uniquement les crashs ne détecte souvent pas.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Réutiliser le corpus de campagne pour générer un rapport de couverture

Après une campagne, rejouez le corpus enregistré dans la file d’attente pour générer un rapport de couverture Go sans exporter manuellement un corpus séparé.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Exécutez la commande depuis le **même package** et avec la **même cible `-fuzz`** afin que gosentry retrouve l’état de campagne mis en cache approprié.



## References

- [1] [Fuzzing par grammaire mutationnelle](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Le fuzzing avec AFL++ en profondeur](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinq ans plus tard : le fuzzing de protocoles guidé par la couverture](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark transforme le code en graphes](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Il manquait la moitié des outils au fuzzing Go. Nous avons forké la chaîne d’outils pour y remédier.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer : un fuzzer greybox rapide pour les protocoles réseau à état utilisant des snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Pas de grammaire, pas de problème : vers le fuzzing du noyau Linux sans descriptions des appels système](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy : fuzzing efficace avec des snapshots adaptatifs et modifiables](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentation LLVM d’AFL++ : couverture des chemins et des appelants](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing prédictif sensible au contexte](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Android Offensive Security - Fuzzing Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer LKL pour Android Binder - documentation de compilation et des seeds de régression](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc : exploration des conditions de concurrence du noyau Linux à l’aide d’entrelacements contrôlés des accès mémoire](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV : couverture de code pour le fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
{{#include ../banners/hacktricks-training.md}}
