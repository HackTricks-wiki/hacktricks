# Méthodologie de fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing par grammaire mutationnelle : couverture vs sémantique

Dans le **fuzzing par grammaire mutationnelle**, les entrées sont mutées tout en restant **valides selon la grammaire**. En mode guidé par la couverture, seuls les échantillons qui déclenchent une **nouvelle couverture** sont conservés comme seeds du corpus. Pour les **cibles de langage** (analyseurs, interpréteurs, moteurs), cela peut faire manquer des bugs qui nécessitent des **chaînes sémantiques/de flux de données**, où la sortie d’une construction devient l’entrée d’une autre.<sup>[[1]](#references)</sup>

**Mode d’échec :** le fuzzer trouve des seeds qui exercent individuellement `document()` et `generate-id()` (ou des primitives similaires), mais **ne préserve pas le flux de données chaîné** ; l’échantillon « plus proche du bug » est donc abandonné parce qu’il n’apporte pas de couverture supplémentaire. Avec **au moins 3 étapes dépendantes**, les recombinaisons aléatoires deviennent coûteuses et le retour de couverture ne guide pas la recherche.<sup>[[1]](#references)</sup>

**Conséquence :** pour les grammaires fortement dépendantes, envisagez de **combiner les phases mutationnelle et générative** ou d’orienter la génération vers des motifs d’**enchaînement de fonctions** (pas uniquement vers la couverture).<sup>[[1]](#references)</sup>

## Pièges liés à la diversité du corpus

La mutation guidée par la couverture est **gloutonne** : un échantillon apportant une nouvelle couverture est immédiatement conservé, souvent avec de grandes régions inchangées. Au fil du temps, les corpus deviennent des **quasi-doublons** peu diversifiés sur le plan structurel. Une minimisation trop agressive peut supprimer du contexte utile ; un compromis pratique consiste donc à effectuer une **minimisation tenant compte de la grammaire** qui **s’arrête après un nombre minimal de tokens** (réduire le bruit tout en conservant suffisamment de structure environnante pour faciliter les mutations).<sup>[[1]](#references)</sup>

Une règle pratique pour les corpus de fuzzing mutationnel consiste à **privilégier un petit ensemble de seeds structurellement différentes qui maximisent la couverture** plutôt qu’une grande quantité de quasi-doublons. En pratique, cela signifie généralement ce qui suit.<sup>[[1]](#references)[[3]](#references)</sup>

- Partez d’**échantillons du monde réel** (corpus publics, crawling, trafic capturé, ensembles de fichiers issus de l’écosystème ciblé).
- Réduisez-les par **minimisation du corpus basée sur la couverture** au lieu de conserver chaque échantillon valide.
- Gardez des seeds **suffisamment petites** pour que les mutations portent sur des champs pertinents, plutôt que de consacrer la majeure partie des cycles à des octets sans intérêt.
- Relancez la minimisation du corpus après toute modification importante du harness ou de l’instrumentation, car le « meilleur » corpus change lorsque la joignabilité évolue.

## Mutation tenant compte des comparaisons pour les valeurs magiques

Les fuzzers plafonnent souvent non pas à cause de la syntaxe, mais à cause de **comparaisons strictes** : octets magiques, vérifications de longueur, chaînes d’énumération, sommes de contrôle ou valeurs de dispatch de l’analyseur, protégées par `memcmp`, des tables de switch ou des comparaisons en cascade. La mutation purement aléatoire gaspille des cycles à essayer de deviner ces valeurs octet par octet.

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

- Cette méthode est particulièrement utile lorsque la cible protège une logique approfondie derrière des **signatures de fichiers**, des **verbes de protocole**, des **balises de type** ou des **bits de fonctionnalité dépendant de la version**.
- Associez-la à des **dictionnaires** extraits d’échantillons réels, de spécifications de protocole ou de journaux de débogage. Un petit dictionnaire contenant des tokens de grammaire, des noms de chunks, des verbes et des délimiteurs est souvent plus utile qu’une énorme wordlist générique.
- Si la cible effectue de nombreuses vérifications séquentielles, résolvez d’abord les premières comparaisons « magic », puis réduisez à nouveau le corpus obtenu afin que les étapes suivantes démarrent à partir de préfixes déjà valides.

## Un feedback plus riche lorsque la couverture des edges confond différents chemins

La couverture normale des edges ne permet pas de distinguer deux exécutions qui traversent le même helper depuis des appelants différents ou qui prennent différentes combinaisons de branches au sein d’une fonction. C’est important dans les décodeurs partagés, les répartiteurs de protocoles et les helpers d’interpréteur, où le **chemin** menant à un edge détermine l’état actif. Suivre naïvement chaque contexte d’appel est également risqué : la carte de couverture et la queue peuvent exploser. Les recherches sur le fuzzing sensible au contexte recommandent donc d’affiner uniquement les contextes prometteurs, plutôt que de rendre sensible au contexte l’ensemble du graphe d’appels.<sup>[[14]](#references)</sup>

Les versions récentes d’AFL++ fournissent la **couverture de chemins par fonction Ball-Larus** en plus de la couverture normale des edges. Elle attribue une feature à chaque chemin acyclique d’une fonction ; les arcs de retour des boucles sont supprimés, ce qui permet à ce feedback de distinguer les combinaisons de branches, mais **pas le nombre d’itérations des boucles**. Commencez par le niveau souple `1`, puis limitez les modes plus stricts au code suspect des parseurs et des machines à états, car le nombre de chemins peut croître de façon exponentielle.<sup>[[13]](#references)</sup>

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

**Conseils pour la campagne :** appliquez le feedback plus riche avec prudence et surveillez son coût en termes de couverture de la map et de taille de la queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Exécutez en parallèle une instance classique de couverture des arêtes ; le feedback plus riche n’est utile que si le coût supplémentaire en queue/map ne réduit pas trop le nombre d’exécutions par seconde.
- Utilisez `AFL_LLVM_ALLOWLIST` pour limiter l’instrumentation des chemins et des appelants lorsque de grandes bibliothèques riches en templates ou du code utilitaire générique dominent la map.
- Les fonctions comportant un nombre excessif de chemins acycliques peuvent être ignorées par AFL++ ; les avertissements à la compilation indiquent que la cible nécessite une allowlist ou un niveau moins strict.
- La couverture des appelants et des chemins ne prend en charge qu’un seul niveau d’appelant. Ne la combinez pas avec des piles de contexte plus profondes.
- Les identifiants de chemin peuvent changer entre les versions majeures de LLVM. Gardez la toolchain fixe pendant une campagne et ne synchronisez pas des corpus basés sur PATH comme si leurs identifiants de fonctionnalité étaient stables d’une build à l’autre.
- Ce feedback complète `CMPLOG` : le traçage des comparaisons détermine **quelle valeur franchit une condition**, tandis que le feedback des chemins et des appelants préserve **quel itinéraire et quelle combinaison de branches y ont conduit**.

## Fuzzing avec état : les séquences sont des graines

Pour les **protocoles**, les **workflows authentifiés** et les **parseurs en plusieurs étapes**, l’unité intéressante n’est souvent pas un blob isolé, mais une **séquence de messages**. Concaténer toute la transcription dans un fichier unique et la muter à l’aveugle est généralement inefficace, car le fuzzer mute chaque étape de la même façon, même lorsque seul le message ultérieur permet d’atteindre l’état fragile.<sup>[[4]](#references)</sup>

Une approche plus efficace consiste à traiter la **séquence elle-même comme la graine** et à utiliser l’**état observable** (codes de réponse, états du protocole, phases du parseur, types des objets renvoyés) comme feedback supplémentaire.<sup>[[4]](#references)</sup>

- Gardez les **messages de préfixe valides** stables et concentrez les mutations sur le message qui **déclenche la transition**.
- Mettez en cache les identifiants et les valeurs générés par le serveur dans les réponses précédentes lorsque l’étape suivante en dépend.
- Privilégiez les mutations et les opérations de splicing par message plutôt que la mutation de toute la transcription sérialisée comme un blob opaque.
- Si le protocole expose des codes de réponse significatifs, utilisez-les comme **oracle d’état peu coûteux** pour prioriser les séquences qui progressent davantage.

C’est pour la même raison que les bugs authentifiés, les transitions cachées ou les bugs de parseur qui ne se manifestent « qu’après le handshake » échappent souvent au fuzzing classique de fichiers : le fuzzer doit préserver **l’ordre, l’état et les dépendances**, pas seulement la structure.<sup>[[4]](#references)</sup>

### Android Binder : fuzzing du pilote avec plusieurs clients

Une couverture élevée des arêtes peut malgré tout passer à côté de bugs du pilote IPC, car la couverture ne décrit pas **la propriété des objets, les compteurs de références, les messages en attente, l’ordre du nettoyage ni les entrelacements de threads**. La page sur les [internes d’Android Binder IPC](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) décrit le modèle d’objets du pilote ; cet exemple se concentre sur le harness du fuzzer. Android Binder est un modèle utile : atteindre les chemins d’allocation et de libération ne suffit pas si le fuzzer ne peut pas faire opérer plusieurs processus sur le même objet du noyau dans l’ordre requis.<sup>[[15]](#references)</sup>

#### Modéliser le protocole, pas des buffers `ioctl` isolés

Représentez un cas de test comme une grammaire ordonnée composée de **l’identité du client + l’opération + des arguments structurés**. Le fuzzer Binder LKL utilise protobuf et `libprotobuf-mutator`, avec un client gestionnaire de contexte persistant et deux clients ordinaires. Un harness sémantique préserve alors les relations que la mutation aveugle d’octets détruirait.<sup>[[15]](#references)</sup>

- Mettez en cache les valeurs renvoyées par les opérations précédentes. Par exemple, `BC_FREE_BUFFER` doit réutiliser un pointeur de buffer de transaction renvoyé par un `ioctl` antérieur.
- Générez des réponses par défaut valides afin que les transactions synchrones puissent aboutir et que les opérations suivantes restent accessibles.
- Rejetez les transitions impossibles, telles que les transactions vers soi-même ou plusieurs transactions en attente pour une même cible.
- Conservez l’état d’initialisation singleton en dehors de la réinitialisation par entrée. Binder n’autorise qu’un seul enregistrement `BINDER_SET_CONTEXT_MGR` par démarrage ; détruire et recréer ce client à répétition invaliderait donc les entrées suivantes.

Un modèle utile de course sur la durée de vie consiste à faire transférer un objet par un client, à démarrer le nettoyage d’un thread ou d’un processus, puis à faire libérer simultanément le buffer de transaction par le client destinataire. Dans l’exemple CVE-2020-0423, le transfert d’un `BINDER_TYPE_WEAK_BINDER`, suivi d’un `BINDER_THREAD_EXIT` entrant en course avec `BC_FREE_BUFFER`, pouvait libérer un `binder_work` intégré alors que le chemin de nettoyage du thread en cours de sortie l’utilisait encore.<sup>[[15]](#references)</sup>

#### Réintroduire des entrelacements contrôlés dans un noyau en espace utilisateur

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) lie le véritable code du noyau à un harness en espace utilisateur et expose son interface d’appels système via `lkl_syscall`. Cela facilite la coordination, au sein d’un même processus, de l’état protobuf, de la couverture et de KASAN. Toutefois, LKL exécute normalement un appel système sans qu’un autre thread du noyau l’interrompe. Pour les campagnes de recherche de courses, insérez des points d’appel à `schedule()` autour de verrous et de limites de durée de vie sélectionnés, puis laissez le harness choisir au hasard le prochain client à chaque yield. Ciblez ces points avec précision, car chacun multiplie l’espace de recherche de l’ordonnancement. L’ordonnanceur aléatoire décrit par les chercheurs ne fait **pas** partie du fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Construire et rejouer des graines de régression sérialisées

Le harness upstream fixe une version compatible de `libprotobuf-mutator`, active l’instrumentation de fuzzing LKL et KASAN avec `LKL_FUZZING=1`, et active `CONFIG_MMU` pour Binder avec `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Après avoir récupéré une révision volontairement vulnérable ou appliqué les correctifs de rollback documentés en amont, une graine sérialisée peut reproduire toute la transition d’état multi-client sans avoir à la reconstruire dans une preuve de concept C ad hoc :<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Considérez le use-after-free détecté par KASAN comme une confirmation que la seed a atteint le chemin de durée de vie vulnérable. Cela ne démontre **pas** la présence des primitives ultérieures nécessaires à l’exécution de code dans le noyau ou à l’élévation de privilèges.<sup>[[16]](#references)</sup>

## Astuce de diversité sur une seule machine (style Jackalope)

Une façon pratique de combiner la **nouveauté générative** et la **réutilisation de la couverture** consiste à **redémarrer des workers de courte durée** face à un serveur persistant. Chaque worker démarre avec un corpus vide, se synchronise après `T` secondes, exécute pendant `T` secondes supplémentaires sur le corpus combiné, se synchronise à nouveau, puis se termine. Cela permet d’obtenir des **structures inédites à chaque génération**, tout en tirant parti de la couverture accumulée.<sup>[[1]](#references)[[2]](#references)</sup>

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

**Notes :**

- `-in empty` force un **corpus vierge** à chaque génération.
- `-server_update_interval T` approxime une **synchronisation différée** (nouveauté d’abord, réutilisation ensuite).
- En mode grammar fuzzing, la **synchronisation initiale avec le serveur est ignorée par défaut** (pas besoin de `-skip_initial_server_sync`).
- La valeur optimale de `T` dépend de la **cible** ; il est généralement préférable de changer de valeur après que le worker a trouvé la majeure partie de la couverture « facile ».

## Snapshot Fuzzing Pour Les Cibles Difficiles À Instrumenter

Lorsque le code que vous voulez tester n’est accessible qu’**après une longue phase de configuration** (démarrage d’une VM, connexion terminée, réception d’un paquet, analyse d’un conteneur, initialisation d’un service), une alternative utile est le **snapshot fuzzing** : capturer l’état du processus ou de la VM prêt à l’emploi, injecter chaque cas de test dans le chemin d’entrée de la cible, exécuter jusqu’au crash/timeout, puis restaurer le snapshot. Cela évite de répéter l’initialisation ou les préfixes de protocole et s’avère utile pour les **services réseau**, le **firmware**, les **surfaces d’attaque post-authentification** et les **cibles binaires uniquement**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Exécutez la cible jusqu’à ce que l’état intéressant soit prêt.
2. Prenez un snapshot de la **mémoire + des registres** à ce stade.
3. Pour chaque cas de test, écrivez directement l’entrée mutée dans le tampon pertinent du processus/guest.
4. Exécutez jusqu’au crash/timeout/reset.
5. Restaurez le snapshot ; pour les cibles VM, ne restaurez que les **pages modifiées** lorsque cela est pris en charge, puis recommencez.

Placez le snapshot aussi près que possible de la première étape coûteuse d’analyse/d’aiguillage, par exemple après un point `recv`/`read` ou de désérialisation de paquet, et enregistrez le tampon d’entrée utilisé par la cible. Cela suit le principe de placement adaptatif, qui consiste à déplacer le snapshot plus loin dans le traitement de l’entrée afin d’éviter de répéter le travail.<sup>[[11]](#references)</sup>

## Introspection Du Harness : Repérer Tôt Les Fuzzers Superficiels

Lorsqu’une campagne stagne, le problème vient souvent non pas du mutateur, mais du **harness**. Utilisez l’**introspection de l’accessibilité/de la couverture** pour trouver les fonctions qui sont statiquement accessibles depuis votre fuzz target, mais rarement ou jamais couvertes dynamiquement. Ces fonctions indiquent généralement l’un de ces trois problèmes.<sup>[[12]](#references)</sup>

- Le harness entre dans la cible trop tard ou trop tôt.
- Le seed corpus ne contient pas toute une famille de fonctionnalités.
- La cible a réellement besoin d’un **deuxième harness** plutôt que d’un unique harness « tout faire » surdimensionné.

Si vous utilisez des workflows de type OSS-Fuzz / ClusterFuzz, Fuzz Introspector peut comparer l’accessibilité statique à la couverture à l’exécution et générer des rapports à partir d’une exécution chronométrée ou d’un corpus public.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Utilisez le rapport pour décider s'il faut ajouter un nouveau harness pour un chemin d'analyseur non testé, enrichir le corpus pour une fonctionnalité donnée ou scinder un harness monolithique en points d'entrée plus petits.

## Sélection des cibles de fuzzing à partir du graphe et triage des mutations

Si vous disposez déjà de **résultats d'analyse statique**, de **mutants survivants aux tests de mutation** et de **rapports de couverture**, ne les triez pas comme des listes indépendantes. Commencez par construire un **graphe d'appels**, annotez les nœuds avec leur **complexité cyclomatique**, leur **accessibilité depuis des points d'entrée/des entrées non fiables** et tout résultat externe, puis posez des questions sur le graphe.<sup>[[5]](#references)[[6]](#references)</sup>

- Quelles fonctions à forte complexité sont accessibles depuis des entrées non fiables ?
- Quels mutants survivants se trouvent sur des chemins reliant les analyseurs/gestionnaires au code critique pour la sécurité ?
- Quelles fonctions sont des points de congestion architecturaux avec un **rayon d'impact** inhabituellement élevé ?

Cette méthode fait généralement ressortir de meilleures cibles de fuzzing que le seul « taux de couverture le plus faible ». Un analyseur/décodeur à **forte complexité** et dont l'**accessibilité externe** est confirmée constitue un meilleur candidat pour un harness qu'une fonction utilitaire interne isolée, peu couverte mais sans chemin contrôlé par un attaquant.

### Workflow pratique de triage

1. Construisez un **graphe de code** à partir du code source et extrayez les métriques de complexité/de branches pour chaque fonction.
2. Recensez les **points d'entrée** qui acceptent des entrées contrôlées par un attaquant : gestionnaires de requêtes, décodeurs, importateurs, analyseurs de protocoles, lecteurs CLI/fichiers.
3. Exécutez des requêtes de chemin depuis ces points d'entrée jusqu'aux fonctions candidates afin de distinguer la surface d'attaque accessible du code mort/interne uniquement.
4. Donnez la priorité aux nœuds qui combinent :
   - une **complexité cyclomatique** élevée
   - une **accessibilité confirmée depuis des entrées non fiables**
   - un **rayon d'impact** élevé ou de nombreux éléments dépendants en aval
   - des éléments corroborants, comme des résultats **SARIF**, des notes d'audit ou des mutants survivants
5. Écrivez d'abord des harnesses ciblés pour les nœuds les mieux notés, en particulier les **analyseurs/codecs** comme les décodeurs hex/Base64/IP/messages.

### Mutants survivants : équivalents ou exploitables

Les tests de mutation produisent souvent une liste de survivants bruitée. Avant de considérer chaque survivant comme une faille de sécurité, utilisez le graphe pour vous demander :

- La fonction mutée est-elle accessible depuis un point d'entrée contrôlé par un attaquant ?
- Tous les chemins d'appel sont-ils soumis à des invariants plus stricts que le contrôle muté ?
- Le nœud se trouve-t-il dans du code mort, de la logique de formatage uniquement ou dans un chemin arithmétique/analyseur à fort impact ?

Les survivants qui restent inaccessibles ou sont structurellement contraints sont souvent des **mutants équivalents**. Les survivants qui restent **accessibles** et touchent aux **conditions limites**, aux **chemins de dépassement/carry** ou à l'**arithmétique/analyse critique pour la sécurité** doivent être promus en :

- nouveaux harnesses de fuzzing
- tests directs de propriétés/invariants
- vecteurs ciblés pour les cas limites

### Reporter les résultats externes sur le graphe

Si votre pipeline SAST exporte des résultats **SARIF**, projetez-les sur les nœuds du graphe à l'aide du **fichier + de la plage de lignes**, puis utilisez le graphe pour étendre l'analyse de l'impact.<sup>[[6]](#references)</sup>

- calculez le **rayon d'impact** de la fonction signalée
- vérifiez si le résultat se trouve sur un chemin depuis un point d'entrée
- regroupez les résultats voisins qui convergent vers le même point de congestion

Cette approche est utile pour décider s'il faut consacrer du temps de fuzzing à une fonction donnée : un nœud **accessible**, **complexe** et qui présente déjà des **résultats SAST** est souvent une meilleure cible qu'un nœud simplement complexe, sans chemin accessible à un attaquant.

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

La méthodologie importante repose sur l’intersection : **complexité x exposition x impact**. Utilisez le graphique pour choisir les cibles de fuzzing offrant la plus grande valeur attendue en matière de sécurité, puis servez-vous des mutations survivantes pour déterminer quelles frontières et quels invariants votre harness doit mettre à l’épreuve.<sup>[[5]](#references)</sup>

## Fuzzing Go avec gosentry : moteur plus puissant, entrées typées et vérifications différentielles

Si une cible Go dispose déjà d’un harness natif `testing.F`, une mise à niveau pratique consiste à exécuter le même harness avec [gosentry](https://github.com/trailofbits/gosentry), une toolchain Go dérivée qui conserve `go test -fuzz`, mais remplace le backend par **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

C'est utile lorsque le fuzzer Go natif cale sur des **comparaisons difficiles**, des **entrées typées** ou des **formats faisant largement appel à des parseurs**. La méthodologie reste la même :

- Continuez à utiliser `f.Add(...)` pour les seeds et `f.Fuzz(...)` pour le callback.
- Réutilisez le même harness, mais exécutez-le avec le binaire `go` de gosentry plutôt qu'avec la toolchain standard.
- Traitez la campagne obtenue comme une exécution normale guidée par la couverture, mais avec l'ordonnancement et les mutations de LibAFL, ainsi que de meilleurs détecteurs complémentaires.

### Transformer les échecs silencieux en findings

Lors des évaluations Go, un problème récurrent est que les comportements dangereux ne provoquent souvent **pas** de crash par défaut. Avec gosentry, vous pouvez transformer plusieurs états « mauvais, mais silencieux » en findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` pour faire en sorte que certains chemins de journalisation/d'erreur se comportent comme des crashs (utile pour les chemins de code de type `log.Fatal` qui, sinon, se contentent de journaliser et de continuer).
- `--catch-races=true` pour rejouer les nouvelles entrées de la queue avec le détecteur de races Go.
- `--catch-leaks=true` pour rejouer les nouvelles entrées de la queue avec `goleak` et s'arrêter en cas de fuite de goroutine.
- La gestion des blocages de LibAFL permet de conserver les **boucles infinies / entrées très lentes** comme findings de fuzzing, au lieu de les laisser disparaître en tant que timeouts.
- Vérifications intégrées des dépassements arithmétiques activées par défaut, ainsi que des vérifications optionnelles de troncature via une instrumentation de type go-panikint.

C'est particulièrement utile pour les cibles dont l'impact sur la sécurité est un **échec de parseur sans panic**, un **bug de concurrence** ou un **blocage relevant uniquement d'un DoS**, plutôt qu'une corruption mémoire.

### Fuzzing tenant compte des structures pour les API Go typées

Le fuzzing Go natif attend principalement des scalaires tels que `[]byte`, `string` et des nombres. Si le code testé consomme des objets typés, gosentry peut directement fuzzer des **valeurs composites** (structs, slices, arrays, pointers) tout en continuant à muter les octets sous-jacents.<sup>[[7]](#references)[[8]](#references)</sup>

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

Utilisez cette approche lors de la création d’un faux format filaire : le parsing réservé au harness masquerait les bugs logiques. Pour les campagnes différentielles ou basées sur une grammaire, gardez l’entrée du harness sous la forme d’un seul `[]byte` ou `string` et effectuez le parsing dans le callback.

### Fuzzing basé sur une grammaire pour les parsers et les entrées de protocoles

Pour les parsers, les formats et les langages d’entrée, gosentry peut exécuter le fuzzing grammatical **Nautilus** avec LibAFL. La grammaire est un tableau JSON de règles de production, et le harness devrait généralement accepter un seul argument `[]byte` ou `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Notes sur la méthodologie :

- Utilisez le mode grammaire lorsque les mutations au niveau des octets échouent principalement lors des premières vérifications syntaxiques.
- Limitez la grammaire au **sous-ensemble du langage/protocole pertinent pour la sécurité**, plutôt que de modéliser toute la spécification.
- Utilisez des valeurs limites élevées dans les terminaux et non-terminaux pour mettre à l’épreuve les limites des entiers, des longueurs et des machines à états.
- Le mode grammaire garantit que les entrées respectent la grammaire, mais la cible reçoit toujours des **octets/chaînes** : l’analyse syntaxique et les vérifications sémantiques restent donc dans le code instrumenté.

### Fuzzing différentiel : comparer les implémentations, pas seulement les crashs

Une approche efficace dans les écosystèmes Go est le **fuzzing différentiel basé sur une grammaire** : générer des entrées structurées valides et les transmettre à deux analyseurs, clients ou moteurs de transition d’état.<sup>[[7]](#references)[[8]](#references)</sup>

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
- des arbres d’analyse ou des objets décodés différents
- des transitions d’état, des nonces, des soldes ou des racines d’état divergents

C’est une méthode pratique pour détecter les **divergences de consensus**, les **ambiguïtés d’analyse syntaxique** et les **écarts entre la spécification et l’implémentation**, souvent ignorés par le fuzzing axé uniquement sur les plantages.

### Réutiliser le corpus de campagne pour générer un rapport de couverture

Après une campagne, rejouez le corpus de la file sauvegardé pour générer un rapport de couverture Go, sans exporter manuellement un corpus distinct.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Exécutez la commande depuis le **même package** et avec la **même cible `-fuzz`** afin que gosentry retrouve l’état de campagne mis en cache correspondant.

## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ : le fuzzing en profondeur](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet, cinq ans plus tard : le fuzzing de protocoles guidé par la couverture](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark transforme le code en graphes](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Le fuzzing Go ne disposait que de la moitié de la boîte à outils. Nous avons forké la toolchain pour y remédier.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer : un fuzzer greybox rapide pour les protocoles réseau à état utilisant des snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Pas de grammaire ? Pas de problème : vers le fuzzing du noyau Linux sans descriptions des appels système](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy : un fuzzing efficace avec des snapshots adaptatifs et modifiables](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentation LLVM d’AFL++ : couverture des chemins et des appelants](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing prédictif sensible au contexte](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Android Offensive Security - Binder Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer Binder Android LKL - documentation sur la compilation et les seeds de régression](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
{{#include ../banners/hacktricks-training.md}}
