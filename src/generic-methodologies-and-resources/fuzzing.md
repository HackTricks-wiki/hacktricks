# Méthodologie du fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing grammatical mutationnel : couverture vs sémantique

Dans le **fuzzing grammatical mutationnel**, les entrées sont modifiées tout en restant **valides selon la grammaire**. En mode guidé par la couverture, seuls les échantillons qui déclenchent une **nouvelle couverture** sont enregistrés comme seeds du corpus. Pour les **cibles de type langage** (parseurs, interpréteurs, moteurs), cette approche peut manquer les bugs qui nécessitent des **chaînes sémantiques/de flux de données**, où la sortie d’une construction devient l’entrée d’une autre.<sup>[[1]](#references)</sup>

**Mode d’échec :** le fuzzer trouve des seeds qui exercent individuellement `document()` et `generate-id()` (ou des primitives similaires), mais **ne préserve pas le flux de données enchaîné**. L’échantillon « plus proche du bug » est alors écarté parce qu’il n’apporte pas de couverture supplémentaire. Avec **au moins 3 étapes dépendantes**, les recombinaisons aléatoires deviennent coûteuses et le retour de couverture ne guide pas la recherche.<sup>[[1]](#references)</sup>

**Conséquence :** pour les grammaires comportant de nombreuses dépendances, envisagez de **combiner les phases mutationnelle et générative**, ou d’orienter la génération vers des motifs d’**enchaînement de fonctions** (et pas uniquement vers la couverture).<sup>[[1]](#references)</sup>

## Pièges liés à la diversité du corpus

La mutation guidée par la couverture est **gloutonne** : un échantillon apportant une nouvelle couverture est enregistré immédiatement, et conserve souvent de grandes régions inchangées. Au fil du temps, les corpus deviennent des **quasi-doublons** à faible diversité structurelle. Une minimisation agressive peut supprimer du contexte utile. Un compromis pratique consiste donc à utiliser une **minimisation tenant compte de la grammaire**, qui **s’arrête après un nombre minimal de tokens** (réduire le bruit tout en conservant assez de structure environnante pour faciliter les mutations).<sup>[[1]](#references)</sup>

Une règle pratique pour les corpus de fuzzing mutationnel consiste à **privilégier un petit ensemble de seeds structurellement différents qui maximisent la couverture** plutôt qu’un grand nombre de quasi-doublons. En pratique, cela implique généralement les mesures suivantes.<sup>[[1]](#references)[[3]](#references)</sup>

- Commencez par des **échantillons du monde réel** (corpus publics, exploration du Web, trafic capturé, ensembles de fichiers de l’écosystème cible).
- Réduisez-les par **minimisation du corpus basée sur la couverture**, au lieu de conserver chaque échantillon valide.
- Gardez des seeds **suffisamment petits** pour que les mutations touchent des champs pertinents, plutôt que de consacrer la plupart des cycles à des octets sans intérêt.
- Relancez la minimisation du corpus après toute modification importante du harness ou de l’instrumentation, car le « meilleur » corpus change lorsque l’accessibilité change.

## Programmes générés volumineux et biais lié aux délais d’expiration

Pour le fuzzing de compilateurs et d’interpréteurs, une entrée peut devoir dépasser un **seuil de taille du code généré**, plutôt que d’atteindre une nouvelle branche du parseur. Dans l’exemple des décalages des gestionnaires d’exceptions de V8, présenté dans [exception-handler offset example](../binary-exploitation/chrome-exploiting.md#exception-handler-offsets-narrower-than-maximum-bytecode-size), un testcase valide devait dépasser 256 Mio de bytecode pour que le décalage tronqué du gestionnaire ait un effet. Des constructions `yield*` répétées pouvaient atteindre cette limite, mais la compilation du testcase prenait plusieurs secondes dans une version de débogage. Les préférences pour les petites entrées et les délais d’expiration courts peuvent défavoriser cette catégorie, même lorsque la couverture de la grammaire est élevée. Lors de l’audit de décalages empaquetés ou d’autres métadonnées sensibles à la longueur, examinez séparément les seuils de taille et la politique de délai d’expiration ; ce conseil découle du mode d’échec rapporté.<sup>[[29]](#references)</sup>

## Mutation tenant compte des comparaisons pour les valeurs magiques

Une raison fréquente pour laquelle les fuzzers plafonnent n’est pas la syntaxe, mais les **comparaisons strictes** : octets magiques, vérifications de longueur, chaînes d’énumération, sommes de contrôle ou valeurs de dispatch du parseur, protégés par `memcmp`, des tables `switch` ou des comparaisons en cascade. Les mutations purement aléatoires gaspillent des cycles à essayer de deviner ces valeurs octet par octet.

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

- Cette méthode est particulièrement utile lorsque la cible protège une logique approfondie derrière des **signatures de fichier**, des **verbes de protocole**, des **balises de type** ou des **bits de fonctionnalités dépendant de la version**.
- Associez-la à des **dictionnaires** extraits d’échantillons réels, de spécifications de protocole ou de journaux de débogage. Un petit dictionnaire contenant des jetons de grammaire, des noms de blocs, des verbes et des délimiteurs est souvent plus utile qu’une immense wordlist générique.
- Si la cible effectue de nombreux contrôles séquentiels, résolvez d’abord les premières comparaisons « magiques », puis minimisez à nouveau le corpus obtenu afin que les étapes suivantes partent de préfixes déjà valides.

## Fuzzing des API de fichiers qui masquent un langage de nom de fichier

Un paramètre nommé `filename`, `path` ou `URL` peut être un point d’entrée d’interpréteur plutôt qu’une simple recherche de fichier. Par exemple, la syntaxe de nom de fichier étendue de CFITSIO (EFS) évalue des sélecteurs entre crochets, des expressions de lignes/pixels, des colonnes calculées, des histogrammes et des transformations avant de renvoyer l’objet ouvert ; certaines formes créent également des copies temporaires. Lors de la cartographie de la surface d’attaque, classez chaque API d’ouverture/importation comme **chemin littéral** ou **chemin interprété**, puis fuzz-ez le point d’entrée de production réellement appelé par les applications.<sup>[[20]](#references)[[22]](#references)</sup>

Pour les primitives SSRF, de copie de fichiers et de gestionnaire de protocole qui en résultent — ainsi que pour les API de chemin littéral plus sûres — consultez [Les mini-langages de nom de fichier comme primitives SSRF/de fichiers](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Garder l’objet de base séparé du programme fuzzé

Lorsque la grammaire se trouve dans un suffixe de nom de fichier, modifier uniquement les octets du fichier référencé ne permet pas de tester l’analyseur. Un petit harness peut plutôt lire un testcase sous forme de chaîne et le transmettre à l’API d’ouverture interprétée ; la campagne CFITSIO a atteint la plupart des analyseurs et évaluateurs EFS en appelant `fits_open_file()` en lecture seule. Gardez les fichiers de base valides disponibles séparément afin que les mutations ciblent le langage des sélecteurs/expressions au lieu de casser constamment le chemin de base.<sup>[[22]](#references)</sup>

Utilisez des seeds qui atteignent chacune une famille de grammaire différente, puis créez un dictionnaire compact à partir de la spécification et du code source de l’analyseur lexical/analyseur syntaxique. Si la couverture plafonne tandis que les entrées échouent sans cesse dans le même chemin d’erreur syntaxique, préservez les préfixes valides et ajoutez des délimiteurs, des opérateurs, des mots-clés, des noms de fonctions et des noms de champs représentatifs au lieu d’augmenter uniquement la durée des mutations aléatoires.<sup>[[22]](#references)</sup>

Exécutez le harness avec le dictionnaire de grammaire, par exemple :<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Contenir les effets secondaires du harness en « lecture seule »

Un indicateur de bibliothèque en lecture seule ne garantit pas qu’un testcase soit exempt d’effets secondaires : le langage des noms de fichiers peut réécrire l’entrée, créer des fichiers de sortie ou matérialiser des objets temporaires. La campagne CFITSIO a d’abord détruit des fichiers seed et laissé des fichiers inattendus sur le système de fichiers ; un nettoyage et une isolation étaient donc nécessaires.<sup>[[22]](#references)</sup>

- Attribuez à chaque worker un répertoire de travail jetable et un répertoire temporaire privé.
- Exposez des copies des fichiers de référence ; ne laissez jamais la cible modifier l’unique copie du corpus.
- Désactivez l’accès réseau, sauf si les backends distants sont la cible prévue, et limitez les chemins accessibles en écriture à l’aide d’un conteneur, d’un espace de noms de montage ou d’un sandbox équivalent.
- Réinitialisez le répertoire après chaque exécution ou lot de workers et traitez toute modification inattendue du système de fichiers comme une découverte supplémentaire.

### Boucle crash-to-patch-to-fuzz

Regroupez les crashes avant de corriger le code, afin que des milliers d’artefacts ne deviennent pas des milliers de tâches de correction. Lors de l’évaluation de CFITSIO, AFLTriage a réduit l’ensemble initial de crashes à quelques causes racines ; l’avis de sécurité qui en a résulté décrit des défaillances distinctes, notamment des vérifications incorrectes de la taille de destination, des pointeurs obsolètes après `realloc()`, des erreurs arithmétiques et des chemins de nettoyage du parser non sécurisés.<sup>[[21]](#references)[[22]](#references)</sup>

1. Réduisez un input représentatif pour chaque groupe et reproduisez-le avec AddressSanitizer.
2. Consignez l’accès exact à l’origine de l’échec, l’emplacement dans le code source, l’historique des allocations et libérations, ainsi que l’état du parser qui a rendu l’invariant faux.
3. Appliquez un patch candidat ciblé et reconstruisez avec la même instrumentation de couverture et de sanitizer.
4. Rejouez le reproducer d’origine **et chaque input de son groupe** ; activez également la détection des leaks, car une correction de sûreté mémoire peut compromettre la gestion des ressources sur un chemin d’erreur.
5. Exécutez des tests fonctionnels avec de vrais fichiers, puis reprenez à partir de la queue accumulée (ou réimportez-la si le moteur exige un nouveau répertoire de sortie après la modification du binaire).
6. Répétez : supprimer le premier crash superficiel permet souvent aux seeds existants d’atteindre un état plus profond du parser.

Un LLM peut accélérer l’étape 2 et rédiger une ébauche pour l’étape 3 s’il reçoit l’input qui provoque le crash, le rapport du sanitizer, le harness et le code source pertinent, mais son patch reste non fiable. Ce sont la relecture par le sanitizer et les contrôles de régression — et non l’explication du modèle — qui déterminent si la correction est acceptée.<sup>[[22]](#references)</sup>

## Un feedback plus riche lorsque la couverture des arêtes confond différents chemins

La couverture normale des arêtes ne permet pas de distinguer deux exécutions qui traversent le même helper depuis différents callers ou suivent différentes combinaisons de branches au sein d’une fonction. Cela compte dans les decoders partagés, les dispatchers de protocoles et les helpers d’interpréteurs, où le **chemin** menant à une arête détermine l’état actif. Suivre naïvement chaque contexte d’appel est également risqué : la carte de couverture et la queue peuvent exploser. Les recherches sur le fuzzing sensible au contexte recommandent donc d’affiner uniquement les contextes prometteurs, plutôt que de rendre tout le graphe d’appels sensible au contexte.<sup>[[14]](#references)</sup>

Les versions récentes d’AFL++ proposent une **couverture des chemins par fonction Ball-Larus**, en plus de la couverture normale des arêtes. Elles attribuent une feature à chaque chemin acyclique traversant une fonction ; les arêtes de retour des boucles sont supprimées, ce feedback distingue donc les combinaisons de branches, mais **pas le nombre d’itérations des boucles**. Commencez avec le niveau souple `1`, puis réservez les modes plus stricts au code suspect des parsers et des machines à états, car le nombre de chemins peut croître de façon exponentielle.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Pour une fonction utilitaire appelée depuis de nombreux endroits sensibles du point de vue de la sécurité, le mode LTO peut associer chaque chemin de fonction à son site d’appel immédiat :<sup>[[13]](#references)</sup>

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

**Conseils pour les campagnes :** appliquez le feedback plus riche avec prudence et surveillez son coût en couverture de carte et de queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Exécutez en parallèle une instance ordinaire avec couverture des edges ; le feedback plus riche n’est utile que si le coût supplémentaire en queue/carte ne réduit pas trop le nombre d’exécutions par seconde.
- Utilisez `AFL_LLVM_ALLOWLIST` pour restreindre l’instrumentation des chemins/appelants lorsque de grandes bibliothèques riches en templates ou du code utilitaire générique dominent la carte.
- Les fonctions avec un nombre excessif de chemins acycliques peuvent être ignorées par AFL++ ; les avertissements lors de la compilation indiquent que la cible nécessite une allowlist ou un niveau moins strict.
- La couverture des appelants et des chemins ne prend en charge qu’un seul niveau d’appelant. Ne la combinez pas avec des piles de contexte plus profondes.
- Les identifiants de chemin peuvent changer d’une version majeure de LLVM à l’autre. Gardez la chaîne d’outils fixe pendant une campagne et ne synchronisez pas des corpus basés sur PATH comme si leurs identifiants de fonctionnalités étaient stables d’une compilation à l’autre.
- Ce feedback complète `CMPLOG` : le traçage des comparaisons détermine **quelle valeur franchit une garde**, tandis que le feedback sur les chemins/appelants préserve **quelle route et quelle combinaison de branches y ont mené**.

## Fuzzing avec état : les séquences sont des seeds

Pour les **protocoles**, les **workflows authentifiés** et les **parseurs à plusieurs étapes**, l’unité intéressante est souvent une **séquence de messages**, et non un blob unique. Concaténer toute la transcription dans un seul fichier et la muter à l’aveugle est généralement inefficace, car le fuzzer mute chaque étape de la même manière, même lorsque seul le message ultérieur atteint l’état fragile.<sup>[[4]](#references)</sup>

Une approche plus efficace consiste à traiter la **séquence elle-même comme le seed** et à utiliser l’**état observable** (codes de réponse, états du protocole, phases du parseur, types d’objets renvoyés) comme feedback supplémentaire.<sup>[[4]](#references)</sup>

- Gardez les **messages de préfixe valides** stables et concentrez les mutations sur le message qui **déclenche la transition**.
- Mettez en cache les identifiants et les valeurs générées par le serveur dans les réponses précédentes lorsque l’étape suivante en dépend.
- Préférez la mutation et l’épissage message par message à la mutation de toute la transcription sérialisée comme un blob opaque.
- Si le protocole expose des codes de réponse pertinents, utilisez-les comme **oracle d’état peu coûteux** pour donner la priorité aux séquences qui progressent davantage.

C’est pour la même raison que les bugs authentifiés, les transitions cachées ou les bugs de parseur qui ne se manifestent « qu’après le handshake » échappent souvent au fuzzing classique de fichiers : le fuzzer doit préserver **l’ordre, l’état et les dépendances**, et pas seulement la structure.<sup>[[4]](#references)</sup>

### Android Binder : fuzzing du driver multi-client

Une couverture élevée des edges peut toujours passer à côté de bugs du driver IPC, car la couverture ne décrit pas **la propriété des objets, les comptes de références, les messages en attente, l’ordre de nettoyage ou les entrelacements de threads**. La page [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) décrit le modèle d’objets du driver ; cet exemple porte sur le harness du fuzzer. Android Binder est un modèle utile : atteindre les chemins d’allocation et de libération ne suffit pas si le fuzzer ne peut pas faire opérer plusieurs processus sur le même objet du noyau dans l’ordre requis.<sup>[[15]](#references)</sup>

#### Modéliser le protocole, pas des buffers `ioctl` isolés

Représentez un cas de test sous forme de grammaire ordonnée composée de **l’identité du client + l’opération + des arguments structurés**. Le fuzzer Binder LKL utilise protobuf et `libprotobuf-mutator`, avec un client gestionnaire de contexte persistant et deux clients ordinaires. Un harness sémantique préserve alors les relations que la mutation aveugle d’octets détruirait.<sup>[[15]](#references)</sup>

- Mettez en cache les valeurs renvoyées par les opérations précédentes. Par exemple, `BC_FREE_BUFFER` doit réutiliser un pointeur de buffer de transaction renvoyé par un précédent `ioctl`.
- Générez des réponses par défaut valides afin que les transactions synchrones puissent se terminer et que les opérations ultérieures restent accessibles.
- Rejetez les transitions impossibles, comme les transactions vers soi-même ou plusieurs transactions en attente vers la même cible.
- Gardez l’état singleton d’initialisation en dehors de la réinitialisation par entrée. Binder n’autorise qu’un seul enregistrement `BINDER_SET_CONTEXT_MGR` par démarrage ; détruire puis recréer ce client à répétition rendrait donc les entrées suivantes invalides.

Un modèle utile de course de durée de vie consiste à faire transférer un objet par un client, à lancer le nettoyage d’un thread ou d’un processus, puis à faire libérer simultanément le buffer de transaction par le client destinataire. Dans l’exemple CVE-2020-0423, le transfert d’un `BINDER_TYPE_WEAK_BINDER`, suivi d’un `BINDER_THREAD_EXIT` en course avec `BC_FREE_BUFFER`, pouvait libérer un `binder_work` intégré alors que le chemin de nettoyage du thread en cours de sortie l’utilisait encore.<sup>[[15]](#references)</sup>

#### Réintroduire des entrelacements contrôlés dans un noyau en espace utilisateur

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) lie le code réel du noyau à un harness en espace utilisateur et expose son interface syscall via `lkl_syscall`. Cela facilite la coordination, dans un même processus, de l’état protobuf, de la couverture et de KASAN. Cependant, LKL exécute normalement un syscall sans qu’un autre thread du noyau ne l’interrompe. Pour les campagnes de course, insérez des points `schedule()` autour de certaines limites de verrouillage/déverrouillage et de durée de vie, puis laissez le harness choisir aléatoirement le prochain client à chaque yield. Ciblez ces points avec soin, car chacun multiplie l’espace de recherche de l’ordonnancement. L’ordonnanceur aléatoire décrit par les chercheurs **ne fait pas** partie du fuzzer Binder upstream.<sup>[[15]](#references)</sup>

#### Compiler et rejouer les seeds de régression sérialisés

Le harness upstream fixe une version compatible de `libprotobuf-mutator`, active l’instrumentation de fuzzing LKL et KASAN avec `LKL_FUZZING=1`, et active `CONFIG_MMU` pour Binder avec `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Après avoir récupéré une révision délibérément vulnérable ou appliqué les correctifs de retour arrière documentés en amont, une graine sérialisée peut reproduire toute la transition d’état multi-client sans avoir à la reconstruire dans une preuve de concept C ad hoc :<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Considérez le use-after-free détecté par KASAN comme la confirmation que la graine a atteint le chemin de durée de vie vulnérable. Cela ne démontre **pas** la présence des primitives ultérieures nécessaires à l’exécution de code dans le noyau ou à l’élévation de privilèges.<sup>[[16]](#references)</sup>

## Astuce de diversité sur une seule machine (style Jackalope)

Une méthode pratique pour combiner la **nouveauté générative** et la **réutilisation de la couverture** consiste à **redémarrer des workers de courte durée** face à un serveur persistant. Chaque worker démarre avec un corpus vide, se synchronise après `T` secondes, fonctionne encore `T` secondes sur le corpus combiné, se synchronise à nouveau, puis s’arrête. Cela produit des **structures inédites à chaque génération** tout en tirant parti de la couverture accumulée.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `-server_update_interval T` simule une **synchronisation différée** (nouveauté d’abord, réutilisation ensuite).
- En mode grammar fuzzing, la **synchronisation initiale avec le serveur est ignorée par défaut** (pas besoin de `-skip_initial_server_sync`).
- La valeur optimale de `T` **dépend de la cible** ; il est généralement préférable de changer de valeur une fois que le worker a trouvé la majeure partie de la couverture « facile ».

## Snapshot Fuzzing Pour Les Cibles Difficiles À Instrumenter

Lorsque le code que vous voulez tester n’est accessible qu’**après une longue phase de configuration** (démarrage d’une VM, connexion, réception d’un paquet, analyse d’un conteneur, initialisation d’un service), une solution de remplacement utile est le **snapshot fuzzing** : capturer l’état prêt du processus ou de la VM, injecter chaque cas de test dans le chemin d’entrée de la cible, exécuter jusqu’au crash ou au timeout, puis restaurer le snapshot. Cette méthode évite de répéter l’initialisation ou les préfixes de protocole et est utile pour les **services réseau**, le **firmware**, les **surfaces d’attaque post-authentification** et les **cibles binaires uniquement**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Exécutez la cible jusqu’à ce que l’état intéressant soit prêt.
2. Créez un snapshot de la **mémoire + des registres** à ce moment-là.
3. Pour chaque cas de test, écrivez directement l’entrée mutée dans le tampon pertinent du processus ou de la machine invitée.
4. Exécutez jusqu’au crash, au timeout ou à la réinitialisation.
5. Restaurez le snapshot ; pour les cibles VM, ne restaurez que les **pages modifiées** lorsque cette option est prise en charge, puis recommencez.

Placez le snapshot aussi près que possible de la première étape coûteuse d’analyse ou de dispatch, par exemple après un `recv`/`read` ou à un point de désérialisation de paquet, et identifiez le tampon d’entrée utilisé par la cible. Cette méthode suit le principe de placement adaptatif : déplacer le snapshot plus profondément dans le traitement de l’entrée afin d’éviter de répéter le travail.<sup>[[11]](#references)</sup>

### Snapshots incrémentiels pour les états de protocole

Un snapshot fixe évite le coût de configuration, mais ne permet pas à lui seul d’explorer les transitions qui nécessitent plusieurs messages valides. Un harness LibAFL-Qemu peut surveiller les écritures dans un champ d’état de protocole et enregistrer un nouveau snapshot lorsque l’état change. Dans le [harness TCP de libslirp](https://github.com/quarkslab/slirp_snapshots_stateful), il surveille `tcpcb.t_state`, hache l’état et les indicateurs de réponse pour dédupliquer les snapshots, et stocke les pages modifiées par rapport à un parent. Avant de muter le prochain message structuré, il restaure le snapshot sélectionné en remontant sa chaîne de parents. Le testcase conserve un `SnapshotId` et les octets d’entrée générés (`gen_bytes`) ; le gestionnaire de snapshots suit la relation parentale nécessaire à la relecture.<sup>[[27]](#references)[[28]](#references)</sup>

Le `SnapshotModule` en mode utilisateur de LibAFL-Qemu enregistre les mappages et la mémoire de la cible, mais pas les registres du CPU ; conservez-les séparément si nécessaire. Le gestionnaire décrit prend en charge un seul arbre de snapshots racine et ne peut pas partager les ID de snapshot entre les workers. Son mode multi-snapshot ne peut pas non plus réutiliser directement l’état shadow de QASAN. Pour le triage hors ligne, reconstruisez la chaîne d’entrée dans un processus instrumenté distinct. Avec `AsanHostModule` et `DrCovModule`, `fuzzer.evaluate_input` exécute les callbacks `pre_exec`/`post_exec` requis ; `qemu.run` ne le fait pas à lui seul.<sup>[[27]](#references)[[28]](#references)</sup>

### Détecter les dépassements de lecture logiques dans les ring buffers

Une lecture au-delà du *nombre d’octets valides* d’un tampon peut rester dans son allocation hôte et échapper à ASAN ordinaire. L’[exemple des données urgentes de libslirp](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) provoque aussi un underflow du nombre d’octets non signé. Lorsque le code source est disponible, l’instrumentation des dépassements d’entiers signés/non signés peut détecter cet effet secondaire ; distinguez le wrap intentionnel des numéros de séquence TCP avant de supprimer les rapports. Un oracle proposé plus robuste consiste à empoisonner l’allocation du ring buffer personnalisé, à n’empoisonner que les plages valides à mesure que son allocateur interne avance, puis à réempoisonner les plages libérées. LibAFL-Qemu expose une API d’empoisonnement ASAN pour les cibles où l’instrumentation du code source est impraticable.<sup>[[27]](#references)</sup>

## Exploration Des Courses Dans Le Noyau Linux Avec MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) transforme les courses dans le noyau Linux sensibles au timing en séquences reproductibles d’accès mémoire. Il peut énumérer automatiquement les exécutions **A-B-A** à deux contextes ou permettre à un analyste d’imposer des contraintes d’ordre dans une interface terminal ou graphique. Il s’agit d’un outil de recherche expérimental, et non d’un fuzzer de concurrence complet : il nécessite actuellement LLVM 23+ et le noyau modifié du projet, les outils en ligne de commande prennent en charge deux threads de test, et la couche de fuzzing en espace utilisateur proposée n’est pas implémentée.<sup>[[17]](#references)[[18]](#references)</sup>

### Collecter les points de communication entre contextes

Compilez le noyau instrumenté avec les callbacks KASAN outline et la prise en charge des enregistrements mémoire KCOV modifiée. Le README du projet recommande également de désactiver l’optimisation des appels entre frères afin que les piles d’appels restent exploitables.<sup>[[17]](#references)[[18]](#references)</sup>

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

Le mode outline de KASAN (`asan-instrumentation-with-call-threshold=0`) convertit les accès instrumentés en appels à des fonctions auxiliaires. Les patches du noyau MAccConc désactivent `asan-opt-same-temp` afin que les accès consécutifs ne soient pas fusionnés ; désactivez également l’optimisation `asan-opt-globals` lorsque les courses sur les variables globales doivent être visibles. KCOV transmet les enregistrements ainsi obtenus à l’espace utilisateur. Comparez les accès provenant de différents contextes d’exécution et conservez les paires dont les plages d’octets se chevauchent et dont au moins un côté effectue une écriture ; traitez `kfree()` comme une écriture afin que les transitions de durée de vie deviennent elles aussi des candidates.<sup>[[17]](#references)</sup>

Pour les tâches qui s’exécutent en dehors de la tâche initiatrice, comme le traitement des paquets ou les callbacks RCU, le sous-système doit propager un handle de couverture distante KCOV. La couverture distante KCOV en amont est opt-in et n’est pas automatiquement disponible pour les tâches d’arrière-plan arbitraires ; l’absence de propagation peut donc rendre invisible une interaction réelle.<sup>[[17]](#references)[[19]](#references)</sup>

### Identifier le même accès dynamique à chaque exécution

Ne rejouez pas l’exécution à partir d’une adresse concrète du tas, qui peut changer après chaque allocation, ni uniquement à partir d’une adresse d’instruction, qui est ambiguë dans des fonctions auxiliaires telles que `memcpy()` et `spin_lock()`. MAccConc utilise une **trace de pile augmentée par des compteurs** : chaque frame identifie un callee ainsi que le nombre d’invocations dans son caller, et le dernier élément identifie l’instruction d’accès mémoire. Les enregistrements d’entrée et de sortie de fonction de SanitizerCoverage permettent à l’espace utilisateur de reconstruire cet identifiant dynamique, qui reste stable malgré les changements d’adresse et le bruit de contrôle de flux sans rapport.<sup>[[17]](#references)</sup>

### Convertir les paires candidates en ordonnancements forcés

L’ioctl patché `KCOV_SET_DI` associe un identifiant d’accès augmenté par des compteurs à une action sur un flag partagé.<sup>[[17]](#references)</sup>

| Action | Sémantique |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Définir le flag *N* juste avant l’accès sélectionné. |
| `DI_STACK_WAIT` | Avant l’accès sélectionné, attendre en boucle jusqu’à ce que le flag *N* soit défini ou que la limite configurée soit atteinte. |
| `DI_STACK_WAKE_POST` | Définir le flag *N* juste après l’accès sélectionné. |

Pour une contrainte partielle **A-happens-before-B**, associez `DI_STACK_WAKE_POST` à A et `DI_STACK_WAIT` à B en utilisant le même flag. Pour un ordonnancement entièrement spécifié entre deux contextes, bloquez d’abord B, puis faites en sorte que A réveille B et attende au premier point de transfert ; B effectue l’opération inverse au transfert suivant. Cette dernière méthode agit comme un changement de contexte déterministe et est utilisée par l’explorateur automatique A-B-A.<sup>[[17]](#references)</sup>

Une campagne minimale consiste à compiler le cas de test à quatre hooks (`test_setup`, deux fonctions de thread et `test_end`) sous forme de bibliothèque partagée, à collecter une trace sans contraintes, puis à énumérer les candidates A-B-A ou à ajouter des contraintes manuelles autour des accès suspects.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Interprétez les timeouts séparément des réordonnancements réussis : l’ordre demandé peut être impossible si un verrou ou une dépendance d’initialisation/publication empêche le second contexte d’atteindre son point d’injection. Tenez également compte des angles morts de KASAN : les accès directs à la pile ne sont généralement pas instrumentés, sauf s’ils risquent de dépasser les limites, les variables globales sont omises avec l’optimisation par défaut, et les compilateurs actuels ne peuvent pas émettre simultanément des hooks ASAN et TSAN. Enfin, le prototype perd son buffer KCOV lorsqu’un invité panique ; préservez donc une console/un oracle de crash indépendant.<sup>[[17]](#references)</sup>

Pour le fuzzing guidé par la concurrence à l’avenir, enregistrez des résumés des accès mémoire par entrée ou par syscall, associez les opérations qui formeraient des points de communication entre contextes, puis explorez uniquement ces combinaisons. Les snapshots de VM stabilisent l’état global et les adresses ; sans snapshots, les métadonnées des sites d’allocation peuvent permettre d’abstraire les objets d’une exécution à l’autre. Il s’agit d’une extension proposée, et non d’une fonctionnalité des outils userspace MAccConc actuels.<sup>[[17]](#references)</sup>

## Introspection du harness : repérer tôt les fuzzers superficiels

Lorsqu’une campagne stagne, le problème vient souvent non pas du mutator, mais du **harness**. Utilisez l’**introspection de l’accessibilité/de la couverture** pour repérer les fonctions statiquement accessibles depuis votre fuzz target, mais rarement ou jamais couvertes dynamiquement. Ces fonctions indiquent généralement l’un de ces trois problèmes.<sup>[[12]](#references)</sup>

- Le harness entre dans la cible trop tard ou trop tôt.
- Le seed corpus ne contient pas toute une famille de fonctionnalités.
- La cible a réellement besoin d’un **second harness**, plutôt que d’un harness « tout faire » surdimensionné.

Si vous utilisez des workflows de type OSS-Fuzz / ClusterFuzz, Fuzz Introspector peut comparer l’accessibilité statique à la couverture d’exécution et générer des rapports à partir d’une exécution chronométrée ou d’un corpus public.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Utilisez le rapport pour décider s’il faut ajouter un nouveau harness pour un chemin d’analyseur non testé, enrichir le corpus pour une fonctionnalité précise ou diviser un harness monolithique en points d’entrée plus petits.

## Sélection des cibles de fuzzing selon le graphe et triage des mutations

Si vous disposez déjà de **résultats d’analyse statique**, de **mutations survivantes aux tests** et de **rapports de couverture**, ne les triez pas comme des listes indépendantes. Commencez par construire un **graphe d’appels**, annotez les nœuds avec la **complexité cyclomatique**, leur **accessibilité depuis des points d’entrée ou des entrées non fiables** et tout résultat externe, puis posez des questions sur le graphe.<sup>[[5]](#references)[[6]](#references)</sup>

- Quelles fonctions à complexité élevée sont accessibles depuis des entrées non fiables ?
- Quelles mutations survivantes se trouvent sur des chemins reliant les analyseurs/gestionnaires au code critique pour la sécurité ?
- Quelles fonctions sont des points de passage architecturaux dont le **rayon d’impact** est particulièrement élevé ?

Cette approche révèle généralement de meilleures cibles de fuzzing que la seule « couverture la plus faible ». Un analyseur/décodeur à **complexité élevée** et dont l’**accessibilité externe** est confirmée constitue un meilleur candidat pour un harness qu’un utilitaire interne isolé, à faible couverture mais sans chemin contrôlé par un attaquant.

### Processus de triage pratique

1. Construisez un **graphe de code** à partir de la base de code et extrayez les métriques de complexité et de branchement de chaque fonction.
2. Recensez les **points d’entrée** qui acceptent des données contrôlées par un attaquant : gestionnaires de requêtes, décodeurs, outils d’importation, analyseurs de protocoles, lecteurs de CLI/fichiers.
3. Exécutez des **requêtes de chemin** depuis ces points d’entrée vers les fonctions candidates afin de distinguer la surface d’attaque accessible du code mort ou accessible uniquement en interne.
4. Donnez la priorité aux nœuds qui combinent :
   - une **complexité cyclomatique** élevée
   - une **accessibilité depuis des entrées non fiables** confirmée
   - un **rayon d’impact** élevé ou de nombreuses dépendances en aval
   - des éléments corroborants, comme des résultats **SARIF**, des notes d’audit ou des mutations survivantes
5. Écrivez d’abord des harnesses ciblés pour les nœuds les mieux notés, en particulier les **analyseurs/codecs** tels que les décodeurs hexadécimaux, Base64, IP et de messages.

### Mutations survivantes : équivalentes ou exploitables

Les tests de mutation produisent souvent une liste de mutations survivantes bruitée. Avant de considérer chaque mutation survivante comme une faille de sécurité, utilisez le graphe pour vérifier :

- La fonction modifiée est-elle accessible depuis un point d’entrée contrôlé par un attaquant ?
- Tous les chemins d’appel sont-ils soumis à des invariants plus stricts que la vérification modifiée ?
- Le nœud se trouve-t-il dans du code mort, une logique de formatage uniquement ou un chemin arithmétique/analyseur à fort impact ?

Les mutations survivantes qui restent inaccessibles ou sont contraintes par la structure du code sont souvent des **mutations équivalentes**. Celles qui restent **accessibles** et touchent des **cas limites**, des **chemins de débordement/de retenue** ou des **opérations arithmétiques/d’analyse critiques pour la sécurité** doivent être promues en :

- nouveaux harnesses de fuzzing
- tests directs de propriétés/invariants
- vecteurs ciblés pour les cas limites

### Reporter les résultats externes sur le graphe

Si votre pipeline SAST exporte du **SARIF**, projetez les résultats sur les nœuds du graphe à partir du **fichier et de l’intervalle de lignes**, puis utilisez le graphe pour étendre l’analyse de l’impact.<sup>[[6]](#references)</sup>

- calculez le **rayon d’impact** de la fonction signalée
- vérifiez si le résultat se trouve sur un chemin depuis un point d’entrée
- regroupez les résultats proches qui convergent vers le même point de passage

Cette approche est utile pour décider s’il faut consacrer du temps au fuzzing d’une fonction précise : un nœud **accessible**, **complexe** et qui présente déjà des **résultats SAST** est souvent une meilleure cible qu’un nœud simplement complexe, sans chemin contrôlé par un attaquant.

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

L’élément essentiel de la méthodologie est l’intersection : **complexité x exposition x impact**. Utilisez le graphique pour choisir les cibles de fuzzing offrant la plus grande valeur de sécurité attendue, puis utilisez les mutations qui survivent pour déterminer quelles frontières et quels invariants votre harness doit mettre à l’épreuve.<sup>[[5]](#references)</sup>

## Fuzzing différentiel des encodages de clés cryptographiques

Partez de clés sérialisées valides ou de vecteurs de test standard. Modifiez les champs encodés sans casser la longueur ni la structure nécessaires pour atteindre les chemins d’importation et d’opération, puis soumettez les mêmes octets à des implémentations indépendantes. Comparez leur acceptation et les erreurs renvoyées. Les signatures et textes chiffrés aléatoires nécessitent des oracles de correction, et non une comparaison octet par octet : vérifiez les signatures ou comparez les secrets partagés obtenus lors d’un aller-retour encapsulation/désencapsulation. Les vecteurs de test établissent la conformité pour des cas connus ; les mutations différentielles sondent les encodages mal formés qui ne sont pas couverts par ces vecteurs.<sup>[[23]](#references)[[26]](#references)</sup>

Pour ces formats de clés, utilisez des oracles spécifiques au format :<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Clés de signature étendues ML-DSA :** modifiez les coefficients `s1` ou `s2` compactés pour qu’ils sortent de l’intervalle `[-η, η]`, tout en gardant la clé analysable. Vérifiez si l’importation ou la signature les rejette, et si une éventuelle signature obtenue est vérifiée. Les différences d’acceptation ne constituent pas à elles seules des violations des normes, car FIPS 204 n’impose pas de vérifications supplémentaires des clés privées. Consultez le [mécanisme de fuite conditionnelle](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Paires de clés ML-KEM :** distinguez les vérifications requises de la clé d’encapsulation et de l’entrée de désencapsulation de la vérification facultative de cohérence de la paire (PCT) lors de l’importation. Effectuez une encapsulation avec la clé publique, puis une désencapsulation avec la clé privée, et comparez les secrets partagés ; une divergence peut interrompre les communications chiffrées même si chaque clé passe séparément les vérifications d’entrée. Vérifiez si l’API valide les entrées pendant l’opération ou via un appel distinct ; libcrux expose `validate_public_key(pk)` et `validate_private_key(sk, ct)`, qui ne remplacent pas une PCT.
- **Clés brutes XMSS/XMSSMT :** testez les allers-retours des clés de **signature et de vérification** sérialisées entre différents ensembles de paramètres, et pas seulement les opérations avec des clés en mémoire. XMSS et XMSSMT ont des espaces de noms OID distincts sur quatre octets ; ainsi, un analyseur qui se base uniquement sur l’OID et essaie d’abord XMSS peut mal identifier une clé XMSSMT ayant un OID identique et rejeter son importation. L’analyseur RustCrypto signalé illustre un échec d’interopérabilité/de disponibilité, et non une falsification de signature.

## Fuzzing Go avec gosentry : moteur plus puissant, entrées typées et vérifications différentielles

Si une cible Go dispose déjà d’un harness natif `testing.F`, une évolution pratique consiste à exécuter ce même harness avec [gosentry](https://github.com/trailofbits/gosentry), une toolchain Go dérivée qui conserve `go test -fuzz`, mais remplace le backend par **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Cela est utile lorsque le fuzzer Go natif cale sur des **comparaisons difficiles**, des **entrées typées** ou des **formats faisant largement appel à des parsers**. La méthodologie reste la même :

- Continuez à utiliser `f.Add(...)` pour les seeds et `f.Fuzz(...)` pour le callback.
- Réutilisez le même harness, mais exécutez-le avec le binaire `go` de gosentry plutôt qu’avec la toolchain standard.
- Traitez la campagne obtenue comme une exécution normale guidée par la couverture, mais avec le scheduling et la mutation de LibAFL, ainsi que de meilleurs détecteurs complémentaires.

### Transformer les échecs silencieux en findings de fuzzing

Un problème récurrent lors des assessments Go est que les comportements dangereux ne provoquent souvent **pas** de crash par défaut. Avec gosentry, vous pouvez transformer plusieurs types d’états « mauvais mais silencieux » en findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` pour faire en sorte que certains chemins de log/erreur se comportent comme des crashs (utile pour les chemins de code de type `log.Fatal` qui, autrement, se contentent de logger et de continuer).
- `--catch-races=true` pour rejouer les nouvelles entrées découvertes dans la queue avec le race detector Go.
- `--catch-leaks=true` pour rejouer les nouvelles entrées de la queue avec `goleak` et s’arrêter en cas de fuites de goroutines.
- La gestion des hangs de LibAFL permet de conserver les **boucles infinies / entrées très lentes** comme findings de fuzzing, au lieu de les laisser disparaître comme des timeouts.
- Vérifications intégrées des débordements arithmétiques par défaut, ainsi que vérifications facultatives de troncature via une instrumentation de type go-panikint.

Cela est particulièrement utile pour les cibles dont l’impact sur la sécurité se limite à un **échec de parser sans panic**, un **bug de concurrence** ou un **hang provoquant uniquement un DoS**, plutôt qu’à une corruption mémoire.

### Fuzzing tenant compte des structs pour les API Go typées

Le fuzzing Go natif attend principalement des scalaires comme `[]byte`, `string` et des nombres. Si le code testé consomme des objets typés, gosentry peut directement fuzzer des **valeurs composites** (structs, slices, arrays, pointeurs), tout en continuant à muter les octets sous-jacents.<sup>[[7]](#references)[[8]](#references)</sup>

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

Utilisez cette approche lorsqu'un faux format filaire créé uniquement pour le fuzzing masquerait des bugs logiques derrière du code de parsing propre au harness. Pour les campagnes différentielles ou basées sur une grammaire, gardez l'entrée du harness sous la forme d'un unique `[]byte` ou `string` et effectuez le parsing dans le callback.

### Fuzzing basé sur une grammaire pour les parseurs et les entrées de protocole

Pour les parseurs, les formats et les langages d'entrée, gosentry peut exécuter le **fuzzing grammatical Nautilus** avec LibAFL. La grammaire est un tableau JSON de règles de production, et le harness devrait généralement prendre un unique argument `[]byte` ou `string`.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Notes méthodologiques :

- Utilisez le mode grammaire lorsque les mutations au niveau des octets échouent généralement lors des premières vérifications syntaxiques.
- Limitez la grammaire au **sous-ensemble du langage/protocole pertinent pour la sécurité**, au lieu de modéliser toute la spécification.
- Utilisez de grandes valeurs limites dans les terminaux/non-terminaux pour mettre à l’épreuve les limites des entiers, des longueurs et des machines à états.
- Le mode grammaire produit des entrées valides du point de vue de la grammaire, mais la cible reçoit toujours des **octets/chaînes** : l’analyse syntaxique et les vérifications sémantiques restent donc dans le code instrumenté.

### Fuzzing différentiel : comparer les implémentations, pas seulement les plantages

Une approche efficace dans les écosystèmes Go consiste à effectuer du **fuzzing différentiel basé sur une grammaire** : générer des entrées structurées valides et les transmettre à deux analyseurs, clients ou moteurs de transition d’état.<sup>[[7]](#references)[[8]](#references)</sup>

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

Considérez les cas suivants comme des résultats :

- une implémentation panique tandis que l’autre rejette correctement l’entrée
- des divergences entre les entrées acceptées et rejetées
- des arbres d’analyse ou des objets décodés différents
- des transitions d’état, des nonces, des soldes ou des racines d’état divergents

C’est une méthode pratique pour détecter les **écarts de consensus**, les **ambiguïtés d’analyse** et les **divergences entre la spécification et l’implémentation**, souvent ignorés par le fuzzing qui ne recherche que les plantages.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Réutiliser le corpus de la campagne pour générer un rapport de couverture

Après une campagne, rejouez le corpus de la file d’attente enregistré pour générer un rapport de couverture Go sans exporter manuellement un corpus distinct.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Exécutez la commande depuis le **même package** et avec la **même cible `-fuzz`** afin que gosentry retrouve le bon état de campagne mis en cache.

## References

- [1] [Fuzzing par grammaire mutationnelle](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Le fuzzing avec AFL++ en détail](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinq ans plus tard : le fuzzing de protocoles guidé par la couverture](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark transforme le code en graphes](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Il manquait la moitié de la boîte à outils du fuzzing Go. Nous avons forké la toolchain pour y remédier.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer : un fuzzer greybox rapide pour les protocoles réseau à états utilisant des snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Pas de grammaire ? Pas de problème : vers le fuzzing du noyau Linux sans descriptions des appels système](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy : un fuzzing efficace grâce à des snapshots adaptatifs et modifiables](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentation LLVM d’AFL++ : couverture des chemins et des appelants](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing prédictif sensible au contexte](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Android Offensive Security - Fuzzing de Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer LKL pour Android Binder - documentation de compilation et des seeds de régression](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc : exploration des conditions de concurrence du noyau Linux avec des entrelacements contrôlés des accès mémoire](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV : couverture de code pour le fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Syntaxe des noms de fichiers étendus de CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Avis de sécurité Doyensec : CFITSIO, T4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing de la syntaxe des noms de fichiers étendus de CFITSIO : 16 vulnérabilités de sécurité mémoire et triage assisté par Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Fuzzing différentiel pour la cryptographie](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203 : norme relative au mécanisme d’encapsulation de clés fondé sur les réseaux euclidiens](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Bug d’analyse de l’OID XMSSMT - problème RustCrypto #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [État des implémentations de la cryptographie post-quantique](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Le snapshotting nous mène à CVE-2026-9539](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
- [29] [Project Zero - Fuzzers contre l’IA : comparaison de Fuzzilli et BigSleep sur des moteurs JavaScript](https://projectzero.google/2026/10/fuzzing-v-AI.html)
{{#include ../banners/hacktricks-training.md}}
