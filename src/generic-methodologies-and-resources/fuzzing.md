# Méthodologie du fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing par grammaire mutationnelle : couverture vs sémantique

Dans le **mutational grammar fuzzing**, les entrées sont mutées tout en restant **valides selon la grammaire**. En mode guidé par la couverture, seuls les échantillons qui déclenchent une **nouvelle couverture** sont sauvegardés comme seeds du corpus. Pour les **cibles liées aux langages** (parseurs, interpréteurs, moteurs), cela peut manquer des bugs qui nécessitent des **chaînes sémantiques/de flux de données**, dans lesquelles la sortie d'une construction devient l'entrée d'une autre.<sup>[[1]](#references)</sup>

**Mode d'échec :** le fuzzer trouve des seeds qui exercent individuellement `document()` et `generate-id()` (ou des primitives similaires), mais **ne préserve pas le flux de données chaîné** ; l'échantillon « plus proche du bug » est donc supprimé parce qu'il n'ajoute pas de couverture. Avec **3 étapes dépendantes ou plus**, la recombinaison aléatoire devient coûteuse et le feedback de couverture ne guide pas la recherche.<sup>[[1]](#references)</sup>

**Implication :** pour les grammaires riches en dépendances, envisagez de **combiner les phases mutationnelle et générative** ou d'orienter la génération vers des motifs de **chaînage de fonctions** (et pas uniquement vers la couverture).<sup>[[1]](#references)</sup>

## Pièges liés à la diversité du corpus

La mutation guidée par la couverture est **gloutonne** : un échantillon apportant une nouvelle couverture est immédiatement sauvegardé, en conservant souvent de grandes régions inchangées. Au fil du temps, les corpus deviennent des **quasi-doublons** présentant une faible diversité structurelle. Une minimisation agressive peut supprimer un contexte utile ; un compromis pratique consiste donc à effectuer une **minimisation tenant compte de la grammaire** qui **s'arrête après avoir atteint un seuil minimal de tokens** (réduire le bruit tout en conservant suffisamment de structure environnante pour rester facile à muter).<sup>[[1]](#references)</sup>

Une règle pratique pour le corpus en mutational fuzzing consiste à **privilégier un petit ensemble de seeds structurellement différents qui maximisent la couverture** plutôt qu'un grand amas de quasi-doublons. En pratique, cela implique généralement ce qui suit.<sup>[[1]](#references)[[3]](#references)</sup>

- Commencer par des **échantillons du monde réel** (corpus publics, crawling, trafic capturé, ensembles de fichiers provenant de l'écosystème de la cible).
- Les distiller avec une **minimisation du corpus basée sur la couverture**, plutôt que de conserver chaque échantillon valide.
- Conserver des seeds **suffisamment petits** pour que les mutations ciblent des champs pertinents au lieu de consacrer la plupart des cycles à des octets sans intérêt.
- Relancer la minimisation du corpus après des modifications importantes du harness ou de l'instrumentation, car le « meilleur » corpus change lorsque l'accessibilité change.

## Mutation tenant compte des comparaisons pour les valeurs magiques

Une raison courante pour laquelle les fuzzers plafonnent ne vient pas de la syntaxe, mais des **comparaisons strictes** : octets magiques, vérifications de longueur, chaînes d'enum, sommes de contrôle ou valeurs de dispatch du parseur protégées par `memcmp`, des tables `switch` ou des comparaisons en cascade. La mutation aléatoire pure gaspille des cycles à tenter de deviner ces valeurs octet par octet.

Pour ces cibles, utilisez le **tracing des comparaisons** (par exemple les workflows de type AFL++ `CMPLOG` / Redqueen), afin que le fuzzer puisse observer les opérandes des comparaisons échouées et orienter les mutations vers des valeurs susceptibles de les satisfaire.<sup>[[3]](#references)</sup>
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

- Cela est particulièrement utile lorsque la cible dissimule une logique complexe derrière des **file signatures**, des **protocol verbs**, des **type tags** ou des **version-dependent feature bits**.
- Associez cette technique à des **dictionaries** extraits d’échantillons réels, de spécifications de protocoles ou de journaux de débogage. Un petit dictionnaire contenant des tokens de grammaire, des noms de chunks, des verbes et des délimiteurs est souvent plus utile qu’une gigantesque wordlist générique.
- Si la cible effectue de nombreuses vérifications séquentielles, résolvez d’abord les premières comparaisons « magiques », puis réduisez à nouveau le corpus obtenu afin que les étapes suivantes commencent avec des préfixes déjà valides.

## Feedback plus riche lorsque l’edge coverage regroupe différents chemins

L’edge coverage normale ne peut pas distinguer deux exécutions qui traversent le même helper via des appelants différents ou qui empruntent différentes combinaisons de branches à l’intérieur d’une fonction. Cela est important dans les shared decoders, les protocol dispatchers et les interpreter helpers, où la **route** menant à une arête détermine l’état actif. Suivre naïvement chaque contexte d’appel est également dangereux : la coverage map et la queue peuvent exploser. Les recherches sur le fuzzing sensible au contexte recommandent donc de ne raffiner que les contextes prometteurs, plutôt que de traiter l’ensemble du graphe d’appels comme sensible au contexte.<sup>[[14]](#references)</sup>

Les versions récentes d’AFL++ fournissent une **Ball-Larus per-function path coverage** en plus de l’edge coverage normale. Elles attribuent une feature à chaque chemin acyclique traversant une fonction ; les loop back-edges sont supprimées, ce qui signifie que ce feedback distingue les combinaisons de branches, mais **pas le nombre d’itérations des boucles**. Commencez avec le niveau assoupli `1`, puis limitez les modes plus stricts au code suspect des parsers et des state machines, car le nombre de chemins peut croître de façon exponentielle.<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
Pour un helper appelé depuis de nombreux endroits pertinents pour la sécurité, le mode LTO peut combiner chaque chemin de fonction avec son site d’appel immédiat :<sup>[[13]](#references)</sup>
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
**Conseil de campagne :** appliquez les feedbacks plus riches avec prudence et surveillez leur coût en termes de coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Exécutez en parallèle une instance ordinaire basée sur l’edge-coverage ; les feedbacks plus riches ne sont utiles que si le coût supplémentaire en queue/map ne détruit pas le nombre d’exécutions par seconde.
- Utilisez `AFL_LLVM_ALLOWLIST` pour limiter l’instrumentation des chemins/appelants lorsque les bibliothèques contenant beaucoup de templates ou le code utilitaire générique dominent la map.
- Les fonctions comportant un nombre excessif de chemins acycliques peuvent être ignorées par AFL++ ; les avertissements lors de la compilation indiquent que la cible nécessite une allowlist ou un niveau moins strict.
- La couverture caller + path ne prend en charge qu’une seule profondeur d’appelant. Ne la combinez pas avec des context stacks plus profonds.
- Les Path IDs peuvent changer entre les versions majeures de LLVM. Conservez le toolchain fixe pour une campagne et ne synchronisez pas les corpus basés sur PATH comme si leurs feature IDs étaient stables entre les builds.
- Ce feedback complète `CMPLOG` : le comparison tracing détermine **quelle valeur passe une guard**, tandis que le feedback path/caller conserve **quelle route et quelle combinaison de branches l’ont atteinte**.

## Fuzzing stateful : les séquences sont des seeds

Pour les **protocoles**, les **workflows authentifiés** et les **parseurs multi-étapes**, l’unité intéressante n’est souvent pas un blob unique, mais une **séquence de messages**. Concaténer toute la transcription dans un seul fichier et la muter aveuglément est généralement inefficace, car le fuzzer mute chaque étape de manière égale, même lorsque seul le message ultérieur atteint l’état fragile.<sup>[[4]](#references)</sup>

Une approche plus efficace consiste à traiter la **séquence elle-même comme le seed** et à utiliser l’**état observable** (codes de réponse, états du protocole, phases du parseur, types des objets retournés) comme feedback supplémentaire.<sup>[[4]](#references)</sup>

- Gardez les **messages préfixes valides** stables et concentrez les mutations sur le message qui **déclenche la transition**.
- Mettez en cache les identifiants et les valeurs générées par le serveur à partir des réponses précédentes lorsque l’étape suivante en dépend.
- Préférez la mutation/splicing par message à la mutation de toute la transcription sérialisée comme un blob opaque.
- Si le protocole expose des codes de réponse pertinents, utilisez-les comme **oracle d’état peu coûteux** afin de donner la priorité aux séquences qui progressent plus profondément.

C’est pour la même raison que les bugs liés à l’authentification, les transitions masquées ou les bugs de parseur qui ne surviennent « qu’après le handshake » sont souvent manqués par le fuzzing vanilla de type fichier : le fuzzer doit préserver **l’ordre, l’état et les dépendances**, et pas seulement la structure.<sup>[[4]](#references)</sup>

## Astuce de diversité sur une seule machine (style Jackalope)

Une manière pratique d’hybrider la **nouveauté générative** avec la **réutilisation de la coverage** consiste à **redémarrer des workers à courte durée de vie** face à un serveur persistant. Chaque worker démarre avec un corpus vide, se synchronise après `T` secondes, exécute une nouvelle période de `T` secondes sur le corpus combiné, se synchronise à nouveau, puis se termine. Cela produit de **nouvelles structures à chaque génération** tout en exploitant la coverage accumulée.<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty` force un **nouveau corpus** à chaque génération.
- `-server_update_interval T` approxime une **synchronisation différée** (nouveauté d'abord, réutilisation ensuite).
- En mode grammar fuzzing, la **synchronisation initiale avec le serveur** est ignorée par défaut (inutile d'utiliser `-skip_initial_server_sync`).
- La valeur optimale de `T` dépend de la **cible** ; effectuer le changement une fois que le worker a trouvé la majeure partie de la couverture « facile » donne généralement les meilleurs résultats.

## Snapshot Fuzzing pour les cibles difficiles à harnesser

Lorsque le code que vous voulez tester n'est accessible qu'après un coût d'initialisation important (démarrage d'une VM, finalisation d'une connexion, réception d'un paquet, parsing d'un conteneur, initialisation d'un service), une alternative utile est le **snapshot fuzzing** : capturer l'état prêt du processus ou de la VM, injecter chaque cas de test dans le chemin d'entrée de la cible, exécuter jusqu'au crash ou au timeout, puis restaurer le snapshot. Cela évite de répéter l'initialisation ou les préfixes de protocole et s'avère utile pour les **services réseau**, les **firmwares**, les **surfaces d'attaque post-authentification** et les **cibles binaires uniquement**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Exécutez la cible jusqu'à ce que l'état intéressant soit prêt.
2. Effectuez un snapshot de la **mémoire + des registres** à ce moment-là.
3. Pour chaque cas de test, écrivez directement l'entrée modifiée dans le tampon guest/processus pertinent.
4. Exécutez jusqu'au crash, au timeout ou à la réinitialisation.
5. Restaurez le snapshot ; pour les cibles VM, ne restaurez que les **pages modifiées** lorsque cela est pris en charge, puis recommencez.

Placez le snapshot aussi près que possible de la première étape coûteuse de parsing/dispatch, par exemple après un `recv`/`read` ou un point de désérialisation de paquet, et notez le tampon d'entrée utilisé par la cible. Cela suit le principe de placement adaptatif, qui consiste à déplacer le snapshot plus profondément dans le traitement de l'entrée afin d'éviter de répéter le travail.<sup>[[11]](#references)</sup>

## Introspection du harness : détecter rapidement les fuzzers superficiels

Lorsqu'une campagne stagne, le problème ne vient souvent pas du **mutateur**, mais du **harness**. Utilisez l'**introspection de l'accessibilité/de la couverture** pour trouver les fonctions qui sont accessibles statiquement depuis votre fuzz target, mais qui sont rarement ou jamais couvertes dynamiquement. Ces fonctions indiquent généralement l'un des trois problèmes suivants.<sup>[[12]](#references)</sup>

- Le harness entre dans la cible trop tard ou trop tôt.
- Le seed corpus ne contient aucune famille complète de fonctionnalités.
- La cible a réellement besoin d'un **second harness**, plutôt que d'un harness surdimensionné qui « fait tout ».

Si vous utilisez des workflows de type OSS-Fuzz / ClusterFuzz, Fuzz Introspector peut comparer l'accessibilité statique à la couverture d'exécution et générer des rapports à partir d'une exécution chronométrée ou d'un corpus public.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Utilisez le rapport pour décider s'il faut ajouter un nouveau harness pour un chemin de parser non testé, étendre le corpus pour une fonctionnalité spécifique ou diviser un harness monolithique en plusieurs points d'entrée.

## Sélection des cibles de fuzzing basée d'abord sur le graphe et triage des mutations

Si vous disposez déjà de **résultats d'analyse statique**, de **survivants de mutation testing** et de **rapports de couverture**, ne les triez pas comme des listes indépendantes. Construisez d'abord un **graphe d'appels**, annotez les nœuds avec la **complexité cyclomatique**, l'**accessibilité depuis des points d'entrée/des entrées non fiables** et les résultats externes éventuels, puis posez des questions sur le graphe.<sup>[[5]](#references)[[6]](#references)</sup>

- Quelles fonctions à forte complexité sont accessibles depuis des entrées non fiables ?
- Quels survivants de mutation se trouvent sur les chemins allant des parsers/handlers vers du code critique pour la sécurité ?
- Quelles fonctions sont des points de concentration architecturaux avec un **rayon d'impact** exceptionnellement élevé ?

Cela fait généralement émerger de meilleures cibles de fuzzing que la seule « couverture la plus faible ». Un parser/décodeur présentant une **complexité élevée** et une **accessibilité externe confirmée** constitue un meilleur candidat pour un harness qu'un helper interne isolé ayant une faible couverture, mais aucun chemin contrôlé par un attaquant.

### Workflow pratique de triage

1. Construisez un **graphe du code** à partir de la codebase et extrayez les métriques de complexité/branches pour chaque fonction.
2. Énumérez les **points d'entrée** qui acceptent des entrées contrôlées par un attaquant : request handlers, décodeurs, importeurs, protocol parsers, lecteurs de CLI/fichiers.
3. Exécutez des **requêtes de chemin** depuis ces points d'entrée vers les fonctions candidates afin de séparer la surface d'attaque accessible du code mort/interne uniquement.
4. Donnez la priorité aux nœuds qui combinent :
- une **complexité cyclomatique** élevée
- une **accessibilité confirmée depuis des entrées non fiables**
- un **rayon d'impact** élevé ou de nombreux dépendants en aval
- des éléments corroborants tels que des résultats **SARIF**, des notes d'audit ou des survivants de mutation testing
5. Écrivez d'abord des harnesses ciblés pour les nœuds obtenant les meilleurs scores, en particulier les **parsers/codecs** tels que les décodeurs hex/Base64/IP/message.

### Survivants de mutation : équivalents ou exploitables

Le mutation testing produit souvent une liste de survivants très bruitée. Avant de considérer chaque survivant comme une faille de sécurité, utilisez le graphe pour poser les questions suivantes :

- La fonction mutée est-elle accessible depuis un point d'entrée contrôlé par un attaquant ?
- Tous les chemins d'appel sont-ils soumis à des invariants plus stricts que la vérification mutée ?
- Le nœud se trouve-t-il dans du code mort, une logique limitée au formatage ou un chemin arithmétique/parser à fort impact ?

Les survivants qui restent inaccessibles ou structurellement contraints sont souvent des **mutants équivalents**. Les survivants qui restent **accessibles** et touchent aux **conditions limites**, aux **chemins d'overflow/carry** ou à l'**arithmétique/analyse critique pour la sécurité** doivent être convertis en :

- nouveaux fuzz harnesses
- tests directs de propriétés/invariants
- vecteurs ciblés de cas limites

### Corréler les résultats externes sur le graphe

Si votre pipeline SAST exporte du **SARIF**, projetez les résultats sur les nœuds du graphe à partir du **fichier + intervalle de lignes**, puis utilisez le graphe pour étendre l'analyse de l'impact.<sup>[[6]](#references)</sup>

- calculez le **rayon d'impact** de la fonction signalée
- vérifiez si le résultat se trouve sur un chemin depuis un point d'entrée
- regroupez les résultats proches qui convergent vers le même point de concentration

Cela est utile pour décider s'il faut consacrer du temps de fuzzing à une fonction spécifique : un nœud **accessible**, **complexe** et comportant déjà des **résultats SAST** constitue souvent une meilleure cible qu'un nœud simplement complexe sans chemin contrôlé par un attaquant.

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
La méthodologie importante est l’intersection : **complexité x exposition x impact**. Utilisez le graphique pour sélectionner les cibles de fuzzing présentant la plus grande valeur attendue en matière de sécurité, puis utilisez les survivants des mutations pour déterminer quelles limites et quels invariants votre harness doit mettre à l’épreuve.<sup>[[5]](#references)</sup>

## Fuzzing Go avec gosentry : moteur plus puissant, entrées typées et vérifications différentielles

Si une cible Go dispose déjà d’un harness natif `testing.F`, une voie de mise à niveau pratique consiste à exécuter le même harness avec [gosentry](https://github.com/trailofbits/gosentry), une chaîne d’outils Go forkée qui conserve `go test -fuzz`, mais remplace le backend par **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Cela est utile lorsque le fuzzer Go natif bloque sur des **comparaisons difficiles**, des **entrées typées** ou des **formats fortement dépendants d’un parser**. La méthodologie reste la même :

- Continuez à utiliser `f.Add(...)` pour les seeds et `f.Fuzz(...)` pour le callback.
- Réutilisez le même harness, mais exécutez-le avec le binaire `go` de gosentry au lieu de la toolchain standard.
- Traitez la campagne obtenue comme une exécution normale guidée par la couverture, mais avec le scheduling/la mutation de LibAFL et de meilleurs détecteurs auxiliaires.

### Transformer les échecs silencieux en résultats de fuzzing

Un problème récurrent dans les évaluations Go est que les comportements dangereux ne provoquent souvent **aucun crash** par défaut. Avec gosentry, vous pouvez transformer plusieurs catégories d’états « mauvais mais silencieux » en résultats.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` pour faire se comporter certains chemins de logging/error comme des crashes (utile pour les chemins de code de type `log.Fatal` qui, autrement, se contentent de logger et de continuer).
- `--catch-races=true` pour rejouer les nouvelles entrées de la queue avec le race detector de Go.
- `--catch-leaks=true` pour rejouer les nouvelles entrées de la queue avec `goleak` et s’arrêter en cas de fuites de goroutines.
- La gestion des hangs de LibAFL pour conserver les **boucles infinies / entrées très lentes** comme résultats de fuzzing au lieu de les laisser disparaître comme timeouts.
- Des vérifications intégrées des dépassements arithmétiques par défaut, ainsi que des vérifications optionnelles de troncature via une instrumentation de type go-panikint.

Cela est particulièrement utile pour les targets où l’impact de sécurité est un **échec de parser sans panic**, un **bug de concurrence** ou un **hang provoquant uniquement un DoS**, plutôt qu’une corruption mémoire.

### Fuzzing prenant en compte les structs pour les APIs Go typées

Le fuzzing Go natif s’attend principalement à des scalaires tels que `[]byte`, `string` et les nombres. Si le code testé consomme des objets typés, gosentry peut directement fuzzer des **valeurs composites** (structs, slices, arrays, pointers) tout en mutant les bytes sous-jacents.<sup>[[7]](#references)[[8]](#references)</sup>
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
Utiliser cela lors de la création d’un faux wire format uniquement pour le fuzzing pourrait dissimuler des bugs de logique derrière du code d’analyse propre au harness. Pour les campagnes différentielles ou basées sur une grammaire, gardez l’entrée du harness sous la forme d’un unique `[]byte` ou `string` et effectuez plutôt l’analyse à l’intérieur du callback.

### Fuzzing basé sur une grammaire pour les parsers et les entrées de protocoles

Pour les parsers, les formats et les langages d’entrée, gosentry peut exécuter le **Nautilus grammar fuzzing** au-dessus de LibAFL. La grammaire est un tableau JSON de règles de production, et le harness devrait généralement accepter un unique argument `[]byte` ou `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Notes méthodologiques :

- Utilisez le grammar mode lorsque les mutations au niveau des octets échouent généralement lors des premières vérifications syntaxiques.
- Gardez la grammaire centrée sur le **sous-ensemble pertinent pour la sécurité** du langage/protocole au lieu de modéliser l’intégralité de la spécification.
- Utilisez de grandes valeurs limites dans les terminaux/non-terminaux afin de solliciter les limites des entiers, des longueurs et des machines à états.
- Le grammar mode garantit que les entrées respectent la grammaire, mais la cible reçoit toujours des **octets/chaînes**, de sorte que l’analyse syntaxique et les vérifications sémantiques restent à l’intérieur du code instrumenté.

### Differential fuzzing : comparer les implémentations, pas seulement les crashes

Dans les écosystèmes Go, un schéma efficace est le **grammar-based differential fuzzing** : générer des entrées structurées valides et les transmettre à deux parseurs, clients ou moteurs de transition d’état.<sup>[[7]](#references)[[8]](#references)</sup>
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
Considérez les éléments suivants comme des findings :

- une implémentation déclenche une panique tandis que l’autre rejette proprement
- des divergences entre les entrées acceptées et rejetées
- des arbres d’analyse ou des objets décodés différents
- des transitions d’état, des nonces, des soldes ou des state roots divergents

Il s’agit d’une méthode pratique pour détecter les **consensus mismatches**, l’**ambiguïté des parseurs** et la **dérive entre la spécification et l’implémentation**, que le fuzzing de crash pur ne permet souvent pas de détecter.

### Réutiliser le corpus de la campagne pour générer un rapport de couverture

Après une campagne, rejouez le corpus de la queue sauvegardée afin de générer un rapport de couverture Go sans exporter manuellement un corpus distinct.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Exécutez la commande depuis le **même package** et avec la **même cible `-fuzz`**, afin que gosentry résolve l’état de campagne mis en cache approprié.



## References

- [1] [Fuzzing par grammaire mutationnelle](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing en profondeur](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinq ans plus tard : le fuzzing de protocoles guidé par la couverture](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark transforme le code en graphes](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Le fuzzing Go ne disposait que de la moitié des outils. Nous avons forké la toolchain pour y remédier.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer : un fuzzer greybox rapide pour les protocoles réseau stateful utilisant des snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Pas de grammaire, pas de problème : vers le fuzzing du kernel Linux sans descriptions des appels système](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy : fuzzing efficace avec des snapshots adaptatifs et mutables](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentation LLVM d’AFL++ : couverture des chemins et des appelants](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing prédictif sensible au contexte](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
{{#include ../banners/hacktricks-training.md}}
