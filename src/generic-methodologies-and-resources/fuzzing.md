# Méthodologie du Fuzzing

## Mutational Grammar Fuzzing : Coverage vs. Sémantique

Dans le **mutational grammar fuzzing**, les entrées sont mutées tout en restant **valides selon la grammaire**. En mode coverage-guided, seuls les échantillons qui déclenchent une **nouvelle couverture** sont enregistrés comme seeds du corpus. Pour les **cibles de langage** (parseurs, interpréteurs, moteurs), cela peut manquer des bugs qui nécessitent des **chaînes sémantiques/de dataflow**, où la sortie d'une construction devient l'entrée d'une autre.<sup>[[1]](#references)</sup>

**Mode d'échec :** le fuzzer trouve des seeds qui exercent individuellement `document()` et `generate-id()` (ou des primitives similaires), mais **ne préserve pas le dataflow enchaîné** ; l'échantillon « plus proche du bug » est donc abandonné parce qu'il n'ajoute pas de couverture. Avec **3 étapes dépendantes ou plus**, la recombinaison aléatoire devient coûteuse et le feedback de couverture ne guide pas la recherche.<sup>[[1]](#references)</sup>

**Implication :** pour les grammaires fortement dépendantes, envisagez de **combiner les phases mutational et generative** ou d'orienter la génération vers des patterns d'**enchaînement de fonctions** (et pas uniquement vers la couverture).<sup>[[1]](#references)</sup>

## Pièges liés à la diversité du corpus

La mutation coverage-guided est **greedy** : un échantillon produisant une nouvelle couverture est immédiatement enregistré, en conservant souvent de grandes régions inchangées. Au fil du temps, les corpus deviennent des **quasi-doublons** présentant une faible diversité structurelle. Une minimisation agressive peut supprimer du contexte utile ; un compromis pratique consiste donc à appliquer une **minimisation tenant compte de la grammaire** qui **s'arrête après avoir atteint un seuil minimal de tokens** (réduire le bruit tout en conservant suffisamment de structure environnante pour rester favorable aux mutations).<sup>[[1]](#references)</sup>

Une règle pratique pour le corpus d'un mutational fuzzing est la suivante : **préférer un petit ensemble de seeds structurellement différents qui maximisent la couverture** plutôt qu'une grande collection de quasi-doublons. En pratique, cela signifie généralement ce qui suit.<sup>[[1]](#references)[[3]](#references)</sup>

- Commencer avec des **échantillons du monde réel** (corpus publics, crawling, trafic capturé, ensembles de fichiers provenant de l'écosystème de la cible).
- Les distiller avec une **minimisation du corpus basée sur la couverture** au lieu de conserver chaque échantillon valide.
- Conserver des seeds **suffisamment petits** pour que les mutations portent sur des champs pertinents plutôt que de consacrer la majorité des cycles à des octets sans intérêt.
- Relancer la minimisation du corpus après des changements majeurs du harness/de l'instrumentation, car le « meilleur » corpus change lorsque la reachability change.

## Mutation orientée par les comparaisons pour les valeurs magiques

Une raison courante pour laquelle les fuzzers plafonnent ne concerne pas la syntaxe, mais les **comparaisons strictes** : octets magiques, vérifications de longueur, chaînes d'enum, checksums ou valeurs de dispatch du parseur protégées par `memcmp`, des tables de switch ou des comparaisons en cascade. La mutation purement aléatoire gaspille des cycles à tenter de deviner ces valeurs octet par octet.

Pour ces cibles, utilisez le **tracing des comparaisons** (par exemple les workflows de type AFL++ `CMPLOG` / Redqueen), afin que le fuzzer puisse observer les opérandes issus des comparaisons échouées et orienter les mutations vers des valeurs qui les satisfont.<sup>[[3]](#references)</sup>
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

- Cela est particulièrement utile lorsque la cible dissimule une logique approfondie derrière des **file signatures**, des **protocol verbs**, des **type tags** ou des **version-dependent feature bits**.
- Associez cette approche à des **dictionaries** extraits d'échantillons réels, de spécifications de protocoles ou de journaux de débogage. Un petit dictionnaire contenant des tokens de grammaire, des noms de chunks, des verbes et des délimiteurs est souvent plus utile qu'une massive wordlist générique.
- Si la cible effectue de nombreuses vérifications séquentielles, résolvez d'abord les premières comparaisons « magic », puis minimisez à nouveau le corpus obtenu afin que les étapes suivantes commencent avec des préfixes déjà valides.

## Stateful Fuzzing: Sequences Are Seeds

Pour les **protocols**, les **authenticated workflows** et les **multi-stage parsers**, l'unité intéressante n'est souvent pas un blob isolé, mais une **message sequence**. Concaténer toute la transcription dans un seul fichier et la muter aveuglément est généralement inefficace, car le fuzzer mute chaque étape de manière égale, même lorsque seul le message ultérieur atteint l'état fragile.<sup>[[4]](#references)</sup>

Une approche plus efficace consiste à traiter la **sequence elle-même comme le seed** et à utiliser l'**observable state** (codes de réponse, états du protocole, phases du parser, types des objets renvoyés) comme feedback supplémentaire.<sup>[[4]](#references)</sup>

- Conservez les **valid prefix messages** stables et concentrez les mutations sur le message qui **pilote la transition**.
- Mettez en cache les identifiants et les valeurs générées par le serveur provenant des réponses précédentes lorsque l'étape suivante en dépend.
- Préférez la mutation et le splicing par message à la mutation de toute la transcription sérialisée en tant que blob opaque.
- Si le protocole expose des codes de réponse significatifs, utilisez-les comme **cheap state oracle** afin de donner la priorité aux séquences qui progressent plus profondément.

C'est la même raison pour laquelle les bugs authentifiés, les transitions cachées ou les bugs de parser « uniquement après le handshake » sont souvent manqués par le file-style fuzzing classique : le fuzzer doit préserver l'**ordre, l'état et les dépendances**, et pas seulement la structure.<sup>[[4]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Une manière pratique d'hybrider la **generative novelty** avec la **coverage reuse** consiste à **redémarrer de courtes instances worker** face à un serveur persistant. Chaque worker démarre avec un corpus vide, se synchronise après `T` secondes, s'exécute pendant `T` secondes supplémentaires sur le corpus combiné, se resynchronise, puis se termine. Cela produit de **nouvelles structures à chaque génération** tout en exploitant la couverture accumulée.<sup>[[1]](#references)[[2]](#references)</sup>

**Serveur :**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Workers séquentiels (boucle d’exemple) :**

<details>
<summary>Boucle de redémarrage d’un worker Jackalope</summary>
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

- `-in empty` force un **fresh corpus** à chaque génération.
- `-server_update_interval T` approxime une **delayed sync** (nouveauté d’abord, réutilisation ensuite).
- En mode grammar fuzzing, la **initial server sync** est ignorée par défaut (pas besoin de `-skip_initial_server_sync`).
- La valeur optimale de `T` dépend de la **target** ; le changement une fois que le worker a trouvé la majeure partie de la couverture « facile » tend à fonctionner au mieux.

## Snapshot Fuzzing For Hard-To-Harness Targets

Lorsque le code que vous voulez tester ne devient accessible qu’après un coût de configuration important (démarrage d’une VM, finalisation d’une connexion, réception d’un paquet, parsing d’un conteneur, initialisation d’un service), une alternative utile est le **Snapshot Fuzzing** : capturer l’état du processus ou de la VM prêt, injecter chaque cas de test dans le chemin d’entrée de la target, exécuter jusqu’au crash/timeout, puis restaurer le snapshot. Cela évite de répéter l’initialisation ou les préfixes de protocole et est utile pour les **network services**, le **firmware**, les **post-auth attack surfaces** et les **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Exécutez la target jusqu’à ce que l’état intéressant soit prêt.
2. Effectuez un snapshot de la **mémoire + registres** à ce moment-là.
3. Pour chaque cas de test, écrivez directement l’entrée mutée dans le buffer pertinent du guest/processus.
4. Exécutez jusqu’au crash/timeout/reset.
5. Restaurez le snapshot ; pour les targets VM, ne restaurez que les **dirty pages** lorsque cela est supporté, puis recommencez.

Placez le snapshot aussi près que possible de la première étape coûteuse de parsing/dispatch, par exemple après un `recv`/`read` ou un point de désérialisation de paquet, et notez le buffer d’entrée utilisé par la target. Cela suit le principe de placement adaptatif, qui consiste à déplacer le snapshot plus profondément dans le traitement de l’entrée afin d’éviter de répéter le travail.<sup>[[11]](#references)</sup>

## Harness Introspection: Find Shallow Fuzzers Early

Lorsqu’une campagne stagne, le problème ne vient souvent pas du mutator, mais du **harness**. Utilisez l’**introspection de reachability/coverage** pour trouver les fonctions qui sont statiquement accessibles depuis votre fuzz target, mais qui sont rarement, voire jamais, couvertes dynamiquement. Ces fonctions indiquent généralement l’un des trois problèmes suivants.<sup>[[12]](#references)</sup>

- Le harness entre dans la target trop tard ou trop tôt.
- Le seed corpus ne contient pas toute une famille de fonctionnalités.
- La target nécessite réellement un **second harness** plutôt qu’un harness « do everything » surdimensionné.

Si vous utilisez des workflows de type OSS-Fuzz / ClusterFuzz, Fuzz Introspector peut comparer la reachability statique à la couverture runtime et générer des rapports à partir d’une exécution chronométrée ou d’un corpus public.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Utilisez le rapport pour décider s'il faut ajouter un nouveau **harness** pour un chemin de parser non testé, étendre le corpus pour une fonctionnalité spécifique ou diviser un **harness** monolithique en points d'entrée plus petits.

## Sélection des cibles de fuzzing et triage des mutations, d'abord par le graphe

Si vous disposez déjà de **static-analysis findings**, de **mutation-testing survivors** et de **coverage reports**, ne les triez pas comme des listes indépendantes. Construisez d'abord un **call graph**, annotez les nœuds avec la **cyclomatic complexity**, la **entrypoint/untrusted-input reachability** et les résultats externes, puis posez des questions sur le graphe.<sup>[[5]](#references)[[6]](#references)</sup>

- Quelles fonctions à haute complexité sont accessibles depuis des entrées non fiables ?
- Quels survivants de mutation se trouvent sur les chemins allant des parsers/handlers vers du code critique pour la sécurité ?
- Quelles fonctions sont des points de concentration architecturaux avec un **blast radius** particulièrement élevé ?

Cela fait généralement émerger de meilleures cibles de fuzzing que la seule « couverture la plus faible ». Un parser/decoder avec une **high complexity** et une **external reachability** confirmée constitue un meilleur candidat pour un harness qu'un helper interne isolé avec une faible couverture, mais sans chemin contrôlé par l'attaquant.

### Workflow pratique de triage

1. Construisez un **code graph** à partir de la codebase et extrayez les métriques de complexité/branches pour chaque fonction.
2. Énumérez les **entrypoints** qui acceptent des entrées contrôlées par l'attaquant : request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Exécutez des **path queries** depuis ces entrypoints vers les fonctions candidates afin de séparer la surface d'attaque accessible du code mort/interne uniquement.
4. Donnez la priorité aux nœuds qui combinent :
- une **cyclomatic complexity** élevée
- une **reachability from untrusted input** confirmée
- un **blast radius** élevé ou de nombreux dépendants en aval
- des éléments corroborants tels que des résultats **SARIF**, des notes d'audit ou des survivants de mutation
5. Écrivez d'abord des harnesses ciblés pour les nœuds obtenant les meilleurs scores, en particulier les **parsers/codecs** tels que les hex/Base64/IP/message decoders.

### Survivants de mutation : équivalents ou exploitables

Le mutation testing produit souvent une liste de survivants bruitée. Avant de considérer chaque survivant comme une faille de sécurité, utilisez le graphe pour poser les questions suivantes :

- La fonction mutée est-elle accessible depuis un entrypoint contrôlé par l'attaquant ?
- Tous les chemins d'appel sont-ils limités par des invariants plus stricts que le check muté ?
- Le nœud se trouve-t-il dans du code mort, une logique uniquement liée au formatage ou un chemin arithmétique/parser à fort impact ?

Les survivants qui restent inaccessibles ou structurellement contraints sont souvent des **equivalent mutants**. Les survivants qui restent **reachable** et touchent aux **boundary conditions**, aux **overflow/carry paths** ou à l'**arithmetic/parsing** critique pour la sécurité doivent être transformés en :

- nouveaux fuzz harnesses
- tests directs de propriétés/invariants
- vecteurs ciblés de cas limites

### Corréler les résultats externes avec le graphe

Si votre pipeline SAST exporte du **SARIF**, projetez les résultats sur les nœuds du graphe à partir du **file + line range**, puis utilisez le graphe pour étendre l'analyse de l'impact.<sup>[[6]](#references)</sup>

- calculez le **blast radius** de la fonction signalée
- vérifiez si le résultat se trouve sur un chemin depuis un entrypoint
- regroupez les résultats proches qui convergent vers le même point de concentration

C'est utile pour décider s'il faut consacrer du temps de fuzzing à une fonction spécifique : un nœud qui est **reachable**, complexe et qui possède déjà des **SAST hits** constitue souvent une meilleure cible qu'un nœud simplement complexe sans chemin contrôlé par l'attaquant.

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
La méthodologie importante est l’intersection : **complexité x exposition x impact**. Utilisez le graphique pour sélectionner les fuzz targets présentant la plus grande valeur de sécurité attendue, puis utilisez les survivants des mutations pour déterminer quelles limites et invariants votre harness doit tester de manière intensive.<sup>[[5]](#references)</sup>

## Fuzzing Go avec gosentry : moteur plus puissant, entrées typées et vérifications différentielles

Si une cible Go possède déjà un harness natif `testing.F`, une voie de mise à niveau pratique consiste à exécuter le même harness avec [gosentry](https://github.com/trailofbits/gosentry), une toolchain Go forkée qui conserve `go test -fuzz`, mais remplace le backend par **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Cela est utile lorsque le fuzzer Go natif bloque sur des **comparaisons difficiles**, des **entrées typées** ou des **formats fortement dépendants d'un parser**. La méthodologie reste la même :

- Continuez à utiliser `f.Add(...)` pour les seeds et `f.Fuzz(...)` pour le callback.
- Réutilisez le même harness, mais exécutez-le avec le binaire `go` de gosentry au lieu de la toolchain standard.
- Traitez la campagne obtenue comme une exécution normale guidée par la couverture, mais avec le scheduling/la mutation de LibAFL et de meilleurs détecteurs auxiliaires.

### Transformer les échecs silencieux en résultats de fuzzing

Un problème récurrent dans les évaluations Go est que les comportements dangereux ne provoquent souvent **pas** de crash par défaut. Avec gosentry, vous pouvez transformer plusieurs catégories d'états « mauvais mais silencieux » en résultats.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` pour faire se comporter certains chemins de logging/erreur comme des crashes (utile pour les chemins de code de type `log.Fatal` qui, autrement, se contentent de logger et continuent).
- `--catch-races=true` pour rejouer les nouvelles entrées de la queue avec le race detector Go.
- `--catch-leaks=true` pour rejouer les nouvelles entrées de la queue avec `goleak` et s'arrêter en cas de fuites de goroutines.
- La gestion des hangs de LibAFL pour conserver les **boucles infinies / entrées très lentes** comme résultats de fuzzing au lieu de les laisser disparaître en tant que timeouts.
- Des vérifications intégrées des débordements arithmétiques par défaut, ainsi que des vérifications optionnelles de troncature via une instrumentation de type go-panikint.

Cela est particulièrement utile pour les cibles dont l'impact de sécurité est un **échec de parser sans panic**, un **bug de concurrence** ou un **hang limité à un DoS**, plutôt qu'une corruption mémoire.

### Fuzzing conscient des structs pour les APIs Go typées

Le fuzzing Go natif attend principalement des scalaires tels que `[]byte`, `string` et les nombres. Si le code testé consomme des objets typés, gosentry peut effectuer le fuzzing directement sur des **valeurs composites** (structs, slices, arrays, pointers), tout en mutant les bytes sous-jacents.<sup>[[7]](#references)[[8]](#references)</sup>
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
Utilisez cela lors de la création d’un faux format wire destiné uniquement au fuzzing, car cela masquerait les bugs de logique derrière du code d’analyse propre au harness. Pour les campagnes différentielles ou basées sur une grammaire, gardez l’entrée du harness sous la forme d’un unique `[]byte` ou `string` et effectuez l’analyse dans le callback à la place.

### Fuzzing basé sur une grammaire pour les parsers et les entrées de protocoles

Pour les parsers, les formats et les langages d’entrée, gosentry peut exécuter du **Nautilus grammar fuzzing** au-dessus de LibAFL. La grammaire est un tableau JSON de règles de production, et le harness doit généralement accepter un unique argument `[]byte` ou `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Notes de méthodologie :

- Utilisez le mode grammar lorsque les mutations au niveau des octets échouent principalement lors des premières vérifications syntaxiques.
- Gardez la grammar centrée sur le **sous-ensemble pertinent pour la sécurité** du langage/protocole au lieu de modéliser la spécification complète.
- Utilisez de grandes valeurs limites dans les terminaux/non-terminaux afin de solliciter les limites des entiers, des longueurs et des machines à états.
- Le mode grammar conserve des entrées valides selon la grammaire, mais la cible reçoit toujours des **bytes/strings** ; l'analyse syntaxique et les vérifications sémantiques restent donc dans le code instrumenté.

### Differential fuzzing : comparer les implémentations, pas seulement les crashes

Un modèle efficace pour les écosystèmes Go est le **grammar-based differential fuzzing** : générer des entrées structurées valides et les fournir à deux parseurs, clients ou moteurs de transition d'état.<sup>[[7]](#references)[[8]](#references)</sup>
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
Traitez les éléments suivants comme des résultats :

- une implémentation déclenche un panic tandis que l’autre rejette proprement
- des différences entre les entrées acceptées et rejetées
- des arbres d’analyse ou des objets décodés différents
- des transitions d’état, des nonces, des soldes ou des racines d’état divergents

Il s’agit d’une méthode pratique pour détecter les **divergences de consensus**, l’**ambiguïté des parsers** et la **dérive entre la spécification et l’implémentation**, que le crash fuzzing pur ne permet souvent pas de détecter.

### Réutiliser le corpus de la campagne pour établir la couverture

Après une campagne, rejouez le corpus de queue enregistré afin de générer un rapport de couverture Go sans exporter manuellement un corpus distinct.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Exécutez la commande depuis le **même package** et avec la **même cible `-fuzz`** afin que gosentry résolve l’état mis en cache de la bonne campagne.

## References

- [1] [Fuzzing par grammaire mutationnelle](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing en profondeur](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinq ans plus tard : le fuzzing de protocoles guidé par la couverture](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark transforme le code en graphes](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Il manquait la moitié de la boîte à outils au fuzzing Go. Nous avons forké la toolchain pour y remédier.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer : un fuzzer greybox rapide pour les protocoles réseau stateful utilisant des snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Pas de grammaire, pas de problème : vers le fuzzing du kernel Linux sans descriptions des appels système](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy : un fuzzing efficace avec des snapshots adaptatifs et mutables](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
