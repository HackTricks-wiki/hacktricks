# Méthodologie du Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing de grammaire mutationnelle : couverture vs. sémantique

Dans le **mutational grammar fuzzing**, les entrées sont modifiées tout en restant **valides selon la grammaire**. En mode coverage-guided, seuls les échantillons qui déclenchent une **nouvelle couverture** sont sauvegardés comme seeds du corpus. Pour les **cibles de langage** (parsers, interpréteurs, moteurs), cela peut manquer des bugs qui nécessitent des **chaînes sémantiques/de dataflow**, où la sortie d'une construction devient l'entrée d'une autre.<sup>[[1]](#references)</sup>

**Mode d'échec :** le fuzzer trouve des seeds qui exercent individuellement `document()` et `generate-id()` (ou des primitives similaires), mais **ne préserve pas le dataflow chaîné** ; l'échantillon « plus proche du bug » est donc supprimé parce qu'il n'ajoute pas de couverture. Avec **3 étapes dépendantes ou plus**, la recombinaison aléatoire devient coûteuse et le feedback de couverture ne guide pas la recherche.<sup>[[1]](#references)</sup>

**Implication :** pour les grammaires fortement dépendantes, envisagez de **combiner les phases mutationnelle et générative** ou d'orienter la génération vers des patterns de **function chaining** (et pas uniquement vers la couverture).<sup>[[1]](#references)</sup>

## Pièges liés à la diversité du corpus

La mutation guidée par la couverture est **greedy** : un échantillon avec une nouvelle couverture est sauvegardé immédiatement, en conservant souvent de grandes régions inchangées. Au fil du temps, les corpus deviennent des **quasi-doublons** présentant une faible diversité structurelle. Une minimisation agressive peut supprimer du contexte utile ; un compromis pratique consiste donc à utiliser une **minimisation sensible à la grammaire** qui **s'arrête après un seuil minimal de tokens** (réduire le bruit tout en conservant suffisamment de structure environnante pour rester compatible avec les mutations).<sup>[[1]](#references)</sup>

Une règle pratique pour le corpus du mutational fuzzing est la suivante : **préférer un petit ensemble de seeds structurellement différents qui maximisent la couverture** à un grand amas de quasi-doublons. En pratique, cela signifie généralement ce qui suit.<sup>[[1]](#references)[[3]](#references)</sup>

- Commencer par des **échantillons du monde réel** (corpus publics, crawling, trafic capturé, ensembles de fichiers issus de l'écosystème de la cible).
- Les distiller avec une **minimisation du corpus basée sur la couverture**, plutôt que de conserver chaque échantillon valide.
- Garder des seeds **suffisamment petits** pour que les mutations ciblent des champs pertinents au lieu de consacrer la plupart des cycles à des octets sans intérêt.
- Relancer la minimisation du corpus après des changements importants du harness ou de l'instrumentation, car le « meilleur » corpus change lorsque la reachability évolue.

## Mutation sensible aux comparaisons pour les valeurs magiques

Une raison courante pour laquelle les fuzzers plafonnent ne tient pas à la syntaxe, mais aux **comparaisons strictes** : octets magiques, vérifications de longueur, chaînes d'enum, checksums ou valeurs de dispatch du parser protégées par `memcmp`, des switch tables ou des comparaisons en cascade. La mutation purement aléatoire gaspille des cycles à tenter de deviner ces valeurs octet par octet.

Pour ces cibles, utilisez le **comparison tracing** (par exemple les workflows de type AFL++ `CMPLOG` / Redqueen), afin que le fuzzer puisse observer les opérandes issus des comparaisons échouées et orienter les mutations vers des valeurs qui les satisfont.<sup>[[3]](#references)</sup>
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

- C'est particulièrement utile lorsque la cible masque une logique avancée derrière des **file signatures**, des **protocol verbs**, des **type tags** ou des **version-dependent feature bits**.
- Associez-le à des **dictionaries** extraits d'échantillons réels, de spécifications de protocoles ou de journaux de débogage. Un petit dictionnaire contenant des tokens de grammaire, des noms de chunks, des verbes et des délimiteurs est souvent plus utile qu'une énorme wordlist générique.
- Si la cible effectue de nombreuses vérifications séquentielles, résolvez d'abord les premières comparaisons « magic », puis minimisez à nouveau le corpus obtenu afin que les étapes suivantes commencent avec des préfixes déjà valides.

## Fuzzing stateful : les séquences sont des seeds

Pour les **protocols**, les **authenticated workflows** et les **multi-stage parsers**, l'unité intéressante n'est souvent pas un blob isolé, mais une **message sequence**. Concaténer toute la conversation dans un seul fichier et la muter aveuglément est généralement inefficace, car le fuzzer mute chaque étape de manière égale, même lorsque seul le message ultérieur atteint l'état fragile.<sup>[[4]](#references)</sup>

Une approche plus efficace consiste à traiter la **sequence elle-même comme le seed** et à utiliser l'**observable state** (codes de réponse, états du protocole, phases du parser, types d'objets renvoyés) comme feedback supplémentaire.<sup>[[4]](#references)</sup>

- Conservez les **valid prefix messages** stables et concentrez les mutations sur le message **transition-driving**.
- Mettez en cache les identifiants et les valeurs générées par le serveur dans les réponses précédentes lorsque l'étape suivante en dépend.
- Préférez la mutation et le splicing par message plutôt que la mutation de toute la conversation sérialisée comme un blob opaque.
- Si le protocole expose des codes de réponse pertinents, utilisez-les comme un **cheap state oracle** pour donner la priorité aux séquences qui progressent plus profondément.

C'est pour la même raison que les bugs authentifiés, les transitions cachées ou les bugs de parser « only-after-handshake » sont souvent manqués par le fuzzing vanilla de type fichier : le fuzzer doit préserver l'**order**, l'**état** et les **dependencies**, et pas seulement la structure.<sup>[[4]](#references)</sup>

## Astuce de diversité sur une seule machine (style Jackalope)

Une méthode pratique pour combiner la **generative novelty** et la **coverage reuse** consiste à **redémarrer de courte durée des workers** contre un serveur persistant. Chaque worker démarre avec un corpus vide, se synchronise après `T` secondes, s'exécute pendant `T` secondes supplémentaires sur le corpus combiné, se synchronise à nouveau, puis se termine. Cela produit des **fresh structures** à chaque génération tout en exploitant la couverture accumulée.<sup>[[1]](#references)[[2]](#references)</sup>

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

**Notes:**

- `-in empty` force un **fresh corpus** à chaque génération.
- `-server_update_interval T` approxime une **delayed sync** (nouveauté d'abord, réutilisation ensuite).
- En mode grammar fuzzing, la **initial server sync** est ignorée par défaut (inutile d'utiliser `-skip_initial_server_sync`).
- La valeur optimale de `T` dépend de la **target** ; le changement après que le worker a trouvé la majeure partie de la couverture « facile » tend à être le plus efficace.

## Snapshot Fuzzing Pour les Targets Difficiles à Harnesser

Lorsque le code que vous souhaitez tester ne devient accessible qu'après un coût d'initialisation important (démarrage d'une VM, finalisation d'une authentification, réception d'un paquet, parsing d'un container, initialisation d'un service), une alternative utile est le **snapshot fuzzing** : capturer l'état prêt du processus ou de la VM, injecter chaque test case dans le chemin d'entrée de la target, exécuter jusqu'au crash/timeout, puis restaurer le snapshot. Cela évite de répéter l'initialisation ou les préfixes de protocole et est utile pour les **network services**, le **firmware**, les **post-auth attack surfaces** et les **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Exécutez la target jusqu'à ce que l'état intéressant soit prêt.
2. Prenez un snapshot de la **memory + registers** à ce moment-là.
3. Pour chaque test case, écrivez directement l'input muté dans le buffer pertinent du guest/processus.
4. Exécutez jusqu'au crash/timeout/reset.
5. Restaurez le snapshot ; pour les targets VM, ne restaurez que les **dirty pages** lorsque cela est pris en charge, puis recommencez.

Placez le snapshot aussi près que possible de la première étape coûteuse de parsing/dispatch, par exemple après un point `recv`/`read` ou de désérialisation de paquet, et notez le buffer d'entrée utilisé par la target. Cela suit le principe de placement adaptatif consistant à déplacer le snapshot plus profondément dans le traitement de l'entrée afin d'éviter de répéter du travail.<sup>[[11]](#references)</sup>

## Introspection du Harness : Détecter Rapidement les Fuzzers Superficiels

Lorsqu'une campagne stagne, le problème ne vient souvent pas du mutator, mais du **harness**. Utilisez l'**introspection de reachability/coverage** pour trouver les fonctions qui sont statiquement atteignables depuis votre fuzz target, mais qui sont rarement, voire jamais, couvertes dynamiquement. Ces fonctions indiquent généralement l'un des trois problèmes suivants.<sup>[[12]](#references)</sup>

- Le harness entre dans la target trop tard ou trop tôt.
- Le seed corpus ne contient aucune famille complète de fonctionnalités.
- La target nécessite réellement un **second harness** plutôt qu'un harness unique et surdimensionné de type « do everything ».

Si vous utilisez des workflows de type OSS-Fuzz / ClusterFuzz, Fuzz Introspector peut comparer la reachability statique avec la couverture runtime et générer des rapports à partir d'un run minuté ou d'un corpus public.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Utilisez le rapport pour décider s’il faut ajouter un nouveau harness pour un chemin de parser non testé, étendre le corpus pour une fonctionnalité spécifique ou diviser un harness monolithique en plusieurs points d’entrée.

## Sélection des cibles de fuzzing et triage des mutations par le graphe

Si vous disposez déjà de **résultats d’analyse statique**, de **survivants de mutation testing** et de **rapports de couverture**, ne les triez pas comme des listes indépendantes. Construisez d’abord un **graphe d’appels**, annotez les nœuds avec la **complexité cyclomatique**, l’**atteignabilité depuis des points d’entrée/des entrées non fiables** et les résultats externes, puis posez des questions sur le graphe.<sup>[[5]](#references)[[6]](#references)</sup>

- Quelles fonctions à forte complexité sont atteignables depuis des entrées non fiables ?
- Quels survivants de mutation se trouvent sur les chemins reliant les parsers/handlers au code critique pour la sécurité ?
- Quelles fonctions sont des points de congestion architecturaux avec un **blast radius** exceptionnellement élevé ?

Cela fait généralement émerger de meilleures cibles de fuzzing que la seule « couverture la plus faible ». Un parser/décodeur avec une **complexité élevée** et une **atteignabilité externe** confirmée constitue un meilleur candidat pour un harness qu’un helper interne isolé, faiblement couvert mais dépourvu de chemin contrôlé par un attaquant.

### Workflow pratique de triage

1. Construisez un **graphe du code** à partir de la codebase et extrayez les métriques de complexité et de branches pour chaque fonction.
2. Énumérez les **points d’entrée** qui acceptent des entrées contrôlées par un attaquant : request handlers, décodeurs, importeurs, protocol parsers, lecteurs CLI/fichiers.
3. Exécutez des **requêtes de chemin** depuis ces points d’entrée vers les fonctions candidates afin de séparer la surface d’attaque atteignable du code mort/interne uniquement.
4. Donnez la priorité aux nœuds qui combinent :
- une **complexité cyclomatique** élevée
- une **atteignabilité confirmée depuis une entrée non fiable**
- un **blast radius** élevé ou de nombreux dépendants en aval
- des éléments corroborants tels que des résultats **SARIF**, des notes d’audit ou des survivants de mutation
5. Écrivez d’abord des harnesses ciblés pour les nœuds ayant les meilleurs scores, en particulier les **parsers/codecs** tels que les décodeurs hexadécimaux, Base64, IP et de messages.

### Survivants de mutation : équivalents ou exploitables

Le mutation testing produit souvent une liste de survivants bruitée. Avant de considérer chaque survivant comme une faille de sécurité, utilisez le graphe pour poser les questions suivantes :

- La fonction mutée est-elle atteignable depuis un point d’entrée contrôlé par un attaquant ?
- Tous les chemins d’appel sont-ils contraints par des invariants plus stricts que la vérification mutée ?
- Le nœud se trouve-t-il dans du code mort, une logique liée uniquement au formatage ou un chemin arithmétique/parser à fort impact ?

Les survivants qui restent inatteignables ou structurellement contraints sont souvent des **mutants équivalents**. Les survivants qui restent **atteignables** et touchent aux **conditions limites**, aux **chemins d’overflow/carry** ou à l’**arithmétique/analyse de données critique pour la sécurité** doivent être promus en :

- nouveaux fuzz harnesses
- tests directs de propriétés/invariants
- vecteurs ciblés de cas limites

### Corréler les résultats externes avec le graphe

Si votre pipeline SAST exporte du **SARIF**, projetez les résultats sur les nœuds du graphe à partir du **fichier + intervalle de lignes** et utilisez le graphe pour étendre l’analyse de l’impact.<sup>[[6]](#references)</sup>

- calculez le **blast radius** de la fonction signalée
- vérifiez si le résultat se trouve sur un chemin depuis un point d’entrée
- regroupez les résultats proches qui convergent vers le même point de congestion

C’est utile pour décider s’il faut consacrer du temps de fuzzing à une fonction spécifique : un nœud **atteignable**, **complexe** et présentant déjà des résultats **SAST** constitue souvent une meilleure cible qu’un nœud simplement complexe, sans chemin contrôlé par un attaquant.

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
La méthodologie importante réside dans l’intersection suivante : **complexité x exposition x impact**. Utilisez le graphique pour sélectionner les fuzz targets présentant la plus grande valeur de sécurité attendue, puis utilisez les survivants des mutations pour déterminer quelles frontières et quels invariants votre harness doit mettre à l’épreuve.<sup>[[5]](#references)</sup>

## Fuzzing Go avec gosentry : moteur plus puissant, entrées typées et vérifications différentielles

Si une cible Go dispose déjà d’un harness `testing.F` natif, une voie de mise à niveau pratique consiste à exécuter le même harness avec [gosentry](https://github.com/trailofbits/gosentry), une toolchain Go forkée qui conserve `go test -fuzz`, mais remplace le backend par **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
C'est utile lorsque le fuzzer Go natif bloque sur des **comparaisons difficiles**, des **entrées typées** ou des **formats lourds à parser**. La méthodologie reste la même :

- Continuez à utiliser `f.Add(...)` pour les seeds et `f.Fuzz(...)` pour le callback.
- Réutilisez le même harness, mais exécutez-le avec le binaire `go` de gosentry au lieu de la toolchain standard.
- Considérez la campagne obtenue comme une exécution normale guidée par la couverture, mais avec le scheduling/mutation de LibAFL et de meilleurs détecteurs complémentaires.

### Transformer les échecs silencieux en résultats de fuzzing

Un problème récurrent lors des évaluations Go est que les comportements dangereux ne provoquent souvent **pas** de crash par défaut. Avec gosentry, vous pouvez transformer plusieurs catégories d'états « mauvais mais silencieux » en résultats de fuzzing.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` pour faire en sorte que certains chemins de logging/erreur se comportent comme des crashes (utile pour les chemins de code de type `log.Fatal` qui, autrement, se contentent de journaliser et de continuer).
- `--catch-races=true` pour rejouer les nouvelles entrées de la queue avec le Go race detector.
- `--catch-leaks=true` pour rejouer les nouvelles entrées de la queue avec `goleak` et s'arrêter en cas de fuites de goroutines.
- La gestion des hangs de LibAFL pour conserver les **boucles infinies / entrées très lentes** comme résultats de fuzzing au lieu de les laisser disparaître en tant que timeouts.
- Des vérifications intégrées des dépassements arithmétiques par défaut, ainsi que des vérifications optionnelles de troncature via une instrumentation de type go-panikint.

Cela est particulièrement utile pour les cibles dont l'impact de sécurité est un **échec de parser sans panic**, un **bug de concurrence** ou un **hang provoquant uniquement un DoS**, plutôt qu'une corruption mémoire.

### Fuzzing prenant en compte les structs pour les APIs Go typées

Le fuzzing Go natif attend principalement des scalaires tels que `[]byte`, `string` et les nombres. Si le code testé consomme des objets typés, gosentry peut directement fuzzer des **valeurs composites** (structs, slices, arrays, pointers) tout en mutant les bytes sous-jacents.<sup>[[7]](#references)[[8]](#references)</sup>
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
Utiliser cela lors de la création d’un faux wire format uniquement pour le fuzzing pourrait dissimuler des erreurs de logique derrière du code d’analyse propre au harness. Pour les campagnes différentielles ou basées sur une grammaire, gardez l’entrée du harness sous la forme d’un unique `[]byte` ou `string`, puis effectuez l’analyse dans le callback.

### Fuzzing basé sur une grammaire pour les parsers et les entrées de protocoles

Pour les parsers, les formats et les langages d’entrée, gosentry peut exécuter du **Nautilus grammar fuzzing** au-dessus de LibAFL. La grammaire est un tableau JSON de règles de production, et le harness doit généralement accepter un unique argument `[]byte` ou `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Methodology notes :

- Utilisez le grammar mode lorsque les mutations au niveau des octets échouent majoritairement lors des premières vérifications syntaxiques.
- Gardez la grammaire ciblée sur le **sous-ensemble pertinent pour la sécurité** du langage/protocole au lieu de modéliser l’intégralité de la spécification.
- Utilisez de grandes valeurs limites dans les terminaux/non-terminaux afin de solliciter les limites des entiers, des longueurs et des machines à états.
- Le grammar mode conserve des entrées valides du point de vue de la grammaire, mais la cible reçoit toujours des **octets/chaînes**, de sorte que l’analyse et les vérifications sémantiques restent exécutées dans le code soumis au harness.

### Differential fuzzing : comparer les implémentations, pas seulement les crashes

Un pattern efficace pour les écosystèmes Go est le **grammar-based differential fuzzing** : générez des entrées structurées valides et transmettez-les à deux parsers, clients ou moteurs de transition d’état.<sup>[[7]](#references)[[8]](#references)</sup>
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

- une implémentation déclenche un panic tandis que l’autre rejette proprement
- des différences entre les entrées acceptées et rejetées
- des arbres syntaxiques ou des objets décodés différents
- des divergences au niveau des transitions d’état, des nonces, des soldes ou des racines d’état

Il s’agit d’une méthode pratique pour détecter les **consensus mismatches**, l’**ambiguïté des parseurs** et la **dérive entre la spécification et l’implémentation**, que le crash fuzzing pur ne détecte souvent pas.

### Réutiliser le corpus de la campagne pour générer le rapport de couverture

Après une campagne, rejouez le corpus de queue enregistré afin de générer un rapport de couverture Go sans exporter manuellement un corpus distinct.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Exécutez la commande depuis le **même package** et avec la même cible `-fuzz` afin que gosentry résolve l’état de campagne mis en cache approprié.

## References

- [1] [Fuzzing de grammaire mutationnelle](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing AFL++ en profondeur](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet cinq ans plus tard : le fuzzing de protocoles guidé par la couverture](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark transforme le code en graphes](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Le fuzzing Go n'avait pas la moitié de la boîte à outils. Nous avons forké la toolchain pour y remédier.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer : un fuzzer greybox rapide pour les protocoles réseau stateful utilisant des snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Pas de grammaire, pas de problème : vers le fuzzing du noyau Linux sans descriptions des appels système](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy : un fuzzing efficace avec des snapshots adaptatifs et mutables](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
