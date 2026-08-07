# Méthodologie du Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing : Coverage vs. Sémantique

Dans le **mutational grammar fuzzing**, les entrées sont mutées tout en restant **valides selon la grammaire**. En mode coverage-guided, seuls les échantillons qui déclenchent une **nouvelle coverage** sont sauvegardés comme corpus seeds. Pour les **cibles liées à des langages** (parsers, interpréteurs, moteurs), cela peut faire manquer des bugs nécessitant des **chaînes sémantiques/dataflow**, dans lesquelles la sortie d’une construction devient l’entrée d’une autre.

**Mode d’échec :** le fuzzer trouve des seeds qui exécutent individuellement `document()` et `generate-id()` (ou des primitives similaires), mais **ne préserve pas le dataflow chaîné**. L’échantillon « plus proche du bug » est donc supprimé parce qu’il n’ajoute pas de coverage. Avec **3 étapes dépendantes ou plus**, la recombinaison aléatoire devient coûteuse et les retours de coverage ne guident pas la recherche.

**Implication :** pour les grammaires comportant de nombreuses dépendances, envisagez de **combiner les phases mutational et generative** ou d’orienter la génération vers des patterns de **function chaining** (et pas uniquement vers la coverage).<sup>[[1]](#references)</sup>

## Pièges liés à la diversité du corpus

La mutation coverage-guided est **greedy** : un échantillon apportant une nouvelle coverage est immédiatement sauvegardé, en conservant souvent de grandes régions inchangées. Au fil du temps, les corpus deviennent des **quasi-doublons** présentant une faible diversité structurelle. Une minimisation agressive peut supprimer du contexte utile ; un compromis pratique consiste donc à utiliser une **minimisation tenant compte de la grammaire** qui **s’arrête après avoir atteint un seuil minimal de tokens** (pour réduire le bruit tout en conservant suffisamment de structure environnante afin de rester favorable aux mutations).<sup>[[1]](#references)</sup>

Une règle pratique pour un corpus de mutational fuzzing est la suivante : **préférer un petit ensemble de seeds structurellement différents qui maximisent la coverage** plutôt qu’un grand amas de quasi-doublons. En pratique, cela signifie généralement :<sup>[[1]](#references)</sup>

- Commencer avec des **échantillons réels** (corpus publics, crawling, trafic capturé, ensembles de fichiers provenant de l’écosystème de la cible).
- Les condenser avec une **minimisation du corpus basée sur la coverage** au lieu de conserver chaque échantillon valide.
- Garder des seeds **suffisamment petits** afin que les mutations touchent des champs pertinents plutôt que de consacrer la plupart des cycles à des octets sans intérêt.
- Relancer la minimisation du corpus après toute modification importante du harness ou de l’instrumentation, car le « meilleur » corpus change lorsque la reachability évolue.

## Mutation tenant compte des comparaisons pour les valeurs magiques

Une raison courante pour laquelle les fuzzers atteignent un plateau n’est pas la syntaxe, mais les **comparaisons strictes** : magic bytes, vérifications de longueur, chaînes d’enum, checksums ou valeurs de dispatch du parser protégées par `memcmp`, des tables switch ou des comparaisons en cascade. La mutation purement aléatoire gaspille des cycles à essayer de deviner ces valeurs octet par octet.

Pour ces cibles, utilisez le **comparison tracing** (par exemple les workflows de type AFL++ `CMPLOG` / Redqueen) afin que le fuzzer puisse observer les opérandes des comparaisons échouées et orienter les mutations vers des valeurs permettant de les satisfaire.<sup>[[3]](#references)</sup>
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

- Cela est particulièrement utile lorsque la cible fait dépendre sa logique avancée de **signatures de fichiers**, de **verbes de protocole**, de **balises de type** ou de **bits de fonctionnalité dépendant de la version**.
- Associez cette technique à des **dictionnaires** extraits d’échantillons réels, de spécifications de protocole ou de journaux de débogage. Un petit dictionnaire contenant des tokens de grammaire, des noms de chunks, des verbes et des délimiteurs est souvent plus utile qu’une immense wordlist générique.
- Si la cible effectue de nombreuses vérifications séquentielles, résolvez d’abord les premières comparaisons « magiques », puis minimisez à nouveau le corpus obtenu afin que les étapes suivantes commencent à partir de préfixes déjà valides.

## Stateful Fuzzing : les séquences sont des seeds

Pour les **protocoles**, les **workflows authentifiés** et les **parseurs en plusieurs étapes**, l’unité intéressante n’est souvent pas un blob unique, mais une **séquence de messages**. Concaténer toute la transcription dans un seul fichier et la muter aveuglément est généralement inefficace, car le fuzzer mute chaque étape de manière équivalente, même lorsque seul le message ultérieur atteint l’état fragile.

Une approche plus efficace consiste à traiter la **séquence elle-même comme la seed** et à utiliser l’**état observable** (codes de réponse, états du protocole, phases du parseur, types des objets retournés) comme feedback supplémentaire :<sup>[[4]](#references)</sup>

- Conservez les **messages de préfixe valides** stables et concentrez les mutations sur le message qui **déclenche la transition**.
- Mettez en cache les identifiants et les valeurs générées par le serveur dans les réponses précédentes lorsque l’étape suivante en dépend.
- Préférez la mutation et le splicing par message plutôt que la mutation de toute la transcription sérialisée comme un blob opaque.
- Si le protocole expose des codes de réponse pertinents, utilisez-les comme un **oracle d’état peu coûteux** afin de donner la priorité aux séquences qui progressent plus profondément.

C’est pour la même raison que les bugs authentifiés, les transitions cachées ou les bugs de parseur « uniquement après le handshake » sont souvent manqués par le fuzzing vanilla de type fichier : le fuzzer doit préserver **l’ordre, l’état et les dépendances**, et pas seulement la structure.

## Astuce de diversité sur une seule machine (style Jackalope)

Une manière pratique d’hybrider la **nouveauté générative** avec la **réutilisation de la couverture** consiste à **redémarrer des workers de courte durée** face à un serveur persistant. Chaque worker démarre avec un corpus vide, se synchronise après `T` secondes, s’exécute pendant encore `T` secondes sur le corpus combiné, se synchronise à nouveau, puis se termine. Cela produit de **nouvelles structures à chaque génération** tout en exploitant la couverture accumulée.<sup>[[2]](#references)</sup>

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
- `-server_update_interval T` approxime une **synchronisation différée** (nouveauté d'abord, réutilisation ensuite).
- En mode de grammar fuzzing, la **synchronisation initiale avec le serveur** est ignorée par défaut (inutile d'utiliser `-skip_initial_server_sync`).
- La valeur optimale de `T` dépend de la **cible** ; le changement après que le worker a trouvé la majeure partie de la couverture « facile » tend à donner les meilleurs résultats.

## Snapshot Fuzzing For Hard-To-Harness Targets

Lorsque le code que vous souhaitez tester ne devient accessible qu'après un **coût d'initialisation élevé** (démarrage d'une VM, fin d'une connexion, réception d'un paquet, parsing d'un conteneur, initialisation d'un service), une alternative utile est le **snapshot fuzzing** :

1. Exécutez la cible jusqu'à ce que l'état intéressant soit prêt.
2. Effectuez un snapshot de la **mémoire et des registres** à ce moment-là.
3. Pour chaque cas de test, écrivez directement l'input muté dans le buffer pertinent du guest/processus.
4. Exécutez jusqu'au crash, au timeout ou au reset.
5. Restaurez uniquement les **pages modifiées**, puis recommencez.

Cela évite de payer le coût complet de l'initialisation à chaque itération et est particulièrement utile pour les **services réseau**, les **firmwares**, les **surfaces d'attaque post-auth** et les **cibles binaires** difficiles à refactoriser en harness in-process classique.

Une astuce pratique consiste à interrompre immédiatement l'exécution après un point `recv`/`read`/de désérialisation de paquet, à noter l'adresse du buffer d'input, puis à effectuer le snapshot à cet endroit et à muter directement ce buffer à chaque itération. Cela permet de fuzz le deep parsing logic sans reconstruire toute la handshake à chaque fois.

## Harness Introspection: Find Shallow Fuzzers Early

Lorsqu'une campagne stagne, le problème ne vient souvent pas du mutator, mais du **harness**. Utilisez l'**introspection de la reachability/couverture** pour repérer les fonctions qui sont statiquement accessibles depuis votre fuzz target, mais qui sont rarement, voire jamais, couvertes dynamiquement. Ces fonctions indiquent généralement l'un des trois problèmes suivants :

- Le harness entre dans la cible trop tôt ou trop tard.
- Le seed corpus ne contient pas toute une famille de fonctionnalités.
- La cible nécessite réellement un **second harness**, plutôt qu'un harness surdimensionné de type « do everything ».

Si vous utilisez des workflows de type OSS-Fuzz / ClusterFuzz, Fuzz Introspector est utile pour ce triage :
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Utilisez le rapport pour décider s'il faut ajouter un nouveau harness pour un chemin de parser non testé, enrichir le corpus pour une fonctionnalité spécifique ou diviser un harness monolithique en points d'entrée plus petits.

## Sélection des cibles de fuzzing basée d'abord sur le graphe et triage des mutations

Si vous disposez déjà de **résultats d'analyse statique**, de **survivants de mutation testing** et de **rapports de couverture**, ne les triez pas comme des listes indépendantes. Construisez d'abord un **graphe d'appels**, annotez les nœuds avec la **complexité cyclomatique**, l'**atteignabilité depuis un entrypoint/une entrée non fiable** et les résultats externes, puis posez des questions sur le graphe :<sup>[[5]](#references)[[6]](#references)</sup>

- Quelles fonctions à forte complexité sont accessibles depuis une entrée non fiable ?
- Quels survivants de mutation se trouvent sur des chemins allant des parsers/handlers vers du code critique pour la sécurité ?
- Quelles fonctions sont des points de concentration architecturaux avec un **blast radius** inhabituellement élevé ?

Cela fait généralement émerger de meilleures cibles de fuzzing que la seule « couverture la plus faible ». Un parser/décodeur à **forte complexité** et dont l'**atteignabilité externe** est confirmée constitue un meilleur candidat pour un harness qu'un helper interne isolé avec une faible couverture, mais sans chemin contrôlé par un attaquant.

### Workflow pratique de triage

1. Construisez un **graphe du code** à partir de la codebase et extrayez les métriques de complexité/branches pour chaque fonction.
2. Énumérez les **entrypoints** qui acceptent des entrées contrôlées par un attaquant : request handlers, décodeurs, importateurs, protocol parsers, lecteurs CLI/de fichiers.
3. Exécutez des **requêtes de chemin** depuis ces entrypoints vers les fonctions candidates afin de séparer la surface d'attaque atteignable du code mort/interne uniquement.
4. Donnez la priorité aux nœuds qui combinent :
- une **complexité cyclomatique** élevée
- une **atteignabilité confirmée depuis une entrée non fiable**
- un **blast radius** élevé ou de nombreux dépendants en aval
- des éléments corroborants tels que des résultats **SARIF**, des notes d'audit ou des survivants de mutation
5. Écrivez d'abord des harnesses ciblés pour les nœuds obtenant les meilleurs scores, en particulier les **parsers/codecs** tels que les décodeurs hexadécimaux, Base64, IP et de messages.

### Survivants de mutation : équivalents ou exploitables

Le mutation testing produit souvent une liste de survivants très bruitée. Avant de considérer chaque survivant comme une faille de sécurité, utilisez le graphe pour poser les questions suivantes :

- La fonction mutée est-elle accessible depuis un entrypoint contrôlé par un attaquant ?
- Tous les chemins d'appel sont-ils contraints par des invariants plus forts que le contrôle muté ?
- Le nœud se trouve-t-il dans du code mort, une logique limitée au formatage ou un chemin arithmétique/parser à fort impact ?

Les survivants qui restent inatteignables ou structurellement contraints sont souvent des **mutants équivalents**. Les survivants qui restent **atteignables** et touchent aux **conditions limites**, aux **chemins d'overflow/carry** ou à l'**arithmétique/au parsing critique pour la sécurité** doivent être transformés en :

- nouveaux fuzz harnesses
- tests directs de propriétés/invariants
- vecteurs ciblés de cas limites

### Corréler les résultats externes sur le graphe

Si votre pipeline SAST exporte du **SARIF**, projetez les résultats sur les nœuds du graphe à partir du **fichier + intervalle de lignes**, puis utilisez le graphe pour étendre l'analyse de l'impact :

- calculez le **blast radius** de la fonction signalée
- vérifiez si le résultat se trouve sur un chemin depuis un entrypoint
- regroupez les résultats proches qui convergent vers le même point de concentration

Cela est utile pour décider s'il faut consacrer du temps de fuzzing à une fonction spécifique : un nœud **atteignable**, **complexe** et présentant déjà des **résultats SAST** constitue souvent une meilleure cible qu'un nœud simplement complexe sans chemin contrôlé par un attaquant.

Exemple de workflow avec Trailmark :<sup>[[6]](#references)</sup>
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
La méthodologie importante est l’intersection : **complexité x exposition x impact**. Utilisez le graphique pour sélectionner les fuzz targets présentant la plus grande valeur de sécurité attendue, puis utilisez les survivants des mutations pour déterminer quelles limites et invariants votre harness doit tester de manière intensive.

## Fuzzing Go avec gosentry : moteur plus puissant, entrées typées et vérifications différentielles

Si une cible Go dispose déjà d’un harness natif `testing.F`, une voie de mise à niveau pratique consiste à exécuter le même harness avec [gosentry](https://github.com/trailofbits/gosentry), une toolchain Go forkée qui conserve `go test -fuzz`, mais remplace le backend par **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
C'est utile lorsque le fuzzer Go natif bloque sur des **comparaisons difficiles**, des **entrées typées** ou des formats fortement dépendants d'un parser. La méthodologie reste la même :

- Continuez à utiliser `f.Add(...)` pour les seeds et `f.Fuzz(...)` pour le callback.
- Réutilisez le même harness, mais exécutez-le avec le binaire `go` de gosentry au lieu de la toolchain standard.
- Traitez la campagne obtenue comme un run normal guidé par la couverture, mais avec le scheduling et les mutations de LibAFL, ainsi que de meilleurs détecteurs périphériques.

### Transformer les échecs silencieux en fuzz findings

Un problème récurrent lors des assessments Go est que les comportements dangereux ne provoquent souvent **pas** de crash par défaut. Avec gosentry, vous pouvez transformer plusieurs catégories d'états « mauvais mais silencieux » en findings :

- `--panic-on=pkg.Func,...` pour faire en sorte que certains chemins de logging/error se comportent comme des crashes (utile pour les chemins de code de type `log.Fatal` qui, autrement, se contentent de logger et de continuer).
- `--catch-races=true` pour rejouer les nouvelles entrées de queue avec le Go race detector.
- `--catch-leaks=true` pour rejouer les nouvelles entrées de queue avec `goleak` et s'arrêter en cas de fuite de goroutines.
- La gestion des hangs de LibAFL pour conserver les **boucles infinies / entrées très lentes** comme fuzz findings au lieu de les laisser disparaître en tant que timeouts.
- Des vérifications intégrées des dépassements arithmétiques par défaut, ainsi que des vérifications optionnelles de troncature via une instrumentation de type go-panikint.

C'est particulièrement utile pour les targets dont l'impact de sécurité est un **échec de parser sans panic**, un **bug de concurrence** ou un **hang DoS-only**, plutôt qu'une corruption mémoire.

### Fuzzing tenant compte des structs pour les APIs Go typées

Le fuzzing Go natif attend principalement des scalaires tels que `[]byte`, `string` et les nombres. Si le code testé consomme des objets typés, gosentry peut directement fuzzer des **valeurs composites** (structs, slices, arrays, pointers) tout en continuant à muter les bytes sous-jacents.
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
Utilisez ceci lors de la création d’un faux wire format uniquement pour le fuzzing, car cela masquerait les bugs logiques derrière du code d’analyse propre au harness. Pour les campagnes différentielles ou basées sur une grammaire, gardez l’entrée du harness sous la forme d’un unique `[]byte` ou d’une `string` et effectuez l’analyse dans le callback.

### Fuzzing basé sur une grammaire pour les parsers et les entrées de protocoles

Pour les parsers, les formats et les langages d’entrée, gosentry peut exécuter du **Nautilus grammar fuzzing** avec LibAFL. La grammaire est un tableau JSON de règles de production, et le harness doit généralement accepter un unique argument `[]byte` ou `string`.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Notes de méthodologie :

- Utilisez le grammar mode lorsque les mutations au niveau des octets échouent principalement lors des premières vérifications syntaxiques.
- Gardez la grammaire ciblée sur le **sous-ensemble de la langue/du protocole pertinent pour la sécurité**, au lieu de modéliser l'ensemble de la spécification.
- Utilisez de grandes valeurs limites dans les terminaux/non-terminaux afin de mettre à l'épreuve les limites des entiers, des longueurs et des machines à états.
- Le grammar mode conserve des entrées valides selon la grammaire, mais la cible reçoit toujours des **octets/chaînes**, de sorte que le parsing et les vérifications sémantiques restent effectués dans le code instrumenté.

### Differential fuzzing : comparer les implémentations, pas seulement les crashes

Un pattern puissant pour les écosystèmes Go est le **grammar-based differential fuzzing** : générer des entrées structurées valides et les transmettre à deux parsers, clients ou moteurs de transitions d'état.
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
Considérez les éléments suivants comme des constatations :

- une implémentation déclenche une panique tandis que l’autre rejette proprement
- des divergences entre les entrées acceptées et rejetées
- des arbres d’analyse ou des objets décodés différents
- des divergences dans les transitions d’état, les nonces, les soldes ou les racines d’état

Il s’agit d’une méthode pratique pour trouver des **divergences de consensus**, des **ambiguïtés de parser** et une **dérive entre la spécification et l’implémentation**, que le fuzzing de crash pur ne permet souvent pas de détecter.

### Réutiliser le corpus de campagne pour les rapports de couverture

Après une campagne, rejouez le corpus de file d’attente enregistré afin de générer un rapport de couverture Go sans exporter manuellement un corpus distinct :
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Exécutez la commande depuis le **même package** et avec la **même cible `-fuzz`** afin que gosentry résolve l’état de campagne mis en cache approprié.

## Références

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
