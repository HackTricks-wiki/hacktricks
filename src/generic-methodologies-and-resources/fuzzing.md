# Méthodologie de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing par grammaire mutationnelle : Couverture vs. Sémantique

Dans le **fuzzing par grammaire mutationnelle**, les entrées sont mutées tout en restant **valides selon la grammaire**. En mode guidé par la couverture, seuls les échantillons qui déclenchent une **nouvelle couverture** sont conservés comme graines du corpus. Pour les **cibles de langage** (parseurs, interpréteurs, moteurs), cela peut manquer des bugs qui exigent des **chaînes sémantiques/de flux de données** où la sortie d’un construit devient l’entrée d’un autre.

**Mode d’échec :** le fuzzer trouve des graines qui exercent individuellement `document()` et `generate-id()` (ou des primitives similaires), mais **ne préserve pas le flux de données chaîné**, donc l’échantillon « plus proche du bug » est supprimé parce qu’il n’ajoute pas de couverture. Avec **3+ étapes dépendantes**, la recombinaison aléatoire devient coûteuse et le retour de couverture ne guide pas la recherche.

**Implication :** pour les grammaires fortement dépendantes, envisagez de **hybrider des phases mutationnelles et génératives** ou de biaiser la génération vers des motifs de **chaînage de fonctions** (pas seulement la couverture).

## Pièges de diversité du corpus

La mutation guidée par la couverture est **gloutonne** : un échantillon à nouvelle couverture est enregistré immédiatement, en conservant souvent de grandes régions inchangées. Avec le temps, les corpus deviennent des **quasi-doublons** avec une faible diversité structurelle. Une minimisation agressive peut supprimer un contexte utile, donc un compromis pratique est une **minimisation sensible à la grammaire** qui **s’arrête après un seuil minimal de tokens** (réduire le bruit tout en conservant assez de structure environnante pour rester favorable aux mutations).

Une règle pratique pour le corpus en fuzzing mutationnel est : **privilégier un petit ensemble de graines structurellement différentes qui maximisent la couverture** plutôt qu’une grande pile de quasi-doublons. En pratique, cela signifie généralement :

- Partir de **vrais échantillons du monde réel** (corpus publics, crawling, trafic capturé, ensembles de fichiers de l’écosystème cible).
- Les distiller avec une **minimisation de corpus basée sur la couverture** au lieu de conserver chaque échantillon valide.
- Garder des graines **assez petites** pour que les mutations tombent sur des champs significatifs plutôt que de passer la plupart des cycles sur des octets non pertinents.
- Relancer la minimisation du corpus après des changements majeurs du harness/de l’instrumentation, car le « meilleur » corpus change lorsque l’accessibilité change.

## Mutation consciente des comparaisons pour les valeurs magiques

Une raison fréquente pour laquelle les fuzzers plafonnent n’est pas la syntaxe mais les **comparaisons dures** : octets magiques, vérifications de longueur, chaînes d’énumération, sommes de contrôle, ou valeurs de dispatch du parseur protégées par `memcmp`, des tables `switch`, ou des comparaisons en cascade. La mutation purement aléatoire gaspille des cycles à essayer de deviner ces valeurs octet par octet.

Pour ces cibles, utilisez le **tracing des comparaisons** (par exemple les workflows AFL++ `CMPLOG` / Redqueen) afin que le fuzzer puisse observer les opérandes des comparaisons ratées et orienter les mutations vers des valeurs qui les satisfont.
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

- C’est particulièrement utile lorsque la cible verrouille la logique profonde derrière des **file signatures**, des **protocol verbs**, des **type tags**, ou des **version-dependent feature bits**.
- Combinez-le avec des **dictionaries** extraits d’échantillons réels, de spécifications de protocoles ou de logs de debug. Un petit dictionnaire avec des grammar tokens, des noms de chunks, des verbs et des délimiteurs est souvent plus précieux qu’une massive generic wordlist.
- Si la cible effectue de nombreux contrôles séquentiels, résolvez d’abord les comparaisons “magic” les plus tôt, puis minimisez à nouveau le corpus résultant afin que les étapes suivantes partent déjà de préfixes valides.

## Stateful Fuzzing: Les séquences sont des seeds

Pour les **protocols**, les **authenticated workflows** et les **multi-stage parsers**, l’unité intéressante n’est souvent pas un blob unique mais une **message sequence**. Concaténer tout le transcript dans un seul fichier et le muter aveuglément est généralement inefficace, car le fuzzer mute chaque étape de façon égale, même lorsque seul le message plus tardif atteint l’état fragile.

Un pattern plus efficace consiste à traiter la **sequence elle-même comme le seed** et à utiliser l’**observable state** (response codes, protocol states, parser phases, returned object types) comme feedback supplémentaire :

- Gardez les **valid prefix messages** stables et concentrez les mutations sur le message **transition-driving**.
- Mettez en cache les identifiants et les valeurs générées par le server à partir des réponses précédentes lorsque l’étape suivante en dépend.
- Préférez la mutation/splicing par message plutôt que de muter tout le transcript sérialisé comme un blob opaque.
- Si le protocol expose des response codes significatifs, utilisez-les comme un **cheap state oracle** pour prioriser les séquences qui progressent plus en profondeur.

C’est la même raison pour laquelle les bugs authentifiés, les transitions cachées ou les bugs de parser “only-after-handshake” sont souvent manqués par le fuzzing de style fichier classique : le fuzzer doit préserver **l’ordre, l’état et les dépendances**, pas seulement la structure.

## Single-Machine Diversity Trick (Jackalope-Style)

Une manière pratique d’hybrider la **generative novelty** avec la **coverage reuse** consiste à **redémarrer des workers de courte durée** contre un server persistant. Chaque worker démarre depuis un corpus vide, se synchronise après `T` secondes, exécute encore `T` secondes sur le corpus combiné, se resynchronise, puis se termine. Cela produit des **fresh structures each generation** tout en exploitant la couverture accumulée.

**Server:**
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

- `-in empty` force un **nouveau corpus** à chaque génération.
- `-server_update_interval T` approxime une **sync différée** (la nouveauté d’abord, la réutilisation ensuite).
- En mode grammar fuzzing, la **sync initiale du server est ignorée par défaut** (pas besoin de `-skip_initial_server_sync`).
- Le `T` optimal dépend de la **cible** ; changer après que le worker a trouvé la plupart des couvertures « faciles » tend à mieux fonctionner.

## Snapshot Fuzzing For Hard-To-Harness Targets

Quand le code que vous voulez tester ne devient accessible **qu’après un coût de setup important** (démarrer une VM, terminer un login, recevoir un packet, parser un container, initialiser un service), une alternative utile est le **snapshot fuzzing** :

1. Exécutez la cible jusqu’à ce que l’état intéressant soit prêt.
2. Faites un snapshot de **la mémoire + les registres** à ce moment-là.
3. Pour chaque test case, écrivez l’input muté directement dans le buffer guest/process pertinent.
4. Exécutez jusqu’au crash/timeout/reset.
5. Restaurez seulement les **dirty pages** et recommencez.

Cela évite de payer le coût de setup complet à chaque itération et est particulièrement utile pour les **network services**, le **firmware**, les **post-auth attack surfaces**, et les **binary-only targets** qu’il est pénible de refactoriser en un harness in-process classique.

Une astuce pratique consiste à s’arrêter immédiatement après un point `recv`/`read`/packet-deserialization, noter l’adresse du buffer d’input, faire un snapshot à cet endroit, puis muter directement ce buffer à chaque itération. Cela permet de fuzz la logique de parsing profonde sans reconstruire à chaque fois tout le handshake.

## Harness Introspection: Find Shallow Fuzzers Early

Quand une campagne bloque, le problème n’est souvent pas le mutator mais le **harness**. Utilisez l’**introspection de reachability/coverage** pour trouver des fonctions qui sont statiquement accessibles depuis votre fuzz target mais rarement ou jamais couvertes dynamiquement. Ces fonctions indiquent généralement un des trois problèmes suivants :

- Le harness entre dans la cible trop tard ou trop tôt.
- Le seed corpus manque toute une famille de fonctionnalités.
- La cible a vraiment besoin d’un **second harness** plutôt que d’un seul harness surdimensionné qui fait « tout ».

Si vous utilisez des workflows de type OSS-Fuzz / ClusterFuzz, Fuzz Introspector est utile pour ce triage :
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Utilisez le rapport pour décider s’il faut ajouter un nouveau harness pour un chemin de parser non testé, étendre le corpus pour une fonctionnalité spécifique, ou diviser un harness monolithique en points d’entrée plus petits.

## Sélection de cible de fuzzing et triage des mutations en priorité au graphe

Si vous avez déjà des **résultats de static-analysis**, des **survivants de mutation-testing** et des **rapports de couverture**, ne les triez pas comme des listes indépendantes. Construisez d’abord un **call graph**, annotez les nœuds avec la **complexité cyclomatique**, la **réalisabilité depuis un entrypoint/données non fiables**, et tout résultat externe, puis posez des questions sur le graphe :

- Quelles fonctions à forte complexité sont atteignables depuis des données non fiables ?
- Quels survivants de mutation se trouvent sur des chemins allant des parsers/handlers vers du code critique pour la sécurité ?
- Quelles fonctions sont des points de passage architecturaux avec un **blast radius** inhabituellement élevé ?

Cela fait généralement ressortir de meilleures cibles de fuzzing que la simple “couverture la plus basse”. Un parser/décodeur avec une **forte complexité** et une **atteignabilité externe** confirmée est un meilleur candidat pour un harness qu’un helper interne isolé avec une faible couverture mais sans chemin contrôlé par un attaquant.

### Workflow pratique de triage

1. Construisez un **code graph** à partir de la base de code et extrayez les métriques de complexité/branches par fonction.
2. Énumérez les **entrypoints** qui acceptent des entrées contrôlées par un attaquant : request handlers, décodeurs, importateurs, parsers de protocoles, lecteurs CLI/fichiers.
3. Exécutez des **path queries** depuis ces entrypoints vers les fonctions candidates pour séparer la surface d’attaque atteignable du code mort ou interne uniquement.
4. Priorisez les nœuds qui combinent :
- une forte **cyclomatic complexity**
- une **reachability depuis des données non fiables** confirmée
- un **blast radius** élevé ou beaucoup de dépendances en aval
- des éléments de preuve corroborants comme des résultats **SARIF**, des notes d’audit ou des survivants de mutation
5. Écrivez d’abord des harnesses ciblés pour les nœuds les mieux notés, en particulier les **parsers/codecs** tels que les décodeurs hex/Base64/IP/message.

### Survivants de mutation : équivalents vs exploitables

La mutation testing produit souvent une liste bruyante de survivants. Avant de traiter chaque survivant comme une faille de sécurité, utilisez le graphe pour poser les questions suivantes :

- La fonction mutée est-elle atteignable depuis un entrypoint contrôlé par un attaquant ?
- Tous les chemins d’appel sont-ils contraints par des invariants plus forts que le test muté ?
- Le nœud se trouve-t-il dans du code mort, de la logique de formatage uniquement, ou dans un chemin arithmétique/parser à fort impact ?

Les survivants qui restent inatteignables ou structurellement contraints sont souvent des **équivalent mutants**. Les survivants qui restent **atteignables** et touchent des **boundary conditions**, des chemins **overflow/carry**, ou une arithmétique/parsing **critique pour la sécurité** doivent être promus vers :

- de nouveaux fuzz harnesses
- des tests de propriété/invariant directs
- des vecteurs ciblés de cas limites

### Corréler les résultats externes sur le graphe

Si votre pipeline SAST exporte des **SARIF**, projetez les résultats sur les nœuds du graphe par **file + line range** et utilisez le graphe pour étendre l’impact :

- calculez le **blast radius** de la fonction signalée
- vérifiez si le résultat se trouve sur un chemin depuis un entrypoint
- regroupez les résultats proches qui se réduisent au même point de passage

C’est utile pour décider s’il faut consacrer du temps de fuzzing à une fonction spécifique : un nœud qui est **atteignable**, **complexe**, et qui a déjà des **SAST hits** est souvent une meilleure cible qu’un simple nœud complexe sans chemin attaquant.

Exemple de workflow avec Trailmark :
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
La méthodologie importante est l’intersection : **complexité x exposition x impact**. Utilise le graphe pour sélectionner les fuzz targets avec la plus grande valeur de sécurité attendue, puis utilise les survivants des mutations pour décider quelles limites et invariants ton harness doit mettre à l’épreuve.

## Go Fuzzing Avec gosentry : Moteur Plus Puissant, Entrées Typées, Et Vérifications Différentielles

Si une target Go a déjà un harness natif `testing.F`, une voie d’upgrade pratique consiste à exécuter le même harness avec [gosentry](https://github.com/trailofbits/gosentry), une toolchain Go forkée qui conserve `go test -fuzz` mais remplace le backend par **LibAFL**.
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
C’est utile lorsque le fuzzer Go natif se bloque sur des **comparaisons difficiles**, des **entrées typées** ou des **formats riches en parser**. La méthodologie reste la même :

- Continuez à utiliser `f.Add(...)` pour les seeds et `f.Fuzz(...)` pour le callback.
- Réutilisez le même harness, mais exécutez-le avec le binaire `go` de gosentry au lieu de la toolchain standard.
- Traitez la campagne obtenue comme une exécution normale guidée par la couverture, mais avec le scheduling/mutation de LibAFL et de meilleurs détecteurs autour.

### Transformer les échecs silencieux en findings de fuzzing

Un problème récurrent dans les assessments Go est que le comportement dangereux ne provoque souvent **pas** de crash par défaut. Avec gosentry, vous pouvez promouvoir plusieurs catégories d’états « mauvais mais silencieux » en findings :

- `--panic-on=pkg.Func,...` pour faire en sorte que certaines voies de logging/erreur sélectionnées se comportent comme des crashes (utile pour les chemins de code de type `log.Fatal` qui, sinon, se contentent de logger et de continuer).
- `--catch-races=true` pour rejouer les nouvelles entrées de la queue avec le détecteur de race Go.
- `--catch-leaks=true` pour rejouer les nouvelles entrées de la queue avec `goleak` et s’arrêter sur les fuites de goroutines.
- La gestion des hangs de LibAFL pour conserver les **boucles infinies / entrées très lentes** comme findings de fuzzing au lieu de les laisser disparaître en timeouts.
- Des vérifications d’overflow arithmétique intégrées par défaut, plus des checks de troncature optionnels via une instrumentation de type go-panikint.

C’est particulièrement utile pour les cibles où l’impact sécurité est un **échec de parser sans panic**, un **bug de concurrence**, ou un **hang de type DoS** plutôt qu’une corruption mémoire.

### Fuzzing conscient des structs pour les API Go typées

Le fuzzing Go natif attend principalement des scalaires comme `[]byte`, `string` et des nombres. Si le code testé consomme des objets typés, gosentry peut fuzz des **valeurs composites** directement (structs, slices, arrays, pointers) tout en continuant à muter des bytes en dessous.
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
Utiliser ceci lors de la construction d’un faux wire format uniquement pour le fuzzing masquerait des bugs logiques derrière du code de parsing propre au harness. Pour des campagnes différentielles ou basées sur des grammaires, gardez plutôt l’entrée du harness comme un seul `[]byte` ou `string` et parsez à l’intérieur du callback.

### Grammar-based fuzzing for parsers and protocol inputs

Pour les parsers, formats et langages d’entrée, gosentry peut exécuter le **Nautilus grammar fuzzing** au-dessus de LibAFL. La grammaire est un tableau JSON de règles de production, et le harness devrait généralement prendre un seul argument `[]byte` ou `string`.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Notes de méthodologie :

- Utilisez le mode grammar lorsque les mutations au niveau des octets meurent surtout lors des premières vérifications syntaxiques.
- Gardez la grammar centrée sur le **sous-ensemble pertinent pour la sécurité** du langage/protocole plutôt que de modéliser toute la spécification.
- Utilisez de grandes valeurs limites dans les terminaux/non-terminaux pour solliciter les bords des entiers, des longueurs et de la machine à états.
- Le mode grammar conserve des entrées valides selon la grammar, mais la cible reçoit toujours des **bytes/strings**, donc le parsing et les vérifications sémantiques restent dans le code instrumenté.

### Differential fuzzing : comparez les implémentations, pas seulement les crashes

Un schéma solide pour les écosystèmes Go est le **grammar-based differential fuzzing** : générez des entrées structurées valides et envoyez-les à deux parsers, clients, ou moteurs de transition d’état.
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
Considérez ce qui suit comme des findings :

- une implémentation panic tandis que l’autre rejette proprement
- des divergences d’input accepté/rejeté
- des arbres d’analyse ou des objets décodés différents
- des transitions d’état, des nonces, des balances ou des state roots divergents

C’est une méthode pratique pour trouver des **consensus mismatches**, de l’**ambiguity du parser**, et une **spec-vs-implementation drift** que le fuzzing de crash pur manque souvent.

### Réutiliser le corpus de campagne pour le coverage reporting

Après une campagne, rejouez le corpus de queue sauvegardé pour générer un rapport Go coverage sans exporter manuellement un corpus séparé :
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Exécutez la commande depuis le **même package** et avec le **même `-fuzz` target** afin que gosentry résolve le bon état de campagne mis en cache.

## Références

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
