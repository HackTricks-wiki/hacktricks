# Méthodologie de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing de grammaire mutative : couverture vs. sémantique

Dans le **fuzzing de grammaire mutative**, les inputs sont mutés tout en restant **valides selon la grammaire**. En mode guidé par la couverture, seuls les échantillons qui déclenchent une **nouvelle couverture** sont conservés comme graines du corpus. Pour les **cibles de langage** (parsers, interpreters, engines), cela peut manquer des bugs qui nécessitent des **chaînes sémantiques/de dataflow** où la sortie d’un construct devient l’input d’un autre.

**Mode d’échec :** le fuzzer trouve des seeds qui exercent individuellement `document()` et `generate-id()` (ou des primitives similaires), mais **ne préserve pas le dataflow chaîné**, donc l’échantillon “plus proche du bug” est écarté parce qu’il n’ajoute pas de couverture. Avec **3+ étapes dépendantes**, la recombinaison aléatoire devient coûteuse et le feedback de couverture ne guide pas la recherche.

**Conséquence :** pour les grammaires fortement dépendantes, envisagez de **combiner des phases mutatives et génératives** ou de biaiser la génération vers des motifs de **function chaining** (pas seulement la couverture).

## Pièges de diversité du corpus

La mutation guidée par la couverture est **gloutonne** : un échantillon à nouvelle couverture est immédiatement conservé, en gardant souvent de grandes régions inchangées. Avec le temps, les corpus deviennent des **quasi-doublons** avec une faible diversité structurelle. Une minimisation agressive peut supprimer un contexte utile, donc un compromis pratique est une **minimisation consciente de la grammaire** qui **s’arrête après un seuil minimal de tokens** (réduire le bruit tout en gardant assez de structure environnante pour rester favorable aux mutations).

Une règle pratique pour le corpus en fuzzing mutatif est : **préférer un petit ensemble de seeds structurellement différents qui maximisent la couverture** plutôt qu’un gros tas de quasi-doublons. En pratique, cela signifie généralement :

- Partir d’**échantillons réels** (corpus publics, crawling, trafic capturé, ensembles de fichiers de l’écosystème cible).
- Les distiller avec une **minimisation de corpus basée sur la couverture** au lieu de conserver chaque échantillon valide.
- Garder des seeds **assez petits** pour que les mutations tombent sur des champs significatifs plutôt que de passer la plupart des cycles sur des bytes non pertinents.
- Relancer la minimisation du corpus après des changements majeurs du harness/de l’instrumentation, car le “meilleur” corpus change lorsque la reachability change.

## Mutation tenant compte des comparaisons pour les Magic Values

Une raison fréquente pour laquelle les fuzzers plafonnent n’est pas la syntaxe mais les **comparaisons dures** : magic bytes, vérifications de longueur, chaînes d’enum, checksums, ou valeurs de dispatch du parser protégées par `memcmp`, des tables de switch, ou des comparaisons en cascade. La mutation aléatoire pure gaspille des cycles à essayer de deviner ces valeurs byte par byte.

Pour ces cibles, utilisez le **comparison tracing** (par exemple les workflows AFL++ `CMPLOG` / Redqueen-style) afin que le fuzzer puisse observer les opérandes des comparaisons ratées et biaiser les mutations vers des valeurs qui les satisfont.
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

- C’est particulièrement utile lorsque la cible cache une logique profonde derrière des **file signatures**, des **protocol verbs**, des **type tags** ou des **version-dependent feature bits**.
- Combinez-le avec des **dictionaries** extraits d’échantillons réels, de specs de protocol, ou de debug logs. Un petit dictionary avec des grammar tokens, des noms de chunk, des verbs et des delimiters est souvent plus précieux qu’une énorme wordlist générique.
- Si la cible effectue beaucoup de vérifications séquentielles, résolvez d’abord les comparaisons “magic” les plus précoces, puis minimisez à nouveau le corpus obtenu afin que les étapes suivantes partent déjà de préfixes valides.

## Stateful Fuzzing : Les séquences sont des seeds

Pour les **protocols**, les **authenticated workflows** et les **multi-stage parsers**, l’unité intéressante n’est souvent pas un blob unique mais une **message sequence**. Concaténer tout le transcript dans un seul fichier et le muter aveuglément est généralement inefficace, car le fuzzer mute chaque étape de manière égale, même lorsque seul le message final atteint l’état fragile.

Un schéma plus efficace consiste à traiter la **sequence elle-même comme seed** et à utiliser l’**observable state** (response codes, protocol states, parser phases, returned object types) comme feedback supplémentaire :

- Conservez stables les **valid prefix messages** et concentrez les mutations sur le message qui **déclenche la transition**.
- Mettez en cache les identifiants et les valeurs générées par le serveur à partir des réponses précédentes lorsque l’étape suivante en dépend.
- Préférez la mutation/le splicing par message plutôt que la mutation de tout le transcript sérialisé comme un blob opaque.
- Si le protocol expose des response codes significatifs, utilisez-les comme un **cheap state oracle** pour prioriser les séquences qui progressent plus profondément.

C’est la même raison pour laquelle les authenticated bugs, les hidden transitions ou les bugs de parser “only-after-handshake” sont souvent manqués par le fuzzing classique de type file-style : le fuzzer doit préserver **l’ordre, l’état et les dépendances**, pas seulement la structure.

## Single-Machine Diversity Trick (Jackalope-Style)

Une façon pratique d’hybrider la **generative novelty** avec la **coverage reuse** consiste à **redémarrer des workers de courte durée** contre un serveur persistant. Chaque worker part d’un corpus vide, se synchronise après `T` secondes, exécute encore `T` secondes sur le corpus combiné, se resynchronise, puis s’arrête. Cela produit des **fresh structures à chaque génération** tout en exploitant toujours la coverage accumulée.

**Server:**
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

**Notes:**

- `-in empty` force un **corpus frais** à chaque génération.
- `-server_update_interval T` approxime une **synchronisation différée** (novelty d’abord, réutilisation ensuite).
- En mode **grammar fuzzing**, la synchronisation initiale avec le server est ignorée par défaut (pas besoin de `-skip_initial_server_sync`).
- Le `T` optimal dépend de la **cible** ; basculer après que le worker a trouvé la plupart des couvertures “faciles” tend à mieux fonctionner.

## Snapshot Fuzzing For Hard-To-Harness Targets

Quand le code que vous voulez tester ne devient accessible **qu’après un gros coût de setup** (démarrer une VM, terminer un login, recevoir un packet, parser un container, initialiser un service), une alternative utile est le **snapshot fuzzing** :

1. Exécutez la cible jusqu’à ce que l’état intéressant soit prêt.
2. Prenez un snapshot de la **mémoire + registres** à ce moment-là.
3. Pour chaque test case, écrivez l’entrée mutée directement dans le buffer guest/process pertinent.
4. Exécutez jusqu’au crash/timeout/reset.
5. Restaurez seulement les **dirty pages** et répétez.

Cela évite de payer le coût complet de setup à chaque itération et est particulièrement utile pour les **network services**, le **firmware**, les **post-auth attack surfaces**, et les **binary-only targets** qu’il est pénible de refactorer en un harness in-process classique.

Une astuce pratique consiste à s’arrêter juste après un point `recv`/`read`/de désérialisation de packet, noter l’adresse du buffer d’entrée, prendre un snapshot à cet endroit, puis muter directement ce buffer à chaque itération. Cela vous permet de fuzzing la logique de parsing profonde sans reconstruire tout le handshake à chaque fois.

## Harness Introspection: Find Shallow Fuzzers Early

Quand une campagne stagne, le problème n’est souvent pas le mutator mais le **harness**. Utilisez l’**introspection de reachability/coverage** pour trouver des fonctions qui sont statiquement accessibles depuis votre fuzz target mais rarement ou jamais couvertes dynamiquement. Ces fonctions indiquent généralement l’un de ces trois problèmes :

- Le harness entre dans la cible trop tard ou trop tôt.
- Le seed corpus manque toute une famille de fonctionnalités.
- La cible a vraiment besoin d’un **second harness** au lieu d’un seul harness “do everything” trop gros.

Si vous utilisez des workflows de type OSS-Fuzz / ClusterFuzz, Fuzz Introspector est utile pour ce triage :
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Utilisez le rapport pour décider s’il faut ajouter un nouveau harness pour un chemin de parser non testé, élargir le corpus pour une fonctionnalité spécifique, ou scinder un harness monolithique en points d’entrée plus petits.

## Sélection de cibles de fuzzing et triage des mutations, en priorité au graphe

Si vous avez déjà des **résultats d’analyse statique**, des **survivants de mutation testing** et des **rapports de couverture**, ne les triez pas comme des listes indépendantes. Construisez d’abord un **graphe d’appels**, annotez les nœuds avec la **complexité cyclomatique**, la **recherche atteignable depuis un point d’entrée/entrée non fiable**, ainsi que toute découverte externe, puis posez des questions sur le graphe :

- Quelles fonctions à forte complexité sont atteignables depuis une entrée non fiable ?
- Quels survivants de mutation se trouvent sur des chemins allant des parsers/handlers vers du code critique pour la sécurité ?
- Quelles fonctions sont des points de passage architecturaux avec un **blast radius** particulièrement élevé ?

Cela fait généralement ressortir de meilleures cibles de fuzzing que le seul critère « plus faible couverture ». Un parser/decoder avec une **forte complexité** et une **atteignabilité externe** confirmée est un meilleur candidat pour un harness qu’un helper interne isolé, peu couvert, mais sans chemin contrôlé par un attaquant.

### Flux de triage pratique

1. Construisez un **graphe de code** à partir de la base de code et extrayez les métriques de complexité/branches par fonction.
2. Énumérez les **points d’entrée** qui acceptent des entrées contrôlées par un attaquant : handlers de requêtes, decoders, importers, parsers de protocoles, lecteurs CLI/fichiers.
3. Exécutez des **requêtes de chemin** depuis ces points d’entrée vers les fonctions candidates pour séparer la surface d’attaque atteignable du code mort/interne uniquement.
4. Donnez la priorité aux nœuds qui combinent :
- une forte **complexité cyclomatique**
- une **atteignabilité confirmée depuis une entrée non fiable**
- un **blast radius** élevé ou de nombreux dépendants en aval
- des preuves corroborantes telles que des résultats **SARIF**, des notes d’audit ou des survivants de mutation
5. Écrivez d’abord des harnesses ciblés pour les nœuds les mieux notés, en particulier les **parsers/codecs** tels que les decodeurs hex/Base64/IP/message.

### Survivants de mutation : équivalents vs exploitables

Le mutation testing produit souvent une liste bruyante de survivants. Avant de considérer chaque survivant comme une faille de sécurité, utilisez le graphe pour poser les questions suivantes :

- La fonction mutée est-elle atteignable depuis un point d’entrée contrôlé par un attaquant ?
- Tous les chemins d’appel sont-ils contraints par des invariants plus forts que la vérification mutée ?
- Le nœud se trouve-t-il dans du code mort, de la logique de formatage uniquement, ou dans un chemin arithmétique/parser à fort impact ?

Les survivants qui restent inatteignables ou structurellement contraints sont souvent des **mutants équivalents**. Les survivants qui restent **atteignables** et touchent des **conditions limites**, des **chemins overflow/carry**, ou de l’**arithmétique/parsing critique pour la sécurité** doivent être promus vers :

- de nouveaux fuzz harnesses
- des tests directs de propriété/invariants
- des vecteurs ciblés de cas limites

### Corréler les résultats externes sur le graphe

Si votre pipeline SAST exporte du **SARIF**, projetez les résultats sur les nœuds du graphe par **fichier + plage de lignes** et utilisez le graphe pour étendre l’impact :

- calculez le **blast radius** de la fonction signalée
- vérifiez si le résultat se trouve sur un chemin depuis un point d’entrée
- regroupez les résultats proches qui convergent vers le même point de passage

C’est utile pour décider s’il faut consacrer du temps de fuzzing à une fonction spécifique : un nœud qui est **atteignable**, **complexe**, et qui a déjà des **hits SAST** est souvent une meilleure cible qu’un nœud simplement complexe sans chemin attaquant.

Exemple de flux de travail avec Trailmark :
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
La méthodologie importante est l’intersection : **complexité x exposition x impact**. Utilisez le graphe pour choisir les cibles de fuzzing ayant la plus grande valeur de sécurité attendue, puis utilisez les survivants des mutations pour décider quelles frontières et invariants votre harness doit stresser.

## Références

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)

{{#include ../banners/hacktricks-training.md}}
