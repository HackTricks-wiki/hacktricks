# Méthodologie de Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing de grammaire mutationnel : Coverage vs. Sémantique

Dans le **mutational grammar fuzzing**, les entrées sont mutées tout en restant **grammar-valid**. En mode guidé par la coverage, seuls les échantillons qui déclenchent une **nouvelle coverage** sont conservés comme graines du corpus. Pour les **language targets** (parseurs, interpréteurs, moteurs), cela peut manquer des bugs qui nécessitent des **chaînes sémantiques/de dataflow** où la sortie d’un construit devient l’entrée d’un autre.

**Mode d’échec :** le fuzzer trouve des graines qui, individuellement, exercent `document()` et `generate-id()` (ou des primitives similaires), mais **ne préservent pas le dataflow chaîné**, donc l’échantillon “plus proche du bug” est écarté parce qu’il n’ajoute pas de coverage. Avec **3+ étapes dépendantes**, la recombinaison aléatoire devient coûteuse et le retour de couverture ne guide pas la recherche.

**Implication :** pour les grammaires très dépendantes, envisagez de **hybrider des phases mutationnelles et génératives** ou de biaiser la génération vers des motifs de **function chaining** (pas seulement la coverage).

## Pièges de diversité du corpus

La mutation guidée par la coverage est **greedy** : un échantillon apportant une nouvelle coverage est enregistré immédiatement, en conservant souvent de grandes régions inchangées. Avec le temps, les corpus deviennent des **quasi-doublons** avec une faible diversité structurelle. Une minimisation agressive peut supprimer un contexte utile, donc un compromis pratique est une **minimisation consciente de la grammaire** qui **s’arrête après un seuil minimal de tokens** (réduire le bruit tout en gardant assez de structure environnante pour rester favorable à la mutation).

Une règle pratique pour les corpus en mutational fuzzing est la suivante : **préférer un petit ensemble de graines structurellement שונות qui maximisent la coverage** plutôt qu’une grande pile de quasi-doublons. En pratique, cela signifie généralement :

- Partir d’**échantillons du monde réel** (corpus publics, crawling, trafic capturé, ensembles de fichiers de l’écosystème cible).
- Les distiller avec une **minimisation de corpus basée sur la coverage** plutôt que de conserver chaque échantillon valide.
- Garder des graines **assez petites** pour que les mutations tombent sur des champs significatifs plutôt que de passer la plupart des cycles sur des octets non pertinents.
- Relancer la minimisation du corpus après des changements majeurs du harness/de l’instrumentation, car le “meilleur” corpus change lorsque la reachability change.

## Mutation sensible aux comparaisons pour les Magic Values

Une raison fréquente pour laquelle les fuzzers plafonnent n’est pas la syntaxe mais les **hard comparisons** : magic bytes, vérifications de longueur, chaînes d’énumération, checksums, ou valeurs de dispatch du parseur protégées par `memcmp`, des tables de switch ou des comparaisons en cascade. La mutation aléatoire pure gaspille des cycles à essayer de deviner ces valeurs octet par octet.

Pour ces cibles, utilisez le **comparison tracing** (par exemple les workflows de type AFL++ `CMPLOG` / Redqueen) afin que le fuzzer puisse observer les opérandes des comparaisons échouées et orienter les mutations vers des valeurs qui les satisfont.
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

- C’est particulièrement utile lorsque la cible verrouille une logique profonde derrière des **file signatures**, des **protocol verbs**, des **type tags**, ou des **version-dependent feature bits**.
- Combinez-le avec des **dictionaries** extraits d’échantillons réels, de protocol specs, ou de debug logs. Un petit dictionary avec des grammar tokens, des chunk names, des verbs, et des delimiters est souvent plus précieux qu’une énorme generic wordlist.
- Si la cible effectue beaucoup de vérifications séquentielles, résolvez d’abord les comparaisons “magic” les plus tôt possible, puis minimisez à nouveau le corpus résultant afin que les étapes suivantes partent déjà de préfixes valides.

## Stateful Fuzzing : Les séquences sont des seeds

Pour les **protocols**, les **authenticated workflows**, et les **multi-stage parsers**, l’unité intéressante n’est souvent pas un blob unique mais une **message sequence**. Concaténer tout le transcript dans un seul fichier et le muter à l’aveugle est généralement inefficace, car le fuzzer mute chaque étape de manière égale, même lorsque seul le message plus tardif atteint l’état fragile.

Un schéma plus efficace consiste à traiter la **sequence elle-même comme seed** et à utiliser l’**observable state** (response codes, protocol states, parser phases, returned object types) comme retour supplémentaire :

- Conservez les **valid prefix messages** stables et concentrez les mutations sur le message qui **déclenche la transition**.
- Mettez en cache les identifiants et les valeurs générées par le serveur à partir des réponses précédentes lorsque l’étape suivante en dépend.
- Préférez la mutation/le splicing par message plutôt que de muter tout le transcript sérialisé comme un blob opaque.
- Si le protocol expose des response codes significatifs, utilisez-les comme une **cheap state oracle** pour prioriser les sequences qui progressent plus en profondeur.

C’est la même raison pour laquelle les bugs authenticated, les transitions cachées, ou les bugs de parser “only-after-handshake” sont souvent manqués par le file-style fuzzing classique : le fuzzer doit préserver **l’ordre, l’état, et les dépendances**, pas seulement la structure.

## Single-Machine Diversity Trick (Jackalope-Style)

Une manière pratique d’hybrider la **generative novelty** avec la **coverage reuse** consiste à **redémarrer des workers de courte durée** contre un server persistant. Chaque worker démarre avec un corpus vide, se synchronise après `T` secondes, exécute encore `T` secondes sur le corpus combiné, se resynchronise, puis se termine. Cela produit des **fresh structures each generation** tout en exploitant la coverage accumulée.

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

- `-in empty` force un **fresh corpus** à chaque génération.
- `-server_update_interval T` approxime une **sync retardée** (la nouveauté d’abord, la réutilisation ensuite).
- En mode grammar fuzzing, la **sync initiale du serveur est ignorée par défaut** (pas besoin de `-skip_initial_server_sync`).
- Le `T` optimal est **dépendant de la cible** ; basculer après que le worker a trouvé la plupart des couvertures “faciles” tend à mieux fonctionner.

## Snapshot Fuzzing For Hard-To-Harness Targets

Quand le code que vous voulez tester ne devient atteignable **qu’après un coût de setup élevé** (démarrer une VM, terminer une connexion, recevoir un paquet, parser un container, initialiser un service), une alternative utile est le **snapshot fuzzing** :

1. Exécutez la cible jusqu’à ce que l’état intéressant soit prêt.
2. Prenez un snapshot de la **mémoire + registres** à ce moment-là.
3. Pour chaque cas de test, écrivez l’entrée mutée directement dans le buffer guest/process pertinent.
4. Exécutez jusqu’au crash/timeout/reset.
5. Restaurez uniquement les **dirty pages** et répétez.

Cela évite de payer le coût complet de setup à chaque itération et est particulièrement utile pour les **network services**, **firmware**, **post-auth attack surfaces**, et les **binary-only targets** qui sont pénibles à refactorer en un harness in-process classique.

Une astuce pratique consiste à s’arrêter immédiatement après un point `recv`/`read`/packet-deserialization, noter l’adresse du buffer d’entrée, faire un snapshot à cet endroit, puis muter directement ce buffer à chaque itération. Cela permet de fuzz la logique de parsing profonde sans reconstruire tout le handshake à chaque fois.

## Harness Introspection: Find Shallow Fuzzers Early

Quand une campagne se bloque, le problème n’est souvent pas le mutator mais le **harness**. Utilisez l’**introspection de reachability/coverage** pour trouver les fonctions qui sont statiquement atteignables depuis votre fuzz target mais rarement ou jamais couvertes dynamiquement. Ces fonctions indiquent généralement l’un de ces trois problèmes :

- Le harness entre dans la cible trop tard ou trop tôt.
- Le seed corpus manque toute une famille de fonctionnalités.
- La cible a vraiment besoin d’un **second harness** au lieu d’un seul harness “fait tout” trop volumineux.

Si vous utilisez des workflows de type OSS-Fuzz / ClusterFuzz, Fuzz Introspector est utile pour ce triage :
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Utilisez le rapport pour décider s’il faut ajouter un nouveau harness pour un chemin de parseur non testé, étendre le corpus pour une fonctionnalité spécifique, ou diviser un harness monolithique en points d’entrée plus petits.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)

{{#include ../banners/hacktricks-training.md}}
