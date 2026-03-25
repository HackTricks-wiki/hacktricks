# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

In **mutational grammar fuzzing**, les inputs sont mutés tout en restant **grammar-valid**. En mode coverage-guided, seules les samples qui déclenchent une **new coverage** sont sauvegardées comme corpus seeds. Pour des **language targets** (parsers, interpreters, engines), cela peut manquer des bugs qui nécessitent des **semantic/dataflow chains** où la sortie d'une construction devient l'entrée d'une autre.

**Failure mode :** le fuzzer trouve des seeds qui exercent individuellement `document()` et `generate-id()` (ou des primitives similaires), mais **does not preserve the chained dataflow**, si bien que l’échantillon « closer-to-bug » est rejeté parce qu’il n’ajoute pas de coverage. Avec **3+ dependent steps**, la recombinaison aléatoire devient coûteuse et le feedback de coverage n’oriente plus la recherche.

**Implication :** pour des grammars à fortes dépendances, envisagez d’hybrider les phases mutational et generative ou de biaiser la génération vers des patterns de function chaining (pas seulement la coverage).

## Corpus Diversity Pitfalls

La mutation coverage-guided est **greedy** : un new-coverage sample est sauvegardé immédiatement, conservant souvent de larges régions inchangées. Avec le temps, les corpora deviennent des **near-duplicates** à faible diversité structurelle. Une minimisation agressive peut supprimer du contexte utile ; un compromis pratique est la **grammar-aware minimization** qui **s’arrête après un seuil minimum de tokens** (réduire le bruit tout en gardant suffisamment de structure environnante pour rester mutation-friendly).

## Single-Machine Diversity Trick (Jackalope-Style)

Une méthode pratique pour hybrider la generative novelty avec la réutilisation de coverage est de redémarrer des workers éphémères contre un server persistant. Chaque worker démarre d’un corpus vide, sync après `T` secondes, tourne encore `T` secondes sur le corpus combiné, sync à nouveau, puis quitte. Cela produit des structures fraîches à chaque génération tout en tirant parti de la coverage accumulée.

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

**Remarques :**

- `-in empty` force un **corpus frais** à chaque génération.
- `-server_update_interval T` approxime la **synchronisation retardée** (nouveauté d'abord, réutilisation ensuite).
- En mode grammar fuzzing, la **synchronisation initiale du serveur est ignorée par défaut** (pas besoin de `-skip_initial_server_sync`).
- Le `T` optimal dépend de la **cible** ; changer après que le worker ait trouvé la majeure partie de la couverture « facile » tend à donner les meilleurs résultats.

## Références

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)

{{#include ../banners/hacktricks-training.md}}
