# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

En **mutational grammar fuzzing**, los inputs se mutan manteniéndose **grammar-valid**. En coverage-guided mode, solo las muestras que provocan **new coverage** se guardan como corpus seeds. Para **language targets** (parsers, interpreters, engines), esto puede pasar por alto bugs que requieren **semantic/dataflow chains** donde la salida de una construcción se convierte en la entrada de otra.

**Modo de fallo:** el fuzzer encuentra seeds que individualmente ejercitan `document()` y `generate-id()` (o primitivas similares), pero **does not preserve the chained dataflow**, por lo que la muestra “closer-to-bug” se descarta porque no añade coverage. Con **3+ dependent steps**, la recombinación aleatoria se vuelve cara y el coverage feedback no guía la búsqueda.

**Implicación:** para gramáticas con muchas dependencias, considerar **hybridizing mutational and generative phases** o sesgar la generación hacia patrones de **function chaining** (no solo coverage).

## Problemas de diversidad del corpus

La coverage-guided mutation es **greedy**: una muestra con **new-coverage** se guarda inmediatamente, reteniendo a menudo grandes regiones sin cambios. Con el tiempo, los corpus se convierten en **near-duplicates** con baja diversidad estructural. La minimización agresiva puede eliminar contexto útil, por lo que un compromiso práctico es la **grammar-aware minimization** que **stops after a minimum token threshold** (reduce ruido manteniendo suficiente estructura circundante para seguir siendo mutation-friendly).

## Single-Machine Diversity Trick (Jackalope-Style)

Una forma práctica de hybridize **generative novelty** con **coverage reuse** es **restart short-lived workers** contra un servidor persistente. Cada worker parte de un corpus vacío, sincroniza tras `T` segundos, ejecuta otros `T` segundos sobre el corpus combinado, sincroniza de nuevo y luego sale. Esto produce **fresh structures each generation** mientras se aprovecha el coverage acumulado.

**Servidor:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Workers secuenciales (ejemplo loop):**

<details>
<summary>Jackalope worker restart loop</summary>
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

**Notas:**

- `-in empty` garantiza un **corpus nuevo** en cada generación.
- `-server_update_interval T` aproxima una **sincronización retrasada** (primero novedades, luego reutilización).
- En el modo grammar fuzzing, **la sincronización inicial con el servidor se omite por defecto** (no hace falta `-skip_initial_server_sync`).
- El `T` óptimo es **target-dependent**; cambiar después de que el worker haya encontrado la mayor parte de la cobertura “easy” suele funcionar mejor.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)

{{#include ../banners/hacktricks-training.md}}
