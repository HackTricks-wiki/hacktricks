# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

In **mutational grammar fuzzing**, inputs are mutated while staying **grammar-valid**. In coverage-guided mode, only samples that trigger **new coverage** are saved as corpus seeds. For **language targets** (parsers, interpreters, engines), this can miss bugs that require **semantic/dataflow chains** where the output of one construct becomes the input to another.

**Failure mode:** o fuzzer encontra seeds que, isoladamente, exercitam `document()` e `generate-id()` (ou primitivas similares), mas **não preserva o encadeamento do dataflow**, então a amostra “mais próxima do bug” é descartada porque não adiciona coverage. Com **3+ dependent steps**, a recombinação aleatória fica cara e o feedback de coverage não guia a busca.

**Implication:** para gramáticas com muitas dependências, considere **hybridizing mutational and generative phases** ou enviesar a geração para padrões de **function chaining** (não apenas coverage).

## Corpus Diversity Pitfalls

Coverage-guided mutation é **greedy**: uma amostra que adiciona coverage é salva imediatamente, frequentemente mantendo grandes regiões inalteradas. Com o tempo, os corpora se tornam **near-duplicates** com baixa diversidade estrutural. Minimização agressiva pode remover contexto útil, então um compromisso prático é a **grammar-aware minimization** que **para após um limiar mínimo de tokens** (reduz ruído mantendo estrutura suficiente ao redor para continuar facilitando mutações).

## Single-Machine Diversity Trick (Jackalope-Style)

Uma maneira prática de hibridizar **generative novelty** com **coverage reuse** é **restart short-lived workers** contra um servidor persistente. Cada worker começa de um corpus vazio, sincroniza após `T` segundos, roda mais `T` segundos sobre o corpus combinado, sincroniza novamente e então sai. Isso produz **fresh structures each generation** enquanto ainda aproveita coverage acumulado.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sequential workers (exemplo de loop):**

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

- `-in empty` força um **corpus novo** a cada geração.
- `-server_update_interval T` aproxima uma **sincronização atrasada** (novidade primeiro, reutilização depois).
- No modo grammar fuzzing, **a sincronização inicial com o servidor é pulada por padrão** (não é necessário `-skip_initial_server_sync`).
- O `T` ideal é **dependente do alvo**; alternar depois que o worker encontrou a maior parte da cobertura “fácil” tende a funcionar melhor.

## Referências

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)

{{#include ../banners/hacktricks-training.md}}
