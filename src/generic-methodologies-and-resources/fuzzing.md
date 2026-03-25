# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

У **mutational grammar fuzzing** вхідні дані модифікуються, залишаючись **grammar-valid**. У режимі **coverage-guided** лише зразки, які викликають **new coverage**, зберігаються як corpus seeds. Для **language targets** (parsers, interpreters, engines) це може пропустити баги, що вимагають **semantic/dataflow chains**, коли вихід одного конструкта стає вхідним для іншого.

**Failure mode:** fuzzer знаходить seeds, які окремо викликають `document()` і `generate-id()` (або подібні примітиви), але **does not preserve the chained dataflow**, тож «closer-to-bug» зразок відкидається, бо не додає coverage. При **3+ dependent steps** випадкова рекомбінація стає дорогою, і coverage feedback не спрямовує пошук.

**Implication:** для граматик з великою кількістю залежностей варто розглянути **hybridizing mutational and generative phases** або зміщувати генерацію в бік **function chaining** патернів (а не лише coverage).

## Corpus Diversity Pitfalls

Coverage-guided mutation є **greedy**: зразок з новим покриттям зберігається негайно, часто з великими незміненими ділянками. Згодом корпора стають **near-duplicates** з низькою структурною різноманітністю. Агресивна мінімізація може видалити корисний контекст, тому практичний компроміс — **grammar-aware minimization**, яка **stops after a minimum token threshold** (зменшити шум, залишивши достатньо навколишньої структури для подальших мутацій).

## Single-Machine Diversity Trick (Jackalope-Style)

Практичний спосіб поєднати **generative novelty** з **coverage reuse** — це **restart short-lived workers** проти персистентного сервера. Кожен worker стартує з порожнього corpus, синхронізується через `T` секунд, працює ще `T` секунд на об’єднаному corpus, знову синхронізується і виходить. Це дає **fresh structures each generation**, одночасно використовуючи накопичене coverage.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Послідовні воркери (приклад циклу):**

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

**Примітки:**

- `-in empty` примушує використовувати **свіжий корпус** для кожної генерації.
- `-server_update_interval T` імітує **відкладену синхронізацію** (спочатку новизна, потім повторне використання).
- У режимі grammar fuzzing **початкова синхронізація сервера пропускається за замовчуванням** (не потрібно `-skip_initial_server_sync`).
- Оптимальне `T` **залежить від цілі**; перемикання після того, як worker знайшов більшість “easy” покриття, зазвичай працює найкраще.

## Посилання

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)

{{#include ../banners/hacktricks-training.md}}
