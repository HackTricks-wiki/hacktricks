# Методологія Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

У **mutational grammar fuzzing** вхідні дані мутуються, залишаючись **grammar-valid**. У режимі coverage-guided зберігаються як corpus seeds лише ті зразки, що викликають **new coverage**. Для **language targets** (parsers, interpreters, engines) це може пропускати баги, які потребують **semantic/dataflow chains**, де вихід одного конструкта стає входом іншого.

**Failure mode:** fuzzer знаходить seeds, які окремо запускають `document()` і `generate-id()` (або подібні primitives), але **не зберігає chained dataflow**, тому зразок “ближче до багу” відкидається, бо не додає coverage. Для **3+ dependent steps** випадкове комбінування стає дорогим, а feedback від coverage не спрямовує пошук.

**Implication:** для граматик із великою кількістю залежностей варто розглянути **hybridizing mutational and generative phases** або зміщувати генерацію в бік патернів **function chaining** (а не лише coverage).

## Corpus Diversity Pitfalls

Coverage-guided mutation є **greedy**: зразок із новим coverage зберігається одразу, часто з великими незмінними регіонами. З часом corpora стають **near-duplicates** з низьким структурним різноманіттям. Агресивна мінімізація може прибрати корисний контекст, тому практичний компроміс — це **grammar-aware minimization**, яка **зупиняється після досягнення мінімального порога tokenів** (зменшити шум, зберігши достатньо навколишньої структури, щоб лишатися зручним для mutation).

Практичне правило для corpus у mutational fuzzing: **віддавати перевагу невеликому набору структурно різних seeds, які максимізують coverage**, замість великої купи near-duplicates. На практиці це зазвичай означає:

- Починати з **real-world samples** (public corpora, crawling, captured traffic, file sets із цільової екосистеми).
- Відсіювати їх через **coverage-based corpus minimization**, а не зберігати кожен valid sample.
- Тримати seeds **достатньо малими**, щоб mutation потрапляли в meaningful fields, а не витрачали більшість циклів на irrelevant bytes.
- Повторно запускати corpus minimization після суттєвих змін harness/instrumentation, бо “best” corpus змінюється, коли змінюється reachability.

## Comparison-Aware Mutation For Magic Values

Поширена причина, чому fuzzers виходять на плато, — це не syntax, а **hard comparisons**: magic bytes, length checks, enum strings, checksums або parser dispatch values, захищені `memcmp`, switch tables чи cascaded comparisons. Pure random mutation марнує цикли, намагаючись вгадати ці значення byte-by-byte.

Для таких цілей використовуйте **comparison tracing** (наприклад AFL++ `CMPLOG` / Redqueen-style workflows), щоб fuzzer міг спостерігати операнди з невдалих порівнянь і зміщувати mutation у бік значень, які їх задовольняють.
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
**Практичні нотатки:**

- Це особливо корисно, коли target приховує глибоку logic за **file signatures**, **protocol verbs**, **type tags** або **version-dependent feature bits**.
- Поєднуйте це з **dictionaries**, витягнутими з реальних sample, protocol specs або debug logs. Невеликий dictionary з grammar tokens, chunk names, verbs і delimiters часто цінніший за величезний generic wordlist.
- Якщо target виконує багато послідовних checks, спочатку розв’яжіть найраніші “magic” comparisons, а потім знову мінімізуйте отриманий corpus, щоб пізніші stage стартували вже з валідних prefixes.

## Stateful Fuzzing: Sequences Are Seeds

Для **protocols**, **authenticated workflows** і **multi-stage parsers** цікавою одиницею часто є не один blob, а **message sequence**. Об’єднання всього transcript в один файл і сліпе мутування зазвичай неефективні, бо fuzzer мутує кожен step однаково, навіть якщо лише пізніше message досягає крихкого state.

Ефективніший підхід — розглядати саму **sequence** як seed і використовувати **observable state** (response codes, protocol states, parser phases, returned object types) як додатковий feedback:

- Залишайте **valid prefix messages** стабільними та зосереджуйте mutation на message, що **drives transition**.
- Кешуйте identifiers і server-generated values з попередніх responses, коли наступний step від них залежить.
- Віддавайте перевагу per-message mutation/splicing замість mutating всього serialized transcript як opaque blob.
- Якщо protocol надає meaningful response codes, використовуйте їх як **cheap state oracle**, щоб пріоритезувати sequences, які просуваються глибше.

Це та сама причина, чому authenticated bugs, hidden transitions або parser bugs типу “only-after-handshake” часто губляться при звичайному file-style fuzzing: fuzzer має зберігати **order, state і dependencies**, а не лише structure.

## Single-Machine Diversity Trick (Jackalope-Style)

Практичний спосіб гібридизувати **generative novelty** з **coverage reuse** — це **перезапускати short-lived workers** проти persistent server. Кожен worker починає з порожнього corpus, синхронізується через `T` seconds, ще `T` seconds працює над combined corpus, знову синхронізується, а потім завершується. Це дає **fresh structures each generation** і водночас використовує накопичений coverage.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Послідовні workers (приклад циклу):**

<details>
<summary>Цикл перезапуску Jackalope worker</summary>
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

- `-in empty` примусово створює **свіжий corpus** для кожної генерації.
- `-server_update_interval T` наближує **відкладену синхронізацію** (спочатку новизна, потім повторне використання).
- У режимі grammar fuzzing початкова синхронізація з server за замовчуванням пропускається (не потрібно `-skip_initial_server_sync`).
- Оптимальне `T` **залежить від target**; перемикання після того, як worker знайшов більшість “easy” coverage, зазвичай працює найкраще.

## Snapshot Fuzzing For Hard-To-Harness Targets

Коли код, який ви хочете тестувати, стає досяжним лише **після великої початкової вартості** (завантаження VM, завершення login, отримання packet, парсинг container, ініціалізація service), корисною альтернативою є **snapshot fuzzing**:

1. Запустіть target, доки не буде готовий цікавий стан.
2. Зробіть snapshot **memory + registers** у цей момент.
3. Для кожного test case записуйте змінений input безпосередньо у відповідний buffer guest/process.
4. Виконуйте до crash/timeout/reset.
5. Відновлюйте лише **dirty pages** і повторюйте.

Це дозволяє уникнути сплати повної початкової вартості на кожній ітерації та особливо корисно для **network services**, **firmware**, **post-auth attack surfaces** і **binary-only targets**, які складно переробити у класичний in-process harness.

Практичний трюк — негайно зупинитися після точки `recv`/`read`/packet-deserialization, запам’ятати адресу input buffer, зробити там snapshot, а потім змінювати цей buffer безпосередньо в кожній ітерації. Це дає змогу fuzzити глибоку логіку парсингу без перебудови всього handshake щоразу.

## Harness Introspection: Find Shallow Fuzzers Early

Коли campaign зупиняється, проблема часто не в mutator, а в **harness**. Використовуйте **reachability/coverage introspection**, щоб знайти functions, які статично досяжні з вашого fuzz target, але динамічно покриваються рідко або ніколи. Такі functions зазвичай вказують на одну з трьох проблем:

- Harness входить у target занадто пізно або занадто рано.
- У seed corpus бракує цілої family features.
- Target насправді потребує **second harness** замість одного надто великого harness “робить усе”.

Якщо ви використовуєте workflows у стилі OSS-Fuzz / ClusterFuzz, Fuzz Introspector корисний для цього triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Використайте звіт, щоб вирішити, чи потрібно додати новий harness для неперевіреного шляху parser, розширити corpus для конкретної feature, чи розділити monolithic harness на менші entry points.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)

{{#include ../banners/hacktricks-training.md}}
