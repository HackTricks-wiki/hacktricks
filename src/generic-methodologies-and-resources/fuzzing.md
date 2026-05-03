# Методологія Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

У **mutational grammar fuzzing** вхідні дані мутуються, але залишаються **grammar-valid**. У coverage-guided режимі зберігаються як seeds corpus лише ті зразки, що викликають **new coverage**. Для **language targets** (parsers, interpreters, engines) це може пропускати bugs, які потребують **semantic/dataflow chains**, де вихід одного конструкта стає входом для іншого.

**Failure mode:** fuzzer знаходить seeds, які окремо перевіряють `document()` і `generate-id()` (або подібні primitives), але **не зберігає chained dataflow**, тому зразок, “ближчий до bug”, відкидається, бо не додає coverage. За наявності **3+ dependent steps** випадкове recombination стає дорогим, а coverage feedback не спрямовує пошук.

**Implication:** для grammar з великою кількістю dependencies варто розглянути **hybridizing mutational and generative phases** або зміщувати generation у бік шаблонів **function chaining** (а не лише coverage).

## Corpus Diversity Pitfalls

Coverage-guided mutation є **greedy**: зразок із new-coverage зберігається одразу, часто з великими незмінними ділянками. З часом corpora стають **near-duplicates** з низькою структурною різноманітністю. Агресивна minimization може прибрати корисний context, тому практичний компроміс — **grammar-aware minimization**, яка **зупиняється після мінімального порогу token-ів** (зменшує noise, але лишає достатньо навколишньої структури, щоб мутації залишалися зручними).

Практичне правило для corpus у mutational fuzzing: **надавати перевагу невеликому набору структурно різних seeds, що максимізують coverage**, замість великої купи near-duplicates. На практиці це зазвичай означає:

- Починайте з **real-world samples** (public corpora, crawling, captured traffic, file sets з target ecosystem).
- Дистилюйте їх за допомогою **coverage-based corpus minimization** замість збереження кожного valid sample.
- Тримайте seeds **достатньо малими**, щоб мутації потрапляли в meaningful fields, а не витрачали більшість циклів на irrelevant bytes.
- Повторно запускайте corpus minimization після великих змін harness/instrumentation, бо “best” corpus змінюється, коли змінюється reachability.

## Comparison-Aware Mutation For Magic Values

Поширена причина, чому fuzzers виходять на плато, — це не syntax, а **hard comparisons**: magic bytes, length checks, enum strings, checksums або parser dispatch values, захищені `memcmp`, switch tables чи cascaded comparisons. Pure random mutation марнує цикли, намагаючись вгадати ці значення byte-by-byte.

Для таких targets використовуйте **comparison tracing** (наприклад, AFL++ `CMPLOG` / Redqueen-style workflows), щоб fuzzer міг бачити operands з невдалих comparisons і зміщувати мутації у бік значень, які їх задовольняють.
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

- Це особливо корисно, коли target ховає глибоку логіку за **file signatures**, **protocol verbs**, **type tags** або **version-dependent feature bits**.
- Поєднуй це з **dictionaries**, витягнутими з реальних samples, protocol specs або debug logs. Невеликий dictionary з grammar tokens, chunk names, verbs і delimiters часто цінніший за величезний generic wordlist.
- Якщо target виконує багато послідовних перевірок, спочатку розв’яжи найраніші “magic” comparisons, а потім знову мінімізуй отриманий corpus, щоб пізніші етапи стартували вже з валідних prefixes.

## Stateful Fuzzing: Sequences Are Seeds

Для **protocols**, **authenticated workflows** і **multi-stage parsers** цікавою одиницею часто є не один blob, а **message sequence**. З’єднання всього transcript в один файл і сліпа мутація зазвичай неефективні, бо fuzzer мутує кожен крок однаково, навіть якщо до крихкого state доходить лише пізніше повідомлення.

Більш ефективний підхід — трактувати **саму sequence як seed** і використовувати **observable state** (response codes, protocol states, parser phases, returned object types) як додатковий feedback:

- Зберігай **valid prefix messages** стабільними та зосереджуй мутації на повідомленні, що **керує transition**.
- Кешуй identifiers і server-generated values з попередніх responses, коли наступний крок від них залежить.
- Віддавай перевагу per-message mutation/splicing замість мутації всього serialized transcript як opaque blob.
- Якщо protocol надає meaningful response codes, використовуй їх як **cheap state oracle**, щоб пріоритизувати sequences, які просуваються глибше.

Саме тому authenticated bugs, hidden transitions або parser bugs типу “only-after-handshake” часто пропускаються звичайним file-style fuzzing: fuzzer має зберігати **order, state і dependencies**, а не лише structure.

## Single-Machine Diversity Trick (Jackalope-Style)

Практичний спосіб поєднати **generative novelty** з **coverage reuse** — це **перезапускати короткоживучі workers** проти persistent server. Кожен worker стартує з порожнього corpus, синхронізується через `T` секунд, ще `T` секунд працює на combined corpus, знову синхронізується, а потім завершується. Це дає **свіжі structures на кожному поколінні** і водночас використовує накопичене coverage.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Послідовні workers (приклад циклу):**

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

- `-in empty` примусово створює **fresh corpus** для кожної генерації.
- `-server_update_interval T` наближує **delayed sync** (novelty first, reuse later).
- У режимі grammar fuzzing початкова server sync за замовчуванням пропускається (не потрібно `-skip_initial_server_sync`).
- Оптимальне `T` є **target-dependent**; перехід після того, як worker знайшов більшість “easy” coverage, зазвичай працює найкраще.

## Snapshot Fuzzing For Hard-To-Harness Targets

Коли код, який ви хочете тестувати, стає досяжним лише **після значних витрат на setup** (завантаження VM, завершення login, отримання packet, parsing container, ініціалізація service), корисною альтернативою є **snapshot fuzzing**:

1. Запустіть target, доки не буде готовий цікавий стан.
2. Зробіть snapshot **memory + registers** у цей момент.
3. Для кожного test case записуйте змінений input безпосередньо у відповідний guest/process buffer.
4. Виконуйте до crash/timeout/reset.
5. Відновлюйте лише **dirty pages** і повторюйте.

Це дозволяє уникнути повної вартості setup на кожній ітерації й особливо корисно для **network services**, **firmware**, **post-auth attack surfaces** та **binary-only targets**, які складно переробити у класичний in-process harness.

Практичний трюк — одразу зупинитися після точки `recv`/`read`/packet-deserialization, записати адресу input buffer, зробити snapshot там, а потім змінювати цей buffer безпосередньо в кожній ітерації. Це дає змогу fuzzувати глибоку parsing logic, не перебудовуючи весь handshake щоразу.

## Harness Introspection: Find Shallow Fuzzers Early

Коли кампанія зупиняється, проблема часто не в mutator, а в **harness**. Використовуйте **reachability/coverage introspection**, щоб знайти functions, які статично досяжні з вашого fuzz target, але динамічно покриваються рідко або взагалі ніколи. Такі functions зазвичай вказують на одну з трьох проблем:

- harness входить у target занадто пізно або занадто рано.
- seed corpus не містить цілу сім’ю features.
- target справді потребує **second harness** замість одного надто великого harness “do everything”.

Якщо ви використовуєте OSS-Fuzz / ClusterFuzz-style workflows, Fuzz Introspector корисний для такого triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Використайте звіт, щоб вирішити, чи додавати новий harness для неперевіреного шляху parser, розширювати corpus для конкретної feature, чи розділити monolithic harness на менші entry points.

## Graph-First Fuzz Target Selection And Mutation Triage

Якщо у вас уже є **static-analysis findings**, **mutation-testing survivors** і **coverage reports**, не triage їх як незалежні списки. Спочатку побудуйте **call graph**, позначте вузли **cyclomatic complexity**, **entrypoint/untrusted-input reachability** та будь-якими зовнішніми findings, а потім ставте graph questions:

- Які функції з високою complexity reachable з untrusted input?
- Які mutation survivors знаходяться на path від parsers/handlers до security-critical code?
- Які функції є architectural choke points із незвично високим **blast radius**?

Зазвичай це виявляє кращі fuzz targets, ніж просто "lowest coverage". parser/decoder з **high complexity** і підтвердженою **external reachability** — сильніший кандидат для harness, ніж ізольований internal helper зі слабким coverage, але без attacker-controlled path.

### Practical triage workflow

1. Побудуйте **code graph** з codebase і витягніть per-function complexity/branch metrics.
2. Перелічіть **entrypoints**, що приймають attacker-controlled input: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Запустіть **path queries** від цих entrypoints до candidate functions, щоб відокремити reachable attack surface від dead/internal-only code.
4. Пріоритезуйте вузли, які поєднують:
- high **cyclomatic complexity**
- confirmed **reachability from untrusted input**
- high **blast radius** або багато downstream dependents
- підтверджуючі докази, такі як **SARIF** findings, audit notes або mutation survivors
5. Пишіть focused harnesses спочатку для найкращих за score вузлів, особливо **parsers/codecs**, таких як hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing часто породжує шумний список survivors. Перш ніж вважати кожен survivor security gap, використайте graph, щоб запитати:

- Чи mutated function reachable з attacker-controlled entrypoint?
- Чи всі call paths обмежені stronger invariants, ніж mutated check?
- Чи знаходиться вузол у dead code, formatting-only logic або у high-impact arithmetic/parser path?

Survivors, що залишаються unreachable або structurally constrained, часто є **equivalent mutants**. Survivors, які залишаються **reachable** і зачіпають **boundary conditions**, **overflow/carry paths** або **security-critical arithmetic/parsing**, слід переводити в:

- new fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

Якщо ваш SAST pipeline експортує **SARIF**, проєктуйте findings на graph nodes за **file + line range** і використовуйте graph, щоб розширити impact:

- обчисліть **blast radius** позначеної функції
- перевірте, чи finding лежить на будь-якому path від entrypoint
- кластеризуйте nearby findings, що зводяться до того самого choke point

Це корисно, коли ви вирішуєте, чи витрачати fuzzing time на конкретну function: вузол, який є **reachable**, **complex** і вже має **SAST hits**, часто краща ціль, ніж просто complex вузол без attacker path.

Example workflow with Trailmark:
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
Важлива методологія — це перетин: **complexity x exposure x impact**. Використовуйте граф, щоб обирати fuzz targets з найвищою очікуваною security value, а потім використовуйте mutation survivors, щоб визначити, які boundaries та invariants ваш harness має перевіряти.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)

{{#include ../banners/hacktricks-training.md}}
