# Методологія Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

У **mutational grammar fuzzing** вхідні дані мутуються, залишаючись **grammar-valid**. У режимі coverage-guided лише ті зразки, що викликають **new coverage**, зберігаються як corpus seeds. Для **language targets** (parsers, interpreters, engines) це може пропускати баги, які вимагають **semantic/dataflow chains**, де вихід одного конструкта стає входом для іншого.

**Failure mode:** fuzzer знаходить seeds, які окремо використовують `document()` і `generate-id()` (або подібні primitives), але **не зберігає chained dataflow**, тому зразок, що “ближчий до багу”, відкидається, бо він не додає coverage. За наявності **3+ dependent steps** випадкове recombination стає дорогим, а coverage feedback не спрямовує пошук.

**Implication:** для граматик із великою кількістю dependencies варто розглянути **hybridizing mutational and generative phases** або змістити генерацію в бік патернів **function chaining** (а не лише coverage).

## Corpus Diversity Pitfalls

Coverage-guided mutation є **greedy**: зразок із новим coverage одразу зберігається, часто залишаючи великі незмінені області. З часом corpora перетворюються на **near-duplicates** із низькою структурною різноманітністю. Агресивна minimization може прибрати корисний context, тому практичний компроміс — **grammar-aware minimization**, яка **зупиняється після мінімального порогу token** (зменшує шум, але зберігає достатньо навколишньої структури, щоб залишатися зручною для mutation).

Практичне правило для corpus у mutational fuzzing таке: **надавати перевагу невеликому набору структурно різних seeds, які максимізують coverage**, замість великої купи near-duplicates. На практиці це зазвичай означає:

- Починати з **real-world samples** (public corpora, crawling, captured traffic, file sets із target ecosystem).
- Відсікати їх за допомогою **coverage-based corpus minimization** замість збереження кожного valid sample.
- Тримати seeds **достатньо малими**, щоб mutations потрапляли в meaningful fields, а не витрачали більшість циклів на irrelevant bytes.
- Повторно запускати corpus minimization після великих змін у harness/instrumentation, бо “найкращий” corpus змінюється, коли змінюється reachability.

## Comparison-Aware Mutation For Magic Values

Поширена причина, чому fuzzer виходить на плато, — це не syntax, а **hard comparisons**: magic bytes, length checks, enum strings, checksums або parser dispatch values, захищені `memcmp`, switch tables чи cascaded comparisons. Чиста random mutation марнує цикли, намагаючись вгадати ці значення byte-by-byte.

Для таких targets використовуйте **comparison tracing** (наприклад, AFL++ `CMPLOG` / Redqueen-style workflows), щоб fuzzer міг спостерігати operands із failed comparisons і зміщувати mutations у бік значень, які їх задовольняють.
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
**Практичні примітки:**

- Це особливо корисно, коли ціль приховує глибоку логіку за **file signatures**, **protocol verbs**, **type tags** або **version-dependent feature bits**.
- Поєднуйте це з **dictionaries**, витягнутими з реальних зразків, protocol specs або debug logs. Невеликий dictionary з grammar tokens, chunk names, verbs і delimiters часто цінніший за величезний generic wordlist.
- Якщо ціль виконує багато послідовних перевірок, спочатку розв’яжіть найраніші “magic” порівняння, а потім знову мінімізуйте отриманий corpus, щоб наступні етапи стартували вже з валідних prefixes.

## Stateful Fuzzing: Sequences Are Seeds

Для **protocols**, **authenticated workflows** і **multi-stage parsers** цікавою одиницею часто є не один blob, а **message sequence**. Просто склеїти весь transcript в один файл і бездумно мутувати його зазвичай неефективно, бо fuzzer мутує кожен крок однаково, навіть коли до крихкого стану доходить лише пізніше повідомлення.

Більш ефективний підхід — трактувати саму **sequence** як seed і використовувати **observable state** (response codes, protocol states, parser phases, returned object types) як додатковий feedback:

- Зберігайте **valid prefix messages** стабільними й зосереджуйте мутації на повідомленні, що **керує переходом**.
- Кешуйте identifiers і server-generated values з попередніх responses, коли наступний крок від них залежить.
- Віддавайте перевагу per-message mutation/splicing замість мутації всього serialized transcript як непрозорого blob.
- Якщо protocol надає змістовні response codes, використовуйте їх як **cheap state oracle**, щоб пріоритизувати sequences, які просуваються глибше.

Це та сама причина, чому authenticated bugs, hidden transitions або parser bugs типу “only-after-handshake” часто пропускаються звичайним file-style fuzzing: fuzzer має зберігати **order, state і dependencies**, а не лише структуру.

## Single-Machine Diversity Trick (Jackalope-Style)

Практичний спосіб поєднати **generative novelty** з **coverage reuse** — **перезапускати короткоживучі workers** проти persistent server. Кожен worker стартує з порожнім corpus, синхронізується через `T` seconds, ще `T` seconds працює з об’єднаним corpus, знову синхронізується, а потім завершується. Це дає **fresh structures each generation** і водночас використовує накопичений coverage.

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

**Нотатки:**

- `-in empty` змушує **свіжий corpus** для кожної генерації.
- `-server_update_interval T` наближує **відкладену синхронізацію** (novelty спочатку, reuse пізніше).
- У режимі grammar fuzzing початкова server sync **пропускається за замовчуванням** (не потрібно `-skip_initial_server_sync`).
- Оптимальне `T` **залежить від target**; перемикання після того, як worker знайшов більшість “easy” coverage, зазвичай працює найкраще.

## Snapshot Fuzzing For Hard-To-Harness Targets

Коли код, який ви хочете тестувати, стає досяжним лише **після великої вартості setup** (запуск VM, завершення login, отримання packet, parsing контейнера, ініціалізація service), корисною альтернативою є **snapshot fuzzing**:

1. Запустіть target до готовності цікавої state.
2. Зніміть snapshot **memory + registers** у цей момент.
3. Для кожного test case записуйте mutated input безпосередньо у відповідний guest/process buffer.
4. Виконуйте до crash/timeout/reset.
5. Відновлюйте лише **dirty pages** і повторюйте.

Це дозволяє уникнути повної вартості setup на кожній ітерації й особливо корисно для **network services**, **firmware**, **post-auth attack surfaces** та **binary-only targets**, які важко переробити на класичний in-process harness.

Практичний прийом — зупинятися одразу після точки `recv`/`read`/packet-deserialization, зафіксувати адресу input buffer, зробити snapshot саме там, а потім змінювати цей buffer безпосередньо в кожній ітерації. Це дає змогу fuzzing глибоку parsing logic без перебудови всього handshake щоразу.

## Harness Introspection: Find Shallow Fuzzers Early

Коли campaign зупиняється, проблема часто не в mutator, а в **harness**. Використовуйте **reachability/coverage introspection**, щоб знайти functions, які статично reachable від вашого fuzz target, але рідко або ніколи не covered динамічно. Такі functions зазвичай вказують на одну з трьох проблем:

- harness входить у target занадто пізно або занадто рано.
- seed corpus не містить цілої family features.
- target справді потребує **second harness** замість одного надто великого harness “do everything”.

Якщо ви використовуєте OSS-Fuzz / ClusterFuzz-style workflows, Fuzz Introspector корисний для цього triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Use the report to decide whether to add a new harness for an untested parser path, expand the corpus for a specific feature, or split a monolithic harness into smaller entry points.

## Graph-First Вибір Fuzz Targetів і Mutation Triage

If you already have **static-analysis findings**, **mutation-testing survivors**, and **coverage reports**, don't triage them as independent lists. Build a **call graph** first, annotate nodes with **cyclomatic complexity**, **entrypoint/untrusted-input reachability**, and any external findings, then ask graph questions:

- Which high-complexity functions are reachable from untrusted input?
- Which mutation survivors sit on paths from parsers/handlers to security-critical code?
- Which functions are architectural choke points with unusually high **blast radius**?

This usually surfaces better fuzz targets than "lowest coverage" alone. A parser/decoder with **high complexity** and confirmed **external reachability** is a stronger harness candidate than an isolated internal helper with weak coverage but no attacker-controlled path.

### Practical triage workflow

1. Build a **code graph** from the codebase and extract per-function complexity/branch metrics.
2. Enumerate **entrypoints** that accept attacker-controlled input: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Run **path queries** from those entrypoints to candidate functions to separate reachable attack surface from dead/internal-only code.
4. Prioritize nodes that combine:
- high **cyclomatic complexity**
- confirmed **reachability from untrusted input**
- high **blast radius** or many downstream dependents
- corroborating evidence such as **SARIF** findings, audit notes, or mutation survivors
5. Write focused harnesses for the best-scoring nodes first, especially **parsers/codecs** such as hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing often produces a noisy survivor list. Before treating every survivor as a security gap, use the graph to ask:

- Is the mutated function reachable from an attacker-controlled entrypoint?
- Are all call paths constrained by stronger invariants than the mutated check?
- Does the node sit in dead code, formatting-only logic, or in a high-impact arithmetic/parser path?

Survivors that remain unreachable or structurally constrained are often **equivalent mutants**. Survivors that stay **reachable** and touch **boundary conditions**, **overflow/carry paths**, or **security-critical arithmetic/parsing** should be promoted into:

- new fuzz harnesses
- direct property/invariant tests
- targeted edge-case vectors

### Correlate external findings onto the graph

If your SAST pipeline exports **SARIF**, project findings onto graph nodes by **file + line range** and use the graph to expand the impact:

- compute the **blast radius** of the flagged function
- check whether the finding is on any path from an entrypoint
- cluster nearby findings that collapse into the same choke point

This is useful when deciding whether to spend fuzzing time on a specific function: a node that is **reachable**, **complex**, and already has **SAST hits** is often a better target than a merely complex node with no attacker path.

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
Важлива методологія — це перетин: **complexity x exposure x impact**. Використовуйте граф, щоб обирати fuzz targets з найвищою очікуваною цінністю для безпеки, а потім використовуйте mutation survivors, щоб визначити, які межі та invariants має навантажувати ваш harness.

## Go Fuzzing With gosentry: Stronger Engine, Typed Inputs, And Differential Checks

Якщо Go target уже має native `testing.F` harness, практичний шлях оновлення — запускати той самий harness з [gosentry](https://github.com/trailofbits/gosentry), forked Go toolchain, який зберігає `go test -fuzz`, але замінює backend на **LibAFL**.
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Це корисно, коли native Go fuzzer зависає на **hard comparisons**, **typed inputs** або **parser-heavy formats**. Методологія лишається тією самою:

- Продовжуйте використовувати `f.Add(...)` для seeds і `f.Fuzz(...)` для callback.
- Повторно використовуйте той самий harness, але запускайте його з `go` binary від gosentry замість стандартного toolchain.
- Сприймайте результат кампанії як звичайний coverage-guided run, але з LibAFL scheduling/mutation і кращими зовнішніми detectors.

### Перетворюйте silent failures на fuzz findings

Повторювана проблема в Go assessments полягає в тому, що небезпечна поведінка часто за замовчуванням не викликає **crash**. З gosentry ви можете перетворити кілька класів “bad but silent” станів на findings:

- `--panic-on=pkg.Func,...` щоб змусити вибрані logging/error paths поводитися як crashes (корисно для `log.Fatal`-style code paths, які інакше лише логують і продовжують).
- `--catch-races=true` щоб повторно програвати newly discovered queue entries з Go race detector.
- `--catch-leaks=true` щоб повторно програвати new queue entries з `goleak` і зупинятися на goroutine leaks.
- LibAFL hang handling, щоб зберігати **infinite loops / very slow inputs** як fuzz findings, а не давати їм зникати як timeouts.
- Вбудовані перевірки arithmetic overflow за замовчуванням, плюс optional truncation checks через go-panikint-style instrumentation.

Це особливо цінно для targets, де security impact — це **panicless parser failure**, **concurrency bug** або **DoS-only hang**, а не memory corruption.

### Struct-aware fuzzing для typed Go APIs

Native Go fuzzing переважно очікує scalars, такі як `[]byte`, `string` і числа. Якщо код під тестом споживає typed objects, gosentry може fuzz **composite values** безпосередньо (structs, slices, arrays, pointers), усе ще mutating bytes під капотом.
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
Використовуйте це під час створення фейкового wire format лише для fuzzing, оскільки це приховує logic bugs за harness-only parsing code. Для differential або grammar-based campaigns краще тримати input harness як один `[]byte` або `string` і парсити всередині callback.

### Grammar-based fuzzing for parsers and protocol inputs

Для parsers, formats і input languages gosentry може запускати **Nautilus grammar fuzzing** поверх LibAFL. Grammar — це JSON array правил production rules, і harness зазвичай має приймати один аргумент `[]byte` або `string`.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Нотатки щодо методології:

- Використовуйте grammar mode, коли побітові мутації здебільшого гинуть на ранніх syntax checks.
- Тримайте grammar зосередженою на **security-relevant subset** мови/протоколу замість моделювання повної специфікації.
- Використовуйте великі boundary values у terminals/nonterminals, щоб навантажити integer, length і state-machine edges.
- Grammar mode зберігає inputs grammar-valid, але target усе ще отримує **bytes/strings**, тож parsing і semantic checks залишаються всередині harnessed code.

### Differential fuzzing: порівнюйте implementations, а не лише crashes

Сильний pattern для Go ecosystems — **grammar-based differential fuzzing**: генеруйте valid structured inputs і передавайте їх двом parsers, clients або state-transition engines.
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
Treat the following as findings:

- одна реалізація panic-ить, тоді як інша коректно відхиляє
- невідповідності у прийнятому/відхиленому input
- різні parse trees або decoded objects
- розбіжні переходи стану, nonce, balances або state roots

Це практичний спосіб знаходити **consensus mismatches**, **parser ambiguity** та **spec-vs-implementation drift**, які чистий crash fuzzing часто пропускає.

### Повторно використовуйте corpus кампанії для coverage reporting

Після кампанії повторно програйте збережений queue corpus, щоб згенерувати Go coverage report без ручного експорту окремого corpus:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Запустіть команду з **того самого package** і з тим самим `-fuzz` target, щоб gosentry визначив правильний cached campaign state.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [Go fuzzing was missing half the toolkit. We forked the toolchain to fix it.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
