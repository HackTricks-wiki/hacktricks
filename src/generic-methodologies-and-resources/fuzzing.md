# Методологія Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: покриття проти семантики

У **mutational grammar fuzzing** вхідні дані мутують, залишаючись **валідними відповідно до граматики**. У режимі, керованому покриттям, до corpus як seeds зберігаються лише зразки, що забезпечують **нове покриття**. Для **мовних targets** (парсерів, інтерпретаторів, рушіїв) це може пропускати баги, які потребують **семантичних/dataflow-ланцюжків**, де вихід одного конструкта стає входом іншого.

**Режим відмови:** fuzzer знаходить seeds, які окремо задіюють `document()` і `generate-id()` (або подібні примітиви), але **не зберігає ланцюжок dataflow**, тому зразок, “ближчий до бага”, відкидається, оскільки не додає покриття. За наявності **3+ залежних кроків** випадкова рекомбінація стає дорогою, а feedback від покриття не спрямовує пошук.

**Наслідок:** для граматик із великою кількістю залежностей варто **гібридизувати mutational і generative фази** або змістити генерацію в бік шаблонів **ланцюжків функцій** (а не лише покриття).<sup>[[1]](#references)</sup>

## Підводні камені різноманітності Corpus

Mutation, керована покриттям, є **жадібною**: зразок із новим покриттям зберігається одразу, часто зберігаючи великі незмінені області. З часом corpus перетворюється на набір **майже дублікатів** із низькою структурною різноманітністю. Агресивна мінімізація може видалити корисний контекст, тому практичним компромісом є **мінімізація з урахуванням граматики**, яка **зупиняється після досягнення мінімального порогу токенів** (зменшуючи шум і зберігаючи достатньо оточувальної структури для зручної mutation).<sup>[[1]](#references)</sup>

Практичне правило для corpus у mutational fuzzing: **краще мати невеликий набір структурно різних seeds, що максимізують покриття**, ніж велику кількість майже дублікатів. На практиці це зазвичай означає:<sup>[[1]](#references)</sup>

- Починайте з **зразків реального світу** (публічних corpus, crawling, захопленого трафіку, наборів файлів з екосистеми target).
- Очищуйте їх за допомогою **мінімізації corpus на основі покриття**, замість зберігання кожного валідного зразка.
- Тримайте seeds **достатньо малими**, щоб mutations потрапляли у значущі поля, а не витрачали більшість циклів на нерелевантні байти.
- Повторно запускайте мінімізацію corpus після значних змін harness або instrumentation, оскільки “найкращий” corpus змінюється зі зміною reachability.

## Comparison-Aware Mutation для Magic Values

Поширена причина, через яку fuzzers досягають плато, полягає не в синтаксисі, а в **жорстких порівняннях**: magic bytes, перевірках довжини, enum-рядках, checksums або значеннях dispatch парсера, захищених через `memcmp`, switch-таблиці чи каскадні порівняння. Чиста випадкова mutation витрачає цикли, намагаючись вгадати ці значення побайтно.

Для таких targets використовуйте **comparison tracing** (наприклад, робочі процеси на основі AFL++ `CMPLOG` / Redqueen), щоб fuzzer міг спостерігати операнди невдалих порівнянь і спрямовувати mutations до значень, які їх задовольняють.<sup>[[3]](#references)</sup>
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

- Це особливо корисно, коли target блокує глибоку логіку за **file signatures**, **protocol verbs**, **type tags** або **version-dependent feature bits**.
- Поєднуйте це зі **словниками**, витягнутими з реальних зразків, специфікацій протоколів або debug logs. Невеликий словник із grammar tokens, назвами chunk, verbs і delimiters часто цінніший за величезний загальний wordlist.
- Якщо target виконує багато послідовних перевірок, спочатку розв'яжіть найраніші порівняння “magic”, а потім знову мінімізуйте отриманий corpus, щоб наступні етапи починалися з уже валідних префіксів.

## Stateful Fuzzing: Sequences Are Seeds

Для **протоколів**, **authenticated workflows** і **multi-stage parsers** цікавою одиницею часто є не один blob, а **послідовність повідомлень**. Об'єднувати весь transcript в один файл і мутувати його наосліп зазвичай неефективно, оскільки fuzzer однаково мутує кожен крок, навіть коли лише пізніше повідомлення досягає вразливого стану.

Ефективніший підхід полягає в тому, щоб розглядати **саму послідовність як seed** і використовувати **спостережуваний стан** (коди відповідей, стани протоколу, фази parser, типи повернених об'єктів) як додатковий feedback:<sup>[[4]](#references)</sup>

- Зберігайте **валідні повідомлення префікса** незмінними та зосередьте мутації на повідомленні, що **керує переходом**.
- Кешуйте ідентифікатори та значення, згенеровані server, з попередніх відповідей, коли наступний крок залежить від них.
- Надавайте перевагу мутації/splicing окремих повідомлень замість мутації всього серіалізованого transcript як непрозорого blob.
- Якщо протокол надає змістовні коди відповідей, використовуйте їх як **дешевий oracle стану**, щоб надавати пріоритет послідовностям, які просуваються глибше.

Саме тому vanilla file-style fuzzing часто пропускає authenticated bugs, приховані переходи або parser bugs, що виникають “лише після handshake”: fuzzer має зберігати **порядок, стан і залежності**, а не лише структуру.

## Single-Machine Diversity Trick (Jackalope-Style)

Практичний спосіб поєднати **generative novelty** із **повторним використанням coverage** — **перезапускати короткоживучі workers** проти persistent server. Кожен worker починає з порожнього corpus, синхронізується через `T` секунд, працює ще `T` секунд із combined corpus, знову синхронізується, а потім завершує роботу. Це забезпечує **свіжі структури в кожному поколінні**, водночас використовуючи накопичений coverage.<sup>[[2]](#references)</sup>

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Послідовні workers (приклад циклу):**

<details>
<summary>Цикл перезапуску worker Jackalope</summary>
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

- `-in empty` змушує використовувати **свіжий corpus** під час кожної генерації.
- `-server_update_interval T` наближено імітує **delayed sync** (спочатку пошук новизни, потім повторне використання).
- У режимі grammar fuzzing **initial server sync** за замовчуванням пропускається (потреби в `-skip_initial_server_sync` немає).
- Оптимальне значення `T` **залежить від target**; зазвичай найкраще перемикатися після того, як worker знайде більшість “легкого” покриття.

## Snapshot Fuzzing Для Target, Які Складно Підготувати

Коли код, який потрібно тестувати, стає доступним лише після значних витрат на підготовку (завантаження VM, завершення login, отримання packet, парсинг container, ініціалізація service), корисною альтернативою є **snapshot fuzzing**:

1. Запустіть target, доки потрібний стан не буде готовий.
2. Зробіть snapshot **memory + registers** у цей момент.
3. Для кожного test case запишіть мутований input безпосередньо у відповідний guest/process buffer.
4. Виконуйте target до crash/timeout/reset.
5. Відновлюйте лише **dirty pages** і повторюйте процес.

Це дає змогу не оплачувати повну вартість підготовки на кожній ітерації та особливо корисно для **network services**, **firmware**, **post-auth attack surfaces** і **binary-only targets**, які складно переробити у класичний in-process harness.

Практичний прийом — зупинитися одразу після точки `recv`/`read`/packet-deserialization, визначити адресу input buffer, зробити snapshot у цей момент, а потім безпосередньо змінювати цей buffer на кожній ітерації. Це дає змогу fuzz-ити глибоку логіку парсингу без повторної побудови всього handshake щоразу.

## Harness Introspection: Раннє Виявлення Shallow Fuzzers

Коли campaign зупиняється, проблема часто полягає не в mutator, а в **harness**. Використовуйте **reachability/coverage introspection**, щоб знаходити функції, які статично доступні з вашої fuzz target, але динамічно покриваються рідко або взагалі не покриваються. Такі функції зазвичай вказують на одну з трьох проблем:

- harness входить у target надто пізно або надто рано.
- У seed corpus відсутнє ціле сімейство feature.
- Насправді target потребує **другого harness**, а не одного надмірно великого harness у стилі “do everything”.

Якщо ви використовуєте workflows у стилі OSS-Fuzz / ClusterFuzz, Fuzz Introspector корисний для такого triage:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Використовуйте звіт, щоб вирішити, чи додати новий harness для нетестованого шляху parser, розширити corpus для конкретної функції або розділити монолітний harness на менші entry point.

## Вибір Fuzz Target на основі графа та triage mutation

Якщо у вас уже є **static-analysis findings**, **mutation-testing survivors** і **coverage reports**, не розглядайте їх як незалежні списки. Спочатку побудуйте **call graph**, додайте до вузлів позначки з **cyclomatic complexity**, **entrypoint/untrusted-input reachability** і всі зовнішні findings, а потім поставте графові запитання:<sup>[[5]](#references)[[6]](#references)</sup>

- Які функції з високою complexity досяжні з untrusted input?
- Які mutation survivors знаходяться на шляхах від parsers/handlers до security-critical code?
- Які функції є архітектурними choke points із незвично великим **blast radius**?

Зазвичай це виявляє кращі fuzz targets, ніж орієнтація лише на "найнижче coverage". Parser/decoder із **високою complexity** і підтвердженою **external reachability** є сильнішим кандидатом для harness, ніж ізольований внутрішній helper зі слабким coverage, але без шляху, контрольованого атакером.

### Практичний workflow triage

1. Побудуйте **code graph** з codebase і отримайте метрики complexity/branch для кожної функції.
2. Перелічіть **entrypoints**, які приймають input, контрольований атакером: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Виконайте **path queries** від цих entrypoints до candidate functions, щоб відокремити reachable attack surface від dead/internal-only code.
4. Пріоритезуйте вузли, які поєднують:
- високу **cyclomatic complexity**
- підтверджену **reachability from untrusted input**
- великий **blast radius** або багато downstream dependents
- додаткові підтвердження, як-от findings у **SARIF**, audit notes або mutation survivors
5. Спочатку створюйте сфокусовані harnesses для вузлів із найвищим балом, особливо для **parsers/codecs**, таких як hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing часто створює зашумлений список survivors. Перш ніж вважати кожен survivor security gap, використайте граф, щоб з’ясувати:

- Чи досяжна mutated function з entrypoint, контрольованого атакером?
- Чи всі call paths обмежені сильнішими invariants, ніж mutated check?
- Чи знаходиться вузол у dead code, logic, пов’язаній лише з formatting, або у high-impact arithmetic/parser path?

Survivors, які залишаються unreachable або структурно обмеженими, часто є **equivalent mutants**. Survivors, які залишаються **reachable** і зачіпають **boundary conditions**, **overflow/carry paths** або **security-critical arithmetic/parsing**, слід перетворити на:

- нові fuzz harnesses
- прямі property/invariant tests
- цільові edge-case vectors

### Correlate external findings onto the graph

Якщо ваш SAST pipeline експортує **SARIF**, спроєктуйте findings на вузли графа за **file + line range** і використайте граф, щоб розширити оцінку впливу:

- обчисліть **blast radius** flagged function
- перевірте, чи знаходиться finding на будь-якому шляху від entrypoint
- кластеризуйте nearby findings, які зводяться до того самого choke point

Це корисно, коли потрібно вирішити, на яку конкретну функцію витратити час fuzzing: вузол, який є **reachable**, **complex** і вже має **SAST hits**, часто є кращою ціллю, ніж просто complex вузол без шляху атакера.

Приклад workflow з Trailmark:<sup>[[6]](#references)</sup>
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
Важлива методологія — це перетин: **складність x відкритість x вплив**. Використовуйте графік, щоб обирати fuzz targets із найвищою очікуваною цінністю для безпеки, а потім використовуйте mutation survivors, щоб визначити, які межі та інваріанти має перевіряти ваш harness.

## Fuzzing у Go за допомогою gosentry: потужніший рушій, типізовані входи та диференційні перевірки

Якщо Go target уже має native harness на основі `testing.F`, практичним шляхом удосконалення є запуск того самого harness за допомогою [gosentry](https://github.com/trailofbits/gosentry) — forked Go toolchain, який зберігає `go test -fuzz`, але замінює backend на **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Це корисно, коли native Go fuzzer зупиняється на **складних порівняннях**, **типізованих входах** або **форматах із великою роллю парсера**. Методологія залишається незмінною:

- Продовжуйте використовувати `f.Add(...)` для seed-ів і `f.Fuzz(...)` для callback.
- Повторно використовуйте той самий harness, але запускайте його за допомогою бінарного файлу `go` від gosentry замість стандартного toolchain.
- Розглядайте отриману кампанію як звичайний coverage-guided запуск, але з плануванням/мутацією LibAFL і кращими супровідними детекторами.

### Перетворення тихих збоїв на fuzz findings

Поширена проблема під час Go assessment полягає в тому, що небезпечна поведінка часто **не спричиняє crash за замовчуванням**. За допомогою gosentry можна перетворити кілька класів станів «погано, але безшумно» на findings:

- `--panic-on=pkg.Func,...` — щоб вибрані шляхи logging/error поводилися як crash. Це корисно для шляхів на кшталт `log.Fatal`, які інакше лише записують log і продовжують виконання.
- `--catch-races=true` — щоб повторно запускати щойно знайдені queue entries з Go race detector.
- `--catch-leaks=true` — щоб повторно запускати нові queue entries за допомогою `goleak` і зупинятися при виявленні goroutine leaks.
- Обробка hang у LibAFL, яка зберігає **нескінченні цикли / дуже повільні inputs** як fuzz findings замість того, щоб вони зникали як timeouts.
- Вбудовані перевірки arithmetic overflow за замовчуванням, а також опційні перевірки truncation через instrumentation у стилі go-panikint.

Це особливо цінно для targets, де наслідком для security є **помилка parser без panic**, **concurrency bug** або **hang, що спричиняє лише DoS**, а не memory corruption.

### Struct-aware fuzzing для типізованих Go API

Native Go fuzzing переважно очікує scalars, як-от `[]byte`, `string` і числа. Якщо код, що тестується, приймає типізовані об’єкти, gosentry може безпосередньо fuzz-ити **composite values** (structs, slices, arrays, pointers), водночас виконуючи мутацію bytes на нижньому рівні.
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
Використовуйте це під час створення фальшивого wire format лише для fuzzing, оскільки це може приховати логічні помилки за кодом парсингу, наявним лише в harness. Для differential або grammar-based кампаній залишайте вхідні дані harness як один `[]byte` або `string` і виконуйте парсинг всередині callback.

### Grammar-based fuzzing для парсерів і протокольних вхідних даних

Для парсерів, форматів і мов введення gosentry може запускати **Nautilus grammar fuzzing** поверх LibAFL. Граматика є JSON-масивом production rules, а harness зазвичай має приймати один аргумент `[]byte` або `string`.
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Нотатки щодо методології:

- Використовуйте grammar mode, коли мутації на рівні байтів здебільшого відсіюються на ранніх syntax checks.
- Зосереджуйте grammar на **security-relevant subset** мови/протоколу замість моделювання всієї specification.
- Використовуйте великі граничні значення в terminals/nonterminals, щоб навантажити межі integer, length і state-machine.
- Grammar mode зберігає inputs валідними відповідно до grammar, але target усе одно отримує **bytes/strings**, тому parsing і semantic checks залишаються всередині harnessed code.

### Differential fuzzing: порівнюйте implementations, а не лише crashes

Надійним підходом для Go ecosystems є **grammar-based differential fuzzing**: генеруйте валідні структуровані inputs і передавайте їх двом parsers, clients або state-transition engines.
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
Розглядайте наведене нижче як результати:

- одна реалізація аварійно завершується, тоді як інша коректно відхиляє дані
- невідповідності між прийнятими та відхиленими вхідними даними
- різні дерева розбору або декодовані об'єкти
- розбіжності в переходах станів, nonce, балансах або коренях стану

Це практичний спосіб виявлення **невідповідностей консенсусу**, **неоднозначності парсера** та **розбіжностей між специфікацією та реалізацією**, які часто не виявляються під час звичайного fuzzing, орієнтованого лише на аварійне завершення.

### Повторно використовуйте corpus кампанії для звітування про покриття

Після кампанії повторно відтворіть збережений queue corpus, щоб згенерувати звіт про покриття Go без ручного експорту окремого corpus:
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Запустіть команду з **того самого package** і з тією самою ціллю `-fuzz`, щоб gosentry визначив правильний стан кешованої кампанії.

## References

- [1] [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet Five Years Later: Про coverage-guided protocol fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark перетворює код на графи](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [У Go fuzzing бракувало половини toolkit. Ми fork-нули toolchain, щоб це виправити.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)

{{#include ../banners/hacktricks-training.md}}
