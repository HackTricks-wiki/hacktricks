# Методологія Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

У **mutational grammar fuzzing** вхідні дані мутують, залишаючись **grammar-valid**. У режимі coverage-guided зберігаються як corpus seeds лише зразки, що забезпечують **new coverage**. Для **language targets** (парсерів, інтерпретаторів, рушіїв) це може пропускати баги, які потребують **semantic/dataflow chains**, де результат одного конструкта стає вхідними даними для іншого.<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer знаходить seeds, які окремо задіюють `document()` і `generate-id()` (або подібні primitives), але **не зберігає chained dataflow**, тому зразок, “ближчий до бага”, відкидається, оскільки не додає coverage. За наявності **3+ dependent steps** випадкова рекомбінація стає дорогою, а coverage feedback не спрямовує пошук.<sup>[[1]](#references)</sup>

**Implication:** для grammar із великою кількістю залежностей варто **гібридизувати mutational і generative phases** або зміщувати генерацію в бік патернів **function chaining** (а не покладатися лише на coverage).<sup>[[1]](#references)</sup>

## Підводні камені різноманітності Corpus

Coverage-guided mutation є **greedy**: зразок із new coverage зберігається одразу, часто із великими незміненими ділянками. З часом corpus перетворюється на набір **near-duplicates** із низькою структурною різноманітністю. Надмірна minimization може видалити корисний контекст, тому практичним компромісом є **grammar-aware minimization**, яка **зупиняється після досягнення мінімального порога токенів** (зменшуючи шум, але зберігаючи достатньо навколишньої структури для зручності mutation).<sup>[[1]](#references)</sup>

Практичне правило для corpus у mutational fuzzing: **надавати перевагу невеликому набору структурно різних seeds, які максимізують coverage**, а не великій кількості near-duplicates. На практиці це зазвичай означає таке.<sup>[[1]](#references)[[3]](#references)</sup>

- Починайте з **real-world samples** (public corpora, crawling, captured traffic, file sets з екосистеми target).
- Скорочуйте їх за допомогою **coverage-based corpus minimization**, а не зберігайте кожен valid sample.
- Зберігайте seeds **достатньо малими**, щоб mutations потрапляли у значущі поля, а не витрачали більшість циклів на нерелевантні байти.
- Повторно запускайте corpus minimization після значних змін harness/instrumentation, оскільки “найкращий” corpus змінюється разом зі зміною reachability.

## Comparison-Aware Mutation Для Magic Values

Поширена причина, через яку fuzzers досягають плато, полягає не в syntax, а в **hard comparisons**: magic bytes, перевірках довжини, enum strings, checksums або значеннях parser dispatch, захищених через `memcmp`, switch tables чи каскадні порівняння. Pure random mutation марнує цикли, намагаючись вгадати ці значення побайтно.

Для таких targets використовуйте **comparison tracing** (наприклад, workflow у стилі AFL++ `CMPLOG` / Redqueen), щоб fuzzer міг спостерігати operands із невдалих comparisons і зміщувати mutations у бік значень, які задовольняють їх.<sup>[[3]](#references)</sup>
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

- Це особливо корисно, коли ціль приховує глибоку логіку за **файловими сигнатурами**, **протокольними дієсловами**, **тегами типів** або **бітами функцій, залежними від версії**.
- Поєднуйте це зі **словниками**, отриманими з реальних зразків, специфікацій протоколів або debug-логів. Невеликий словник із токенами граматики, назвами chunk, дієсловами та роздільниками часто цінніший за величезний загальний wordlist.
- Якщо ціль виконує багато послідовних перевірок, спочатку розв'яжіть найперші порівняння з “magic”, а потім знову мінімізуйте отриманий corpus, щоб наступні етапи починалися з уже валідних префіксів.

## Stateful Fuzzing: послідовності є seed

Для **протоколів**, **автентифікованих робочих процесів** і **багатоетапних парсерів** цікавою одиницею часто є не один blob, а **послідовність повідомлень**. Об'єднання всього transcript в один файл і його сліпа мутація зазвичай неефективні, оскільки fuzzer однаково змінює кожен крок, навіть коли лише пізніше повідомлення досягає вразливого стану.<sup>[[4]](#references)</sup>

Ефективніший підхід полягає в тому, щоб розглядати **саму послідовність як seed** і використовувати **спостережуваний стан** (коди відповідей, стани протоколу, фази парсера, типи повернених об'єктів) як додатковий feedback.<sup>[[4]](#references)</sup>

- Залишайте **валідні повідомлення префікса** стабільними та зосередьте мутації на повідомленні, що **керує переходом**.
- Кешуйте ідентифікатори та згенеровані сервером значення з попередніх відповідей, якщо наступний крок залежить від них.
- Надавайте перевагу мутації/splicing окремих повідомлень, а не мутації всього серіалізованого transcript як непрозорого blob.
- Якщо протокол надає змістовні коди відповідей, використовуйте їх як **дешевий oracle стану**, щоб надавати пріоритет послідовностям, які просуваються глибше.

Саме тому authenticated bugs, приховані переходи або parser bugs, що виникають “лише після handshake”, часто залишаються непоміченими під час vanilla file-style fuzzing: fuzzer має зберігати **порядок, стан і залежності**, а не лише структуру.<sup>[[4]](#references)</sup>

## Трюк із різноманітністю на одній машині (у стилі Jackalope)

Практичний спосіб поєднати **генеративну новизну** з **повторним використанням coverage** — **перезапускати короткоживучі workers** проти persistent server. Кожен worker починає з порожнього corpus, синхронізується через `T` секунд, працює ще `T` секунд із об'єднаним corpus, знову синхронізується, а потім завершує роботу. Це забезпечує **свіжі структури в кожному поколінні**, водночас використовуючи накопичене coverage.<sup>[[1]](#references)[[2]](#references)</sup>

**Сервер:**
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

- `-in empty` змушує створювати **новий corpus** під час кожної генерації.
- `-server_update_interval T` наближено моделює **відкладену синхронізацію** (спочатку пошук новизни, потім повторне використання).
- У режимі grammar fuzzing **початкова синхронізація сервера** за замовчуванням пропускається (потреби в `-skip_initial_server_sync` немає).
- Оптимальне значення `T` **залежить від target**; зазвичай найкраще перемикатися після того, як worker знайде більшість «легкого» покриття.

## Snapshot Fuzzing Для Складних Target, Які Важко Підготувати

Коли код, який потрібно тестувати, стає доступним лише **після значних витрат на підготовку** (завантаження VM, завершення login, отримання packet, парсинг container, ініціалізація service), корисною альтернативою є **snapshot fuzzing**: зберегти стан готового process або VM, вставляти кожен test case у потрібний target input path, виконувати до crash/timeout і відновлювати snapshot. Це усуває повторення ініціалізації або protocol prefixes і корисно для **network services**, **firmware**, **post-auth attack surfaces** та **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Запустіть target до моменту, коли потрібний стан буде готовий.
2. Збережіть snapshot **пам’яті + регістрів** у цей момент.
3. Для кожного test case записуйте mutated input безпосередньо у відповідний guest/process buffer.
4. Виконуйте до crash/timeout/reset.
5. Відновіть snapshot; для VM targets, якщо це підтримується, відновлюйте лише **змінені сторінки**, а потім повторюйте.

Розміщуйте snapshot максимально близько до першого дорогого кроку parse/dispatch, наприклад після `recv`/`read` або точки десеріалізації packet, і фіксуйте input buffer, який використовує target. Це відповідає принципу adaptive placement: переміщуйте snapshot глибше в обробку input, щоб уникнути повторного виконання вже зробленої роботи.<sup>[[11]](#references)</sup>

## Harness Introspection: Раннє Виявлення Shallow Fuzzers

Коли campaign зупиняється, проблема часто полягає не в mutator, а в **harness**. Використовуйте **reachability/coverage introspection**, щоб знаходити функції, які статично досяжні з fuzz target, але рідко або ніколи не покриваються динамічно. Такі функції зазвичай вказують на одну з трьох проблем.<sup>[[12]](#references)</sup>

- Harness входить у target надто пізно або надто рано.
- У seed corpus відсутнє ціле сімейство функцій.
- Target насправді потребує **другого harness**, а не одного надмірно великого harness за принципом «робити все».

Якщо ви використовуєте workflows у стилі OSS-Fuzz / ClusterFuzz, Fuzz Introspector може порівнювати статичну reachability з runtime coverage і створювати звіти на основі timed run або public corpus.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Використовуйте звіт, щоб вирішити, чи потрібно додати новий harness для неперевіреного шляху parser, розширити corpus для певної функції або розділити монолітний harness на менші entry points.

## Вибір Fuzz Target на основі графа та тріаж мутацій

Якщо у вас уже є **static-analysis findings**, **mutation-testing survivors** і **coverage reports**, не розглядайте їх як незалежні списки. Спочатку побудуйте **call graph**, а потім додайте до вузлів **cyclomatic complexity**, **entrypoint/untrusted-input reachability** і всі зовнішні findings та поставте графові запитання.<sup>[[5]](#references)[[6]](#references)</sup>

- Які функції з високою складністю досяжні з untrusted input?
- Які mutation survivors розташовані на шляхах від parser/handler до security-critical code?
- Які функції є архітектурними вузькими місцями з незвично великим **blast radius**?

Зазвичай це виявляє кращі fuzz targets, ніж орієнтація лише на "найнижче покриття". Parser/decoder із **high complexity** і підтвердженою **external reachability** є сильнішим кандидатом для harness, ніж ізольований internal helper зі слабким покриттям, але без шляху, контрольованого атакером.

### Практичний workflow тріажу

1. Побудуйте **code graph** з codebase та отримайте метрики складності/гілок для кожної функції.
2. Перелічіть **entrypoints**, які приймають input, контрольований атакером: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Виконайте **path queries** від цих entrypoints до candidate functions, щоб відокремити reachable attack surface від dead/internal-only code.
4. Пріоритезуйте вузли, які поєднують:
- високу **cyclomatic complexity**
- підтверджену **reachability from untrusted input**
- великий **blast radius** або багато downstream dependents
- додаткові підтвердження, як-от **SARIF** findings, audit notes або mutation survivors
5. Спочатку напишіть focused harnesses для вузлів із найвищими оцінками, особливо для **parsers/codecs**, як-от hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing часто створює шумний список survivors. Перш ніж вважати кожен survivor security gap, використайте граф, щоб з’ясувати:

- Чи є mutated function досяжною з attacker-controlled entrypoint?
- Чи всі call paths обмежені сильнішими invariants, ніж mutated check?
- Чи розташований вузол у dead code, formatting-only logic або у high-impact arithmetic/parser path?

Survivors, які залишаються недосяжними або структурно обмеженими, часто є **equivalent mutants**. Survivors, які залишаються **reachable** і зачіпають **boundary conditions**, **overflow/carry paths** або **security-critical arithmetic/parsing**, слід перетворити на:

- нові fuzz harnesses
- прямі property/invariant tests
- цільові edge-case vectors

### Correlate external findings onto the graph

Якщо ваш SAST pipeline експортує **SARIF**, нанесіть findings на вузли графа за **file + line range** і використайте граф, щоб розширити оцінку впливу.<sup>[[6]](#references)</sup>

- обчисліть **blast radius** flagged function
- перевірте, чи знаходиться finding на будь-якому шляху від entrypoint
- об’єднайте nearby findings, які зводяться до того самого choke point

Це корисно, коли потрібно вирішити, на яку конкретну function спрямувати fuzzing time: вузол, який є **reachable**, **complex** і вже має **SAST hits**, часто є кращою ціллю, ніж просто complex вузол без attacker path.

Приклад workflow з Trailmark.<sup>[[6]](#references)</sup>
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
Важлива методологія полягає в перетині: **складність x експонованість x вплив**. Використовуйте граф, щоб вибирати fuzz targets із найвищою очікуваною цінністю для безпеки, а потім використовуйте мутації, що вижили, щоб визначити, які межі та інваріанти має перевіряти ваш harness.<sup>[[5]](#references)</sup>

## Go Fuzzing With gosentry: Потужніший рушій, типізовані входи та диференційні перевірки

Якщо Go target уже має нативний harness `testing.F`, практичним шляхом оновлення є запуск того самого harness за допомогою [gosentry](https://github.com/trailofbits/gosentry) — форкнутого toolchain Go, який зберігає `go test -fuzz`, але замінює backend на **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Це корисно, коли native Go fuzzer зупиняється на **hard comparisons**, **typed inputs** або **parser-heavy formats**. Методологія залишається незмінною:

- Продовжуйте використовувати `f.Add(...)` для seed-ів і `f.Fuzz(...)` для callback.
- Повторно використовуйте той самий harness, але запускайте його за допомогою бінарного файлу `go` від gosentry замість стандартного toolchain.
- Розглядайте отриману кампанію як звичайний coverage-guided запуск, але з плануванням/мутаціями LibAFL і кращими додатковими детекторами.

### Перетворення тихих збоїв на fuzz findings

Поширена проблема під час Go assessments полягає в тому, що небезпечна поведінка часто **не спричиняє** crash за замовчуванням. За допомогою gosentry можна перетворити кілька класів станів «погано, але безшумно» на findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` щоб вибрані logging/error paths поводилися як crashes (корисно для code paths у стилі `log.Fatal`, які інакше лише записують log і продовжують виконання).
- `--catch-races=true` щоб повторно запускати нещодавно виявлені queue entries за допомогою Go race detector.
- `--catch-leaks=true` щоб повторно запускати нові queue entries за допомогою `goleak` і зупинятися у разі goroutine leaks.
- Обробка hangs у LibAFL, щоб зберігати **infinite loops / very slow inputs** як fuzz findings, замість того щоб вони зникали через timeouts.
- Вбудовані перевірки arithmetic overflow за замовчуванням, а також опційні перевірки truncation через instrumentation у стилі go-panikint.

Це особливо цінно для targets, де security impact полягає у **panicless parser failure**, **concurrency bug** або **DoS-only hang**, а не в memory corruption.

### Struct-aware fuzzing для typed Go APIs

Native Go fuzzing переважно очікує scalars, як-от `[]byte`, `string` і числа. Якщо code під тестуванням використовує typed objects, gosentry може напряму fuzz-ити **composite values** (structs, slices, arrays, pointers), водночас мутуючи байти на нижчому рівні.<sup>[[7]](#references)[[8]](#references)</sup>
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
Використовуйте це під час створення фіктивного wire format лише для fuzzing, оскільки це може приховати логічні помилки за кодом парсингу, який існує тільки в harness. Для differential або grammar-based кампаній залишайте вхідні дані harness як єдиний `[]byte` або `string` і виконуйте парсинг усередині callback.

### Grammar-based fuzzing для парсерів і протокольних вхідних даних

Для парсерів, форматів і мов введення gosentry може запускати **Nautilus grammar fuzzing** поверх LibAFL. Граматика є JSON-масивом production rules, а harness зазвичай має приймати один аргумент `[]byte` або `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Нотатки щодо методології:

- Використовуйте grammar mode, коли мутації на рівні байтів здебільшого відсіюються на ранніх перевірках синтаксису.
- Зосередьте grammar на **підмножині мови/протоколу, що має значення для безпеки**, замість моделювання повної специфікації.
- Використовуйте великі граничні значення в терміналах/нетерміналах, щоб навантажити межі цілих чисел, довжин і state machine.
- Grammar mode зберігає відповідність вхідних даних граматиці, але target усе одно отримує **bytes/strings**, тому перевірки парсингу та семантики залишаються всередині harness-коду.

### Differential fuzzing: порівнюйте реалізації, а не лише crashes

Надійним підходом для Go-екосистем є **grammar-based differential fuzzing**: генеруйте коректні структуровані вхідні дані та передавайте їх двом парсерам, клієнтам або engines переходів станів.<sup>[[7]](#references)[[8]](#references)</sup>
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
Розглядайте як findings:

- одна реалізація аварійно завершується, тоді як інша коректно відхиляє ввід
- невідповідності між прийнятим і відхиленим вводом
- різні дерева розбору або декодовані об'єкти
- розбіжності у переходах станів, nonce, балансах або коренях стану

Це практичний спосіб виявлення **невідповідностей консенсусу**, **неоднозначності парсера** та **розбіжностей між специфікацією й реалізацією**, які чисте fuzzing аварійних завершень часто не виявляє.

### Повторне використання corpus кампанії для звіту про coverage

Після кампанії повторно відтворіть збережений queue corpus, щоб згенерувати звіт про Go coverage без ручного експорту окремого corpus.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Запустіть команду з **того самого пакета** і з тією самою ціллю `-fuzz`, щоб gosentry розпізнав правильний стан кампанії в кеші.

## References

- [1] [Мутаційне grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing поглиблено](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet через п’ять років: про fuzzing протоколів, керований покриттям](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark перетворює код на графи](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [У Go fuzzing бракувало половини інструментарію. Ми форкнули toolchain, щоб це виправити.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: швидкий greybox fuzzer для stateful мережевих протоколів із використанням snapshot-ів](https://arxiv.org/abs/2202.03643)
- [10] [Немає grammar — немає проблем: на шляху до fuzzing ядра Linux без описів системних викликів](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: ефективний fuzzing з адаптивними та змінюваними snapshot-ами](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
