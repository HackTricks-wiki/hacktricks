# Методологія Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Покриття vs. Семантика

У **mutational grammar fuzzing** вхідні дані мутують, залишаючись **валідними за граматикою**. У режимі coverage-guided зберігаються як seeds corpus лише зразки, що активують **нове покриття**. Для **мовних targets** (парсерів, інтерпретаторів, рушіїв) це може пропустити вразливості, які потребують **семантичних/dataflow-ланцюжків**, де результат одного конструкта стає вхідними даними для іншого.<sup>[[1]](#references)</sup>

**Режим відмови:** fuzzer знаходить seeds, які окремо задіюють `document()` і `generate-id()` (або подібні примітиви), але **не зберігає ланцюжок dataflow**, тому зразок, “ближчий до вразливості”, відкидається, оскільки він не додає покриття. За наявності **3+ залежних кроків** випадкова рекомбінація стає дорогою, а feedback від покриття не спрямовує пошук.<sup>[[1]](#references)</sup>

**Наслідок:** для граматик із великою кількістю залежностей розгляньте **гібридизацію mutational і generative фаз** або зміщення генерації в бік шаблонів **function chaining** (а не лише покриття).<sup>[[1]](#references)</sup>

## Пастки різноманітності Corpus

Coverage-guided mutation є **жадібною**: зразок із новим покриттям зберігається негайно, часто зберігаючи великі незмінені області. З часом corpus перетворюються на **майже дублікати** з низьким структурним різноманіттям. Агресивна мінімізація може видалити корисний контекст, тому практичним компромісом є **grammar-aware minimization**, яка **зупиняється після досягнення мінімального порогу токенів** (зменшуючи шум і зберігаючи достатню кількість навколишньої структури для зручної мутації).<sup>[[1]](#references)</sup>

Практичне правило для corpus у mutational fuzzing: **надавати перевагу невеликому набору структурно різних seeds, які максимізують покриття**, а не великій кількості майже дублікатів. На практиці це зазвичай означає наступне.<sup>[[1]](#references)[[3]](#references)</sup>

- Починайте з **зразків реального світу** (публічних corpus, результатів crawling, захопленого трафіку, наборів файлів з екосистеми target).
- Відбирайте з них необхідне за допомогою **coverage-based corpus minimization**, замість зберігання кожного валідного зразка.
- Зберігайте seeds **достатньо малими**, щоб мутації потрапляли у змістовні поля, а не витрачали більшість циклів на нерелевантні байти.
- Повторно запускайте corpus minimization після значних змін harness/instrumentation, оскільки “найкращий” corpus змінюється разом зі змінами reachability.

## Comparison-Aware Mutation Для Magic Values

Поширена причина, через яку fuzzers досягають плато, полягає не в синтаксисі, а в **жорстких порівняннях**: magic bytes, перевірках довжини, рядках enum, checksums або значеннях dispatch парсера, захищених за допомогою `memcmp`, таблиць switch чи каскадних порівнянь. Чиста випадкова мутація марнує цикли, намагаючись вгадати ці значення байт за байтом.

Для таких targets використовуйте **comparison tracing** (наприклад, робочі процеси AFL++ `CMPLOG` / Redqueen), щоб fuzzer міг спостерігати операнди невдалих порівнянь і спрямовувати мутації до значень, які задовольняють ці порівняння.<sup>[[3]](#references)</sup>
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

- Це особливо корисно, коли target приховує глибоку логіку за **file signatures**, **protocol verbs**, **type tags** або **version-dependent feature bits**.
- Поєднуйте це зі **словниками**, отриманими з реальних зразків, специфікацій протоколів або debug-логів. Невеликий словник із grammar-токенами, назвами chunk, verbs і delimiters часто цінніший за величезний загальний wordlist.
- Якщо target виконує багато послідовних перевірок, спочатку розв’яжіть найперші порівняння з “magic”, а потім знову мінімізуйте отриманий corpus, щоб наступні етапи починалися з уже валідних префіксів.

## Багатший feedback, коли Edge Coverage об’єднує різні шляхи

Звичайний edge coverage не може розрізнити два виконання, які проходять через один і той самий helper від різних callers або використовують різні комбінації branch усередині функції. Це важливо у спільних decoders, protocol dispatchers та interpreter helpers, де **маршрут** до edge визначає активний стан. Наївне відстеження кожного calling context також небезпечне: coverage map і queue можуть вибухово розростися. Тому дослідження context-sensitive fuzzing рекомендують уточнювати лише перспективні contexts, а не розглядати весь call graph як context-sensitive.<sup>[[14]](#references)</sup>

Нові збірки AFL++ надають **Ball-Larus per-function path coverage** на додаток до звичайного edge coverage. Він призначає feature кожному ациклічному шляху через функцію; loop back-edges видаляються, тому цей feedback розрізняє комбінації branch, але **не кількість ітерацій loop**. Почніть із послабленого рівня `1`, а потім застосовуйте суворіші режими лише до підозрілого parser/state-machine code, оскільки кількість шляхів може зростати експоненційно.<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
Для helper, який викликається з багатьох важливих для безпеки місць, режим LTO може об’єднати кожен шлях функції з його безпосереднім місцем виклику:<sup>[[13]](#references)</sup>
```bash
make clean
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LTO_CALLER=1
export AFL_LLVM_LTO_PATH=1
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```
**Рекомендації щодо кампанії:** застосовуйте розширений зворотний зв’язок обережно та контролюйте його вплив на карту покриття й витрати черги.<sup>[[13]](#references)[[14]](#references)</sup>

- Паралельно запускайте звичайний екземпляр edge-coverage; розширений зворотний зв’язок корисний лише в тому разі, якщо додаткові витрати на чергу/карту не знижують кількість виконань за секунду до критичного рівня.
- Використовуйте `AFL_LLVM_ALLOWLIST`, щоб обмежити інструментування шляхів/викликачів, коли великі бібліотеки з великою кількістю шаблонів або загальний службовий код домінують у карті.
- Функції з надмірною кількістю ациклічних шляхів можна пропускати в AFL++; попередження під час компіляції свідчать, що ціль потребує allowlisting або менш суворого рівня.
- Caller + path coverage підтримує лише одну глибину викликачів. Не поєднуйте його з глибшими стеками контексту.
- Path IDs можуть змінюватися між основними версіями LLVM. Зафіксуйте toolchain для кампанії та не синхронізуйте PATH-based corpora так, ніби їхні feature IDs стабільні між збірками.
- Цей зворотний зв’язок доповнює `CMPLOG`: трасування порівнянь визначає **яке значення проходить перевірку**, тоді як зворотний зв’язок щодо шляхів/викликачів зберігає **яка комбінація маршрутів і гілок до нього привела**.

## Stateful Fuzzing: послідовності є сідами

Для **протоколів**, **автентифікованих робочих процесів** і **багатоетапних парсерів** цікавою одиницею часто є не окремий blob, а **послідовність повідомлень**. Об’єднання всієї транскрипції в один файл і її сліпа мутація зазвичай неефективні, оскільки fuzzer однаково змінює кожен крок, навіть коли лише пізніше повідомлення досягає вразливого стану.<sup>[[4]](#references)</sup>

Ефективніший підхід полягає в тому, щоб розглядати **саму послідовність як seed** і використовувати **спостережуваний стан** (коди відповідей, стани протоколу, фази парсера, типи повернених об’єктів) як додатковий зворотний зв’язок.<sup>[[4]](#references)</sup>

- Зберігайте **коректні повідомлення префікса** незмінними та зосередьте мутації на повідомленні, що **визначає перехід**.
- Кешуйте ідентифікатори та значення, згенеровані сервером у попередніх відповідях, коли наступний крок залежить від них.
- Надавайте перевагу мутації/сплайсингу окремих повідомлень замість мутації всієї серіалізованої транскрипції як непрозорого blob.
- Якщо протокол надає змістовні коди відповідей, використовуйте їх як **дешевий оракул стану**, щоб пріоритизувати послідовності, які просуваються глибше.

Саме тому vanilla file-style fuzzing часто не виявляє автентифіковані баги, приховані переходи або баги парсера, що виникають “лише після handshake”: fuzzer має зберігати **порядок, стан і залежності**, а не лише структуру.<sup>[[4]](#references)</sup>

## Трюк для різноманітності на одній машині (у стилі Jackalope)

Практичний спосіб поєднати **генеративну новизну** з **повторним використанням покриття** — **перезапускати короткоживучі workers** проти persistent server. Кожен worker починає з порожнього corpus, синхронізується через `T` секунд, працює ще `T` секунд із об’єднаним corpus, знову синхронізується, а потім завершує роботу. Це забезпечує **свіжі структури в кожному поколінні**, водночас використовуючи накопичене покриття.<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty` змушує використовувати **новий corpus** під час кожної генерації.
- `-server_update_interval T` приблизно імітує **відкладену синхронізацію** (спочатку новизна, потім повторне використання).
- У режимі grammar fuzzing **початкова синхронізація сервера** за замовчуванням пропускається (потреби в `-skip_initial_server_sync` немає).
- Оптимальне значення `T` **залежить від target**; найкраще зазвичай перемикатися після того, як worker знайде більшість «легкого» покриття.

## Snapshot Fuzzing Для Targets, Які Важко Підготувати

Коли код, який потрібно тестувати, стає доступним лише **після значних витрат на налаштування** (завантаження VM, завершення login, отримання packet, парсинг container, ініціалізація service), корисною альтернативою є **snapshot fuzzing**: захопити стан готового process або VM, вставити кожен test case у відповідний шлях введення target, виконувати до crash/timeout і відновити snapshot. Це усуває необхідність повторювати ініціалізацію або префікси протоколу та корисно для **network services**, **firmware**, **post-auth attack surfaces** і **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Запустіть target, доки потрібний стан не буде готовий.
2. Створіть snapshot **memory + registers** у цей момент.
3. Для кожного test case запишіть змінений input безпосередньо у відповідний guest/process buffer.
4. Виконуйте до crash/timeout/reset.
5. Відновіть snapshot; для VM targets, якщо підтримується, відновлюйте лише **dirty pages**, а потім повторюйте.

Розміщуйте snapshot якомога ближче до першого дорогого кроку парсингу/диспетчеризації, наприклад після точки `recv`/`read` або десеріалізації packet, і зафіксуйте input buffer, який використовує target. Це відповідає принципу адаптивного розміщення: переміщуйте snapshot глибше в процес обробки input, щоб уникати повторного виконання роботи.<sup>[[11]](#references)</sup>

## Harness Introspection: Раннє Виявлення Поверхневих Fuzzers

Коли campaign зупиняється, проблема часто полягає не в mutator, а в **harness**. Використовуйте **introspection reachability/coverage**, щоб знаходити функції, які статично доступні з вашого fuzz target, але рідко або ніколи не покриваються динамічно. Такі функції зазвичай вказують на одну з трьох проблем.<sup>[[12]](#references)</sup>

- Harness входить у target надто пізно або надто рано.
- У seed corpus відсутнє ціле сімейство функцій.
- Target насправді потребує **другого harness**, а не одного надмірно великого harness «для всього».

Якщо ви використовуєте робочі процеси на кшталт OSS-Fuzz / ClusterFuzz, Fuzz Introspector може порівнювати статичну reachability з runtime coverage і генерувати звіти на основі timed run або public corpus.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Використовуйте звіт, щоб вирішити, чи додати новий harness для неперевіреного шляху парсера, розширити corpus для певної функції або розділити монолітний harness на менші entry points.

## Вибір цілей для Fuzzing і triage мутацій на основі графа

Якщо у вас уже є **static-analysis findings**, **mutation-testing survivors** і **coverage reports**, не розглядайте їх як незалежні списки. Спочатку побудуйте **call graph**, а потім анотуйте вузли за допомогою **cyclomatic complexity**, досяжності з **entrypoint/untrusted-input** і зовнішніх findings, після чого ставте запитання про граф.<sup>[[5]](#references)[[6]](#references)</sup>

- Які функції з високою складністю досяжні з untrusted input?
- Які mutation survivors розташовані на шляхах від парсерів/обробників до security-critical коду?
- Які функції є архітектурними вузькими місцями з незвично великим **blast radius**?

Зазвичай це виявляє кращі цілі для fuzzing, ніж орієнтація лише на «найнижче покриття». Парсер/декодер із **високою складністю** та підтвердженою **зовнішньою досяжністю** є сильнішим кандидатом для harness, ніж ізольований внутрішній helper зі слабким покриттям, але без шляху, контрольованого атакувальником.

### Практичний workflow triage

1. Побудуйте **code graph** на основі codebase і отримайте метрики складності/гілок для кожної функції.
2. Перелічіть **entrypoints**, які приймають дані, контрольовані атакувальником: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Виконайте **path queries** від цих entrypoints до функцій-кандидатів, щоб відокремити досяжну attack surface від dead/internal-only code.
4. Визначте пріоритет для вузлів, які поєднують:
- високу **cyclomatic complexity**
- підтверджену **досяжність із untrusted input**
- великий **blast radius** або багато downstream dependents
- додаткові підтвердження, як-от **SARIF** findings, audit notes або mutation survivors
5. Спочатку напишіть сфокусовані harnesses для вузлів із найвищими оцінками, особливо для **parsers/codecs**, таких як hex/Base64/IP/message decoders.

### Mutation survivors: equivalent vs actionable

Mutation testing часто створює зашумлений список survivors. Перш ніж вважати кожен survivor security gap, використайте граф і з’ясуйте:

- Чи досяжна mutated function з entrypoint, контрольованого атакувальником?
- Чи всі шляхи виклику обмежені сильнішими інваріантами, ніж mutated check?
- Чи розташований вузол у dead code, логіці, пов’язаній лише з форматуванням, або у high-impact arithmetic/parser path?

Survivors, які залишаються недосяжними або структурно обмеженими, часто є **equivalent mutants**. Survivors, які залишаються **досяжними** та зачіпають **boundary conditions**, **overflow/carry paths** або **security-critical arithmetic/parsing**, слід перетворити на:

- нові fuzz harnesses
- прямі property/invariant tests
- цільові edge-case vectors

### Correlate external findings onto the graph

Якщо ваш SAST pipeline експортує **SARIF**, нанесіть findings на вузли графа за допомогою **file + line range** і використайте граф для розширення оцінки впливу.<sup>[[6]](#references)</sup>

- обчисліть **blast radius** flagged function
- перевірте, чи міститься finding на будь-якому шляху від entrypoint
- кластеризуйте сусідні findings, які зводяться до одного choke point

Це корисно, коли потрібно вирішити, чи витрачати час на fuzzing певної функції: вузол, який є **досяжним**, **складним** і вже має **SAST hits**, часто є кращою ціллю, ніж просто складний вузол без шляху від атакувальника.

Приклад workflow із Trailmark.<sup>[[6]](#references)</sup>
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
Важлива методологія полягає в перетині: **складність x експонування x вплив**. Використовуйте граф, щоб обирати fuzz targets із найвищою очікуваною цінністю для безпеки, а потім використовуйте mutation survivors, щоб визначити, які межі та інваріанти має стресово перевіряти ваш harness.<sup>[[5]](#references)</sup>

## Go Fuzzing With gosentry: Потужніший рушій, типізовані входи та диференційні перевірки

Якщо Go target уже має native harness на основі `testing.F`, практичний шлях оновлення — запускати той самий harness за допомогою [gosentry](https://github.com/trailofbits/gosentry), форкованого Go toolchain, який зберігає `go test -fuzz`, але замінює backend на **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Це корисно, коли native Go fuzzer зупиняється на **hard comparisons**, **typed inputs** або форматах, насичених **parser**-логікою. Методологія залишається незмінною:

- Продовжуйте використовувати `f.Add(...)` для seed-ів і `f.Fuzz(...)` для callback.
- Повторно використовуйте той самий harness, але запускайте його за допомогою бінарного файлу `go` від gosentry замість стандартного toolchain.
- Розглядайте отриману кампанію як звичайний coverage-guided запуск, але з плануванням/мутаціями LibAFL і кращими додатковими детекторами.

### Перетворення тихих збоїв на fuzz findings

Поширена проблема під час Go assessments полягає в тому, що небезпечна поведінка часто **не** спричиняє crash за замовчуванням. За допомогою gosentry можна перетворити кілька класів станів «погано, але тихо» на findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` змушує вибрані logging/error paths поводитися як crashes (корисно для code paths у стилі `log.Fatal`, які інакше лише записують log і продовжують виконання).
- `--catch-races=true` повторно запускає нещодавно знайдені queue entries за допомогою Go race detector.
- `--catch-leaks=true` повторно запускає нові queue entries за допомогою `goleak` і зупиняється у разі витоків goroutine.
- Обробка hang-ів у LibAFL дає змогу зберігати **нескінченні цикли / дуже повільні inputs** як fuzz findings, замість того щоб вони зникали як timeouts.
- Вбудовані перевірки arithmetic overflow за замовчуванням, а також опційні перевірки truncation через instrumentation у стилі go-panikint.

Це особливо цінно для targets, де наслідком для безпеки є **помилка parser без panic**, **concurrency bug** або hang, що спричиняє лише **DoS**, а не пошкодження пам’яті.

### Struct-aware fuzzing для typed Go API

Native Go fuzzing переважно очікує scalars, як-от `[]byte`, `string` і числа. Якщо код, що тестується, споживає typed objects, gosentry може безпосередньо fuzz-ити **composite values** (structs, slices, arrays, pointers), водночас виконуючи мутації байтів на нижчому рівні.<sup>[[7]](#references)[[8]](#references)</sup>
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
Використовуйте це під час створення фіктивного wire format лише для fuzzing, оскільки це може приховати логічні помилки за кодом парсингу, призначеним лише для harness. Для differential або grammar-based кампаній залишайте вхідні дані harness як один `[]byte` або `string` і виконуйте парсинг усередині callback.

### Grammar-based fuzzing для парсерів і протокольних вхідних даних

Для парсерів, форматів і мов введення gosentry може запускати **Nautilus grammar fuzzing** поверх LibAFL. Граматика є JSON-масивом production rules, а harness зазвичай має приймати один аргумент типу `[]byte` або `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Нотатки щодо методології:

- Використовуйте grammar mode, коли мутації на рівні байтів здебільшого гинуть на ранніх перевірках синтаксису.
- Зосереджуйте grammar на **підмножині мови/протоколу, релевантній для безпеки**, замість моделювання повної специфікації.
- Використовуйте великі граничні значення в терміналах/нетерміналах, щоб навантажити граничні випадки цілих чисел, довжин і state machine.
- Grammar mode підтримує відповідність вхідних даних grammar, але target усе одно отримує **bytes/strings**, тому parsing і semantic checks залишаються всередині harnessed code.

### Differential fuzzing: порівнюйте реалізації, а не лише crashes

Потужним підходом для Go-екосистем є **grammar-based differential fuzzing**: генеруйте дійсні структуровані вхідні дані та передавайте їх двом парсерам, клієнтам або engine переходів станів.<sup>[[7]](#references)[[8]](#references)</sup>
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
Розглядайте наведене як findings:

- одна реалізація викликає panic, тоді як інша коректно відхиляє вхідні дані
- невідповідності між прийнятими та відхиленими вхідними даними
- різні дерева парсингу або декодовані об’єкти
- розбіжності у переходах станів, nonce, балансах або state roots

Це практичний спосіб виявити **невідповідності консенсусу**, **неоднозначність парсера** та **розбіжності між специфікацією й реалізацією**, які часто залишаються непоміченими під час чистого fuzzing crash-ів.

### Повторне використання corpus кампанії для звітності про coverage

Після кампанії повторно відтворіть збережений queue corpus, щоб згенерувати звіт про coverage для Go без ручного експорту окремого corpus.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Запускайте команду з **того самого пакета** і з тією самою ціллю `-fuzz`, щоб gosentry визначив правильний стан кешованої кампанії.



## References

- [1] [Мутаційне grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing поглиблено](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet через п’ять років: про coverage-guided fuzzing протоколів](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark перетворює код на графи](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [У Go fuzzing бракувало половини інструментарію. Ми форкнули toolchain, щоб це виправити.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: швидкий Greybox Fuzzer для stateful мережевих протоколів із використанням snapshot-ів](https://arxiv.org/abs/2202.03643)
- [10] [Немає grammar — немає проблем: на шляху до fuzzing ядра Linux без описів системних викликів](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: ефективний fuzzing з адаптивними та змінними snapshot-ами](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Інструментування AFL++ LLVM: покриття шляхів і caller coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Predictive Context-sensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
{{#include ../banners/hacktricks-training.md}}
