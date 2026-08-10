# Методологія Fuzzing

## Mutational Grammar Fuzzing: Coverage проти Semantics

У **mutational grammar fuzzing** inputs мутуються, залишаючись **grammar-valid**. У coverage-guided режимі лише samples, які спричиняють **new coverage**, зберігаються як corpus seeds. Для **language targets** (парсерів, інтерпретаторів, engines) це може пропустити bugs, що потребують **semantic/dataflow chains**, де output однієї конструкції стає input іншої.<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer знаходить seeds, які окремо перевіряють `document()` і `generate-id()` (або подібні primitives), але **не зберігає chained dataflow**, тому sample, що “ближчий до bug”, відкидається, оскільки не додає coverage. За наявності **3+ dependent steps** випадкова recombination стає дорогою, а coverage feedback не спрямовує пошук.<sup>[[1]](#references)</sup>

**Implication:** для dependency-heavy grammars варто розглянути **hybridizing mutational and generative phases** або зміщувати генерацію в бік патернів **function chaining** (а не лише coverage).<sup>[[1]](#references)</sup>

## Підводні камені Corpus Diversity

Coverage-guided mutation є **greedy**: sample з new-coverage зберігається одразу, часто зберігаючи великі незмінені області. З часом corpora стають **near-duplicates** із низькою структурною різноманітністю. Агресивна minimization може видалити корисний context, тому практичним компромісом є **grammar-aware minimization**, яка **зупиняється після досягнення мінімального token threshold** (зменшує шум, зберігаючи достатньо навколишньої структури, щоб залишатися зручною для mutation).<sup>[[1]](#references)</sup>

Практичне правило для corpus у mutational fuzzing: **надавати перевагу невеликому набору структурно різних seeds, які максимізують coverage**, а не великій кількості near-duplicates. На практиці це зазвичай означає таке.<sup>[[1]](#references)[[3]](#references)</sup>

- Починайте з **real-world samples** (public corpora, crawling, captured traffic, file sets з target ecosystem).
- Distill їх за допомогою **coverage-based corpus minimization**, замість зберігати кожен valid sample.
- Тримайте seeds **достатньо малими**, щоб mutations потрапляли у meaningful fields, а не витрачали більшість циклів на нерелевантні bytes.
- Повторно запускайте corpus minimization після значних змін harness/instrumentation, оскільки “найкращий” corpus змінюється зі зміною reachability.

## Comparison-Aware Mutation Для Magic Values

Поширена причина, через яку fuzzers досягають plateau, полягає не в syntax, а в **hard comparisons**: magic bytes, перевірках length, enum strings, checksums або parser dispatch values, захищених через `memcmp`, switch tables чи cascaded comparisons. Pure random mutation марнує cycles, намагаючись вгадати ці values byte-by-byte.

Для таких targets використовуйте **comparison tracing** (наприклад, workflows у стилі AFL++ `CMPLOG` / Redqueen), щоб fuzzer міг спостерігати operands із failed comparisons і спрямовувати mutations до values, які задовольняють їх.<sup>[[3]](#references)</sup>
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

- Це особливо корисно, коли ціль приховує глибоку логіку за **сигнатурами файлів**, **дієсловами протоколу**, **тегами типів** або **бітами функцій, залежними від версії**.
- Поєднуйте це зі **словниками**, отриманими з реальних зразків, специфікацій протоколів або debug-логів. Невеликий словник із токенами граматики, назвами chunk, дієсловами та роздільниками часто цінніший за величезний загальний wordlist.
- Якщо ціль виконує багато послідовних перевірок, спочатку розв’яжіть найраніші порівняння з “magic”, а потім знову мінімізуйте отриманий corpus, щоб наступні етапи починалися вже з валідних префіксів.

## Stateful Fuzzing: Послідовності є seed

Для **протоколів**, **автентифікованих workflow** і **багатоетапних парсерів** цікавою одиницею часто є не один blob, а **послідовність повідомлень**. Об’єднувати весь transcript в один файл і сліпо мутувати його зазвичай неефективно, оскільки fuzzer однаково мутує кожен крок, навіть коли лише пізніше повідомлення досягає вразливого стану.<sup>[[4]](#references)</sup>

Ефективніший підхід полягає в тому, щоб розглядати **саму послідовність як seed** і використовувати **спостережуваний стан** (коди відповідей, стани протоколу, фази парсера, типи повернених об’єктів) як додатковий feedback.<sup>[[4]](#references)</sup>

- Зберігайте **валідні повідомлення префікса** незмінними й зосередьте мутації на повідомленні, що **визначає перехід**.
- Кешуйте ідентифікатори та згенеровані сервером значення з попередніх відповідей, коли наступний крок залежить від них.
- Надавайте перевагу мутації/сплайсингу окремих повідомлень, а не мутації всього серіалізованого transcript як непрозорого blob.
- Якщо протокол надає змістовні коди відповідей, використовуйте їх як **дешевий oracle стану**, щоб визначати пріоритет послідовностей, які просуваються глибше.

Саме тому bugs в authenticated workflow, приховані переходи або parser bugs, що виникають “лише після handshake”, часто залишаються непоміченими під час звичайного file-style fuzzing: fuzzer має зберігати **порядок, стан і залежності**, а не лише структуру.<sup>[[4]](#references)</sup>

## Трюк із різноманітністю на одній машині (у стилі Jackalope)

Практичний спосіб поєднати **генеративну новизну** з **повторним використанням coverage** — **перезапускати короткоживучі workers** проти persistent server. Кожен worker починає з порожнього corpus, синхронізується через `T` секунд, працює ще `T` секунд із combined corpus, потім завершує роботу. Це забезпечує **свіжі структури в кожному поколінні**, водночас використовуючи накопичений coverage.<sup>[[1]](#references)[[2]](#references)</sup>

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

- `-in empty` примусово створює **новий corpus** під час кожної генерації.
- `-server_update_interval T` наближено імітує **відкладену синхронізацію** (спочатку пошук новизни, потім повторне використання).
- У режимі grammar fuzzing **початкова синхронізація сервера** за замовчуванням пропускається (потреби в `-skip_initial_server_sync` немає).
- Оптимальне значення `T` **залежить від target**; зазвичай найкраще перемикатися після того, як worker знайде більшість «легкого» покриття.

## Snapshot Fuzzing Для Target, Які Важко Підготувати

Коли код, який потрібно тестувати, стає доступним лише **після значних витрат на підготовку** (завантаження VM, завершення login, отримання пакета, парсинг контейнера, ініціалізація сервісу), корисною альтернативою є **snapshot fuzzing**: захопити стан готового процесу або VM, передати кожен test case до цільового шляху введення, виконувати до crash/timeout, а потім відновити snapshot. Це усуває необхідність повторювати ініціалізацію або префікси протоколу й корисно для **мережевих сервісів**, **firmware**, **post-auth attack surfaces** і **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Запустіть target, доки потрібний стан не буде готовий.
2. Створіть snapshot **пам'яті + регістрів** у цей момент.
3. Для кожного test case записуйте мутований input безпосередньо у відповідний буфер guest/process.
4. Виконуйте до crash/timeout/reset.
5. Відновіть snapshot; для VM targets, якщо це підтримується, відновлюйте лише **змінену пам'ять**, а потім повторюйте.

Розміщуйте snapshot якомога ближче до першого витратного кроку парсингу/диспетчеризації, наприклад після `recv`/`read` або точки десеріалізації пакета, і фіксуйте input buffer, який використовує target. Це відповідає принципу адаптивного розміщення: переміщуйте snapshot глибше в процес обробки input, щоб уникати повторного виконання зайвої роботи.<sup>[[11]](#references)</sup>

## Інтроспекція Harness: Рано Знаходьте Поверхневі Fuzzers

Коли кампанія зупиняється, проблема часто полягає не в **mutator**, а в **harness**. Використовуйте **інтроспекцію reachability/coverage**, щоб знаходити функції, які статично доступні з вашого fuzz target, але рідко або ніколи не покриваються динамічно. Такі функції зазвичай вказують на одну з трьох проблем.<sup>[[12]](#references)</sup>

- Harness входить у target надто пізно або надто рано.
- У seed corpus відсутнє ціле сімейство функцій.
- Target насправді потребує **другого harness**, а не одного надмірно великого harness «для всього».

Якщо ви використовуєте робочі процеси на кшталт OSS-Fuzz / ClusterFuzz, Fuzz Introspector може порівнювати статичну reachability з runtime coverage і створювати звіти на основі часового запуску або public corpus.<sup>[[12]](#references)</sup>
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Використовуйте звіт, щоб вирішити, чи додати новий harness для неперевіреного шляху parser-а, розширити corpus для певної функції або розділити монолітний harness на менші entry point-и.

## Вибір Fuzz Target на основі графа та triage мутацій

Якщо у вас уже є **результати static analysis**, **survivors mutation testing** і **звіти про coverage**, не розглядайте їх як незалежні списки. Спочатку побудуйте **граф викликів**, а потім анотуйте вузли за допомогою **цикломатичної складності**, **досяжності з entrypoint-ів/небезпечного вводу** та будь-яких зовнішніх результатів, після чого ставте запитання щодо графа.<sup>[[5]](#references)[[6]](#references)</sup>

- Які функції з високою складністю доступні з небезпечного вводу?
- Які mutation survivors розташовані на шляхах від parser-ів/handler-ів до критичного для безпеки коду?
- Які функції є архітектурними вузькими місцями з незвично великим **радіусом впливу**?

Зазвичай це виявляє кращі fuzz targets, ніж орієнтація лише на «найнижчий coverage». Parser/decoder із **високою складністю** та підтвердженою **зовнішньою досяжністю** є кращим кандидатом для harness, ніж ізольований внутрішній helper зі слабким coverage, але без шляху, контрольованого атакером.

### Практичний workflow triage

1. Побудуйте **граф коду** на основі codebase і отримайте метрики складності/гілок для кожної функції.
2. Перелічіть **entrypoint-и**, які приймають ввід, контрольований атакером: request handler-и, decoder-и, importer-и, protocol parser-и, CLI/file reader-и.
3. Виконайте **запити шляхів** від цих entrypoint-ів до функцій-кандидатів, щоб відокремити досяжну attack surface від мертвого коду/коду, доступного лише внутрішньо.
4. Визначте пріоритет для вузлів, які поєднують:
- високу **цикломатичну складність**
- підтверджену **досяжність із небезпечного вводу**
- великий **радіус впливу** або багато downstream-залежностей
- додаткові підтвердження, як-от результати **SARIF**, нотатки аудиту або mutation survivors
5. Спочатку напишіть сфокусовані harness-и для вузлів із найвищим рейтингом, особливо для **parser-ів/codecs**, таких як hex/Base64/IP/message decoder-и.

### Mutation survivors: equivalent vs actionable

Mutation testing часто створює зашумлений список survivors. Перш ніж вважати кожен survivor прогалиною в безпеці, використайте граф, щоб з’ясувати:

- Чи доступна мутована функція з entrypoint-а, контрольованого атакером?
- Чи всі шляхи виклику обмежені сильнішими інваріантами, ніж мутована перевірка?
- Чи розташований вузол у мертвому коді, логіці, що стосується лише форматування, або у важливому arithmetic/parser-шляху?

Survivors, які залишаються недосяжними або структурно обмеженими, часто є **еквівалентними мутантами**. Survivors, які залишаються **досяжними** та стосуються **граничних умов**, **шляхів overflow/carry** або **критичних для безпеки arithmetic/parsing**, слід перетворити на:

- нові fuzz harness-и
- прямі property/invariant tests
- цільові vectors для edge cases

### Співвіднесення зовнішніх результатів із графом

Якщо ваш SAST pipeline експортує **SARIF**, нанесіть результати на вузли графа за **файлом + діапазоном рядків** і використайте граф, щоб розширити оцінку впливу.<sup>[[6]](#references)</sup>

- обчисліть **радіус впливу** flagged function
- перевірте, чи є результат на будь-якому шляху від entrypoint-а
- об’єднайте сусідні результати, які зводяться до того самого вузького місця

Це корисно, коли потрібно вирішити, на яку конкретну функцію спрямувати час fuzzing: вузол, який є **досяжним**, **складним** і вже має **SAST findings**, часто є кращою ціллю, ніж просто складний вузол без шляху від атакера.

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
Важлива методологія — це перетин: **complexity x exposure x impact**. Використовуйте графік, щоб вибрати fuzz targets із найвищою очікуваною цінністю для безпеки, а потім використовуйте mutation survivors, щоб визначити, які межі та інваріанти має перевіряти ваш harness.<sup>[[5]](#references)</sup>

## Go Fuzzing із gosentry: потужніший рушій, типізовані входи та диференційні перевірки

Якщо Go target уже має нативний harness на основі `testing.F`, практичним шляхом оновлення буде запуск того самого harness за допомогою [gosentry](https://github.com/trailofbits/gosentry) — forked Go toolchain, який зберігає `go test -fuzz`, але замінює backend на **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```
Це корисно, коли native Go fuzzer зупиняється на **hard comparisons**, **typed inputs** або **parser-heavy formats**. Методологія залишається такою самою:

- Продовжуйте використовувати `f.Add(...)` для seed-значень, а `f.Fuzz(...)` — для callback.
- Повторно використовуйте той самий harness, але запускайте його за допомогою бінарного файлу `go` від gosentry замість стандартного toolchain.
- Розглядайте отриману кампанію як звичайний coverage-guided запуск, але з плануванням/мутаціями LibAFL і кращими додатковими детекторами.

### Перетворення тихих збоїв на fuzz findings

Поширена проблема під час Go assessments полягає в тому, що небезпечна поведінка часто **не** спричиняє crash за замовчуванням. За допомогою gosentry можна перетворити кілька класів «поганих, але тихих» станів на findings.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` щоб вибрані logging/error paths поводилися як crashes (корисно для code paths у стилі `log.Fatal`, які інакше лише записують log і продовжують виконання).
- `--catch-races=true` щоб повторно запускати щойно виявлені queue entries за допомогою Go race detector.
- `--catch-leaks=true` щоб повторно запускати нові queue entries за допомогою `goleak` і зупинятися через goroutine leaks.
- Обробка hang у LibAFL, яка зберігає **infinite loops / very slow inputs** як fuzz findings, замість того щоб вони зникали як timeouts.
- Вбудовані перевірки arithmetic overflow за замовчуванням, а також необов'язкові truncation checks за допомогою instrumentation у стилі go-panikint.

Це особливо цінно для targets, де наслідком для security є **panicless parser failure**, **concurrency bug** або **DoS-only hang**, а не memory corruption.

### Struct-aware fuzzing для typed Go APIs

Native Go fuzzing переважно очікує scalars, як-от `[]byte`, `string` і числа. Якщо код, що тестується, обробляє typed objects, gosentry може безпосередньо fuzz-ити **composite values** (structs, slices, arrays, pointers), водночас виконуючи мутації байтів під ними.<sup>[[7]](#references)[[8]](#references)</sup>
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
Використовуйте це під час створення фіктивного wire format лише для fuzzing, оскільки це може приховати логічні помилки за кодом парсингу, наявним лише в harness. Для differential- або grammar-based кампаній залишайте вхідні дані harness як один `[]byte` або `string`, а парсинг виконуйте всередині callback.

### Grammar-based fuzzing для парсерів і protocol inputs

Для парсерів, форматів і input languages gosentry може запускати **Nautilus grammar fuzzing** поверх LibAFL. Граматика є JSON-масивом production rules, а harness зазвичай має приймати один аргумент `[]byte` або `string`.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```
Нотатки щодо методології:

- Використовуйте grammar mode, коли мутації на рівні байтів здебільшого відсіюються на ранніх синтаксичних перевірках.
- Зосередьте grammar на **підмножині мови/протоколу, важливій для безпеки**, замість моделювання всієї специфікації.
- Використовуйте великі граничні значення в terminals/nonterminals, щоб навантажити межі цілих чисел, довжин і state machine.
- Grammar mode зберігає відповідність вхідних даних grammar, але ціль усе одно отримує **bytes/strings**, тому перевірки парсингу та семантики залишаються всередині harnessed code.

### Differential fuzzing: порівнюйте реалізації, а не лише crashes

Потужним підходом для Go ecosystems є **grammar-based differential fuzzing**: генерувати коректні структуровані вхідні дані та передавати їх двом парсерам, клієнтам або рушіям переходів станів.<sup>[[7]](#references)[[8]](#references)</sup>
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

- одна реалізація спричиняє panic, тоді як інша коректно відхиляє вхідні дані
- невідповідності між прийнятими та відхиленими вхідними даними
- різні дерева розбору або декодовані об’єкти
- розбіжності у переходах станів, nonce, балансах або state roots

Це практичний спосіб виявлення **consensus mismatches**, **parser ambiguity** і **spec-vs-implementation drift**, які pure crash fuzzing часто пропускає.

### Повторне використання campaign corpus для звітування про coverage

Після campaign повторно відтворіть збережений queue corpus, щоб згенерувати Go coverage report без ручного експорту окремого corpus.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```
Запускайте команду з **того самого package** і з **тим самим target `-fuzz`**, щоб gosentry правильно визначив стан campaign у кеші.

## References

- [1] [Fuzzing на основі мутаційної граматики](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++ Fuzzing поглиблено](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet через п’ять років: fuzzing протоколів з керуванням покриттям](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark перетворює код на графи](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [У Go fuzzing бракувало половини інструментарію. Ми форкнули toolchain, щоб це виправити.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: швидкий greybox fuzzer для stateful мережевих протоколів із використанням snapshot-ів](https://arxiv.org/abs/2202.03643)
- [10] [Немає grammar — немає проблем: до fuzzing Linux kernel без описів system call-ів](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: ефективний fuzzing з адаптивними та змінюваними snapshot-ами](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
{{#include ../banners/hacktricks-training.md}}
