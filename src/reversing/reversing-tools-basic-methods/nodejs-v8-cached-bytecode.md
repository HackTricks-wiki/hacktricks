# Static Deobfuscation of Node.js/V8 Cached Bytecode

{{#include ../../banners/hacktricks-training.md}}

Кешовані дані V8 — це **залежне від версії представлення з втратою даних**, а не вихідний код JavaScript і не звичайний нативний виконуваний файл. Тому корисний статичний workflow має такий вигляд: видалити зовнішнє пакування, дизасемблювати кеш за допомогою відповідної збірки V8, підняти його до проміжної моделі псевдокоду та застосувати перетворення з урахуванням залежностей, не виконуючи sample. [View8](https://github.com/suleram/View8) і [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) реалізують цей підхід для Node.js payloads, захищених `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Отримання та дизасемблювання кешу

Спочатку перевірте preload/launcher, а не припускайте, що кожен файл `.jsc` має однакову обгортку. Наприклад, launcher на кшталт `node.exe -r preflight.js app.jsc` виконує `preflight.js` перед основним модулем; у проаналізованому family preload видаляв шар Brotli. Після розпакування визначте точне покоління Node.js/V8 за bundled runtime. Кеш, створений однією версією V8, може бути відхилений або неправильно декодований іншою версією, тому зберіть або отримайте `v8dasm` для точної версії V8 та застосуйте необхідні патчі View8 і string-printing.<sup>[[1]](#references)[[2]](#references)</sup>

Не виконуваний workflow toolkit має такий вигляд:<sup>[[2]](#references)</sup>
```bash
brotli -d app.jsc -o app.decompressed.jsc
/path/to/matching-v8dasm app.decompressed.jsc > app.jsc.disasm.txt
mkdir -p decompiled deobfuscated
python3 View8/view8.py --input_format disassembled \
--inp app.jsc.disasm.txt --normalize \
--out decompiled/app.dec.txt \
--export_format decompiled serialized
python3 deobf_all.py --inp decompiled/app.dec.pkl \
--out deobfuscated/app.deobf.txt \
--export_format decompiled serialized
```
`--normalize` надає згенерованим функціям стабільні ідентифікатори під час різних запусків. Текстовий вивід призначений для інспекції; серіалізований граф об'єктів дає змогу незалежним проходам зберігати зв'язки між функціями, declarer, scope і метаданими. Це **не відновлений і не придатний до виконання JavaScript**.<sup>[[1]](#references)[[2]](#references)</sup>

### Читайте псевдокод View8 як IR

Типові імена мають вигляд `func_<name>_0x<address>`, аргументи — `a0...aN`, віртуальні регістри — `r0...rN`, а `ACCU` — це accumulator V8. `start` є кореневим declarer, тоді як `Scope[...]`, globals і dictionaries моделюють значення, захоплені або спільно використовувані вкладеними функціями. Не слід трактувати кожен вираз як синтаксис JavaScript: наприклад, `!r6 === "0"` у View8 означає заперечення всього порівняння (`r6 !== "0"`), що важливо під час відновлення гілок.<sup>[[1]](#references)[[3]](#references)</sup>

## Deobfuscation з урахуванням залежностей

Застосовуйте трансформації в такому порядку, щоб відкривати входи, потрібні наступному проходу, і повторюйте propagation, доки вивід не стабілізується. Практичний порядок такий:<sup>[[1]](#references)[[2]](#references)</sup>

1. Обійдіть ієрархію declarer і поширте значення з globals, registers, dictionaries та посилань `Scope[...]`.
2. Відновіть аргументи string-decoder і замініть зашифровані виклики plaintext.
3. Об'єднайте сусідні string chunks; отримані імена властивостей і dispatcher-order strings відкриють наступні проходи.
4. Unflatten control flow, вбудуйте call proxies та atomic-operation wrappers і розв'яжіть посилання на функції, що зберігаються в dictionaries.
5. Повторіть propagation, оскільки кожен розв'язаний string, key або proxy може відкрити ще один рівень непрямого посилання.
6. Об'єднайте розпізнані одноразові initialization thunks і видаліть dead helpers лише після розв'язання місць їхніх викликів.

### Відновлення shifted RC4 string arrays як black box

Поширений layout `javascript-obfuscator` зберігає Base64-encoded RC4 chunks в одному array. Decoder wrappers передають numeric offset і короткий key, іноді у зворотному порядку аргументів, а потім додають або віднімають constants, захоплені в closure scopes. Коли root decoder надто сильно обфускований, відновлюйте його невідомий array-index shift емпірично, замість реконструювання всієї функції.<sup>[[1]](#references)</sup>

Для array із `N` chunks і кількох викликів того самого decoder:<sup>[[1]](#references)</sup>
```text
for each observed (numeric_argument, rc4_key):
candidates = {}
for shift in 0 .. N-1:
index = apply_observed_sign(numeric_argument, shift)
plaintext = RC4(Base64Decode(chunks[index]), rc4_key)
if plaintext passes encoding/printability checks:
candidates.add(shift)
root_shift = intersection(candidate_sets)
```
Не приймайте зсув на основі одного printable розшифрування: неправильний ciphertext може випадково виглядати printable. Використовуйте щонайменше три різні спостереження та приймайте лише унікальний зсув, який дає правдоподібний текст для всіх них. Потім пройдіть графом wrapper/declarer, накопичуючи кожне додавання або віднімання та фіксуючи, чи числовий аргумент іде першим. Кешуйте ці метадані для кожного sample, замінюйте decoder calls, об'єднуйте сусідні фрагменти plaintext і експортуйте рядки окремо для triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Збереження семантики під час unflattening

Для dispatcher loops, керованих рядками на кшталт `3|2|1|0|4`, декодуйте рядок порядку, зіставте кожне порівняння стану з його блоком, врахуйте позначення заперечених умов у View8, а потім виведіть блоки в порядку dispatcher. Вкладений `continue` може означати ранній jump назад до dispatcher, а не звичайний fall-through. Видаляючи loop, видаліть цей `continue` і перемістіть statements, які спочатку йшли після його enclosing `if`, у згенеровану гілку `else`; просте видалення dispatcher змінює поведінку.<sup>[[1]](#references)</sup>

### Вбудовування проксі, операцій і lazy thunks

Нормалізуйте forwarding helpers, наприклад `return a0(a1, a2)`, перш ніж замінювати їхні call sites на direct calls. Аналогічно обробляйте wrappers для subtraction, division, comparison, membership tests або invocation. Оскільки reference на helper може зберігатися за decrypted dictionary key або closure value, виконуйте string і structure propagation до та після inlining.<sup>[[1]](#references)</sup>

Також розпізнавайте closures, які один раз викликають збережену function, очищають її reference, кешують результат і повертають цей cache під час наступних викликів. Collapsing такого thunk на initialization site відкриває underlying dispatcher або capability function, але позначайте, що початкове виконання було **одноразовим і кешованим**, а не моделюйте кожен виклик як нове invocation.<sup>[[1]](#references)</sup>

## Примітки щодо безпеки та validation

- Завантаження Python `pickle` може виконувати code. Завантажуйте лише `.pkl` files, згенеровані локально довіреним запуском View8; ніколи не вважайте pickle, наданий sample, даними.<sup>[[2]](#references)</sup>
- Pattern-driven passes не є general JavaScript decompiler. Зберігайте unresolved expressions і вручну перевіряйте неоднозначні dispatcher variants, а не змушуйте їх переписуватися.<sup>[[1]](#references)[[2]](#references)</sup>
- LLM-assisted function names є лише navigation hints, а не evidence. Якщо використовуєте їх, обробляйте dependencies leaf-first, але перевіряйте кожен label за body, arguments, strings, data flow, APIs і side effects.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Злам печатки: статичний deobfuscation скомпільованого V8 bytecode JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
{{#include ../../banners/hacktricks-training.md}}
