# Mutation Testing для Smart Contracts (slither-mutate, mewt, MuTON)

Mutation testing «тестує ваші тести», систематично вносячи невеликі зміни (мутанти) в код контракту та повторно запускаючи набір тестів. Якщо тест завершується помилкою, мутант убито. Якщо тести все ще проходять, мутант виживає, виявляючи сліпу зону, яку не можуть виявити покриття рядків або гілок.

Ключова ідея: покриття показує, що код було виконано; mutation testing показує, чи справді поведінка перевіряється твердженнями.<sup>[[2]](#references)</sup>

## Чому покриття може вводити в оману

Розглянемо цю просту перевірку порогу:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Юніт-тести, які перевіряють лише значення нижче та значення вище порогового значення, можуть досягти 100% покриття рядків/гілок, не перевіряючи межу рівності (==). Рефакторинг на `deposit >= 2 ether` все одно пройде такі тести, непомітно порушивши логіку протоколу.<sup>[[2]](#references)</sup>

Mutation testing виявляє цю прогалину, мутуючи умову та перевіряючи, що тести завершуються невдачею.

Для smart contracts surviving mutants часто вказують на відсутність перевірок, пов’язаних із:
- Авторизацією та межами ролей
- Інваріантами обліку та передачі значень
- Умовами revert і шляхами помилок
- Граничними умовами (`==`, нульові значення, порожні масиви, максимальні/мінімальні значення)

## Mutation operators with the highest security signal

Корисні класи мутацій для аудиту контрактів:<sup>[[1]](#references)[[2]](#references)</sup>
- **Висока критичність**: заміна інструкцій на `revert()` для виявлення невиконаних шляхів
- **Середня критичність**: закоментувати рядки / видалити логіку, щоб виявити неперевірені побічні ефекти
- **Низька критичність**: непомітні заміни операторів або констант, наприклад `>=` -> `>` або `+` -> `-`
- Інші поширені зміни: заміна присвоювань, інверсія boolean-значень, заперечення умов і зміни типів

Практична мета: знищити всі значущі мутанти та явно обґрунтувати тих, що залишилися, якщо вони нерелевантні або семантично еквівалентні.

## Why syntax-aware mutation is better than regex

Старіші mutation engines покладалися на regex або переписування, орієнтоване на рядки. Це працює, але має важливі обмеження:<sup>[[1]](#references)</sup>
- Багаторядкові інструкції складно безпечно мутувати
- Структура мови не враховується, тому коментарі/токени можуть бути вибрані неправильно
- Генерування кожного можливого варіанта для слабкого рядка витрачає значні обсяги runtime

Інструменти на основі AST або Tree-sitter покращують це, націлюючись на структуровані вузли, а не на необроблені рядки:<sup>[[1]](#references)</sup>
- **slither-mutate** використовує Solidity AST від Slither.<sup>[[4]](#references)</sup>
- **mewt** використовує Tree-sitter як language-agnostic ядро.<sup>[[6]](#references)</sup>
- **MuTON** побудований на `mewt` і додає повноцінну підтримку мов TON, таких як FunC, Tolk і Tact.<sup>[[7]](#references)</sup>

Це робить роботу з багаторядковими конструкціями та мутаціями на рівні виразів значно надійнішою, ніж підходи, що використовують лише regex.

## Running mutation testing with slither-mutate

Вимоги: Slither v0.10.2+.

- Перелік опцій і mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Приклад Foundry (збереження результатів і повного журналу):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Якщо ви не використовуєте Foundry, замініть `--test-cmd` на команду, яку ви використовуєте для запуску тестів (наприклад, `npx hardhat test`, `npm test`).

Артефакти за замовчуванням зберігаються в `./mutation_campaign`. Неперехоплені (такі, що вижили) мутанти копіюються туди для перевірки.<sup>[[5]](#references)</sup>

### Розуміння результатів

Рядки звіту мають такий вигляд:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Тег у дужках — це alias мута́тора (наприклад, `CR` = Comment Replacement).
- `UNCAUGHT` означає, що тести пройшли за зміненої поведінки → відсутня assertion.

## Скорочення часу виконання: пріоритизація впливових мутантів

Mutation campaigns можуть тривати годинами або днями. Поради для зменшення витрат:<sup>[[1]](#references)[[2]](#references)</sup>
- Область застосування: починайте лише з критичних контрактів/директорій, а потім розширюйте охоплення.
- Пріоритизація mutators: якщо high-priority mutant у рядку виживає (наприклад, `revert()` або comment-out), пропустіть варіанти з нижчим пріоритетом для цього рядка.
- Використовуйте двофазні campaigns: спочатку запускайте сфокусовані/швидкі тести, потім повторно тестуйте лише uncaught mutants за допомогою повного набору тестів.
- За можливості зіставляйте цілі mutation з конкретними командами тестування (наприклад, auth-код -> auth-тести).
- Коли час обмежений, обмежуйте campaigns мутантами з high/medium severity.
- Виконуйте тести паралельно, якщо ваш runner це підтримує; кешуйте dependencies/builds.
- Fail-fast: зупиняйтеся раніше, коли зміна явно демонструє прогалину в assertions.

Математика часу виконання жорстока: `1000 mutants x 5-minute tests ~= 83 hours`, тому дизайн campaign має не менше значення, ніж сам mutator.<sup>[[1]](#references)</sup>

## Постійні campaigns і triage у великих масштабах

Однією зі слабких сторін старих workflows є виведення результатів лише до `stdout`. Для тривалих campaigns це ускладнює призупинення/відновлення, фільтрацію та review.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` покращують це, зберігаючи mutants і результати в campaigns на основі SQLite. Переваги:<sup>[[1]](#references)</sup>
- Призупинення та відновлення тривалих запусків без втрати прогресу
- Фільтрація лише uncaught mutants у певному файлі або mutation class
- Експорт/переклад результатів у SARIF для review tooling
- Надання AI-assisted triage менших, відфільтрованих наборів результатів замість необроблених terminal logs

Постійні результати особливо корисні, коли mutation testing стає частиною audit pipeline, а не одноразовим manual review.

## Workflow triage для мутантів, що вижили

1) Перевірте змінений рядок і поведінку.
- Відтворіть проблему локально, застосувавши змінений рядок і запустивши сфокусований тест.

2) Посильте тести, щоб вони перевіряли state, а не лише return values.
- Додайте перевірки меж рівності (наприклад, протестуйте threshold `==`).
- Перевіряйте post-conditions: balances, total supply, authorization effects і emitted events.

3) Замініть надто permissive mocks реалістичною поведінкою.
- Переконайтеся, що mocks застосовують transfers, failure paths і event emissions, які відбуваються on-chain.

4) Додайте invariants для fuzz-тестів.
- Наприклад, conservation of value, non-negative balances, authorization invariants, monotonic supply, де це доречно.

5) Відокремлюйте true positives від semantic no-ops.
- Приклад: `x > 0` -> `x != 0` не має значення, коли `x` є unsigned.

6) Повторюйте campaign, доки мутанти, що вижили, не будуть killed або явно обґрунтовані.

## Приклад: виявлення відсутніх state assertions (Arkis protocol)

Mutation campaign під час аудиту DeFi protocol Arkis виявила мутантів, що вижили, зокрема:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Коментування присвоєння не зламало тести, що доводить відсутність post-state assertions. Першопричина: код довіряв контрольованому користувачем `_cmd.value`, а не перевіряв фактичні token transfers. Зловмисник міг розсинхронізувати очікувані та фактичні transfers, щоб вивести кошти. Результат: високий ризик для платоспроможності протоколу.<sup>[[2]](#references)[[3]](#references)</sup>

Рекомендація: вважайте survivors, які впливають на transfers вартості, accounting або access control, високоризиковими, доки їх не буде усунуто.

## Не генеруйте тести для знищення кожного мутанта бездумно

Генерація тестів на основі mutation testing може мати зворотний ефект, якщо поточна реалізація неправильна. Наприклад, мутація `priority >= 2` у `priority > 2` змінює поведінку, але правильне виправлення не завжди полягає в тому, щоб "написати тест для `priority == 2`". Така поведінка сама може бути помилкою.<sup>[[1]](#references)</sup>

Безпечніший процес:
- Використовуйте survivors, щоб виявити неоднозначні вимоги
- Перевіряйте очікувану поведінку за специфікаціями, документацією протоколу або з рецензентами
- Лише після цього кодуйте поведінку як тест/invariant

Інакше ви ризикуєте жорстко закріпити випадкові особливості реалізації в наборі тестів і отримати хибну впевненість.

## Практичний checklist

- Запустіть targeted campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- За можливості надавайте перевагу syntax-aware mutators (AST/Tree-sitter), а не мутації лише на основі regex.
- Проаналізуйте survivors і напишіть тести/invariants, які завершувалися б помилкою за мутованої поведінки.
- Перевіряйте balances, supply, authorizations та events.
- Додайте boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Замініть нереалістичні mocks; моделюйте failure modes.
- Зберігайте результати, якщо tooling це підтримує, і відфільтровуйте uncaught mutants до triage.
- Використовуйте two-phase або per-target campaigns, щоб зберегти прийнятний час виконання.
- Повторюйте процес, доки всі мутанти не буде знищено або обґрунтовано коментарями та поясненням.

## References

- [1] [Мутаційне тестування для agentic ери](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Використовуйте mutation testing, щоб знаходити помилки, які не виявляють ваші тести (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Перевірка безпеки Arkis DeFi Prime Brokerage (Додаток C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Документація Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
