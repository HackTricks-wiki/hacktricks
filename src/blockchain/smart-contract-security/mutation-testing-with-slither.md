# Mutation Testing для Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing «тестує ваші тести», систематично вносячи невеликі зміни (мутанти) в код контракту та повторно запускаючи test suite. Якщо тест завершується помилкою, мутант вважається знищеним. Якщо тести все ще проходять, мутант виживає, виявляючи blind spot, який не може виявити покриття рядків/гілок.

Ключова ідея: покриття показує, що код було виконано; mutation testing показує, чи справді поведінка перевіряється.<sup>[[2]](#references)</sup>

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
Модульні тести, які перевіряють лише значення нижче та значення вище порогового значення, можуть досягти 100% покриття рядків/гілок, не перевіряючи межу рівності (==). Рефакторинг до `deposit >= 2 ether` все одно пройде такі тести, непомітно порушивши логіку протоколу.<sup>[[2]](#references)</sup>

Mutation testing виявляє цю прогалину, мутуючи умову та перевіряючи, що тести завершуються невдало.

Для smart contracts мутанти, що вижили, часто вказують на відсутність перевірок щодо:
- Авторизації та меж ролей
- Інваріантів обліку/передавання значень
- Умов revert і шляхів обробки помилок
- Граничних умов (`==`, нульові значення, порожні масиви, максимальні/мінімальні значення)

## Mutation operators із найвищим security signal

Корисні класи мутацій для аудиту контрактів:<sup>[[1]](#references)[[2]](#references)</sup>
- **Висока критичність**: заміна операторів на `revert()` для виявлення невиконаних шляхів
- **Середня критичність**: закоментування рядків / видалення логіки для виявлення неперевірених побічних ефектів
- **Низька критичність**: непомітні заміни операторів або констант, наприклад `>=` -> `>` або `+` -> `-`
- Інші поширені зміни: заміна присвоювання, інверсія булевих значень, заперечення умов і зміна типів

Практична мета: знищити всі змістовні мутанти та явно обґрунтувати тих, що вижили, якщо вони нерелевантні або семантично еквівалентні.

## Чому syntax-aware mutation краща за regex

Старіші mutation engines покладалися на regex або переписування, орієнтовані на рядки. Це працює, але має важливі обмеження:<sup>[[1]](#references)</sup>
- Багаторядкові оператори складно безпечно мутувати
- Структура мови не розпізнається, тому коментарі/токени можуть бути помилково вибрані
- Генерування кожного можливого варіанта у слабкому рядку витрачає значні обсяги runtime

Інструменти на основі AST або Tree-sitter покращують це, націлюючись на структуровані вузли, а не на необроблені рядки:<sup>[[1]](#references)</sup>
- **slither-mutate** використовує Solidity AST від Slither
- **mewt** використовує Tree-sitter як language-agnostic ядро
- **MuTON** побудований на `mewt` і додає first-class support для мов TON, таких як FunC, Tolk і Tact

Це робить мутації багаторядкових конструкцій і на рівні виразів значно надійнішими порівняно з підходами, що використовують лише regex.

## Запуск mutation testing за допомогою slither-mutate

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
- Якщо ви не використовуєте Foundry, замініть `--test-cmd` на команду, за допомогою якої ви запускаєте тести (наприклад, `npx hardhat test`, `npm test`).

Артефакти за замовчуванням зберігаються в `./mutation_campaign`. Неперехоплені (ті, що вижили) мутанти копіюються туди для перевірки.<sup>[[5]](#references)</sup>

### Розуміння результатів

Рядки звіту мають такий вигляд:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Тег у дужках — це alias мутатора (наприклад, `CR` = Comment Replacement).
- `UNCAUGHT` означає, що тести пройшли за мутованої поведінки → відсутня assertion.

## Скорочення часу виконання: пріоритизація впливових мутантів

Mutation campaigns можуть тривати годинами або днями. Поради для зменшення витрат:<sup>[[1]](#references)[[2]](#references)</sup>
- Scope: спочатку охопіть лише критичні контракти/директорії, потім розширюйте охоплення.
- Пріоритизація мутаторів: якщо high-priority mutant у рядку виживає (наприклад, `revert()` або comment-out), пропустіть варіанти з нижчим пріоритетом для цього рядка.
- Використовуйте two-phase campaigns: спочатку запускайте сфокусовані/швидкі тести, потім повторно тестуйте лише uncaught mutants повним набором тестів.
- За можливості зіставляйте mutation targets із конкретними тестовими командами (наприклад, auth code -> auth tests).
- Коли час обмежений, обмежуйте campaigns мутантами високої/середньої severity.
- Виконуйте тести паралельно, якщо це дозволяє ваш runner; кешуйте dependencies/builds.
- Fail-fast: зупиняйтеся раніше, коли зміна явно демонструє assertion gap.

Математика часу безжальна: `1000 mutants x 5-minute tests ~= 83 hours`, тому design campaign має таке саме значення, як і сам mutator.

## Persistent campaigns і triage у великому масштабі

Однією з проблем старіших workflows є виведення результатів лише до `stdout`. Для довгих campaigns це ускладнює pause/resume, filtering і review.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` покращують це, зберігаючи mutants і outcomes у campaigns на основі SQLite. Переваги:<sup>[[1]](#references)</sup>
- Призупиняйте та відновлюйте довгі runs без втрати прогресу
- Фільтруйте лише uncaught mutants у певному файлі або mutation class
- Експортуйте/перекладайте результати у SARIF для review tooling
- Надавайте AI-assisted triage менші, відфільтровані набори результатів замість raw terminal logs

Persistent results особливо корисні, коли mutation testing стає частиною audit pipeline, а не одноразовим manual review.

## Triage workflow для surviving mutants

1) Перевірте mutated line і поведінку.
- Відтворіть локально, застосувавши mutated line і запустивши focused test.

2) Посильте тести, щоб вони перевіряли state, а не лише return values.
- Додайте equality-boundary checks (наприклад, тестуйте threshold `==`).
- Перевіряйте post-conditions: balances, total supply, authorization effects і emitted events.

3) Замініть надто permissive mocks на behavior, наближений до реального.
- Переконайтеся, що mocks enforce transfers, failure paths і event emissions, які відбуваються on-chain.

4) Додайте invariants для fuzz tests.
- Наприклад, conservation of value, non-negative balances, authorization invariants і monotonic supply, де це застосовно.

5) Відокремлюйте true positives від semantic no-ops.
- Приклад: `x > 0` -> `x != 0` не має значення, коли `x` є unsigned.

6) Повторюйте campaign, доки survivors не будуть killed або явно обґрунтовані.

## Case study: виявлення відсутніх state assertions (Arkis protocol)

Mutation campaign під час аудиту Arkis DeFi protocol виявила survivors на кшталт:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Коментування присвоєння не зламало тести, що доводить відсутність post-state assertions. Першопричина: код довіряв контрольованому користувачем `_cmd.value`, замість перевірки фактичних переказів токенів. Зловмисник міг десинхронізувати очікувані та фактичні перекази, щоб вивести кошти. Результат: високий ризик для платоспроможності протоколу.<sup>[[2]](#references)[[3]](#references)</sup>

Рекомендація: вважайте мутантів, що вижили та впливають на перекази коштів, облік або контроль доступу, високоризиковими, доки їх не буде знищено.

## Не генеруйте тести бездумно, щоб знищити кожного мутанта

Генерація тестів на основі мутацій може мати зворотний ефект, якщо поточна реалізація неправильна. Наприклад, мутація `priority >= 2` на `priority > 2` змінює поведінку, але правильним виправленням не завжди є «написати тест для `priority == 2`». Сама ця поведінка може бути помилкою.<sup>[[1]](#references)</sup>

Безпечніший робочий процес:
- Використовуйте мутантів, що вижили, для виявлення неоднозначних вимог
- Перевірте очікувану поведінку за специфікаціями, документацією протоколу або з рев’юерами
- Лише після цього кодуйте поведінку як тест/invariant

Інакше ви ризикуєте жорстко зафіксувати випадкові особливості реалізації в наборі тестів і отримати хибну впевненість.

## Практичний checklist

- Запустіть цільову кампанію:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- За можливості надавайте перевагу syntax-aware mutators (AST/Tree-sitter), а не мутації лише на основі regex.
- Проведіть triage мутантів, що вижили, і напишіть тести/invariants, які завершувалися б помилкою за мутованої поведінки.
- Перевіряйте баланси, supply, авторизації та events.
- Додайте boundary tests (`==`, переповнення/втрата значущих розрядів, zero-address, zero-amount, порожні масиви).
- Замініть нереалістичні mocks; моделюйте сценарії відмови.
- Зберігайте результати, якщо tooling це підтримує, і відфільтровуйте uncaught mutants перед triage.
- Використовуйте двофазні кампанії або кампанії для окремих цілей, щоб тривалість виконання залишалася прийнятною.
- Повторюйте процес, доки всі мутанти не буде знищено або обґрунтовано коментарями та поясненням.

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
