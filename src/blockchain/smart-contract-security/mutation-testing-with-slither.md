# Mutation Testing для Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "тестує ваші тести", систематично вносячи невеликі зміни (мутанти) до коду контракту та повторно запускаючи набір тестів. Якщо тест завершується помилкою, мутант убито. Якщо тести все ще проходять, мутант виживає, виявляючи сліпу пляму, яку неможливо виявити за допомогою покриття рядків/гілок.

Ключова ідея: покриття показує, що код було виконано; mutation testing показує, чи справді перевіряється поведінка.<sup>[[2]](#references)</sup>

## Чому покриття може вводити в оману

Розглянемо цю просту перевірку порога:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Модульні тести, які лише перевіряють значення нижче та значення вище порогового значення, можуть досягти 100% покриття рядків/гілок, не перевіривши граничний випадок рівності (==). Рефакторинг до `deposit >= 2 ether` усе ще пройде такі тести, непомітно порушивши логіку протоколу.<sup>[[2]](#references)</sup>

Mutation testing виявляє цю прогалину, мутуючи умову та перевіряючи, що тести завершуються помилкою.

Для смарт-контрактів мутанти, що вижили, часто вказують на відсутні перевірки щодо:
- Авторизації та меж ролей
- Інваріантів обліку та переказу значень
- Умов revert і шляхів помилок
- Граничних умов (`==`, нульові значення, порожні масиви, максимальні/мінімальні значення)

## Оператори мутацій із найвищим security signal

Корисні класи мутацій для аудиту контрактів:<sup>[[1]](#references)[[2]](#references)</sup>
- **Висока критичність**: заміна операторів на `revert()` для виявлення невиконаних шляхів
- **Середня критичність**: закоментування рядків / видалення логіки для виявлення неперевірених побічних ефектів
- **Низька критичність**: непомітні заміни операторів або констант, наприклад `>=` -> `>` або `+` -> `-`
- Інші поширені зміни: заміна присвоювань, інверсія булевих значень, заперечення умов і зміни типів

Практична мета: знищити всіх значущих мутантів і явно обґрунтувати мутантів, що вижили, якщо вони не мають значення або семантично еквівалентні.

## Чому syntax-aware mutation краща за regex

Старіші mutation engines покладалися на regex або переписування, орієнтовані на рядки. Це працює, але має важливі обмеження:<sup>[[1]](#references)</sup>
- Багаторядкові оператори складно безпечно мутувати
- Структура мови не розуміється, тому коментарі/токени можуть бути неправильно обрані
- Генерування всіх можливих варіантів у слабкому рядку витрачає значні обсяги runtime

Інструменти на основі AST або Tree-sitter покращують це, націлюючись на структуровані вузли замість необроблених рядків:<sup>[[1]](#references)</sup>
- **slither-mutate** використовує AST Solidity у Slither<sup>[[4]](#references)</sup>
- **mewt** використовує Tree-sitter як language-agnostic ядро<sup>[[6]](#references)</sup>
- **MuTON** побудований на `mewt` і додає first-class support для мов TON, таких як FunC, Tolk і Tact<sup>[[7]](#references)</sup>

Це робить багаторядкові конструкції та мутації на рівні виразів значно надійнішими, ніж підходи, що використовують лише regex.

## Запуск mutation testing за допомогою slither-mutate

Вимоги: Slither v0.10.2+.

- Перелік параметрів і mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Приклад Foundry (запис результатів і ведення повного журналу):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Якщо ви не використовуєте Foundry, замініть `--test-cmd` на команду, за допомогою якої ви запускаєте тести (наприклад, `npx hardhat test`, `npm test`).

Артефакти за замовчуванням зберігаються в `./mutation_campaign`. Неперехоплені (такі, що вижили) мутанти копіюються туди для перевірки.<sup>[[5]](#references)</sup>

### Розуміння результату

Рядки звіту мають такий вигляд:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Тег у дужках — це alias mutator (наприклад, `CR` = Comment Replacement).
- `UNCAUGHT` означає, що тести пройшли за зміненої поведінки → відсутня assertion.

## Скорочення часу виконання: пріоритизація найвпливовіших mutant

Mutation campaigns можуть тривати годинами або днями. Поради для зменшення витрат:<sup>[[1]](#references)[[2]](#references)</sup>
- Scope: починайте лише з критичних контрактів/директорій, а потім розширюйте охоплення.
- Пріоритизація mutator: якщо mutant із високим пріоритетом у рядку виживає (наприклад, `revert()` або comment-out), пропустіть варіанти з нижчим пріоритетом для цього рядка.
- Використовуйте двофазні campaigns: спочатку запускайте сфокусовані/швидкі тести, потім повторно тестуйте лише uncaught mutants повним набором тестів.
- За можливості зіставляйте mutation targets із конкретними командами тестування (наприклад, код автентифікації -> auth tests).
- Коли час обмежений, обмежуйте campaigns mutant із високою/середньою severity.
- Виконуйте тести паралельно, якщо ваш runner це підтримує; кешуйте dependencies/builds.
- Fail-fast: зупиняйтеся раніше, коли зміна явно демонструє assertion gap.

Математика runtime жорстока: `1000 mutants x 5-minute tests ~= 83 hours`, тому дизайн campaign має не менше значення, ніж сам mutator.<sup>[[1]](#references)</sup>

## Persistent campaigns і triage у великих масштабах

Одна з проблем старих workflows — виведення результатів лише до `stdout`. Для тривалих campaigns це ускладнює pause/resume, фільтрацію та review.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` покращують це, зберігаючи mutants і результати в campaigns на базі SQLite. Переваги:<sup>[[1]](#references)</sup>
- Призупиняйте та відновлюйте тривалі runs без втрати прогресу
- Фільтруйте лише uncaught mutants у певному файлі або mutation class
- Експортуйте/перекладайте результати у SARIF для review tooling
- Надавайте AI-assisted triage менші, відфільтровані набори результатів замість необроблених terminal logs

Persistent results особливо корисні, коли mutation testing стає частиною audit pipeline, а не одноразовим manual review.

## Triage workflow для mutant, що вижили

1) Перевірте змінений рядок і поведінку.
- Відтворіть проблему локально, застосувавши змінений рядок і запустивши сфокусований тест.

2) Посилюйте тести, перевіряючи state, а не лише return values.
- Додавайте перевірки меж рівності (наприклад, тестуйте threshold `==`).
- Перевіряйте post-conditions: balances, total supply, authorization effects і emitted events.

3) Замінюйте надто permissive mocks реалістичною поведінкою.
- Переконайтеся, що mocks застосовують transfers, failure paths і event emissions, які відбуваються on-chain.

4) Додавайте invariants для fuzz tests.
- Наприклад, conservation of value, non-negative balances, authorization invariants і monotonic supply, де це застосовно.

5) Відокремлюйте true positives від semantic no-ops.
- Приклад: `x > 0` -> `x != 0` не має значення, коли `x` є unsigned.

6) Повторюйте campaign, доки survivors не буде знищено або явно обґрунтовано.

## Case study: виявлення відсутніх state assertions (Arkis protocol)

Mutation campaign під час аудиту DeFi protocol Arkis виявила survivors, зокрема:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Коментування assignment не зламало тести, що доводить відсутність post-state assertions. Першопричина: код довіряв контрольованому користувачем `_cmd.value`, замість того щоб перевіряти фактичні token transfers. Зловмисник міг десинхронізувати очікувані та фактичні transfers і вивести кошти. Результат: high severity ризик для платоспроможності протоколу.<sup>[[2]](#references)[[3]](#references)</sup>

Рекомендація: вважайте survivors, які впливають на transfers вартості, accounting або access control, high-risk, доки їх не буде усунуто.

## Не генеруйте тести бездумно, щоб убити кожного мутанта

Генерація тестів на основі mutation testing може мати зворотний ефект, якщо поточна реалізація неправильна. Наприклад, мутація `priority >= 2` на `priority > 2` змінює поведінку, але правильним виправленням не завжди є «написати тест для `priority == 2`». Сама ця поведінка може бути помилкою.<sup>[[1]](#references)</sup>

Безпечніший workflow:
- Використовуйте survivors для виявлення неоднозначних вимог
- Перевіряйте очікувану поведінку за specs, документацією протоколу або з рев’юерами
- Лише після цього кодуйте поведінку як тест/invariant

Інакше ви ризикуєте зафіксувати випадкові особливості реалізації в test suite та отримати хибну впевненість.

## Практичний checklist

- Запустіть цільову кампанію:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- За можливості надавайте перевагу syntax-aware mutators (AST/Tree-sitter), а не мутації лише на основі regex.
- Проведіть triage survivors і напишіть тести/invariants, які завершувалися б помилкою за мутованої поведінки.
- Перевіряйте balances, supply, authorizations і events.
- Додайте boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Замініть нереалістичні mocks; симулюйте failure modes.
- Зберігайте результати, якщо tooling це підтримує, і відфільтровуйте uncaught mutants перед triage.
- Використовуйте двофазні кампанії або кампанії для кожної цілі, щоб підтримувати прийнятний runtime.
- Повторюйте процес, доки всіх мутантів не буде вбито або обґрунтовано коментарями та rationale.

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
