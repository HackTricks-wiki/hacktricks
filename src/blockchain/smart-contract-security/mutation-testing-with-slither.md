# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" by systematically introducing small changes (mutants) into your Solidity code and re-running your test suite. If a test fails, the mutant is killed. If the tests still pass, the mutant survives, revealing a blind spot in your test suite that line/branch coverage cannot detect.

Key idea: Coverage shows code was executed; mutation testing shows whether behavior is actually asserted.

## Чому покриття може вводити в оману

Розгляньте цю просту перевірку порогу:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Модульні тести, що перевіряють лише значення нижче та вище порогу, можуть досягти 100% покриття рядків/гілок, одночасно не перевіряючи граничну перевірку на рівність (==). Рефакторинг до `deposit >= 2 ether` все одно пройде такі тести, тихо порушивши логіку протоколу.

Мутаційне тестування виявляє цю прогалину шляхом мутації умови та перевірки, що ваші тести не проходять.

## Поширені оператори мутацій Solidity

Slither’s mutation engine застосовує багато невеликих змін, що змінюють семантику, таких як:
- Заміна операторів: `+` ↔ `-`, `*` ↔ `/`, etc.
- Заміна присвоєння: `+=` → `=`, `-=` → `=`
- Заміна констант: ненульове → `0`, `true` ↔ `false`
- Заперечення/заміна умови всередині `if`/loops
- Коментування цілих рядків (CR: Comment Replacement)
- Замінити рядок на `revert()`
- Заміна типів даних: наприклад, `int128` → `int64`

Мета: знищити 100% згенерованих мутантів або обґрунтувати тих, що вижили, чітким поясненням.

## Running mutation testing with slither-mutate

Requirements: Slither v0.10.2+.

- Перелік опцій та мутаційних операторів:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Приклад Foundry (зафіксувати результати й вести повний журнал):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Якщо ви не використовуєте Foundry, замініть `--test-cmd` на команду, якою ви запускаєте тести (наприклад, `npx hardhat test`, `npm test`).

Артефакти та звіти за замовчуванням зберігаються в `./mutation_campaign`. Незловлені (вцілілі) мутанти копіюються туди для перевірки.

### Розуміння виводу

Рядки звіту виглядають так:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Тег у дужках — це псевдонім мутатора (наприклад, `CR` = Comment Replacement).
- `UNCAUGHT` означає, що тести пройшли за зміненої поведінки → відсутня перевірка.

## Скорочення часу виконання: надавайте пріоритет впливовим мутантам

Кампії з мутацій можуть тривати години або дні. Поради для зменшення витрат:
- Scope: почніть лише з критичних контрактів/директорій, потім розширюйте.
- Prioritize mutators: якщо високопріоритетний мутант на рядку вижив (наприклад, цілий рядок закоментовано), можна пропустити менш пріоритетні варіанти для цього рядка.
- Parallelize tests if your runner allows it; кешуйте залежності/зборки.
- Fail-fast: зупиняйтеся раніше, коли зміна явно демонструє відсутність перевірки.

## Робочий процес триажу для мутантів, що вижили

1) Огляньте змінений рядок коду та поведінку.
- Відтворіть локально, застосувавши змінений рядок і запустивши цілеспрямований тест.

2) Посиліть тести, щоб перевіряти стан, а не лише значення, що повертаються.
- Додайте перевірки меж рівності (наприклад, тест порогу `==`).
- Перевіряйте постумови: баланси, total supply, ефекти авторизації та згенеровані події.

3) Замініть надто ліберальні mocks на реалістичну поведінку.
- Переконайтеся, що mocks відображають transfers, failure paths і event emissions, які відбуваються on-chain.

4) Додайте інваріанти для fuzz-тестів.
- Наприклад: збереження вартості, невід'ємні баланси, інваріанти авторизації, монотонність total supply там, де це застосовно.

5) Перезапускайте slither-mutate, доки всі вижилі мутанти не будуть вбиті або явно обґрунтовані.

## Приклад: виявлення відсутніх перевірок стану (Arkis protocol)

Кампанія мутацій під час аудиту Arkis DeFi protocol виявила вижилі, наприклад:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Закоментування присвоєння не зламало тести, що підтверджує відсутність post-state assertions. Корінь проблеми: код довіряв керованому користувачем `_cmd.value` замість перевіряти фактичні перекази токенів. Атакуючий міг би десинхронізувати очікувані й фактичні перекази, щоб вивести кошти. Наслідок: ризик високої критичності для платоспроможності протоколу.

Guidance: Вважайте survivors, які впливають на перекази вартості, облік або контроль доступу, високоризиковими, поки їх не вбито.

## Практичний чекліст

- Запустіть цілеспрямовану кампанію:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Проведіть триаж survivors і напишіть тести/інваріанти, які проваляться при мутованій поведінці.
- Перевірте баланси, supply, авторизації та події.
- Додайте тести меж (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Замініть нереалістичні mocks; змоделюйте режими відмов.
- Повторюйте, поки всі mutants не будуть killed або виправдані коментарями та обґрунтуванням.

## Посилання

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
