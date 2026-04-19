# Mutation Testing for Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" шляхом систематичного внесення малих змін (mutants) у код контракту та повторного запуску test suite. Якщо test fails, mutant is killed. Якщо тести все ще pass, mutant survives, revealing a blind spot that line/branch coverage cannot detect.

Key idea: Coverage shows code was executed; mutation testing shows whether behavior is actually asserted.

## Why coverage can deceive

Consider this simple threshold check:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Юніт-тести, які перевіряють лише значення нижче та значення вище порогу, можуть досягти 100% line/branch coverage, але не перевірити границю рівності (==). Рефактор до `deposit >= 2 ether` все одно пройшов би такі тести, тихо зламавши protocol logic.

Mutation testing виявляє цю прогалину шляхом мутації умови та перевірки, що тести падають.

Для smart contracts такі surviving mutants часто вказують на відсутні перевірки в:
- Authorization і role boundaries
- Accounting/value-transfer invariants
- Revert conditions і failure paths
- Boundary conditions (`==`, zero values, empty arrays, max/min values)

## Mutation operators with the highest security signal

Корисні mutation classes для contract auditing:
- **High severity**: replace statements with `revert()` to expose unexecuted paths
- **Medium severity**: comment out lines / remove logic to reveal unverified side effects
- **Low severity**: subtle operator or constant swaps such as `>=` -> `>` or `+` -> `-`
- Other common edits: assignment replacement, boolean flips, condition negation, and type changes

Практична мета: kill all meaningful mutants і явно обґрунтовувати survivors, які є нерелевантними або semantically equivalent.

## Why syntax-aware mutation is better than regex

Старі mutation engines покладалися на regex або line-oriented rewrites. Це працює, але має важливі обмеження:
- Multi-line statements важко безпечно мутувати
- Language structure не розуміється, тому comments/tokens можуть бути targeted badly
- Генерація кожного можливого варіанту на weak line витрачає великі обсяги runtime

AST- або Tree-sitter-based tooling покращує це, targeting structured nodes замість raw lines:
- **slither-mutate** використовує Slither's Solidity AST
- **mewt** використовує Tree-sitter як language-agnostic core
- **MuTON** будується на `mewt` і додає first-class support для TON languages such as FunC, Tolk, and Tact

Це робить multi-line constructs і expression-level mutations значно надійнішими, ніж regex-only approaches.

## Running mutation testing with slither-mutate

Requirements: Slither v0.10.2+.

- List options and mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Приклад Foundry (захопити результати та зберегти повний log):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Якщо ви не використовуєте Foundry, замініть `--test-cmd` на те, як ви запускаєте тести (наприклад, `npx hardhat test`, `npm test`).

Artifacts зберігаються в `./mutation_campaign` за замовчуванням. Uncaught (surviving) mutants копіюються туди для аналізу.

### Understanding the output

Рядки звіту виглядають так:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Тег у дужках — це alias mutator’a (наприклад, `CR` = Comment Replacement).
- `UNCAUGHT` означає, що тести пройшли під mutated behavior → missing assertion.

## Зменшення runtime: пріоритезуйте impactful mutants

Mutation campaigns можуть тривати години або дні. Поради, щоб зменшити cost:
- Scope: починайте лише з critical contracts/directories, потім розширюйте.
- Пріоритезуйте mutators: якщо high-priority mutant у рядку survives (наприклад `revert()` або comment-out), пропускайте lower-priority variants для цього рядка.
- Використовуйте two-phase campaigns: спочатку запускайте focused/fast tests, потім повторно тестуйте лише uncaught mutants повним suite.
- За можливості мапте mutation targets на specific test commands (наприклад auth code -> auth tests).
- Обмежуйте campaigns high/medium severity mutants, коли час обмежений.
- Parallelize тести, якщо ваш runner це дозволяє; cache dependencies/builds.
- Fail-fast: зупиняйтеся раніше, якщо зміна явно демонструє assertion gap.

Runtime math brutal: `1000 mutants x 5-minute tests ~= 83 hours`, тож design campaign має значення не менше, ніж сам mutator.

## Persistent campaigns і triage at scale

Одна слабкість старіших workflows — скидати результати лише в `stdout`. Для long campaigns це ускладнює pause/resume, filtering і review.

`mewt`/`MuTON` покращують це, зберігаючи mutants і outcomes у SQLite-backed campaigns. Переваги:
- Pause і resume довгих прогонів без втрати progress
- Filter лише uncaught mutants у конкретному файлі або mutation class
- Export/translate results to SARIF для review tooling
- Давати AI-assisted triage менші, відфільтровані result sets замість raw terminal logs

Persistent results особливо корисні, коли mutation testing стає частиною audit pipeline, а не одноразового manual review.

## Triage workflow для surviving mutants

1) Перевірте mutated line і behavior.
- Reproduce locally, застосувавши mutated line і запустивши focused test.

2) Посильте тести, щоб вони перевіряли state, а не лише return values.
- Додайте equality-boundary checks (наприклад, test threshold `==`).
- Assert post-conditions: balances, total supply, authorization effects і emitted events.

3) Замініть надто permissive mocks на realistic behavior.
- Переконайтеся, що mocks enforce transfers, failure paths і event emissions, які відбуваються on-chain.

4) Додайте invariants для fuzz tests.
- Наприклад, conservation of value, non-negative balances, authorization invariants, monotonic supply where applicable.

5) Розділіть true positives від semantic no-ops.
- Приклад: `x > 0` -> `x != 0` не має сенсу, коли `x` unsigned.

6) Перезапускайте campaign, доки survivors не будуть killed або явно justified.

## Case study: revealing missing state assertions (Arkis protocol)

Mutation campaign під час audit of the Arkis DeFi protocol виявила survivors на кшталт:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Коментування призначення не зламало тести, що доводить відсутність post-state assertions. Коренева причина: код довіряв `_cmd.value`, контрольованому користувачем, замість перевірки фактичних transfer token. Зловмисник міг би десинхронізувати очікувані та фактичні transfers, щоб вивести кошти. Результат: високий ризик для платоспроможності protocol.

Рекомендація: Розглядайте survivors, які впливають на value transfers, accounting або access control, як high-risk, доки їх не kill.

## Не генеруйте сліпо тести, щоб kill кожен mutant

Mutation-driven generation tests може дати зворотний ефект, якщо поточна implementation неправильна. Приклад: мутація `priority >= 2` на `priority > 2` змінює поведінку, але правильне виправлення не завжди "напишіть тест для `priority == 2`". Така поведінка сама може бути bug.

Безпечніший workflow:
- Використовуйте surviving mutants, щоб виявити неоднозначні requirements
- Validate очікувану поведінку за specs, protocol docs або reviewer-ами
- Лише після цього кодуйте поведінку як test/invariant

Інакше ви ризикуєте закодувати implementation accidents у test suite та отримати хибну впевненість.

## Практичний checklist

- Запустіть targeted campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Віддавайте перевагу syntax-aware mutators (AST/Tree-sitter) над regex-only mutation, коли це можливо.
- Тріажте survivors і пишіть тести/invariants, які б падали за mutated behavior.
- Перевіряйте balances, supply, authorizations та events.
- Додавайте boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Замінюйте нереалістичні mocks; симулюйте failure modes.
- Зберігайте результати, якщо tooling це підтримує, і фільтруйте uncaught mutants перед triage.
- Використовуйте two-phase або per-target campaigns, щоб runtime був керованим.
- Ітеруйте, доки всі mutants не буде kill або не буде обґрунтовано їх залишення коментарями та rationale.

## References

- [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)
- [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [mewt](https://github.com/trailofbits/mewt)
- [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
