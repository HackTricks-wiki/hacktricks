# Мутаційне тестування для Solidity зі Slither (slither-mutate)

{{#include ../../../banners/hacktricks-training.md}}

Мутаційне тестування "tests your tests" систематично вносить невеликі зміни (mutants) у ваш код на Solidity і повторно запускає набір тестів. Якщо тест падає — мутант вбито. Якщо тести все ще проходять — мутант виживає, що виявляє сліпу зону у вашому наборі тестів, яку line/branch coverage не може виявити.

Ключова ідея: покриття показує, що код був виконаний; мутаційне тестування показує, чи поведінка фактично перевіряється.

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
Модульні тести, які перевіряють лише значення нижче і вище порога, можуть досягати 100% покриття рядків/гілок, при цьому не перевіряючи граничну рівність (==). Рефакторинг до `deposit >= 2 ether` все одно пройде такі тести, тихо порушивши логіку протоколу.

Mutation testing виявляє цю прогалину шляхом мутування умови і перевірки, що ваші тести провалюються.

## Поширені mutation-оператори для Solidity

Механізм мутацій Slither застосовує багато дрібних змін, що змінюють семантику, наприклад:
- Заміна операторів: `+` ↔ `-`, `*` ↔ `/`, etc.
- Заміна присвоєння: `+=` → `=`, `-=` → `=`
- Заміна констант: ненульове → `0`, `true` ↔ `false`
- Заперечення/заміна умови всередині `if`/loops
- Закоментувати цілі рядки (CR: Comment Replacement)
- Замінити рядок на `revert()`
- Заміна типів даних: напр., `int128` → `int64`

Мета: усунути 100% згенерованих мутантів або обґрунтувати тих, що вижили, чітким поясненням.

## Running mutation testing with slither-mutate

Requirements: Slither v0.10.2+.

- Перелік опцій і мутаторів:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry приклад (захопити результати та зберегти повний лог):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Якщо ви не використовуєте Foundry, замініть `--test-cmd` на спосіб запуску тестів (наприклад, `npx hardhat test`, `npm test`).

Артефакти та звіти зберігаються за замовчуванням у `./mutation_campaign`. Невиявлені (виживші) мутанти копіюються туди для перевірки.

### Розуміння виводу

Рядки звіту виглядають так:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Тег у дужках — mutator alias (наприклад, `CR` = Comment Replacement).
- `UNCAUGHT` означає, що tests пройшли під mutated поведінкою → відсутнє твердження.

## Зменшення часу виконання: віддавайте пріоритет impactful mutants

Mutation campaigns можуть займати години або дні. Поради, щоб зменшити витрати:
- Scope: Починайте лише з критичних contracts/directories, потім розширюйте.
- Prioritize mutators: Якщо high-priority mutant на рядку виживає (наприклад, цілий рядок закоментований), можна пропустити lower-priority variants для цього рядка.
- Parallelize tests, якщо ваш runner це дозволяє; кешуйте dependencies/builds.
- Fail-fast: зупиняйтеся раніше, коли зміна явно демонструє прогалину в assertion.

## Triage workflow для surviving mutants

1) Inspect the mutated line and behavior.
- Reproduce locally by applying the mutated line and running a focused test.

2) Strengthen tests to assert state, not only return values.
- Add equality-boundary checks (e.g., test threshold `==`).
- Assert post-conditions: balances, total supply, authorization effects, and emitted events.

3) Replace overly permissive mocks with realistic behavior.
- Ensure mocks enforce transfers, failure paths, and event emissions that occur on-chain.

4) Add invariants for fuzz tests.
- E.g., conservation of value, non-negative balances, authorization invariants, monotonic supply where applicable.

5) Re-run slither-mutate until survivors are killed or explicitly justified.

## Case study: revealing missing state assertions (Arkis protocol)

Mutation campaign під час аудиту Arkis DeFi protocol виявила survivors, такі як:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Закоментування присвоєння не порушило тести, що свідчить про відсутність перевірок кінцевого стану. Корінь проблеми: код довіряв керованому користувачем `_cmd.value` замість перевірки фактичних переказів токенів. Атакуючий міг десинхронізувати очікувані та фактичні перекази, щоб викрасти кошти. Наслідок: високий ризик для платоспроможності протоколу.

Guidance: вважайте вцілілих мутантів, які впливають на перекази коштів, облік або контроль доступу, високоризиковими доти, доки їх не ліквідують.

## Practical checklist

- Run a targeted campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Проаналізуйте вцілілих мутантів і напишіть тести/інваріанти, які провалювалися б при модифікованій поведінці.
- Assert balances, supply, authorizations, and events.
- Add boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Replace unrealistic mocks; simulate failure modes.
- Iterate until all mutants are killed or justified with comments and rationale.

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../../banners/hacktricks-training.md}}
