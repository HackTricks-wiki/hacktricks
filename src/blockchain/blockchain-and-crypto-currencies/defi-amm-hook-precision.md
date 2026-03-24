# DeFi/AMM Експлуатація: Uniswap v4 Hook — зловживання точністю/округленням

{{#include ../../banners/hacktricks-training.md}}



На цій сторінці описано клас технік експлуатації DeFi/AMM проти DEXів у стилі Uniswap v4, які розширюють базову математику кастомними hooks. Нещодавній інцидент у Bunni V2 використав помилку округлення/точності в Liquidity Distribution Function (LDF), що виконувалася під час кожного swap, дозволивши атакуючому накопичувати позитивні кредити та зливати ліквідність.

Ключова ідея: якщо hook реалізує додатковий облік, який залежить від fixed‑point математики, округлення ticks і логіки порогів, атакуючий може сформувати exact‑input свопи, які перетинають конкретні пороги так, що розбіжності округлення накопичуються на його користь. Повторення патерну та після цього виведення завищеного балансу приносить прибуток, часто фінансований flash loan.

## Передумови: Uniswap v4 hooks та процес swap

- Hooks — це контракти, які PoolManager викликає у певні моменти життєвого циклу (наприклад, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- Pools ініціалізуються з PoolKey, що включає адресу hooks. Якщо вона ненульова, PoolManager виконує callbacks при кожній релевантній операції.
- Hooks можуть повертати **custom deltas**, які змінюють кінцеві змінення балансів swap або дій з ліквідністю (custom accounting). Ці дельти розглядаються як нетто‑баланси в кінці виклику, тому будь‑яка помилка округлення всередині математики hook накопичується до моменту розрахунку.
- Базова математика використовує fixed‑point формати, такі як Q64.96 для sqrtPriceX96 та арифметику tick з 1.0001^tick. Будь‑яка кастомна математика зверху має точно відповідати семантиці округлення, щоб уникнути дрейфу інваріанту.
- Swaps можуть бути exactInput або exactOutput. У v3/v4 ціна рухається уздовж ticks; перетин межі tick може активувати/деактивувати range liquidity. Hooks можуть впроваджувати додаткову логіку при перетинах порогів/tick.

## Архетип вразливості: дрейф через перетин порогів та округлення

Типовий вразливий патерн у кастомних hooks:

1. Hook обчислює дельти ліквідності або балансу за своп за допомогою цілочисельного ділення, mulDiv або конверсій fixed‑point (наприклад, token ↔ liquidity за допомогою sqrtPrice і tick діапазонів).
2. Логіка порогів (наприклад, ребалансування, покрокова редистрибуція або активація по діапазонах) тригериться, коли розмір свопу або рух ціни перетинає внутрішню межу.
3. Округлення застосовується непослідовно (наприклад, усічення до нуля, floor проти ceil) між шляхом прямих обчислень і шляхом розрахунку розрахунку/settlement. Невеликі розбіжності не взаємокомпенсуються і натомість кредитують викликачa.
4. Exact‑input свопи, точно підібрані щоб охопити ці межі, багаторазово збирають позитивний залишок округлення. Атакуючий потім виводить накопичений кредит.

Передумови для атаки
- Пул, який використовує кастомний v4 hook, що виконує додаткову математику при кожному swap (наприклад, LDF/rebalancer).
- Принаймні один шлях виконання, де округлення приносить користь ініціатору swap при перетині порогів.
- Можливість багаторазово повторити свопи атомарно (flash loans ідеально підходять для забезпечення тимчасової плаваючої ліквідності та амортизації gas).

## Практична методологія атаки

1) Виявлення кандидатів — пулів з hooks
- Перелічити v4 пули і перевірити PoolKey.hooks != address(0).
- Проінспектувати байткод/ABI hook на наявність callbacks: beforeSwap/afterSwap та будь‑яких кастомних методів ребалансування.
- Шукати математику, яка: ділить на liquidity, конвертує між token amounts і liquidity, або агрегує BalanceDelta з округленням.

2) Моделювання математики hook і порогів
- Відтворити формулу ліквідності/редистрибуції hook: на вході зазвичай sqrtPriceX96, tickLower/Upper, currentTick, fee tier, та net liquidity.
- Замапити порогові/крокові функції: ticks, межі бакетів або breakpoints LDF. Визначити, на якій стороні кожної межі дельта округлюється.
- Ідентифікувати місця, де конверсії кастять між uint256/int256, використовують SafeCast або покладаються на mulDiv з неявним floor.

3) Калібрування exact‑input свопів для перетину меж
- Використати Foundry/Hardhat simulations щоб обчислити мінімальний Δin, потрібний щоб зрушити ціну трохи через межу і викликати гілку hook.
- Перевірити, що після settlement післяSwap ініціатор отримує більше кредиту, ніж витратив, залишаючи позитивний BalanceDelta або кредит в обліку hook.
- Повторювати свопи для накопичення кредиту; потім викликати шлях виведення/settlement hook.

Example Foundry‑style test harness (pseudocode)
```solidity
function test_precision_rounding_abuse() public {
// 1) Arrange: set up pool with hook
PoolKey memory key = PoolKey({
currency0: USDC,
currency1: USDT,
fee: 500, // 0.05%
tickSpacing: 10,
hooks: address(bunniHook)
});
pm.initialize(key, initialSqrtPriceX96);

// 2) Determine a boundary‑crossing exactInput
uint256 exactIn = calibrateToCrossThreshold(key, targetTickBoundary);

// 3) Loop swaps to accrue rounding credit
for (uint i; i < N; ++i) {
pm.swap(
key,
IPoolManager.SwapParams({
zeroForOne: true,
amountSpecified: int256(exactIn), // exactInput
sqrtPriceLimitX96: 0 // allow tick crossing
}),
""
);
}

// 4) Realize inflated credit via hook‑exposed withdrawal
bunniHook.withdrawCredits(msg.sender);
}
```
Калібрування exactInput
- Обчислити ΔsqrtP для кроку tick: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Наближено обчислити Δin, використовуючи формули v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Переконайтеся, що напрямок округлення відповідає основній математиці.
- Змінюйте Δin на ±1 wei поблизу границі, щоб знайти гілку, де hook округлює на вашу користь.

4) Посиліть за допомогою flash loans
- Позичте великий номінал (наприклад, 3M USDT або 2000 WETH), щоб виконати багато ітерацій атомарно.
- Виконайте калібрований цикл swap, потім виведіть кошти і поверніть позику в межах flash loan callback.

Скелет flash loan для Aave V3
```solidity
function executeOperation(
address[] calldata assets,
uint256[] calldata amounts,
uint256[] calldata premiums,
address initiator,
bytes calldata params
) external returns (bool) {
// run threshold‑crossing swap loop here
for (uint i; i < N; ++i) {
_exactInBoundaryCrossingSwap();
}
// realize credits / withdraw inflated balances
bunniHook.withdrawCredits(address(this));
// repay
for (uint j; j < assets.length; ++j) {
IERC20(assets[j]).approve(address(POOL), amounts[j] + premiums[j]);
}
return true;
}
```
5) Вихід і крос‑чейн реплікація
- Якщо hooks розгорнуті на кількох ланцюгах, повторіть ту саму калібровку для кожного.
- Bridge повертає proceeds назад на цільовий chain і опціонально прокручує їх через lending protocols, щоб заплутати потоки.

## Common root causes in hook math

- Mixed rounding semantics: mulDiv floors while later paths effectively round up; or conversions between token/liquidity apply different rounding.
- Tick alignment errors: using unrounded ticks in one path and tick‑spaced rounding in another.
- BalanceDelta sign/overflow issues when converting between int256 and uint256 during settlement.
- Precision loss in Q64.96 conversions (sqrtPriceX96) not mirrored in reverse mapping.
- Accumulation pathways: per‑swap remainders tracked as credits that are withdrawable by the caller instead of being burned/zero‑sum.


## Custom accounting & delta amplification

- Uniswap v4 custom accounting lets hooks return deltas that directly adjust what the caller owes/receives. If the hook tracks credits internally, rounding residue can accumulate across many small operations **before** the final settlement happens.
- This makes boundary/threshold abuse stronger: the attacker can alternate `swap → withdraw → swap` in the same tx, forcing the hook to recompute deltas on slightly different state while all balances are still pending.
- When reviewing hooks, always trace how BalanceDelta/HookDelta is produced and settled. A single biased rounding in one branch can become a compounding credit when deltas are repeatedly re‑computed.

## Defensive guidance

- Differential testing: mirror the hook’s math vs a reference implementation using high‑precision rational arithmetic and assert equality or bounded error that is always adversarial (never favorable to caller).
- Invariant/property tests:
- Sum of deltas (tokens, liquidity) across swap paths and hook adjustments must conserve value modulo fees.
- No path should create positive net credit for the swap initiator over repeated exactInput iterations.
- Threshold/tick boundary tests around ±1 wei inputs for both exactInput/exactOutput.
- Rounding policy: centralize rounding helpers that always round against the user; eliminate inconsistent casts and implicit floors.
- Settlement sinks: accumulate unavoidable rounding residue to protocol treasury or burn it; never attribute to msg.sender.
- Rate‑limits/guardrails: minimum swap sizes for rebalancing triggers; disable rebalances if deltas are sub‑wei; sanity‑check deltas against expected ranges.
- Review hook callbacks holistically: beforeSwap/afterSwap and before/after liquidity changes should agree on tick alignment and delta rounding.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) with an LDF applied per swap to rebalance.
- Affected pools: USDC/USDT on Ethereum and weETH/ETH on Unichain, totaling about $8.4M.
- Step 1 (price push): the attacker flash‑borrowed ~3M USDT and swapped to push the tick to ~5000, shrinking the **active** USDC balance down to ~28 wei.
- Step 2 (rounding drain): 44 tiny withdrawals exploited floor rounding in `BunniHubLogic::withdraw()` to reduce the active USDC balance from 28 wei to 4 wei (‑85.7%) while only a tiny fraction of LP shares was burned. Total liquidity was underestimated by ~84.4%.
- Step 3 (liquidity rebound sandwich): a large swap moved the tick to ~839,189 (1 USDC ≈ 2.77e36 USDT). Liquidity estimates flipped and increased by ~16.8%, enabling a sandwich where the attacker swapped back at the inflated price and exited with profit.
- Fix identified in the post‑mortem: change the idle‑balance update to round **up** so repeated micro‑withdrawals can’t ratchet the pool’s active balance downward.

Simplified vulnerable line (and post‑mortem fix)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Контрольний список для пошуку вразливостей

- Чи використовує pool ненульову hooks address? Які callbacks увімкнені?
- Чи відбуваються per‑swap redistributions/rebalances із використанням custom math? Є якась tick/threshold logic?
- Де використовуються divisions/mulDiv, Q64.96 conversions або SafeCast? Чи семантика округлення глобально послідовна?
- Чи можна сконструювати Δin, що ледь перетинає кордон і дає вигідну гілку округлення? Протестуйте в обох напрямках і для exactInput та exactOutput.
- Чи відстежує hook per‑caller credits або deltas, які можна буде зняти пізніше? Переконайтесь, що залишки нейтралізовано.

## Посилання

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
