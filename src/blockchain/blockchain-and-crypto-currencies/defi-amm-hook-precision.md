# DeFi/AMM Exploitation: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}



This page documents a class of DeFi/AMM exploitation techniques against Uniswap v4–style DEXes that extend core math with custom hooks. A recent incident in Bunni V2 leveraged a rounding/precision flaw in a Liquidity Distribution Function (LDF) executed on each swap, enabling the attacker to accrue positive credits and drain liquidity.

Key idea: if a hook implements additional accounting that depends on fixed‑point math, tick rounding, and threshold logic, an attacker can craft exact‑input swaps that cross specific thresholds so that rounding discrepancies accumulate in their favor. Repeating the pattern and then withdrawing the inflated balance realizes profit, often financed with a flash loan.

## Background: Uniswap v4 hooks and swap flow

- Hooks are contracts that the PoolManager calls at specific lifecycle points (e.g., beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).
- Pools are initialized with a PoolKey including hooks address. If non‑zero, PoolManager performs callbacks on every relevant operation.
- Hooks can return **custom deltas** that modify the final balance changes of a swap or liquidity action (custom accounting). Those deltas are settled as net balances at the end of the call, so any rounding error inside hook math accumulates before settlement.
- Core math uses fixed‑point formats such as Q64.96 for sqrtPriceX96 and tick arithmetic with 1.0001^tick. Any custom math layered on top must carefully match rounding semantics to avoid invariant drift.
- Swaps can be exactInput or exactOutput. In v3/v4, price moves along ticks; crossing a tick boundary may activate/deactivate range liquidity. Hooks may implement extra logic on threshold/tick crossings.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

A typical vulnerable pattern in custom hooks:

1. The hook computes per‑swap liquidity or balance deltas using integer division, mulDiv, or fixed‑point conversions (e.g., token ↔ liquidity using sqrtPrice and tick ranges).
2. Threshold logic (e.g., rebalancing, stepwise redistribution, or per‑range activation) is triggered when a swap size or price movement crosses an internal boundary.
3. Rounding is applied inconsistently (e.g., truncation toward zero, floor versus ceil) between the forward calculation and the settlement path. Small discrepancies don’t cancel and instead credit the caller.
4. Exact‑input swaps, precisely sized to straddle those boundaries, repeatedly harvest the positive rounding remainder. The attacker later withdraws the accumulated credit.

Attack preconditions
- A pool using a custom v4 hook that performs additional math on each swap (e.g., an LDF/rebalancer).
- At least one execution path where rounding benefits the swap initiator across threshold crossings.
- Ability to repeat many swaps atomically (flash loans are ideal to supply temporary float and amortize gas).

## Practical attack methodology

1) Identify candidate pools with hooks
- Enumerate v4 pools and check PoolKey.hooks != address(0).
- Inspect hook bytecode/ABI for callbacks: beforeSwap/afterSwap and any custom rebalancing methods.
- Look for math that: divides by liquidity, converts between token amounts and liquidity, or aggregates BalanceDelta with rounding.

2) Model the hook’s math and thresholds
- Recreate the hook’s liquidity/redistribution formula: inputs typically include sqrtPriceX96, tickLower/Upper, currentTick, fee tier, and net liquidity.
- Map threshold/step functions: ticks, bucket boundaries, or LDF breakpoints. Determine which side of each boundary the delta is rounded on.
- Identify where conversions cast between uint256/int256, use SafeCast, or rely on mulDiv with implicit floor.

3) Calibrate exact‑input swaps to cross boundaries
- Use Foundry/Hardhat simulations to compute the minimal Δin needed to move price just across a boundary and trigger the hook’s branch.
- Verify that afterSwap settlement credits the caller more than the cost, leaving a positive BalanceDelta or credit in the hook’s accounting.
- Repeat swaps to accumulate credit; then call the hook’s withdrawal/settlement path.

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
- Аппроксимувати Δin, використовуючи v3/v4 формули: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Переконайтеся, що напрямок округлення відповідає core math.
- Підкоригуйте Δin на ±1 wei навколо межі, щоб знайти гілку, де hook округлює на вашу користь.

4) Посилення за допомогою flash loans
- Позичте великий номінал (наприклад, 3M USDT або 2000 WETH), щоб виконати багато ітерацій атомарно.
- Виконайте калібрований swap loop, потім зніміть кошти і поверніть їх у межах flash loan callback.

Aave V3 flash loan skeleton
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
5) Вихід та міжланцюгова реплікація
- Якщо hooks розгорнуті на кількох ланцюгах, повторіть ту ж калібрування для кожного ланцюга.
- Міст повертає кошти назад на цільовий ланцюг і опційно маршрутизує через протоколи кредитування для заплутування потоків.

## Поширені кореневі причини в обчисленнях hook'а

- Mixed rounding semantics: mulDiv floors while later paths effectively round up; або перетворення між token/liquidity застосовують різні правила округлення.
- Tick alignment errors: використання неокруглених tick'ів в одному шляху та округлення по tick‑spacing в іншому.
- BalanceDelta sign/overflow issues при конвертації між int256 і uint256 під час settlement.
- Втрата точності в Q64.96 конвертаціях (sqrtPriceX96), яка не відтворюється при зворотньому відображенні.
- Accumulation pathways: залишки після кожного swap відслідковуються як кредити, які може зняти викликач замість того, щоб вони були знищені/бути нульовою сумою.

## Custom accounting & delta amplification

- Uniswap v4 custom accounting дозволяє hooks повертати дельти, які прямо коригують те, що caller винен/отримує. Якщо hook відслідковує кредити внутрішньо, округлювальні залишки можуть накопичуватись через велику кількість дрібних операцій **before** остаточного settlement.
- Це посилює можливість зловживань граничними значеннями: зловмисник може чергувати `swap → withdraw → swap` в тій самій tx, змушуючи hook перераховувати дельти на трохи відмінному стані, поки всі баланси ще очікують на завершення.
- При огляді hooks завжди простежуйте, як BalanceDelta/HookDelta генерується і вирішується. Одна зміщена округлова операція в одній гілці може стати кумулятивним кредитом, якщо дельти повторно перераховуються.

## Оборонні рекомендації

- Differential testing: відтворіть математику hook'а проти референтної реалізації з використанням раціональної арифметики високої точності і перевіряйте рівність або обмежену помилку, яка завжди антагоністична (ніколи не на користь caller).
- Invariant/property tests:
  - Сума дельт (tokens, liquidity) по swap-шляхах і коригуваннях hook повинна зберігати вартість модульно відносно fees.
  - Жоден шлях не повинен створювати позитивний чистий кредит для ініціатора swap при повторних exactInput ітераціях.
  - Тести меж/граней tick навколо ±1 wei для обох exactInput/exactOutput.
- Rounding policy: централізуйте допоміжні функції округлення, які завжди округлюють проти користувача; ліквідуйте неконсистентні касти й неявні floor-операції.
- Settlement sinks: акумулюйте неминучі округлювальні залишки в протокольну скарбницю або спалюйте їх; ніколи не приписуйте їх msg.sender.
- Rate‑limits/guardrails: мінімальні розміри swap для тригерів ребалансування; відключайте ребаланси, якщо дельти менші за wei; перевіряйте дельти на адекватність очікуваним діапазонам.
- Переглядайте callbacks hook'а цілісно: beforeSwap/afterSwap і before/after зміни ліквідності повинні погоджуватися по вирівнюванню tick і правилах округлення дельт.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) з LDF, застосованим на кожен swap для ребалансування.
- Affected pools: USDC/USDT на Ethereum та weETH/ETH на Unichain, загалом близько $8.4M.
- Step 1 (price push): зловмисник flash‑borrowed ~3M USDT і обміняв їх, щоб протиснути tick до ~5000, зменшивши **active** USDC баланс до ~28 wei.
- Step 2 (rounding drain): 44 малі withdraws використали floor округлення в `BunniHubLogic::withdraw()` щоб зменшити active USDC баланс з 28 wei до 4 wei (‑85.7%) при тому, що була знищена лише незначна частка LP shares. Загальна ліквідність була недооцінена приблизно на ~84.4%.
- Step 3 (liquidity rebound sandwich): великий swap перемістив tick до ~839,189 (1 USDC ≈ 2.77e36 USDT). Оцінки ліквідності змінились і зросли на ~16.8%, що дозволило провести sandwich, де зловмисник повернувся по завищеній ціні і вийшов з прибутком.
- Фікс, ідентифікований у постмортемі: змінити оновлення idle‑balance так, щоб округлювати **up**, щоб повторні мікровиведення не могли опускати active баланс пулу вниз.

Simplified vulnerable line (and post‑mortem fix)
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Контрольний список полювання

- Чи використовує пул ненульову hooks address? Які callbacks увімкнені?
- Чи присутні per‑swap redistributions/rebalances, що використовують кастомну математику? Якась tick/threshold логіка?
- Де використовуються divisions/mulDiv, Q64.96 conversions, or SafeCast? Чи семантика округлення узгоджена глобально?
- Чи можна сконструювати Δin, який ледь перетинає межу і призводить до вигідної гілки округлення? Протестуйте в обох напрямках та для обох exactInput і exactOutput.
- Чи відстежує hook per‑caller credits or deltas, які можна буде вивести пізніше? Переконайтеся, що залишок нейтралізовано.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
