# Експлуатація DeFi/AMM: Uniswap v4 Hook Precision/Rounding Abuse

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка описує клас технік експлуатації DeFi/AMM проти DEX-ів типу Uniswap v4, що розширюють базову математику кастомними hooks. Нещодавній інцидент у Bunni V2 використав помилку округлення/точності в Liquidity Distribution Function (LDF), яка виконувалася на кожен swap, дозволивши атакуючому накопичувати позитивні кредити й викачати ліквідність.

Ключова ідея: якщо hook реалізує додатковий облік, що залежить від fixed‑point math, округлення tick та логіки порогів, атакуючий може сформувати exact‑input swaps, які проходять через конкретні пороги так, що розбіжності округлення акумулюються на його користь. Повторення патерну і подальше виведення здутого балансу приносить прибуток, часто профінансований flash loan.

## Background: Uniswap v4 hooks and swap flow

- Hooks — це контракти, які PoolManager викликає у певні точки життєвого циклу (наприклад, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity).
- Пули ініціалізуються з PoolKey, що включає адресу hooks. Якщо вона відрізняється від нуля, PoolManager робить callbacks при кожній відповідній операції.
- Базова математика використовує fixed‑point формати, такі як Q64.96 для sqrtPriceX96 і арифметику tick з 1.0001^tick. Будь‑яка кастомна математика зверху має точно відповідати семантиці округлення, щоб уникнути дрейфу інваріантів.
- Swaps можуть бути exactInput або exactOutput. У v3/v4 ціна рухається уздовж ticks; перетин межі tick може активувати/деактивувати range liquidity. Hooks можуть реалізувати додаткову логіку при порогах/перетинах tick.

## Vulnerability archetype: threshold‑crossing precision/rounding drift

Типовий вразливий патерн у кастомних hooks:

1. Hook обчислює дельти ліквідності або балансу за swap з використанням integer division, mulDiv або fixed‑point конверсій (наприклад, token ↔ liquidity за допомогою sqrtPrice та tick ranges).
2. Порогова логіка (наприклад, rebalancing, покрокова redistribuiton або активація по діапазонах) тригериться, коли розмір swap або рух ціни перетинає внутрішню межу.
3. Округлення застосовується непослідовно (наприклад, усічення до нуля, floor проти ceil) між прямим обчисленням і шляхом settlement. Маленькі розбіжності не компенсуються і натомість зараховуються викликувачеві.
4. Exact‑input swaps, точно підібрані щоб перетнути ці межі, багаторазово збирають позитивний залишок округлення. Атакуючий пізніше виводить накопичений кредит.

Умови для атаки
- Пул з кастомним v4 hook, який виконує додаткову математику на кожен swap (наприклад, LDF/rebalancer).
- Принаймні один шлях виконання, де округлення вигідне ініціатору swap при перетинах порогів.
- Можливість багаторазового повторення swaps атомарно (flash loans ідеальні для забезпечення тимчасової ліквідності та амортизації gas).

## Practical attack methodology

1) Ідентифікувати кандидатні пули з hooks
- Перерахувати v4 пули і перевірити PoolKey.hooks != address(0).
- Проінспектувати hook bytecode/ABI на предмет callbacks: beforeSwap/afterSwap та будь‑яких кастомних rebalancing методів.
- Шукати математику, що: ділить на liquidity, конвертує між token amounts і liquidity, або агрегує BalanceDelta з округленням.

2) Замоделювати математику hook і пороги
- Відтворити формулу liquidity/redistribution hook: вхідні дані зазвичай включають sqrtPriceX96, tickLower/Upper, currentTick, fee tier і net liquidity.
- Замапити порогові/покрокові функції: ticks, bucket boundaries або LDF breakpoints. Визначити, на якій стороні кожної межі дельта округлюється.
- Ідентифікувати місця, де конверсії кастять між uint256/int256, використовують SafeCast або залежать від mulDiv з імпліцитним floor.

3) Калібрувати exact‑input swaps для перетину меж
- Використовувати Foundry/Hardhat симуляції, щоб обчислити мінімальний Δin, необхідний, щоб зрушити ціну трохи понад межу і викликати гілку hook.
- Перевірити, що після afterSwap settlement викликвач отримує більше, ніж коштує операція, залишаючи позитивний BalanceDelta або кредит у обліку hook.
- Повторювати свопи для накопичення кредиту; потім викликати шлях withdrawal/settlement hook.

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
- Обчисліть ΔsqrtP для кроку тика: sqrtP_next = sqrtP_current × 1.0001^(Δtick).
- Наближено оцініть Δin, використовуючи формули v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Переконайтесь, що напрямок округлення відповідає математиці ядра.
- Відрегулюйте Δin на ±1 wei навколо межі, щоб знайти гілку, де hook округлює на вашу користь.

4) Підсиліть за допомогою flash loans
- Позичте великий номінал (наприклад, 3M USDT або 2000 WETH), щоб виконати багато ітерацій атомарно.
- Виконайте калібрований swap-цикл, потім зніміть і поверніть кошти в межах callback'а flash loan.

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
5) Вихід і крос‑чейн реплікація
- Якщо hooks розгорнуті на кількох ланцюгах, повторіть ту саму калібрування для кожного.
- Bridge повертає кошти назад на цільовий ланцюг і опційно прокручує їх через протоколи кредитування для ускладнення трасування потоків.

## Поширені кореневі причини в обчисленнях hook'а

- Mixed rounding semantics: mulDiv floors while later paths effectively round up; or conversions between token/liquidity apply different rounding.
- Tick alignment errors: using unrounded ticks in one path and tick‑spaced rounding in another.
- BalanceDelta sign/overflow issues when converting between int256 and uint256 during settlement.
- Precision loss in Q64.96 conversions (sqrtPriceX96) not mirrored in reverse mapping.
- Accumulation pathways: per‑swap remainders tracked as credits that are withdrawable by the caller instead of being burned/zero‑sum.

## Захисні рекомендації

- Differential testing: mirror the hook’s math vs a reference implementation using high‑precision rational arithmetic and assert equality or bounded error that is always adversarial (never favorable to caller).
- Invariant/property tests:
- Sum of deltas (tokens, liquidity) across swap paths and hook adjustments must conserve value modulo fees.
- No path should create positive net credit for the swap initiator over repeated exactInput iterations.
- Threshold/tick boundary tests around ±1 wei inputs for both exactInput/exactOutput.
- Rounding policy: centralize rounding helpers that always round against the user; eliminate inconsistent casts and implicit floors.
- Settlement sinks: accumulate unavoidable rounding residue to protocol treasury or burn it; never attribute to msg.sender.
- Rate‑limits/guardrails: minimum swap sizes for rebalancing triggers; disable rebalances if deltas are sub‑wei; sanity‑check deltas against expected ranges.
- Review hook callbacks holistically: beforeSwap/afterSwap and before/after liquidity changes should agree on tick alignment and delta rounding.

## Дослідження випадку: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) with an LDF applied per swap to rebalance.
- Root cause: rounding/precision error in LDF liquidity accounting during threshold‑crossing swaps; per‑swap discrepancies accrued as positive credits for the caller.
- Ethereum leg: attacker took a ~3M USDT flash loan, performed calibrated exact‑input swaps on USDC/USDT to build credits, withdrew inflated balances, repaid, and routed funds via Aave.
- UniChain leg: repeated the exploit with a 2000 WETH flash loan, siphoning ~1366 WETH and bridging to Ethereum.
- Impact: ~USD 8.3M drained across chains. No user interaction required; entirely on‑chain.

## Чекліст для виявлення

- Does the pool use a non‑zero hooks address? Which callbacks are enabled?
- Are there per‑swap redistributions/rebalances using custom math? Any tick/threshold logic?
- Where are divisions/mulDiv, Q64.96 conversions, or SafeCast used? Are rounding semantics globally consistent?
- Can you construct Δin that barely crosses a boundary and yields a favorable rounding branch? Test both directions and both exactInput and exactOutput.
- Does the hook track per‑caller credits or deltas that can be withdrawn later? Ensure residue is neutralized.

## References

- [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)

{{#include ../../banners/hacktricks-training.md}}
