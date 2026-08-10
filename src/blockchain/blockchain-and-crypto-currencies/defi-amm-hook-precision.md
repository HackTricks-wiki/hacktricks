# Експлуатація DeFi/AMM: зловживання точністю/округленням у Uniswap v4 Hook

На цій сторінці описано клас технік експлуатації DeFi/AMM проти DEX у стилі Uniswap v4, які розширюють базову математику за допомогою custom hooks. Інцидент Bunni V2 демонструє споріднену помилку: помилка в напрямку округлення під час обліку виведення занизила активну ліквідність, а подальший swap розкрив це заниження у вигідній sandwich-атаці.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Ключова ідея: якщо hook реалізує додатковий облік, що залежить від fixed‑point математики, округлення tick і логіки порогів, атакер може створювати exact‑input swaps, які перетинають певні пороги, щоб розбіжності округлення накопичувалися на його користь. Повторення цього шаблону з подальшим виведенням збільшеного балансу дає прибуток, часто профінансований flash loan.

## Передумови: Uniswap v4 hooks і swap flow

- Hooks — це контракти, які PoolManager викликає на певних етапах життєвого циклу (наприклад, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Пули ініціалізуються з PoolKey, що містить hook contract. Ненульова hook address активує callbacks, вибрані для цього пулу.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks можуть повертати **custom deltas**, які змінюють фінальні зміни балансів під час swap або операції з ліквідністю (custom accounting). Ці deltas погашаються як net balances наприкінці виклику, тому будь-яка помилка округлення всередині hook math накопичується до settlement.<sup>[[4]](#references)</sup>
- Core math використовує fixed-point формати, такі як Q64.96 для sqrtPriceX96, а також арифметику tick із 1.0001^tick. Будь-яка custom math поверх цього повинна точно відповідати семантиці округлення, щоб уникнути drift інваріанта.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps можуть бути exactInput або exactOutput. У v3/v4 ціна рухається вздовж tick; перетин межі tick може активувати або деактивувати range liquidity. Hooks можуть реалізовувати додаткову логіку під час перетину порогів/tick.<sup>[[9]](#references)[[11]](#references)</sup>

## Тип вразливості: drift точності/округлення під час перетину порогів

Типовий вразливий шаблон у custom hooks:

1. Hook обчислює per-swap liquidity або balance deltas за допомогою цілочисельного ділення, mulDiv або fixed-point перетворень (наприклад, token ↔ liquidity із використанням sqrtPrice і діапазонів tick).
2. Логіка порогів (наприклад, rebalancing, покроковий розподіл або активація per-range) запускається, коли розмір swap або рух ціни перетинає внутрішню межу.
3. Округлення застосовується непослідовно (наприклад, truncation до нуля, floor замість ceil) між прямим обчисленням і шляхом settlement. Малі розбіжності не компенсуються, а натомість зараховуються caller.
4. Exact‑input swaps, точно підібрані для перетину таких меж, багаторазово отримують додатний залишок округлення. Пізніше атакер виводить накопичений credit.

Передумови атаки
- Pool із custom v4 hook, який виконує додаткові обчислення під час кожного swap (наприклад, LDF/rebalancer).
- Щонайменше один execution path, у якому округлення вигідне ініціатору swap під час перетину порогів.
- Можливість атомарно повторювати багато swaps (flash loans ідеально підходять для надання тимчасового float та розподілу gas-витрат).

## Практична методологія атаки

1) Визначити candidate pools із hooks
- Перерахувати v4 pools і перевірити, що PoolKey.hooks != address(0).
- Перевірити bytecode/ABI hook на наявність callbacks: beforeSwap/afterSwap та будь-яких custom rebalancing methods.
- Шукати math, яка: ділить на liquidity, перетворює token amounts на liquidity або агрегує BalanceDelta з округленням.

2) Змоделювати math і thresholds hook
- Відтворити формулу liquidity/redistribution hook: inputs зазвичай містять sqrtPriceX96, tickLower/Upper, currentTick, fee tier і net liquidity.
- Побудувати карту threshold/step functions: ticks, bucket boundaries або LDF breakpoints. Визначити, з якого боку кожної межі округлюється delta.
- Визначити місця, де виконуються cast між uint256/int256, використовується SafeCast або застосовується mulDiv з неявним floor.

3) Калібрувати exact‑input swaps для перетину меж
- Використати Foundry/Hardhat simulations, щоб обчислити мінімальний Δin, необхідний для переміщення ціни трохи за межу та запуску гілки hook.
- Перевірити, що afterSwap settlement зараховує caller більше, ніж коштує операція, залишаючи додатний BalanceDelta або credit в accounting hook.
- Повторювати swaps для накопичення credit, а потім викликати withdrawal/settlement path hook.

У v4 swap loop має виконуватися з callback unlock PoolManager; від’ємне значення `amountSpecified` позначає exact input, а `sqrtPriceLimitX96` має бути строго всередині допустимого діапазону. Нульовий price limit спричиняє revert, тому наведений нижче pseudocode використовує нижню межу для swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Приклад test harness у стилі Foundry (pseudocode)
```solidity
function test_precision_rounding_abuse() public {
// 1) Arrange: set up pool with hook
PoolKey memory key = PoolKey({
currency0: USDC,
currency1: USDT,
fee: 500, // 0.05%
tickSpacing: 10,
hooks: IHooks(address(bunniHook))
});
pm.initialize(key, initialSqrtPriceX96);

// 2) Determine a boundary‑crossing exactInput
uint256 exactIn = calibrateToCrossThreshold(key, targetTickBoundary);

// 3) Loop swaps to accrue rounding credit
// This loop runs inside the PoolManager unlockCallback.
for (uint i; i < N; ++i) {
pm.swap(
key,
SwapParams({
zeroForOne: true,
amountSpecified: -int256(exactIn), // exactInput
sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1 // allow movement to the lower bound
}),
""
);
}

// 4) Realize inflated credit via hook‑exposed withdrawal
bunniHook.withdrawCredits(msg.sender);
}
```
Калібрування exactInput
- Обчисліть цільове значення за допомогою core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) у термінах реальних значень; результат Q64.96 округлюється TickMath.<sup>[[13]](#references)</sup>
- Наближено обчисліть вхід token0 (zero-for-one), використовуючи формулу з урахуванням Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Узгодьте напрямне округлення з core routine.<sup>[[12]](#references)</sup>
- Змініть Δin на ±1 wei біля межі, щоб знайти гілку, у якій hook округлює на вашу користь.

4) Посильте атаку за допомогою flash loans
- Позичте великий notional (наприклад, 3M USDT або 2000 WETH), щоб атомарно виконати багато ітерацій.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Виконайте відкалібрований swap loop, потім виведіть кошти та поверніть позику в межах flash loan callback.

Каркас flash loan для Aave V3
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
5) Вихід і cross-chain реплікація
- Якщо hooks розгорнуті в кількох chains, повторіть ту саму калібровку для кожного chain.
- В інциденті Bunni flash-loan liquidity і bridge routes відрізнялися залежно від chain, тому під час відтворення аналізу враховуйте обмеження, специфічні для кожного chain.<sup>[[1]](#references)[[2]](#references)</sup>

## Поширені першопричини в математиці hooks

- Змішані правила округлення: mulDiv округлює вниз, тоді як наступні шляхи фактично округлюють угору; або конвертації між token/liquidity застосовують різне округлення.
- Помилки вирівнювання tick: в одному шляху використовуються неокруглені ticks, а в іншому — округлення з урахуванням tick spacing.
- Проблеми зі знаком/переповненням BalanceDelta під час конвертації між int256 і uint256 у процесі settlement.
- Втрата точності в Q64.96-конвертаціях (sqrtPriceX96), не відображена в зворотному mapping.
- Шляхи накопичення: залишки від кожного swap обліковуються як credits, які може вивести caller, замість того щоб вони спалювалися або компенсувалися до нульової суми.

## Custom accounting і delta amplification

- Uniswap v4 custom accounting дозволяє hooks повертати deltas, які безпосередньо коригують суму, яку caller має сплатити або отримати. Якщо hook внутрішньо обліковує credits, залишок від округлення може накопичуватися протягом багатьох малих операцій **до** виконання final settlement.<sup>[[4]](#references)</sup>
- Якщо hook відкриває сумісний withdrawal path, attacker може чергувати `swap → withdraw → swap` у межах того самого PoolManager unlock callback, змушуючи hook повторно обчислювати deltas для дещо іншого state, поки balances залишаються pending до завершення unlock.<sup>[[4]](#references)[[10]](#references)</sup>
- Під час аудиту hooks завжди відстежуйте, як створюється та виконується settlement для BalanceDelta/HookDelta. Одне упереджене округлення в окремій гілці може перетворитися на credit, що накопичується, якщо deltas обчислюються повторно.

## Рекомендації щодо захисту

- Differential testing: порівнюйте математику hook із reference implementation, використовуючи високоточну rational arithmetic, і перевіряйте рівність або обмежену похибку, яка завжди є несприятливою для caller.
- Invariant/property tests:
- Сума deltas (tokens, liquidity) для всіх swap paths і hook adjustments має зберігати value з урахуванням fees.
- Жоден path не має створювати позитивний net credit для swap initiator під час повторних ітерацій exactInput.
- Перевірки threshold/tick boundary навколо введень ±1 wei для обох exactInput/exactOutput.
- Політика округлення: централізуйте rounding helpers, які завжди округлюють проти user; усуньте непослідовні casts і неявні floors.
- Settlement sinks: спрямовуйте неминучий залишок від округлення до protocol treasury або спалюйте його; ніколи не зараховуйте його на msg.sender.
- Rate-limits/guardrails: мінімальні розміри swap для rebalancing triggers; вимикайте rebalances, якщо deltas менші за wei; перевіряйте deltas на відповідність очікуваним діапазонам.
- Перевіряйте hook callbacks комплексно: beforeSwap/afterSwap і before/after liquidity changes мають узгоджено обробляти tick alignment та delta rounding.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2, Uniswap v4 hook, що використовує Liquidity Density Function (LDF) для обчислення token density і total-liquidity estimates.<sup>[[1]](#references)[[2]](#references)</sup>
- Зачеплені pools: USDC/USDT в Ethereum і weETH/ETH в Unichain, загалом приблизно $8.4M.<sup>[[1]](#references)</sup>
- Step 1 (price push): attacker позичив через flash loan приблизно 3M USDT і виконав swap, щоб перемістити tick приблизно до 5000, зменшивши **активний** баланс USDC приблизно до 28 wei.<sup>[[1]](#references)</sup>
- Step 2 (rounding drain): 44 малих withdrawals використали floor rounding у `BunniHubLogic::withdraw()`, щоб зменшити активний баланс USDC з 28 wei до 4 wei (-85.7%), при цьому було спалено лише дуже малу частку LP shares. Загальна liquidity зменшилася приблизно на 84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Step 3 (liquidity rebound sandwich): великий swap перемістив tick приблизно до 839,189 (1 USDC ≈ 2.77e36 USDT). Оцінки liquidity змінилися та зросли приблизно на 16.8%, що уможливило sandwich: attacker виконав зворотний swap за завищеною ціною та вийшов із прибутком.<sup>[[1]](#references)</sup>
- Виправлення, визначене в post-mortem: змінити оновлення idle balance так, щоб воно округлювалося **вгору** і повторні micro-withdrawals більше не зменшували поступово active balance pool.<sup>[[1]](#references)</sup>

Спрощений вразливий рядок (і виправлення з post-mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Чекліст пошуку

- Чи використовує пул ненульову адресу hooks? Які callbacks увімкнено?
- Чи виконуються перерозподіли/rebalance для кожного swap із використанням custom math? Чи є логіка tick/threshold?
- Де використовуються divisions/mulDiv, конвертації Q64.96 або SafeCast? Чи є семантика округлення узгодженою глобально?
- Чи можна сконструювати Δin, яке ледь перетинає межу та призводить до вигідної гілки округлення? Перевірте обидва напрямки, а також exactInput і exactOutput.
- Чи відстежує hook кредити або дельти для кожного caller, які можна вивести пізніше? Переконайтеся, що залишок нейтралізується.

## References

- [1] [Звіт про інцидент Bunni Exploit (вересень 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Bunni V2 Exploit: повний аналіз hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Bunni V2 Exploit: $8.3M виведено через вразливість ліквідності (резюме)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Whitepaper Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Передумови Uniswap v4 (дослідження QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Механіка ліквідності в Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Механіка swap в Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks Uniswap v4 та міркування щодо безпеки](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol у Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol у Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams у Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol у Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol у Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey у Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
