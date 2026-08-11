# Експлуатація DeFi/AMM: зловживання точністю/округленням у Uniswap v4 Hook

{{#include ../../banners/hacktricks-training.md}}

На цій сторінці описано клас технік експлуатації DeFi/AMM проти DEX у стилі Uniswap v4, які розширюють базову математику за допомогою custom hooks. Інцидент із Bunni V2 ілюструє пов’язану помилку: помилка в напрямку округлення під час обліку виведення занизила активну ліквідність, а подальший swap розкрив це заниження в прибутковій sandwich-атаці.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Ключова ідея: якщо hook реалізує додатковий облік, що залежить від fixed-point математики, округлення tick і логіки порогів, атакер може створювати exact-input swaps, які перетинають визначені пороги, щоб discrepancies округлення накопичувалися на його користь. Повторення цього патерну з подальшим виведенням завищеного балансу дає прибуток, часто профінансований за допомогою flash loan.

## Передумови: Uniswap v4 hooks і процес swap

- Hooks — це контракти, які PoolManager викликає на визначених етапах життєвого циклу (наприклад, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Pools ініціалізуються з PoolKey, що містить hook-контракт. Ненульова hook-адреса активує callbacks, вибрані для цього pool.<sup>[[4]](#references)[[14]](#references)</sup>
- Hooks можуть повертати **custom deltas**, які змінюють остаточні зміни балансів під час swap або операції з ліквідністю (custom accounting). Ці deltas погашаються як net balances наприкінці виклику, тому будь-яка помилка округлення всередині hook накопичується до settlement.<sup>[[4]](#references)</sup>
- Базова математика використовує fixed-point формати, такі як Q64.96 для sqrtPriceX96, і арифметику tick із 1.0001^tick. Будь-яка custom math, додана поверх цього, має ретельно відповідати семантиці округлення, щоб уникнути drift інваріанта.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps можуть бути exactInput або exactOutput. У v3/v4 ціна рухається вздовж ticks; перетин межі tick може активувати/деактивувати range liquidity. Hooks можуть реалізовувати додаткову логіку під час перетину порогів/ticks.<sup>[[9]](#references)[[11]](#references)</sup>

## Тип вразливості: drift точності/округлення під час перетину порогів

Типовий вразливий патерн у custom hooks:

1. Hook обчислює liquidity або balance deltas для кожного swap за допомогою integer division, mulDiv або fixed-point conversions (наприклад, token ↔ liquidity через sqrtPrice і діапазони tick).
2. Логіка порогів (наприклад, rebalancing, покроковий перерозподіл або активація для кожного range) запускається, коли розмір swap або рух ціни перетинає внутрішню межу.
3. Округлення застосовується непослідовно (наприклад, truncation до нуля, floor замість ceil) між прямим обчисленням і шляхом settlement. Незначні discrepancies не компенсують одна одну, а натомість зараховуються caller.
4. Exact-input swaps, точно підібрані для перетину таких меж, неодноразово збирають додатний залишок округлення. Пізніше атакер виводить накопичений credit.

Передумови атаки
- Pool, що використовує custom v4 hook, який виконує додаткову математику під час кожного swap (наприклад, LDF/rebalancer).
- Принаймні один execution path, у якому округлення під час перетину порогів вигідне ініціатору swap.
- Можливість атомарно повторювати багато swaps (flash loans ідеально підходять для забезпечення тимчасового float та розподілу gas-витрат).

## Практична методологія атаки

1) Визначення candidate pools із hooks
- Перелічити v4 pools і перевірити, що PoolKey.hooks != address(0).
- Проаналізувати bytecode/ABI hook на наявність callbacks: beforeSwap/afterSwap та будь-яких custom rebalancing methods.
- Шукати math, яка: ділить на liquidity, конвертує token amounts у liquidity або агрегує BalanceDelta з округленням.

2) Моделювання математики hook і порогів
- Відтворити формулу liquidity/redistribution hook: inputs зазвичай містять sqrtPriceX96, tickLower/Upper, currentTick, fee tier і net liquidity.
- Відобразити threshold/step functions: ticks, bucket boundaries або LDF breakpoints. Визначити, з якого боку кожної межі округлюється delta.
- Визначити місця, де виконується cast між uint256/int256, використовується SafeCast або застосовується mulDiv з неявним floor.

3) Калібрування exact-input swaps для перетину меж
- Використовувати Foundry/Hardhat simulations для обчислення мінімального Δin, необхідного для переміщення ціни трохи за межу та запуску відповідної гілки hook.
- Перевірити, що afterSwap settlement зараховує caller більше, ніж становить вартість, залишаючи додатний BalanceDelta або credit в обліку hook.
- Повторювати swaps для накопичення credit, а потім викликати withdrawal/settlement path hook.

У v4 swap loop має виконуватися з callback unlock PoolManager; від’ємне `amountSpecified` позначає exact input, а `sqrtPriceLimitX96` має бути строго всередині допустимого діапазону. Нульовий price limit спричиняє revert, тому наведений нижче pseudocode використовує нижню межу для swap zero-for-one.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

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
- Обчисліть цільове значення за допомогою core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) у термінах дійсних значень; результат у форматі Q64.96 округлюється TickMath.<sup>[[13]](#references)</sup>
- Наближено обчисліть вхідну кількість token0 (zero-for-one) за формулою з урахуванням Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Узгодьте округлення з напрямком у core routine.<sup>[[12]](#references)</sup>
- Змінюйте Δin на ±1 wei біля межового значення, щоб знайти гілку, у якій hook округлює на вашу користь.

4) Збільшення масштабу за допомогою flash loans
- Позичте значний обсяг (наприклад, 3M USDT або 2000 WETH), щоб атомарно виконати багато ітерацій.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Виконайте калібрований цикл swap, потім виведіть кошти й погасіть позику в межах callback flash loan.

Каркас flash loan Aave V3
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
- Якщо hooks розгорнуті в кількох мережах, повторіть те саме калібрування для кожної мережі.
- Під час інциденту Bunni ліквідність flash-loan і bridge-маршрути відрізнялися залежно від мережі, тому під час відтворення аналізу враховуйте специфічні для кожної мережі обмеження.<sup>[[1]](#references)[[2]](#references)</sup>

## Поширені першопричини в математиці hooks

- Змішані правила округлення: mulDiv округлює вниз, тоді як наступні шляхи фактично округлюють вгору; або перетворення між токенами/ліквідністю застосовують різні правила округлення.
- Помилки вирівнювання tick: в одному шляху використовуються неокруглені ticks, а в іншому — округлення з урахуванням кроку tick.
- Проблеми зі знаком/переповненням BalanceDelta під час перетворення між int256 і uint256 у процесі settlement.
- Втрата точності під час перетворень Q64.96 (sqrtPriceX96), яка не відтворюється у зворотному mapping.
- Шляхи накопичення: залишки після кожного swap обліковуються як credits, які може withdraw caller, замість того щоб їх було спалено або зведено до нуля.

## Custom accounting і посилення delta

- Custom accounting у Uniswap v4 дає hooks змогу повертати deltas, які безпосередньо коригують суму, що caller має сплатити або отримати. Якщо hook внутрішньо обліковує credits, залишок від округлення може накопичуватися під час багатьох малих операцій **до** виконання фінального settlement.<sup>[[4]](#references)</sup>
- Якщо hook надає сумісний withdrawal path, attacker може чергувати `swap → withdraw → swap` у межах того самого callback розблокування PoolManager, змушуючи hook повторно обчислювати deltas на дещо іншому стані, тоді як баланси залишаються pending до завершення unlock.<sup>[[4]](#references)[[10]](#references)</sup>
- Під час перевірки hooks завжди простежуйте, як створюється та виконується settlement для BalanceDelta/HookDelta. Одне зміщене округлення в одній гілці може перетворитися на compound credit, якщо deltas обчислюються повторно.

## Рекомендації щодо захисту

- Differential testing: порівнюйте математику hook із reference implementation, використовуючи високоточну раціональну арифметику, і перевіряйте рівність або обмежену похибку, яка завжди є adversarial (ніколи не вигідна caller).
- Invariant/property tests:
- Сума deltas (токенів, ліквідності) для всіх swap paths і коригувань hook має зберігати value з урахуванням fees.
- Жоден path не має створювати позитивний net credit для ініціатора swap під час повторюваних ітерацій exactInput.
- Перевірки порогів/tick boundary для inputs у ±1 wei для обох режимів exactInput/exactOutput.
- Політика округлення: централізуйте helper-функції округлення, які завжди округлюють проти user; усуньте несумісні casts і неявні округлення вниз.
- Settlement sinks: спрямовуйте неминучий залишок від округлення до protocol treasury або спалюйте його; ніколи не зараховуйте його на msg.sender.
- Rate-limits/guardrails: мінімальні розміри swap для тригерів rebalancing; вимикайте rebalances, якщо deltas менші за wei; перевіряйте deltas на відповідність очікуваним діапазонам.
- Перевіряйте callback-и hook комплексно: beforeSwap/afterSwap і before/after зміни ліквідності мають узгоджено використовувати вирівнювання tick та округлення delta.

## Case study: Bunni V2 (2025-09-02)

- Protocol: Bunni V2, Uniswap v4 hook, що використовує Liquidity Density Function (LDF) для обчислення щільності токенів і оцінок загальної ліквідності.<sup>[[1]](#references)[[2]](#references)</sup>
- Affected pools: USDC/USDT в Ethereum і weETH/ETH в Unichain, загальною вартістю близько $8.4M.<sup>[[1]](#references)</sup>
- Step 1 (price push): attacker позичив через flash-loan приблизно 3M USDT і виконав swap, піднявши tick приблизно до 5000 та зменшивши **активний** баланс USDC приблизно до 28 wei.<sup>[[1]](#references)</sup>
- Step 2 (rounding drain): 44 малих withdrawals використали округлення вниз у `BunniHubLogic::withdraw()`, щоб зменшити активний баланс USDC з 28 wei до 4 wei (-85.7%), тоді як було спалено лише крихітну частку LP shares. Загальна ліквідність зменшилася приблизно на 84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Step 3 (liquidity rebound sandwich): великий swap перемістив tick приблизно до 839,189 (1 USDC ≈ 2.77e36 USDT). Оцінки ліквідності змінилися та зросли приблизно на 16.8%, що уможливило sandwich: attacker виконав зворотний swap за завищеною ціною та вийшов із прибутком.<sup>[[1]](#references)</sup>
- Fix identified in the post-mortem: змінити оновлення idle-balance так, щоб воно округлювало **вгору**, завдяки чому повторювані micro-withdrawals більше не зможуть поступово зменшувати активний баланс pool.<sup>[[1]](#references)</sup>

Спрощений вразливий рядок (і fix із post-mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Чекліст перевірки

- Чи використовує pool ненульову адресу hooks? Які callbacks увімкнено?
- Чи виконуються перерозподіли/rebalance для кожного swap із використанням custom math? Чи є логіка tick/threshold?
- Де використовуються divisions/mulDiv, перетворення Q64.96 або SafeCast? Чи є семантика округлення узгодженою глобально?
- Чи можете ви створити Δin, який ледь перетинає boundary і активує вигідну гілку округлення? Перевірте обидва напрямки, а також exactInput і exactOutput.
- Чи відстежує hook credits або deltas для кожного caller, які можна буде згодом withdraw? Переконайтеся, що залишок нейтралізується.

## References

- [1] [Посмертний аналіз експлойту Bunni (вересень 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Експлойт Bunni V2: повний аналіз hack](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Експлойт Bunni V2: $8,3 млн виведено через ваду liquidity (короткий огляд)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Whitepaper Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Передумови Uniswap v4 (дослідження QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Механіка liquidity у Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Механіка swap у Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks Uniswap v4 і міркування щодо безпеки](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol у Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol у Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams у Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol у Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol у Uniswap v4 core](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey у Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
