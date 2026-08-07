# Експлуатація DeFi/AMM: зловживання точністю/округленням у Uniswap v4 Hook

{{#include ../../banners/hacktricks-training.md}}

На цій сторінці описано клас технік експлуатації DeFi/AMM проти DEX у стилі Uniswap v4, які розширюють базову математику за допомогою custom hooks. У нещодавньому інциденті з Bunni V2 було використано помилку округлення/точності у функції розподілу ліквідності (Liquidity Distribution Function, LDF), що виконувалася під час кожного swap і давала змогу атакувальнику накопичувати позитивні кредити та виводити ліквідність.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>

Ключова ідея: якщо hook реалізує додатковий облік, що залежить від fixed‑point математики, округлення tick і порогової логіки, атакувальник може створювати exact‑input swaps, які перетинають певні пороги, завдяки чому розбіжності округлення накопичуються на його користь. Після повторення цієї схеми та виведення завищеного балансу атакувальник отримує прибуток, часто фінансуючи операцію через flash loan.

## Передумови: hooks Uniswap v4 і потік swap

- Hooks — це контракти, які PoolManager викликає на визначених етапах життєвого циклу (наприклад, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[3]](#references)[[6]](#references)</sup>
- Pools ініціалізуються з PoolKey, що містить адресу hooks. Якщо вона не дорівнює нулю, PoolManager виконує callbacks під час кожної відповідної операції.<sup>[[6]](#references)</sup>
- Hooks можуть повертати **custom deltas**, які змінюють фінальні зміни балансу для swap або операції з ліквідністю (custom accounting). Ці deltas розраховуються як net balances наприкінці виклику, тому будь-яка помилка округлення всередині математики hook накопичується до моменту розрахунку.<sup>[[5]](#references)</sup>
- Базова математика використовує fixed‑point формати, такі як Q64.96 для sqrtPriceX96, а також арифметику tick із 1.0001^tick. Будь-яка custom math, додана поверх цього, має точно відповідати семантиці округлення, щоб уникнути drift інваріанта.<sup>[[4]](#references)[[8]](#references)</sup>
- Swaps можуть бути exactInput або exactOutput. У v3/v4 ціна рухається вздовж ticks; перетин межі tick може активувати/деактивувати range liquidity. Hooks можуть реалізовувати додаткову логіку під час перетину порогів/ticks.<sup>[[5]](#references)</sup>

## Типова вразливість: drift точності/округлення під час перетину порогів

Типовий вразливий шаблон у custom hooks:

1. Hook обчислює per‑swap зміни ліквідності або балансу за допомогою цілочисельного ділення, mulDiv чи fixed‑point перетворень (наприклад, перетворення між token і liquidity з використанням sqrtPrice та діапазонів tick).
2. Порогова логіка (наприклад, rebalancing, поетапний розподіл або активація окремого range) запускається, коли розмір swap або рух ціни перетинає внутрішню межу.
3. Округлення застосовується непослідовно (наприклад, truncation до нуля, floor замість ceil) між прямим обчисленням і шляхом розрахунку. Незначні розбіжності не компенсують одна одну, а натомість зараховуються на користь caller.
4. Exact‑input swaps, точно підібрані для перетину таких меж, дають змогу багаторазово отримувати позитивний залишок округлення. Пізніше атакувальник виводить накопичений credit.

Передумови атаки
- Pool із custom v4 hook, який виконує додаткову математику під час кожного swap (наприклад, LDF/rebalancer).
- Принаймні один execution path, у якому округлення приносить користь ініціатору swap під час перетину порогів.
- Можливість атомарно повторювати багато swaps (flash loans ідеально підходять для надання тимчасового float та розподілу витрат на gas).

## Практична методологія атаки

1) Визначення candidate pools із hooks
- Перелічити v4 pools і перевірити, що PoolKey.hooks != address(0).
- Перевірити bytecode/ABI hook на наявність callbacks: beforeSwap/afterSwap та будь-яких custom методів rebalancing.
- Шукати математику, яка: ділить на liquidity, перетворює token amounts у liquidity або агрегує BalanceDelta з округленням.

2) Моделювання математики hook і порогів
- Відтворити формулу liquidity/redistribution hook: inputs зазвичай містять sqrtPriceX96, tickLower/Upper, currentTick, fee tier і net liquidity.
- Відобразити threshold/step functions: ticks, межі bucket або breakpoints LDF. Визначити, з якого боку кожної межі округлюється delta.
- Визначити місця, де виконується cast між uint256/int256, використовується SafeCast або застосовується mulDiv із неявним floor.

3) Калібрування exact‑input swaps для перетину меж
- Використати Foundry/Hardhat simulations для обчислення мінімального Δin, необхідного для переміщення ціни трохи за межу та запуску гілки hook.
- Перевірити, що settlement у afterSwap зараховує caller більше, ніж становить вартість, залишаючи позитивний BalanceDelta або credit в accounting hook.
- Повторити swaps для накопичення credit, а потім викликати withdrawal/settlement path hook.

Приклад тестового harness у стилі Foundry (pseudocode)
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
- Оцініть Δin за формулами v3/v4: Δx ≈ L × (ΔsqrtP / (sqrtP_next × sqrtP_current)). Переконайтеся, що напрямок округлення відповідає core math.
- Змініть Δin на ±1 wei біля межі, щоб знайти гілку, у якій hook округлює на вашу користь.

4) Посилення за допомогою flash loans
- Позичте велику номінальну суму (наприклад, 3M USDT або 2000 WETH), щоб атомарно виконати багато ітерацій.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- Виконайте калібрований цикл swap, потім виведіть кошти та погасіть позику в callback flash loan.

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
- Якщо hooks розгорнуті в кількох chains, повторіть таке саме калібрування для кожного chain.
- Переведіть прибуток через bridge назад у цільовий chain і за потреби проведіть його через lending protocols для обфускації потоків.<sup>[[2]](#references)</sup>

## Поширені першопричини в математиці hooks

- Змішані правила округлення: mulDiv округлює вниз, тоді як наступні шляхи фактично округлюють угору; або конвертації між token/liquidity застосовують різне округлення.
- Помилки вирівнювання tick: в одному шляху використовуються неокруглені ticks, а в іншому — округлення з урахуванням кроку tick.
- Проблеми зі знаком/переповненням BalanceDelta під час конвертації між int256 і uint256 у процесі settlement.
- Втрата точності під час конвертацій Q64.96 (sqrtPriceX96), яка не відтворюється у зворотному mapping.
- Шляхи накопичення: залишки після кожного swap обліковуються як credits, які може вивести caller, замість того щоб вони спалювалися або балансувалися до нульової суми.

## Custom accounting і підсилення delta

- Uniswap v4 custom accounting дає hooks змогу повертати deltas, які безпосередньо коригують суму, яку caller має сплатити або отримати. Якщо hook внутрішньо відстежує credits, залишок округлення може накопичуватися протягом багатьох малих операцій **до** виконання фінального settlement.<sup>[[5]](#references)</sup>
- Це посилює зловживання boundary/threshold: attacker може чергувати `swap → withdraw → swap` в межах однієї tx, змушуючи hook повторно обчислювати deltas на трохи іншому state, поки всі balances ще очікують settlement.
- Під час аудиту hooks завжди відстежуйте, як BalanceDelta/HookDelta створюється та проходить settlement. Одне упереджене округлення в окремій гілці може перетворитися на складений credit, якщо deltas обчислюються повторно.

## Рекомендації щодо захисту

- Differential testing: порівнюйте математику hook із reference implementation, використовуючи високоточну раціональну арифметику, і перевіряйте рівність або обмежену похибку, яка завжди є несприятливою для caller.
- Invariant/property tests:
- Сума deltas (tokens, liquidity) у всіх swap paths і hook adjustments має зберігати value з урахуванням fees.
- Жоден path не має створювати позитивний net credit для ініціатора swap під час повторних ітерацій exactInput.
- Тести threshold/tick boundary навколо входів ±1 wei для обох exactInput/exactOutput.
- Політика округлення: централізуйте helpers для округлення, які завжди округлюють проти user; усуньте непослідовні casts і неявні округлення вниз.
- Settlement sinks: спрямовуйте неминучий залишок округлення до protocol treasury або спалюйте його; ніколи не зараховуйте його на msg.sender.
- Rate-limits/guardrails: мінімальні розміри swap для тригерів rebalancing; вимикайте rebalances, якщо deltas менші за wei; перевіряйте deltas на відповідність очікуваним діапазонам.
- Переглядайте callback-и hook комплексно: beforeSwap/afterSwap і before/after liquidity changes мають узгоджено застосовувати вирівнювання tick і округлення delta.

## Case study: Bunni V2 (2025‑09‑02)

- Protocol: Bunni V2 (Uniswap v4 hook) із LDF, що застосовується для кожного swap з метою rebalancing.<sup>[[7]](#references)</sup>
- Affected pools: USDC/USDT в Ethereum і weETH/ETH в Unichain, загалом близько $8.4M.<sup>[[1]](#references)[[2]](#references)</sup>
- Step 1 (price push): attacker виконав flash-borrow приблизно 3M USDT і здійснив swap, щоб підняти tick приблизно до 5000, зменшивши **активний** баланс USDC приблизно до 28 wei.<sup>[[7]](#references)</sup>
- Step 2 (rounding drain): 44 малих withdrawals використали округлення вниз у `BunniHubLogic::withdraw()`, щоб зменшити активний баланс USDC з 28 wei до 4 wei (‑85.7%), при цьому було спалено лише дуже малу частку LP shares. Загальний обсяг liquidity був занижений приблизно на 84.4%.<sup>[[2]](#references)[[7]](#references)</sup>
- Step 3 (liquidity rebound sandwich): великий swap перемістив tick приблизно до 839,189 (1 USDC ≈ 2.77e36 USDT). Оцінки liquidity змінилися та зросли приблизно на 16.8%, уможлививши sandwich, у якому attacker здійснив зворотний swap за завищеною ціною та вийшов із прибутком.<sup>[[7]](#references)</sup>
- Fix identified in the post-mortem: змінити оновлення idle-balance так, щоб воно округлювалося **вгору** — тоді повторні micro-withdrawals не зможуть поступово зменшувати active balance пулу.<sup>[[7]](#references)</sup>

Спрощений вразливий рядок (і fix із post-mortem)<sup>[[7]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```
## Чекліст пошуку

- Чи використовує пул ненульову адресу hooks? Які callbacks увімкнено?
- Чи виконуються per-swap redistributions/rebalances із використанням custom math? Чи є логіка tick/threshold?
- Де використовуються divisions/mulDiv, перетворення Q64.96 або SafeCast? Чи є семантика округлення узгодженою глобально?
- Чи можна створити Δin, який ледь перетинає межу та забезпечує сприятливу гілку округлення? Перевірте обидва напрямки, а також exactInput і exactOutput.
- Чи відстежує hook credits або deltas для кожного caller, які можна буде вивести пізніше? Переконайтеся, що residue нейтралізується.

## References

- [1] [Bunni V2 Exploit: $8.3M Drained via Liquidity Flaw (summary)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [2] [Bunni V2 Exploit: Full Hack Analysis](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Uniswap v4 background (QuillAudits research)](https://www.quillaudits.com/research/uniswap-development)
- [4] [Liquidity mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [5] [Swap mechanics in Uniswap v4 core](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [6] [Uniswap v4 Hooks and Security Considerations](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [7] [Bunni Exploit Post Mortem (Sep 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [8] [Uniswap v4 Core Whitepaper](https://app.uniswap.org/whitepaper-v4.pdf)

{{#include ../../banners/hacktricks-training.md}}
