# Експлуатація DeFi/AMM: зловживання точністю/округленням у хуках Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

На цій сторінці описано клас методів експлуатації DeFi/AMM проти DEX у стилі Uniswap v4, які розширюють основну математику за допомогою власних хуків. Інцидент із Bunni V2 демонструє пов’язану помилку: помилка у напрямку округлення під час обліку виведення занижувала активну ліквідність, а подальший swap дав змогу виявити це заниження за допомогою прибуткового sandwich.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Ключова ідея: якщо хук виконує додатковий облік, що залежить від математики з фіксованою комою, округлення тіків і логіки порогових значень, зловмисник може створювати exact-input swaps, які перетинають певні пороги, щоб похибки округлення накопичувалися на його користь. Повторюючи цей шаблон, а потім виводячи завищений баланс, він отримує прибуток, часто фінансуючи операції за допомогою flash loan.

## Передумови: хуки Uniswap v4 і перебіг swap

- Хуки — це контракти, які PoolManager викликає на певних етапах життєвого циклу (наприклад, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Пули ініціалізуються з PoolKey, що містить контракт хука. Ненульова адреса хука активує вибрані для цього пулу callback-функції.<sup>[[4]](#references)[[14]](#references)</sup>
- Хуки можуть повертати **власні дельти**, які змінюють підсумкову зміну балансів під час swap або операції з ліквідністю (custom accounting). Ці дельти погашаються як чисті баланси наприкінці виклику, тож будь-яка похибка округлення у математиці хука накопичується до моменту погашення.<sup>[[4]](#references)</sup>
- Основна математика використовує формати з фіксованою комою, як-от Q64.96 для sqrtPriceX96, і арифметику тіків із 1.0001^tick. Будь-яка власна математика поверх неї має точно відповідати семантиці округлення, щоб уникнути дрейфу інваріанта.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps можуть бути exactInput або exactOutput. У v3/v4 ціна рухається вздовж тіків; перетин межі тіку може активувати або деактивувати ліквідність діапазону. Хуки можуть реалізовувати додаткову логіку для перетинів порогів/тіків.<sup>[[9]](#references)[[11]](#references)</sup>

## Типова вразливість: дрейф точності/округлення під час перетину порогів

Типовий вразливий шаблон у власних хуках:

1. Хук обчислює дельти ліквідності або балансу для кожного swap за допомогою цілочисельного ділення, mulDiv або перетворень із фіксованою комою (наприклад, перетворення токенів ↔ ліквідності з використанням sqrtPrice і діапазонів тіків).
2. Порогова логіка (наприклад, перебалансування, покроковий перерозподіл або активація діапазону) запускається, коли розмір swap або рух ціни перетинає внутрішню межу.
3. Округлення застосовується непослідовно (наприклад, відсікання до нуля, округлення вниз або вгору) під час прямого обчислення та погашення. Невеликі розбіжності не компенсуються, а натомість зараховуються на користь ініціатора.
4. Exact-input swaps, точно підібрані для перетину цих меж, знову й знову збирають додатний залишок округлення. Пізніше зловмисник виводить накопичений кредит.

Передумови атаки
- Пул використовує власний хук v4, який виконує додаткову математику під час кожного swap (наприклад, LDF/rebalancer).
- Принаймні один шлях виконання, де округлення під час перетину порогів дає перевагу ініціатору swap.
- Можливість атомарно повторювати багато swaps (flash loans ідеально підходять для надання тимчасового капіталу й розподілу витрат на gas).

## Практична методологія атаки

1) Визначте пули-кандидати з хуками
- Перелічіть пули v4 і перевірте, що PoolKey.hooks != address(0).
- Перевірте байткод/ABI хука на наявність callback-функцій: beforeSwap/afterSwap і методів власного перебалансування.
- Шукайте математику, яка: ділить на ліквідність, перетворює суми токенів на ліквідність або навпаки, чи агрегує BalanceDelta з округленням.

2) Змоделюйте математику й порогові значення хука
- Відтворіть формулу ліквідності/перерозподілу хука: типові вхідні дані — sqrtPriceX96, tickLower/Upper, currentTick, рівень комісії та чиста ліквідність.
- Визначте порогові/ступінчасті функції: тіки, межі кошиків або точки розриву LDF. З’ясуйте, у який бік округлюється дельта відносно кожної межі.
- Визначте місця, де перетворення приводять до типів uint256/int256, використовують SafeCast або покладаються на mulDiv із неявним округленням вниз.

3) Налаштуйте exact-input swaps для перетину меж
- Використайте симуляції Foundry/Hardhat, щоб обчислити мінімальне Δin, необхідне для руху ціни трохи за межу й активації гілки хука.
- Переконайтеся, що погашення afterSwap зараховує ініціатору більше, ніж коштує swap, залишаючи додатний BalanceDelta або кредит в обліку хука.
- Повторюйте swaps для накопичення кредиту, а потім викличте шлях виведення/погашення хука.

У v4 цикл swap має виконуватися з callback-функції розблокування PoolManager; від’ємне значення `amountSpecified` означає exact input, а `sqrtPriceLimitX96` має бути строго в межах допустимого діапазону. Нульовий ціновий ліміт спричиняє revert, тому в наведеному нижче псевдокоді для swap zero-for-one використано нижню межу.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Приклад тестового стенду в стилі Foundry (псевдокод)
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

Налаштування exactInput
- Обчисліть цільове значення за допомогою core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) у реальних значеннях; результат Q64.96 округлюється TickMath.<sup>[[13]](#references)</sup>
- Приблизно розрахуйте вхідну кількість token0 (zero-for-one) за формулою з урахуванням Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Дотримуйтеся напрямку округлення основної процедури.<sup>[[12]](#references)</sup>
- Скоригуйте Δin на ±1 wei поблизу граничного значення, щоб знайти гілку, у якій hook округлює на вашу користь.

4) Збільшення масштабу за допомогою flash loan
- Позичте значну суму (наприклад, 3M USDT або 2000 WETH), щоб атомарно виконати багато ітерацій.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Виконайте налаштований цикл свопів, а потім виведіть кошти й погасіть позику в межах callback flash loan.

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

5) Виведення коштів і кросчейн-відтворення
- Якщо hooks розгорнуті в кількох мережах, виконайте таке саме калібрування для кожної мережі.
- Під час інциденту Bunni ліквідність flash-loan і маршрути мостів відрізнялися залежно від мережі, тому враховуйте ці специфічні для кожної мережі обмеження під час відтворення аналізу.<sup>[[1]](#references)[[2]](#references)</sup>

## Поширені першопричини помилок у математиці hooks

- Різна семантика округлення: mulDiv округлює вниз, тоді як наступні шляхи фактично округлюють вгору; або під час перетворень між токенами й ліквідністю застосовується різне округлення.
- Помилки вирівнювання tick: в одному шляху використовуються неокруглені ticks, а в іншому — округлення з кроком tick.
- Проблеми зі знаком/переповненням BalanceDelta під час перетворення між int256 і uint256 у процесі розрахунків.
- Втрата точності під час перетворень Q64.96 (sqrtPriceX96), яка не враховується у зворотному перетворенні.
- Шляхи накопичення: залишки після кожного swap обліковуються як кредити, які може вивести caller, замість того, щоб їх спалювати або забезпечувати нульовий баланс.

## Кастомний облік і посилення delta

- Кастомний облік Uniswap v4 дає hooks змогу повертати deltas, які безпосередньо коригують суму, яку caller має сплатити або отримати. Якщо hook веде внутрішній облік кредитів, залишок від округлення може накопичуватися під час багатьох дрібних операцій **до** завершення остаточних розрахунків.<sup>[[4]](#references)</sup>
- Якщо hook надає сумісний шлях виведення коштів, зловмисник може чергувати `swap → withdraw → swap` у межах одного callback розблокування PoolManager, змушуючи hook повторно обчислювати deltas за дещо іншим станом, поки баланси залишаються незакритими до завершення розрахунків під час розблокування.<sup>[[4]](#references)[[10]](#references)</sup>
- Під час аудиту hooks завжди відстежуйте, як формується та розраховується BalanceDelta/HookDelta. Одне зміщене округлення в окремій гілці може перетворитися на кредит, що накопичується, коли deltas обчислюються повторно.

## Рекомендації із захисту

- Диференційне тестування: порівнюйте математику hook із еталонною реалізацією, що використовує раціональну арифметику високої точності, і перевіряйте рівність або обмежену похибку, яка завжди діє на шкоду зловмиснику (ніколи не на користь caller).
- Інваріантні/property-тести:
  - Сума deltas (токенів, ліквідності) для шляхів swap і коригувань hook має зберігати вартість з урахуванням комісій.
  - Жоден шлях не повинен створювати чистий позитивний кредит для ініціатора swap під час повторних ітерацій exactInput.
  - Перевіряйте межі порогів/tick з входами ±1 wei для exactInput/exactOutput.
- Політика округлення: централізуйте допоміжні функції округлення, які завжди округлюють на шкоду користувачу; усуньте непослідовні приведення типів і неявне округлення вниз.
- Напрямлення залишків розрахунків: накопичуйте неминучі залишки від округлення у скарбниці протоколу або спалюйте їх; ніколи не зараховуйте їх на msg.sender.
- Обмеження частоти/запобіжники: встановіть мінімальні розміри swap для запуску ребалансування; вимикайте ребалансування, якщо deltas менші за wei; перевіряйте відповідність deltas очікуваним діапазонам.
- Комплексно перевіряйте callbacks hook: beforeSwap/afterSwap і before/after зміни ліквідності мають використовувати узгоджені вирівнювання tick і округлення delta.

## Розбір інциденту: Bunni V2 (2025‑09‑02)

- Протокол: Bunni V2, hook Uniswap v4, який використовує Liquidity Density Function (LDF) для обчислення щільності токенів і оцінок загальної ліквідності.<sup>[[1]](#references)[[2]](#references)</sup>
- Уражені пули: USDC/USDT в Ethereum і weETH/ETH в Unichain, загальна сума — близько $8.4M.<sup>[[1]](#references)</sup>
- Крок 1 (зміщення ціни): зловмисник позичив близько 3M USDT через flash-loan і виконав swap, щоб змістити tick приблизно до 5000, зменшивши **активний** баланс USDC приблизно до 28 wei.<sup>[[1]](#references)</sup>
- Крок 2 (виведення через округлення): 44 невеликі виведення коштів використали округлення вниз у `BunniHubLogic::withdraw()`, щоб зменшити активний баланс USDC із 28 wei до 4 wei (-85.7%), спаливши лише крихітну частку LP shares. Загальна ліквідність зменшилася приблизно на 84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Крок 3 (сендвіч із відновленням ліквідності): великий swap змістив tick приблизно до 839,189 (1 USDC ≈ 2.77e36 USDT). Оцінки ліквідності змінилися на протилежні й зросли приблизно на 16.8%, що дало змогу провести сендвіч: зловмисник виконав зворотний swap за завищеною ціною та вийшов із прибутком.<sup>[[1]](#references)</sup>
- Виправлення, визначене під час post-mortem: змінити оновлення неактивного балансу так, щоб округлювати **вгору**; тоді повторні мікровиведення більше не зменшуватимуть активний баланс пулу.<sup>[[1]](#references)</sup>

Спрощений вразливий рядок (і виправлення за результатами post-mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Чекліст пошуку

- Чи використовує пул ненульову адресу hooks? Які callbacks увімкнено?
- Чи є перерозподіл/ребалансування під час кожного swap із використанням власної математики? Чи є логіка tick/порогових значень?
- Де використовуються divisions/mulDiv, перетворення Q64.96 або SafeCast? Чи є правила округлення узгодженими в усьому коді?
- Чи можна сконструювати Δin, що ледь перетинає межу й забезпечує вигідну гілку округлення? Перевірте обидва напрямки, а також exactInput і exactOutput.
- Чи обліковує hook кредити або дельти для кожного caller, які можна згодом вивести? Переконайтеся, що залишок нейтралізується.

## References

- [1] [Розбір інциденту Bunni (вересень 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Експлойт Bunni V2: повний аналіз злому](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Експлойт Bunni V2: $8.3M викрадено через ваду ліквідності (короткий виклад)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Технічний документ Uniswap v4 Core](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Передумови Uniswap v4 (дослідження QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Механізми ліквідності в ядрі Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Механізми swap в ядрі Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks Uniswap v4 і міркування щодо безпеки](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol ядра Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol ядра Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol ядра Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol ядра Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
