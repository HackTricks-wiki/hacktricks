# Експлуатація DeFi/AMM: зловживання точністю/округленням у хуках Uniswap v4

{{#include ../../banners/hacktricks-training.md}}

На цій сторінці описано клас технік експлуатації DeFi/AMM проти DEX у стилі Uniswap v4, які розширюють базову математику за допомогою кастомних хуків. Інцидент із Bunni V2 демонструє пов’язаний збій: помилка в напрямку округлення під час обліку виведення занижувала активну ліквідність, а пізніший swap виявив це заниження в прибутковій sandwich-атаці.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Ключова ідея: якщо хук виконує додатковий облік, залежний від математики з фіксованою точкою, округлення tick і логіки порогів, атакувальник може сформувати exact-input swaps, які перетинають конкретні пороги, щоб розбіжності округлення накопичувалися на його користь. Повторення цієї схеми з подальшим виведенням завищеного балансу приносить прибуток; часто для цього використовують flash loan.

## Передумови: хуки Uniswap v4 і перебіг swap

- Хуки — це контракти, які PoolManager викликає на певних етапах життєвого циклу (наприклад, beforeSwap/afterSwap, beforeAddLiquidity/afterAddLiquidity, beforeRemoveLiquidity/afterRemoveLiquidity, beforeInitialize/afterInitialize, beforeDonate/afterDonate).<sup>[[4]](#references)</sup>
- Пули ініціалізуються з PoolKey, що містить контракт хука. Ненульова адреса хука активує вибрані для цього пулу callback-функції.<sup>[[4]](#references)[[14]](#references)</sup>
- Хуки можуть повертати **custom deltas**, які змінюють остаточні зміни балансів під час swap або операції з ліквідністю (custom accounting). Ці deltas враховуються як чисті баланси наприкінці виклику, тому будь-яка помилка округлення у формулах хука накопичується до моменту розрахунку.<sup>[[4]](#references)</sup>
- У базовій математиці використовуються формати з фіксованою точкою, як-от Q64.96 для sqrtPriceX96, і арифметика tick із 1.0001^tick. Будь-яка кастомна математика поверх цього має точно узгоджувати семантику округлення, щоб уникнути дрейфу інваріанта.<sup>[[12]](#references)[[13]](#references)</sup>
- Swaps можуть бути exactInput або exactOutput. У v3/v4 ціна змінюється вздовж tick; перетин межі tick може активувати або деактивувати ліквідність діапазону. Хуки можуть реалізовувати додаткову логіку під час перетину порогів/tick.<sup>[[9]](#references)[[11]](#references)</sup>

## Типова вразливість: дрейф точності/округлення під час перетину порогів

Типовий вразливий шаблон у кастомних хуках:

1. Хук обчислює зміни ліквідності або балансу для кожного swap за допомогою цілочисельного ділення, mulDiv або перетворень із фіксованою точкою (наприклад, конвертації між токенами та ліквідністю з використанням sqrtPrice і діапазонів tick).
2. Логіка порогів (наприклад, ребалансування, поетапний розподіл або активація діапазонів) запускається, коли розмір swap або зміна ціни перетинає внутрішню межу.
3. Округлення застосовується непослідовно (наприклад, усічення до нуля, floor замість ceil) у прямому обчисленні та в шляху розрахунку. Незначні розбіжності не компенсуються, а натомість зараховуються на користь викликувача.
4. Точно підібрані exact-input swaps, які перетинають ці межі, знову й знову збирають додатний залишок від округлення. Згодом атакувальник виводить накопичений кредит.

Передумови атаки
- Пул використовує кастомний хук v4, який виконує додаткові обчислення під час кожного swap (наприклад, LDF/rebalancer).
- Існує принаймні один шлях виконання, де округлення під час перетину порогів працює на користь ініціатора swap.
- Є можливість атомарно повторити багато swaps (flash loan ідеально підходить для надання тимчасового капіталу та розподілу витрат на gas).

## Практична методологія атаки

1) Визначте пули-кандидати з хуками
- Перелічіть пули v4 і перевірте, чи PoolKey.hooks != address(0).
- Перегляньте байткод/ABI хука на наявність callback-функцій: beforeSwap/afterSwap і методів кастомного ребалансування.
- Шукайте математику, яка ділить на ліквідність, конвертує суми токенів у ліквідність або агрегує BalanceDelta з округленням.

2) Змоделюйте математику хука та пороги
- Відтворіть формулу ліквідності/перерозподілу хука: серед вхідних даних зазвичай є sqrtPriceX96, tickLower/Upper, currentTick, рівень комісії та чиста ліквідність.
- Визначте пороги/ступінчасті функції: tick, межі сегментів або точки розриву LDF. З’ясуйте, у який бік округлюється delta з кожного боку межі.
- Знайдіть місця, де перетворення приводять до uint256/int256, використовують SafeCast або покладаються на mulDiv із неявним округленням донизу.

3) Підберіть exact-input swaps для перетину меж
- Використайте симуляції у Foundry/Hardhat, щоб обчислити мінімальний Δin, потрібний для переміщення ціни трохи за межу й запуску гілки хука.
- Переконайтеся, що після розрахунку afterSwap викликувачу зараховується більше, ніж коштує swap, залишаючи додатний BalanceDelta або кредит у внутрішньому обліку хука.
- Повторюйте swaps для накопичення кредиту, а потім викличте шлях виведення/розрахунку хука.

У v4 цикл swap має виконуватися з callback-функції розблокування PoolManager; від’ємне значення `amountSpecified` означає exact input, а `sqrtPriceLimitX96` має бути строго в межах допустимого діапазону. Нульове обмеження ціни призводить до revert, тому в псевдокоді нижче для swap zero-for-one використовується нижня межа.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Приклад тестового каркаса у стилі Foundry (псевдокод)
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

Calibrating the exactInput
- Обчисліть цільове значення за допомогою core TickMath: sqrtP_next = sqrtP_current × 1.0001^(Δtick) у термінах дійсних значень; результат Q64.96 округлюється TickMath.<sup>[[13]](#references)</sup>
- Оцініть вхідну суму token0 (zero-for-one) за формулою з урахуванням Q64.96: Δx ≈ L × |ΔsqrtP| × 2^96 / (sqrtP_next × sqrtP_current). Дотримуйтеся округлення за напрямком у core routine.<sup>[[12]](#references)</sup>
- Змініть Δin на ±1 wei поблизу межі, щоб знайти гілку, у якій hook округлює на вашу користь.

4) Збільшення масштабу за допомогою flash loans
- Позичте велику номінальну суму (наприклад, 3M USDT або 2000 WETH), щоб атомарно виконати багато ітерацій.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Виконайте відкалібрований цикл swap, а потім виведіть кошти й поверніть позику в межах callback flash loan.

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

5) Вихід і міжмережеве відтворення
- Якщо hooks розгорнуто в кількох мережах, виконайте ту саму калібровку для кожної мережі.
- Під час інциденту з Bunni ліквідність для флеш-позики та маршрути мостів відрізнялися залежно від мережі, тому враховуйте ці специфічні для мережі обмеження під час відтворення аналізу.<sup>[[1]](#references)[[2]](#references)</sup>

## Поширені першопричини помилок у математиці hooks

- Різні правила округлення: mulDiv округлює донизу, тоді як подальші шляхи фактично округлюють угору; або під час конвертації між токенами й ліквідністю застосовується різне округлення.
- Помилки вирівнювання tick: в одному шляху використовуються неокруглені ticks, а в іншому — округлення з урахуванням кроку tick.
- Проблеми зі знаком/переповненням BalanceDelta під час конвертації між int256 і uint256 у процесі розрахунку.
- Втрата точності під час конвертації Q64.96 (sqrtPriceX96), яка не відтворюється під час зворотного перетворення.
- Шляхи накопичення: залишки після кожного swap обліковуються як кредити, які може вивести caller, замість того щоб їх спалити або звести до нуля.

## Кастомний облік і посилення дельт

- Кастомний облік Uniswap v4 дає змогу hooks повертати дельти, які безпосередньо коригують суму, яку caller має сплатити або отримати. Якщо hook внутрішньо обліковує кредити, залишки від округлення можуть накопичуватися в багатьох малих операціях **до** остаточного розрахунку.<sup>[[4]](#references)</sup>
- Якщо hook надає сумісний шлях виведення, зловмисник може чергувати `swap → withdraw → swap` у межах того самого callback розблокування PoolManager, змушуючи hook повторно обчислювати дельти на дещо іншому стані, поки баланси залишаються в очікуванні до завершення розрахунку під час розблокування.<sup>[[4]](#references)[[10]](#references)</sup>
- Під час аудиту hooks завжди відстежуйте, як формується та розраховується BalanceDelta/HookDelta. Одне упереджене округлення в окремій гілці може перетворитися на накопичуваний кредит, якщо дельти обчислюються повторно.

## Рекомендації щодо захисту

- Диференційне тестування: порівнюйте математику hook із еталонною реалізацією, що використовує високоточну раціональну арифметику, та перевіряйте рівність або обмежену похибку, яка завжди працює на шкоду caller, а не на його користь.
- Інваріантні/властивісні тести:
  - Сума дельт (токенів, ліквідності) в усіх шляхах swap і коригуваннях hook має зберігати вартість з урахуванням комісій.
  - Жоден шлях не має створювати чистий позитивний кредит для ініціатора swap під час повторних ітерацій exactInput.
  - Перевіряйте порогові значення й межі tick для вхідних сум ±1 wei в режимах exactInput/exactOutput.
- Політика округлення: централізуйте допоміжні функції округлення, які завжди округлюють на шкоду користувачу; усуньте непослідовні приведення типів і неявне округлення донизу.
- Напрямлення залишків розрахунку: спрямовуйте неминучі залишки від округлення до скарбниці протоколу або спалюйте їх; ніколи не зараховуйте їх на адресу msg.sender.
- Обмеження частоти/захисні механізми: установлюйте мінімальні розміри swap для тригерів ребалансування; вимикайте ребалансування, якщо дельти менші за wei; перевіряйте, чи відповідають дельти очікуваним діапазонам.
- Комплексно перевіряйте callback-функції hook: beforeSwap/afterSwap і функції до/після зміни ліквідності мають узгоджено обробляти вирівнювання tick та округлення дельт.

## Приклад: Bunni V2 (2025‑09‑02)

- Протокол: Bunni V2 — hook для Uniswap v4, який використовує Liquidity Density Function (LDF) для обчислення щільності токенів і оцінок загальної ліквідності.<sup>[[1]](#references)[[2]](#references)</sup>
- Уражені пули: USDC/USDT в Ethereum і weETH/ETH в Unichain, загалом близько $8.4M.<sup>[[1]](#references)</sup>
- Крок 1 (зміна ціни): зловмисник позичив близько 3M USDT через флеш-позику й обміняв їх, щоб зрушити tick приблизно до 5000, скоротивши **активний** баланс USDC приблизно до 28 wei.<sup>[[1]](#references)</sup>
- Крок 2 (виведення через округлення): 44 невеликі виведення використали округлення донизу в `BunniHubLogic::withdraw()`, щоб зменшити активний баланс USDC з 28 wei до 4 wei (-85.7%), спаливши лише незначну частку часток LP. Загальна ліквідність зменшилася приблизно на 84.4%.<sup>[[1]](#references)[[2]](#references)</sup>
- Крок 3 (сендвіч зі зростанням ліквідності): великий swap зрушив tick приблизно до 839,189 (1 USDC ≈ 2.77e36 USDT). Оцінки ліквідності змінилися й зросли приблизно на 16.8%, що дало змогу провести сендвіч: зловмисник обміняв токени назад за завищеною ціною та вийшов із прибутком.<sup>[[1]](#references)</sup>
- Виправлення, визначене в post-mortem: змінити оновлення неактивного балансу так, щоб воно округлювало **вгору**. Це не дозволить повторним мікровиведенням поступово зменшувати активний баланс пулу.<sup>[[1]](#references)</sup>

Спрощений вразливий рядок коду (і виправлення з post-mortem).<sup>[[1]](#references)</sup>
```solidity
// BunniHubLogic::withdraw() idle balance update (simplified)
uint256 newBalance = balance - balance.mulDiv(shares, currentTotalSupply);
// Fix: round up to avoid cumulative underestimation
uint256 newBalance = balance - balance.mulDivUp(shares, currentTotalSupply);
```

## Контрольний список для пошуку вразливостей

- Чи використовує пул ненульову адресу hooks? Які callbacks увімкнено?
- Чи є перерозподіли/ребаланси для кожного swap із власною математикою? Чи використовується логіка на основі tick/порогових значень?
- Де використовуються ділення/mulDiv, перетворення Q64.96 або SafeCast? Чи узгоджена семантика округлення в усьому коді?
- Чи можна підібрати Δin, який ледь перетинає межу й активує вигідний варіант округлення? Перевірте обидва напрямки та exactInput і exactOutput.
- Чи відстежує hook кредити або дельти для кожного caller, які можна вивести пізніше? Переконайтеся, що залишок нейтралізується.

## References

- [1] [Розбір експлойту Bunni (вересень 2025)](https://blog.bunni.xyz/posts/exploit-post-mortem/)
- [2] [Експлойт Bunni V2: повний аналіз зламу](https://www.quillaudits.com/blog/hack-analysis/bunni-v2-exploit)
- [3] [Експлойт Bunni V2: $8.3M виведено через помилку ліквідності (короткий виклад)](https://quillaudits.medium.com/bunni-v2-exploit-8-3m-drained-50acbdcd9e7b)
- [4] [Технічний документ ядра Uniswap v4](https://app.uniswap.org/whitepaper-v4.pdf)
- [5] [Передумови Uniswap v4 (дослідження QuillAudits)](https://www.quillaudits.com/research/uniswap-development)
- [6] [Механізми ліквідності в ядрі Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/liquidity-mechanics-in-uniswap-v4-core)
- [7] [Механізми swap в ядрі Uniswap v4](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/swap-mechanics-in-uniswap-v4-core)
- [8] [Hooks Uniswap v4 та міркування щодо безпеки](https://www.quillaudits.com/research/uniswap-development/uniswap-v4/uniswap-v4-hooks-and-security)
- [9] [Pool.sol ядра Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Pool.sol)
- [10] [PoolManager.sol ядра Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol)
- [11] [SwapParams Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolOperation.sol)
- [12] [SqrtPriceMath.sol ядра Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/SqrtPriceMath.sol)
- [13] [TickMath.sol ядра Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/libraries/TickMath.sol)
- [14] [PoolKey Uniswap v4](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol)
{{#include ../../banners/hacktricks-training.md}}
