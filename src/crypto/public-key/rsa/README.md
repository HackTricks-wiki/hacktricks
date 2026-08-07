# Атаки на RSA

{{#include ../../../banners/hacktricks-training.md}}

## Швидкий triage

Зберіть:

- `n`, `e`, `c` (а також будь-які додаткові ciphertexts)
- Будь-які зв’язки між повідомленнями (той самий plaintext? спільний modulus? структурований plaintext?)
- Будь-які leaks (часткові `p/q`, біти `d`, `dp/dq`, відоме padding)

Потім спробуйте:

- Перевірку факторизації (Factordb / `sage: factor(n)` для відносно малих чисел)
- Патерни малих експонент (`e=3`, broadcast)
- Common modulus / повторювані прості числа
- Lattice methods (Coppersmith/LLL), коли щось майже відоме

## Поширені атаки на RSA

### Common modulus

Якщо два ciphertexts `c1, c2` шифрують **те саме повідомлення** за допомогою **того самого modulus** `n`, але з різними експонентами `e1, e2` (і `gcd(e1,e2)=1`), можна відновити `m` за допомогою розширеного алгоритму Евкліда:

`m = c1^a * c2^b mod n`, де `a*e1 + b*e2 = 1`.

Приблизний алгоритм:

1. Обчисліть `(a, b) = xgcd(e1, e2)`, щоб `a*e1 + b*e2 = 1`
2. Якщо `a < 0`, інтерпретуйте `c1^a` як `inv(c1)^{-a} mod n` (так само для `b`)
3. Перемножте та зведіть за модулем `n`

### Спільні прості числа між modulus

Якщо у вас є кілька RSA modulus з одного challenge, перевірте, чи не мають вони спільного простого числа:

- `gcd(n1, n2) != 1` означає катастрофічну помилку генерації ключів.

Це часто трапляється в CTF як наслідок ситуацій на кшталт "ми швидко згенерували багато ключів" або "погана випадковість".

### Розріджені / short-sleeve modulus

Деякі зламані генератори big-integer безпосередньо витікають структуру в public modulus: кожен limb містить лише невелике випадкове підполе, а решта бітів дорівнює `0`. На практиці це проявляється як **регулярно розташовані блоки нулів** у `n`, часто вирівняні за 32-бітними або 128-бітними limbs.<sup>[[1]](#references)</sup>

Швидкі перевірки:

- Виведіть `n` у hex і пошукайте повторювані нульові вікна з фіксованим stride.
- Повторно розділіть `n` на limbs (`2^32`, `2^64`, `2^128`) і перевірте, чи не є кожен limb незвично малим.
- Перевірте public SSH/TLS keys за допомогою таких інструментів, як **badkeys**, якщо підозрюєте слабку генерацію host-key.<sup>[[2]](#references)[[3]](#references)</sup>

Це серйозніше за статистичне відхилення: якщо обидва приватні множники `p` і `q` мають short-sleeve структуру, modulus може стати **легким для факторизації**.<sup>[[1]](#references)</sup>

### Polynomial factorization структурованих RSA keys

Для підозрюваної ширини limb `w` запишіть modulus у базі `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Оскільки обчислення є мультиплікативним, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Якщо factors також мають розріджені limb coefficients, тоді:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Приблизний алгоритм атаки:

1. Вгадайте ширину limb `w`.
2. Перетворіть public modulus `n` на `f_n(x)`, використовуючи базу `2^w`.
3. Розкладіть `f_n(x)` на множники над цілими числами.
4. Обчисліть candidate factors назад при `B = 2^w`.
5. Перевірте, які candidates перемножуються в `n`.

Це **не ламає нормальний RSA**. Метод працює лише тоді, коли прості множники самі мають дуже малі, чітко структуровані limb coefficients.<sup>[[1]](#references)</sup>

### Shifted limb leakage

Розріджені bytes не завжди вирівняні за молодшим кінцем кожного limb. Якщо пряме перетворення в базу `2^w` створює великі coefficients, шукайте зсуви `i,j`, за яких `2^i p` і `2^j q` стають розрідженими в цій limb basis. Product polynomial усе ще можна вивести з public modulus, розкласти на множники та recombine в оригінальні цілі множники.<sup>[[1]](#references)</sup>

### Запах реалізації: byte-to-limb RNG bug

Небезпечний патерн полягає в обчисленні кількості **32-бітних limbs**, виділенні лише такої кількості **bytes** та їх копіюванні в масив limbs:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Це дає кожній 32-бітній частині лише **8 бітів ентропії** плюс примусово встановлений старший біт в останній частині. Отримані RSA-прості числа часто можна розпізнати й факторизувати, маючи лише відкритий ключ.<sup>[[1]](#references)</sup>

### Related DSA failure mode

Якщо ту саму зламану процедуру роботи з великими цілими числами повторно використовують для генерації приватного експонента DSA, відкритий ключ `y = g^x` може розкрити **різко зменшений і структурований** простір пошуку для `x`. Коли шаблон частин відомий, атаки на дискретний логарифм, такі як **baby-step giant-step**, можуть стати практичними проти публічних параметрів.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

Якщо те саме повідомлення надсилається кільком одержувачам із малим `e` (часто `e=3`) і без належного padding, можна відновити `m` за допомогою CRT та цілочисельного кореня.

Технічна умова:

Якщо у вас є `e` ciphertexts того самого повідомлення під попарно взаємно простими модулями `n_i`:

- Використайте CRT, щоб відновити `M = m^e` за модулем добутку `N = Π n_i`
- Якщо `m^e < N`, тоді `M` є справжнім цілочисельним степенем, а `m = integer_root(M, e)`

### Wiener attack: small private exponent

Якщо `d` занадто мале, continued fractions можуть відновити його з `e/n`.

### Textbook RSA pitfalls

Якщо ви бачите:

- Відсутність OAEP/PSS, raw modular exponentiation
- Deterministic encryption

тоді алгебраїчні атаки та зловживання oracle стають набагато ймовірнішими.

### Інструменти

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Шаблони пов'язаних повідомлень

Якщо ви бачите два ciphertexts під тим самим модулем із повідомленнями, що мають алгебраїчний зв'язок (наприклад, `m2 = a*m1 + b`), шукайте атаки "related-message", такі як Franklin–Reiter. Зазвичай для цього потрібні:

- той самий модуль `n`
- той самий експонент `e`
- відомий зв'язок між plaintexts

На практиці це часто розв'язують у Sage, задаючи поліноми за модулем `n` і обчислюючи GCD.

## Lattices / Coppersmith

Застосовуйте цей підхід, коли маєте часткові біти, структурований plaintext або близькі зв'язки, які роблять невідоме малим.

Lattice methods (LLL/Coppersmith) з'являються щоразу, коли у вас є часткова інформація:

- Частково відомий plaintext (структуроване повідомлення з невідомим хвостом)
- Частково відомі `p`/`q` (старші біти leaked)
- Малі невідомі різниці між пов'язаними значеннями

### Що розпізнавати

Типові підказки у challenge:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Інструменти

На практиці ви використовуватимете Sage для LLL і відомий template для конкретного екземпляра.

Хороші початкові матеріали:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
