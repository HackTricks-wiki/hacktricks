# Атаки RSA

{{#include ../../../banners/hacktricks-training.md}}

## Швидка оцінка

Збирайте:

- `n`, `e`, `c` (і будь-які додаткові ciphertexts)
- Будь-які зв'язки між повідомленнями (same plaintext? shared modulus? structured plaintext?)
- Any leaks (partial `p/q`, bits of `d`, `dp/dq`, known padding)

Потім спробуйте:

- Перевірка факторизації (Factordb / `sage: factor(n)` для досить малих значень)
- Патерни з малим показником (`e=3`, broadcast)
- Спільний modulus / повторювані прості
- Методи решіток (Coppersmith/LLL), коли дещо майже відомо

## Поширені атаки RSA

### Common modulus

Якщо два ciphertexts `c1, c2` шифрують **те саме message** під **тим самим modulus** `n`, але з різними показниками `e1, e2` (і `gcd(e1,e2)=1`), можна відновити `m` за допомогою розширеного алгоритму Евкліда:

`m = c1^a * c2^b mod n` де `a*e1 + b*e2 = 1`.

Орієнтовний приклад:

1. Обчисліть `(a, b) = xgcd(e1, e2)` так що `a*e1 + b*e2 = 1`
2. Якщо `a < 0`, трактуйте `c1^a` як `inv(c1)^{-a} mod n` (те ж для `b`)
3. Помножте й зведіть по модулю `n`

### Shared primes across moduli

Якщо у вас є кілька RSA moduli з одного завдання, перевірте, чи вони ділять просте:

- `gcd(n1, n2) != 1` означає катастрофічну помилку генерації ключів.

Це часто трапляється в CTFs як "we generated many keys quickly" або "bad randomness".

### Håstad broadcast / low exponent

Якщо той самий plaintext відправлено кільком отримувачам з малим `e` (часто `e=3`) і без коректного padding, можна відновити `m` за допомогою CRT і integer_root.

Технічна умова:

Якщо у вас є `e` ciphertexts того самого message під попарно-взаємно-простими moduli `n_i`:

- Використайте CRT, щоб відновити `M = m^e` по модулю добутку `N = Π n_i`
- Якщо `m^e < N`, тоді `M` — справжній цілий ступінь, і `m = integer_root(M, e)`

### Wiener attack: small private exponent

Якщо `d` занадто малий, continued fractions можуть його відновити з `e/n`.

### Textbook RSA pitfalls

Якщо бачите:

- Немає OAEP/PSS, сире modular exponentiation
- Deterministic encryption

то algebraic attacks і oracle abuse стають значно ймовірнішими.

### Інструменти

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Схеми пов'язаних повідомлень

Якщо бачите два ciphertexts під тим самим modulus, де messages алгебраїчно пов'язані (наприклад, `m2 = a*m1 + b`), шукайте related-message атаки, такі як Franklin–Reiter. Зазвичай це вимагає:

- same modulus `n`
- same exponent `e`
- відомого зв'язку між plaintexts

На практиці це часто вирішують у Sage, задавши поліноми по модулю `n` і обчисливши GCD.

## Lattices / Coppersmith

Звертайтесь до цього, коли у вас є частково відомі біти, структурований plaintext або близькі відношення, які роблять невідоме малим.

Методи решіток (LLL/Coppersmith) застосовують, коли є часткова інформація:

- Частково відомий plaintext (структуроване повідомлення з невідомим кінцем)
- Частково відомі `p`/`q` (втрачено верхні/нижні біти)
- Малі невідомі різниці між пов'язаними величинами

### На що звертати увагу

Типові підказки в задачах:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Інструментарій

На практиці ви будете використовувати Sage для LLL і відомі шаблони для конкретного випадку.

Хороші стартові точки:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

{{#include ../../../banners/hacktricks-training.md}}
