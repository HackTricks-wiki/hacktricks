# Криптографія з відкритим ключем

{{#include ../../banners/hacktricks-training.md}}

Більшість складних CTF-криптозадач потрапляє сюди: RSA, ECC/ECDSA, lattices і проблеми з випадковістю.

## Рекомендовані інструменти

- SageMath (LLL/lattices, модульна арифметика): https://www.sagemath.org/
- RsaCtfTool (універсальний інструмент): https://github.com/Ganapati/RsaCtfTool
- factordb (швидкі перевірки факторизації): http://factordb.com/

## RSA

Починайте тут, коли у вас є `n,e,c` та якийсь додатковий натяк (shared modulus, low exponent, partial bits, related messages).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Якщо задіяні підписи, спочатку перевірте проблеми з nonce (reuse/bias/leaks) перш ніж припускати складну математику.

### ECDSA nonce reuse / bias

Якщо два підписи повторно використовують той самий nonce `k`, приватний ключ можна відновити.

Навіть якщо `k` не ідентичний, **bias/leakage** бітів nonce між підписами може вистачити для відновлення через lattices (поширена тема в CTF).

Технічне відновлення при повторному використанні `k`:

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Якщо той самий `k` використовується для двох повідомлень `m1, m2`, які дають підписи `(r, s1)` і `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Якщо протокол не перевіряє, що точки знаходяться на очікуваній кривій (або в правильній subgroup), атакуючий може змусити операції у слабкій групі і відновити секрети.

Технічна нотатка:

- Перевіряйте, що точки знаходяться on-curve і в правильній subgroup.
- Багато CTF задач моделюють це як "server multiplies attacker-chosen point by secret scalar and returns something."

### Інструменти

- SageMath для арифметики кривих / lattices
- `ecdsa` Python library для розбору/перевірки

{{#include ../../banners/hacktricks-training.md}}
