# Homograph / Homoglyph Attacks in Phishing

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Атака гомографів (також відома як атака гомогліфів) використовує той факт, що багато **кодів Unicode з нелатинських скриптів візуально ідентичні або надзвичайно схожі на ASCII-символи**. Замінюючи один або кілька латинських символів на їх візуально схожі аналоги, зловмисник може створити:

* Імена відправників, теми або тіла повідомлень, які виглядають легітимно для людського ока, але обходять виявлення на основі ключових слів.
* Доменні імена, піддомени або URL-адреси, які обманюють жертв, змушуючи їх вірити, що вони відвідують надійний сайт.

Оскільки кожен гліф ідентифікується внутрішньо за його **кодом Unicode**, однієї заміни символу достатньо, щоб обійти наївні порівняння рядків (наприклад, `"Παypal.com"` проти `"Paypal.com"`).

## Типовий робочий процес фішингу

1. **Створити вміст повідомлення** – Замінити конкретні латинські літери в підробленому бренді / ключовому слові на візуально нерозрізнені символи з іншого скрипту (грецький, кирилиця, вірменський, черокі, тощо).
2. **Зареєструвати підтримуючу інфраструктуру** – За бажанням зареєструвати домен гомогліфів і отримати сертифікат TLS (більшість ЦП не проводить перевірок візуальної схожості).
3. **Відправити електронну пошту / SMS** – Повідомлення містить гомогліфи в одному або кількох з наступних місць:
* Ім'я відправника (наприклад, `Ηеlрdеѕk`)
* Тема (`Urgеnt Аctіon Rеquіrеd`)
* Текст гіперпосилання або повністю кваліфіковане доменне ім'я
4. **Ланцюг перенаправлень** – Жертва проходить через, здавалося б, безпечні веб-сайти або скорочувачі URL перед тим, як потрапити на шкідливий хост, який збирає облікові дані / доставляє шкідливе ПЗ.

## Діапазони Unicode, які часто зловживають

| Скрипт | Діапазон | Приклад гліфа | Схоже на |
|--------|-------|---------------|------------|
| Грецький  | U+0370-03FF | `Η` (U+0397) | Латинське `H` |
| Грецький  | U+0370-03FF | `ρ` (U+03C1) | Латинське `p` |
| Кирилиця | U+0400-04FF | `а` (U+0430) | Латинське `a` |
| Кирилиця | U+0400-04FF | `е` (U+0435) | Латинське `e` |
| Вірменський | U+0530-058F | `օ` (U+0585) | Латинське `o` |
| Черокі | U+13A0-13FF | `Ꭲ` (U+13A2) | Латинське `T` |

> Порада: Повні таблиці Unicode доступні на [unicode.org](https://home.unicode.org/).

## Техніки виявлення

### 1. Перевірка змішаних скриптів

Фішингові електронні листи, спрямовані на англомовну організацію, рідко повинні змішувати символи з кількох скриптів. Простий, але ефективний евристичний метод полягає в тому, щоб:

1. Перебрати кожен символ перевіряємого рядка.
2. Відобразити код символу на його блок Unicode.
3. Підняти тривогу, якщо присутні більше ніж один скрипт **або** якщо нелатинські скрипти з'являються там, де їх не очікують (ім'я відправника, домен, тема, URL тощо).

Python proof-of-concept:
```python
import unicodedata as ud
from collections import defaultdict

SUSPECT_FIELDS = {
"display_name": "Ηоmоgraph Illusion",     # example data
"subject": "Finаnꮯiаl Տtatеmеnt",
"url": "https://xn--messageconnecton-2kb.blob.core.windows.net"  # punycode
}

for field, value in SUSPECT_FIELDS.items():
blocks = defaultdict(int)
for ch in value:
if ch.isascii():
blocks['Latin'] += 1
else:
name = ud.name(ch, 'UNKNOWN')
block = name.split(' ')[0]     # e.g., 'CYRILLIC'
blocks[block] += 1
if len(blocks) > 1:
print(f"[!] Mixed scripts in {field}: {dict(blocks)} -> {value}")
```
### 2. Нормалізація Punycode (Домени)

Міжнародні доменні імена (IDN) кодуються за допомогою **punycode** (`xn--`). Перетворення кожного імені хоста в punycode, а потім назад в Unicode дозволяє порівнювати з білою списком або виконувати перевірки на схожість (наприклад, відстань Левенштейна) **після** того, як рядок був нормалізований.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Гомогліфні словники / Алгоритми

Tools such as **dnstwist** (`--homoglyph`) or **urlcrazy** can enumerate visually-similar domain permutations and are useful for proactive takedown / monitoring.

## Запобігання та пом'якшення

* Enforce strict DMARC/DKIM/SPF policies – prevent spoofing from unauthorised domains.
* Implement the detection logic above in **Secure Email Gateways** and **SIEM/XSOAR** playbooks.
* Flag or quarantine messages where display name domain ≠ sender domain.
* Educate users: copy-paste suspicious text into a Unicode inspector, hover links, never trust URL shorteners.

## Реальні приклади

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Domain chain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ fake Microsoft login at `mlcorsftpsswddprotcct.approaches.it.com` protected by custom OTP CAPTCHA.
* Spotify impersonation: `Sρօtifւ` sender with link hidden behind `redirects.ca`.

These samples originate from Unit 42 research (July 2025) and illustrate how homograph abuse is combined with URL redirection and CAPTCHA evasion to bypass automated analysis.

## Посилання

- [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [Unicode Character Database](https://home.unicode.org/)
- [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
