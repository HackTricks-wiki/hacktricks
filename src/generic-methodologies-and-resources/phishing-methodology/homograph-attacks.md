# Homograph / Homoglyph Attacks у Phishing

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Атака homograph (також homoglyph) використовує той факт, що багато **Unicode code points з нелатинських скриптів візуально ідентичні або надзвичайно схожі на ASCII-символи**. Замінюючи один або кілька латинських символів на відповідні символи-двійники, зловмисник може створити:

* Display names, теми або тіла повідомлень, які виглядають легітимно для людського ока, але обходять keyword-based detections.
* Домени, sub-domains або URL paths, які змушують жертв вважати, що вони відвідують довірений сайт.

Оскільки кожен glyph внутрішньо ідентифікується за його **Unicode code point**, одного заміненого символу достатньо, щоб обійти наївні порівняння рядків (наприклад, `"Παypal.com"` проти `"Paypal.com"`).

## Типовий Phishing Workflow

1. **Створення вмісту повідомлення** – Замініть окремі латинські літери в імітованому бренді / keyword на візуально нерозрізнимі символи з іншого скрипту (грецького, кириличного, вірменського, Cherokee тощо).
2. **Реєстрація supporting infrastructure** – За потреби зареєструйте homoglyph domain і отримайте TLS certificate (більшість CA не виконують перевірку візуальної схожості).
3. **Надсилання email / SMS** – Повідомлення містить homoglyphs в одному або кількох із таких місць:
* Sender display name (наприклад, `Ηеlрdеѕk`)
* Subject line (`Urgеnt Аctіon Rеquіrеd`)
* Текст гіперпосилання або fully qualified domain name
4. **Redirect chain** – Жертва перенаправляється через, на перший погляд, нешкідливі вебсайти або URL shorteners, перш ніж потрапити на malicious host, який збирає credentials / доставляє malware.

## Unicode Ranges, які часто зловживаються

| Script | Range | Example glyph | Виглядає як |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Порада: повні Unicode charts доступні на [unicode.org](https://home.unicode.org/).<sup>[[2]](#references)</sup>

## Detection Techniques

### 1. Mixed-Script Inspection

Phishing emails, спрямовані на англомовну організацію, рідко повинні містити символи з кількох скриптів. Простою, але ефективною heuristic є:

1. Проаналізувати кожен символ перевірюваного рядка.
2. Визначити Unicode block за code point.
3. Створити alert, якщо присутній більше ніж один скрипт **або** якщо нелатинські скрипти з’являються там, де їх не очікують (display name, domain, subject, URL тощо).

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
### 2. Нормалізація Punycode (доменів)

Міжнародизовані доменні імена (IDN) кодуються за допомогою **punycode** (`xn--`). Перетворення кожного hostname у punycode, а потім назад у Unicode дає змогу виконувати зіставлення з whitelist або перевірки схожості (наприклад, відстані Левенштейна) **після** нормалізації рядка.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Homoglyph Dictionaries / Algorithms

Tools such as **dnstwist** (`--homoglyph`) or **urlcrazy** can enumerate visually-similar domain permutations and are useful for proactive takedown / monitoring.<sup>[[3]](#references)</sup>

## Prevention & Mitigation

* Enforce strict DMARC/DKIM/SPF policies – prevent spoofing from unauthorised domains.
* Implement the detection logic above in **Secure Email Gateways** and **SIEM/XSOAR** playbooks.
* Flag or quarantine messages where display name domain ≠ sender domain.
* Educate users: copy-paste suspicious text into a Unicode inspector, hover links, never trust URL shorteners.

## Real-World Examples

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Domain chain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ fake Microsoft login at `mlcorsftpsswddprotcct.approaches.it.com` protected by custom OTP CAPTCHA.
* Spotify impersonation: `Sρօtifս` sender with link hidden behind `redirects.ca`.

These samples originate from Unit 42 research (July 2025) and illustrate how homograph abuse is combined with URL redirection and CAPTCHA evasion to bypass automated analysis.<sup>[[1]](#references)</sup>

## References

- [1] [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Database](https://home.unicode.org/)
- [3] [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
