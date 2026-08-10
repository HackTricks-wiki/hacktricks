# Атаки Homograph / Homoglyph у Phishing

## Огляд

Атака Homograph (також Homoglyph) використовує той факт, що багато **Unicode code points із нелатинських скриптів візуально ідентичні або надзвичайно схожі на ASCII-символи**. Замінюючи один або кілька латинських символів на їхні візуальні аналоги, атакер може створити:

* Display names, теми або тіла повідомлень, які виглядають легітимно для людського ока, але обходять keyword-based detections.
* Домени, субдомени або URL paths, які змушують жертв вважати, що вони відвідують довірений сайт.<sup>[[1]](#references)</sup>

Оскільки кожен glyph внутрішньо ідентифікується його **Unicode code point**, однієї заміни символу достатньо, щоб обійти наївні порівняння рядків (наприклад, `"Παypal.com"` проти `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Типовий Phishing workflow

1. **Створення вмісту повідомлення** – Замінити певні латинські літери в імітованому бренді / keyword на візуально нерозрізнювані символи з іншого скрипту (грецького, кириличного, вірменського, Cherokee тощо).
2. **Реєстрація supporting infrastructure** – За потреби зареєструвати homoglyph domain і отримати TLS-сертифікат (більшість CA не виконують перевірки візуальної схожості).
3. **Надсилання email / SMS** – Повідомлення містить homoglyphs в одному або кількох із таких місць:
* Sender display name (наприклад, `Ηеlрdеѕk`)
* Subject line (`Urgеnt Аctіon Rеquіrеd`)
* Текст гіперпосилання або fully qualified domain name
4. **Redirect chain** – Жертва проходить через на перший погляд нешкідливі вебсайти або URL shorteners, перш ніж потрапити на malicious host, який викрадає credentials / доставляє malware.<sup>[[1]](#references)</sup>

## Unicode ranges, які часто зловживаються

Нижче наведено приклади Unicode blocks, що містять символи, які часто використовуються для створення міжскриптових візуальних аналогів.<sup>[[2]](#references)[[3]](#references)</sup>

| Скрипт | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Грецький  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Грецький  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Кириличний | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Кириличний | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Вірменський | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Порада: Використовуйте Unicode code charts, щоб знаходити blocks і code points.

## Техніки виявлення

### 1. Перевірка Mixed-Script

Phishing emails, спрямовані на англомовну організацію, рідко мають змішування символів із кількох скриптів. Простою, але ефективною евристикою є:

1. Перебрати кожен символ перевірюваного рядка.
2. Визначити script name або Unicode block для code point.
3. Згенерувати alert, якщо присутній більше ніж один скрипт **або** якщо нелатинські скрипти з’являються там, де вони не очікуються (display name, domain, subject, URL тощо).<sup>[[3]](#references)</sup>

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

Інтернаціоналізовані доменні імена (IDN) мають форму Unicode та ASCII-сумісну форму **Punycode** з префіксом `xn--`. Перетворюйте імена хостів у форму IDNA/Punycode перед додаванням до allow-list або порівнянням, зберігаючи форму Unicode для відображення.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Homoglyph Dictionaries / Algorithms

Інструменти на кшталт **dnstwist** (`--fuzzers homoglyph`) або **urlcrazy** можуть перераховувати візуально схожі варіанти доменів і корисні для проактивного видалення / моніторингу.<sup>[[4]](#references)[[5]](#references)</sup>

## Prevention & Mitigation

* Застосовуйте суворі політики DMARC/DKIM/SPF — запобігайте spoofing з неавторизованих доменів.
* Реалізуйте наведену вище логіку виявлення в **Secure Email Gateways** і плейбуках **SIEM/XSOAR**.
* Позначайте або переміщуйте в карантин повідомлення, у яких домен display name ≠ домен відправника.
* Навчайте користувачів: вставляйте підозрілий текст у Unicode inspector, наводьте курсор на links, ніколи не довіряйте URL shorteners.

## Real-World Examples

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Ланцюжок доменів: `bestseoservices.com` ➜ каталог municipal `/templates` ➜ `kig.skyvaulyt.ru` ➜ фіктивна сторінка входу Microsoft за адресою `mlcorsftpsswddprotcct.approaches.it.com`, захищена custom OTP CAPTCHA.
* Імітація Spotify: відправник `Sρօtifս` із link, прихованим за `redirects.ca`.

Ці зразки походять із дослідження Unit 42 (липень 2025 року) та демонструють, як зловживання homograph поєднується з перенаправленням URL і обходом CAPTCHA, щоб обійти автоматизований аналіз.<sup>[[1]](#references)</sup>

## References

- [1] [Ілюзія Homograph: не все є таким, яким здається](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Таблиці кодів символів Unicode](https://www.unicode.org/charts/)
- [3] [Технічний стандарт Unicode № 39: механізми безпеки Unicode](https://unicode.org/reports/tr39/)
- [4] [dnstwist — рушій пермутацій доменів](https://github.com/elceef/dnstwist)
- [5] [URLCrazy — генератор доменів із typo та варіаціями](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Інтернаціоналізовані доменні імена для застосунків (IDNA): визначення та структура документа](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
