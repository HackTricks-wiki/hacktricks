# Атаки Homograph / Homoglyph у Phishing

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Атака homograph (також відома як homoglyph) використовує той факт, що багато **кодів Unicode з нелатинських писемностей візуально ідентичні або надзвичайно схожі на символи ASCII**. Замінивши один або кілька латинських символів на схожі відповідники, зловмисник може створити:

* Імена відображення, теми або тіла повідомлень, які виглядають легітимними для людини, але обходять виявлення на основі ключових слів.
* Домени, піддомени або шляхи URL, які змушують жертв вважати, що вони відвідують надійний сайт.<sup>[[1]](#references)</sup>

Оскільки кожен гліф внутрішньо ідентифікується його **кодом Unicode**, одного заміненого символу достатньо, щоб обійти наївне порівняння рядків (наприклад, `"Παypal.com"` проти `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Типовий Phishing Workflow

1. **Створити вміст повідомлення** – Замінити певні латинські літери в імені бренду / ключовому слові, що імітується, на візуально невідмінні символи з іншої писемності (грецької, кириличної, вірменської, Cherokee тощо).
2. **Зареєструвати допоміжну інфраструктуру** – За потреби зареєструвати homoglyph-домен і отримати TLS-сертифікат (більшість CA не виконує перевірку візуальної схожості).
3. **Надіслати email / SMS** – Повідомлення містить homoglyphs в одному або кількох із наведених місць:
* Ім’я відправника, що відображається (наприклад, `Ηеlрdеѕk`)
* Рядок теми (`Urgеnt Аctіon Rеquіrеd`)
* Текст гіперпосилання або повне доменне ім’я
4. **Redirect chain** – Жертва проходить через начебто нешкідливі вебсайти або URL shorteners, перш ніж потрапити на шкідливий хост, який викрадає облікові дані / доставляє malware.<sup>[[1]](#references)</sup>

## Діапазони Unicode, які часто зловживаються

Наведені нижче приклади — це блоки Unicode, що містять символи, які часто використовуються для створення схожих символів з різних писемностей.<sup>[[2]](#references)[[3]](#references)</sup>

| Писемність | Діапазон | Приклад гліфа | Виглядає як |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Порада: Використовуйте таблиці кодів Unicode, щоб знаходити блоки та кодові точки.

## Методи виявлення

### 1. Перевірка змішаних писемностей

Phishing emails, націлені на англомовну організацію, рідко повинні містити символи з кількох писемностей. Простий, але ефективний heuristic полягає в тому, щоб:

1. Перебрати кожен символ перевірюваного рядка.
2. Визначити назву його писемності або блок Unicode за кодовою точкою.
3. Створити alert, якщо присутня більш ніж одна писемність **або** якщо нелатинські писемності з’являються там, де їх не очікують (ім’я відображення, домен, тема, URL тощо).<sup>[[3]](#references)</sup>

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

Інтернаціоналізовані доменні імена (IDN) мають форму Unicode та ASCII-сумісну форму **Punycode** із префіксом `xn--`. Перетворюйте імена хостів у форму IDNA/Punycode перед додаванням до списку дозволених або порівнянням, зберігаючи форму Unicode для відображення.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Словники / алгоритми Homoglyph

Інструменти на кшталт **dnstwist** (`--fuzzers homoglyph`) або **urlcrazy** можуть перераховувати візуально схожі варіанти доменів і корисні для проактивного видалення / моніторингу.<sup>[[4]](#references)[[5]](#references)</sup>

## Запобігання та пом'якшення наслідків

* Застосовуйте суворі політики DMARC/DKIM/SPF — запобігайте spoofing із неавторизованих доменів.
* Реалізуйте наведену вище логіку виявлення у **Secure Email Gateways** та playbooks **SIEM/XSOAR**.
* Позначайте або переміщуйте в карантин повідомлення, у яких домен display name ≠ домен відправника.
* Навчайте користувачів: вставляйте підозрілий текст у Unicode-інспектор, наводьте курсор на посилання, ніколи не довіряйте скорочувачам URL.

## Приклади з реального світу

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (кириличні `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Ланцюжок доменів: `bestseoservices.com` ➜ каталог муніципалітету `/templates` ➜ `kig.skyvaulyt.ru` ➜ фальшивий вхід Microsoft на `mlcorsftpsswddprotcct.approaches.it.com`, захищений спеціальною OTP CAPTCHA.
* Імітація Spotify: відправник `Sρօtifս` із посиланням, прихованим за `redirects.ca`.

Ці зразки походять із дослідження Unit 42 (липень 2025 року) та демонструють, як зловживання homograph поєднується з перенаправленням URL і обходом CAPTCHA, щоб обійти автоматизований аналіз.<sup>[[1]](#references)</sup>

## References

- [1] [Ілюзія Homograph: не все є таким, як здається](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Таблиці кодів символів Unicode](https://www.unicode.org/charts/)
- [3] [Технічний стандарт Unicode № 39: механізми безпеки Unicode](https://unicode.org/reports/tr39/)
- [4] [dnstwist – рушій перебирання варіантів доменів](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – генератор помилок і варіантів доменів](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Інтернаціоналізовані доменні імена для застосунків (IDNA): визначення та структура документа](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
