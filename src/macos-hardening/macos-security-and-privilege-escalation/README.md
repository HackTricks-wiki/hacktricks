# Безпека macOS і підвищення привілеїв

{{#include ../../banners/hacktricks-training.md}}

## Основи macOS

Якщо ви не знайомі з macOS, почніть із вивчення основ macOS:

- Спеціальні **файли та дозволи** macOS:


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- Поширені **користувачі** macOS


{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- **Архітектура** **kernel**


{{#ref}}
mac-os-architecture/
{{#endref}}

- Поширені **мережеві служби та протоколи** macOS


{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Щоб завантажити `tar.gz`, змініть URL, наприклад [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) на [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MDM macOS

У компаніях системи **macOS**, найімовірніше, будуть **керуватися за допомогою MDM**. Тому з погляду атакера цікаво знати, **як це працює**:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### macOS — перевірка, налагодження та fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Засоби захисту macOS


{{#ref}}
macos-security-protections/
{{#endref}}

## Поверхня атаки

### Дозволи файлів

Якщо **процес, що працює від імені root, записує** файл, яким може керувати користувач, користувач може скористатися цим для **підвищення привілеїв**.\
Це може відбуватися в таких ситуаціях:

- Файл уже був створений користувачем (належить користувачеві)
- Файл доступний для запису користувачеві через групу
- Файл розташований у каталозі, що належить користувачеві (користувач може створити файл)
- Файл розташований у каталозі, що належить root, але користувач має доступ до запису через групу (користувач може створити файл)

Можливість **створити файл**, який буде **використовуватися root**, дає користувачеві змогу **скористатися його вмістом** або навіть створити **symlinks/hardlinks**, що вказують на інше місце.

Для цього типу вразливостей не забудьте **перевірити вразливі інсталятори `.pkg`**:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Обробники розширень файлів і схем URL

Дивні програми, зареєстровані для розширень файлів, можуть бути використані зловмисниками, а різні програми можуть бути зареєстровані для відкриття певних протоколів


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## Підвищення привілеїв macOS TCC / SIP

У macOS **програми та binaries можуть мати дозволи** на доступ до каталогів або налаштувань, що робить їх привілейованішими за інші.

Тому атакеру, який хоче успішно скомпрометувати машину macOS, потрібно буде **підвищити свої привілеї TCC** (або навіть **обійти SIP**, залежно від його потреб).

Ці привілеї зазвичай надаються у формі **entitlements**, з якими підписано програму, або програма могла запитати певний доступ, і після **його схвалення користувачем** ці дозволи можна знайти в **базах даних TCC**. Інший спосіб, у який процес може отримати ці привілеї, — бути **дочірнім процесом** процесу, що має такі **привілеї**, оскільки вони зазвичай **успадковуються**.

Перейдіть за цими посиланнями, щоб дізнатися про різні способи [**підвищення привілеїв у TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), [**обходу TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) і про те, як у минулому [**обходили SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## Традиційне підвищення привілеїв macOS

Звичайно, з погляду red team вам також має бути цікаво підвищити привілеї до root. Перегляньте наступну публікацію, щоб знайти підказки:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## Відповідність macOS вимогам безпеки

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Посилання

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
