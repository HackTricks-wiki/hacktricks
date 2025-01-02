# macOS Security & Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic MacOS

Якщо ви не знайомі з macOS, вам слід почати вивчати основи macOS:

- Спеціальні файли та **дозволи macOS:**

{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- Загальні **користувачі macOS**

{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**

{{#ref}}
macos-applefs.md
{{#endref}}

- **Архітектура** ядра

{{#ref}}
mac-os-architecture/
{{#endref}}

- Загальні **мережеві сервіси та протоколи macOS**

{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Щоб завантажити `tar.gz`, змініть URL, наприклад, [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) на [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

У компаніях системи **macOS**, ймовірно, будуть **керуватися за допомогою MDM**. Тому з точки зору зловмисника цікаво знати, **як це працює**:

{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Інспекція, налагодження та фуззинг

{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS Security Protections

{{#ref}}
macos-security-protections/
{{#endref}}

## Attack Surface

### File Permissions

Якщо **процес, що працює від імені root, записує** файл, який може контролюватися користувачем, користувач може зловживати цим для **ескалації привілеїв**.\
Це може статися в наступних ситуаціях:

- Файл, що використовується, вже був створений користувачем (належить користувачу)
- Файл, що використовується, доступний для запису користувачем через групу
- Файл, що використовується, знаходиться в каталозі, що належить користувачу (користувач може створити файл)
- Файл, що використовується, знаходиться в каталозі, що належить root, але користувач має доступ на запис через групу (користувач може створити файл)

Можливість **створити файл**, який буде **використовуватися root**, дозволяє користувачу **використовувати його вміст** або навіть створювати **символьні/жорсткі посилання** на інше місце.

Для таких вразливостей не забудьте **перевірити вразливі `.pkg` інсталятори**:

{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### File Extension & URL scheme app handlers

Дивні програми, зареєстровані за допомогою розширень файлів, можуть бути зловживані, і різні програми можуть бути зареєстровані для відкриття конкретних протоколів

{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

У macOS **додатки та бінарні файли можуть мати дозволи** на доступ до папок або налаштувань, які роблять їх більш привілейованими, ніж інші.

Отже, зловмисник, який хоче успішно скомпрометувати машину macOS, повинен **ескалувати свої привілеї TCC** (або навіть **обійти SIP**, залежно від його потреб).

Ці привілеї зазвичай надаються у формі **прав** з якими підписаний додаток, або додаток може запитати деякі доступи, і після **схвалення їх користувачем** вони можуть бути знайдені в **базах даних TCC**. Інший спосіб, яким процес може отримати ці привілеї, - це бути **дочірнім процесом** з такими **привілеями**, оскільки вони зазвичай **успадковуються**.

Слідуйте цим посиланням, щоб знайти різні способи [**ескалації привілеїв у TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), [**обійти TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) і як у минулому [**SIP було обійдено**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Traditional Privilege Escalation

Звичайно, з точки зору червоних команд, вам також слід бути зацікавленим в ескалації до root. Перегляньте наступний пост для деяких підказок:

{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS Compliance

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## References

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
- [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
