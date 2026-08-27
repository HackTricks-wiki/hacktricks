# Ін’єкція в Shell Applications macOS

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Коли Bash запускається неінтерактивно для виконання скрипту або команди `-c`, він розгортає значення `BASH_ENV` і підключає отриманий файл перед виконанням запитуваної команди. Bash не використовує `PATH` для пошуку цього файлу. Тому процес, який запускає неінтерактивний Bash із контрольованими зловмисником змінними середовища, можна змусити спочатку виконати доступне для читання shell payload.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Хук запускається лише тоді, коли ціль фактично запускає Bash; `/bin/sh` на іншій платформі або програма, яка виконує команду без shell, не обов’язково його враховуватиме. Bash у привілейованому режимі ігнорує `BASH_ENV`. Коли ефективні та реальні ідентифікатори користувача/групи відрізняються, Bash також пропускає startup files і скидає ефективні ідентифікатори, якщо не вказано `-p`; з `-p` привілейований режим залишається увімкненим, а `BASH_ENV` і надалі ігнорується.<sup>[[1]](#references)[[2]](#references)</sup>

У macOS завдання `launchd` можуть визначати успадковані змінні середовища або змінні середовища для окремих завдань, тому перевіряйте plists і контексти запуску, з яких отримують змінні привілейовані скрипти. Не покладайтеся лише на SIP для очищення змінних інтерпретатора: використовуйте мінімальне середовище (`env -i`), явно скасовуйте `BASH_ENV`, викликайте потрібний інтерпретатор за абсолютним шляхом і уникайте startup files, доступних для запису.

## zsh `ZDOTDIR`

zsh читає `$ZDOTDIR/.zshenv` для кожної звичайної shell, включно з неінтерактивними shell; якщо `ZDOTDIR` не встановлено, використовується `HOME`. Тому перенаправлення `ZDOTDIR` до каталогу, доступного для запису, виконує його `.zshenv` перед командою або скриптом `zsh -c`.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` скасовує опцію `RCS` і пропускає цей користувацький startup-файл. Глобальний `/etc/zshenv` усе ще читається, тому він має залишатися довіреним і мінімальним.

## fish `XDG_CONFIG_HOME`

fish читає `$XDG_CONFIG_HOME/fish/conf.d/*.fish` і `$XDG_CONFIG_HOME/fish/config.fish` під час запуску кожної shell, а не лише інтерактивних або login shell. Він також виконує `fish/vendor_conf.d/*.fish` у каталогах, перелічених у `XDG_DATA_DIRS`. Тому зловмисник, який контролює одну з цих змінних і доступний для читання каталог, може виконати код до запуску fish-скрипту або команди `-c`.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Для trusted invocation використовуйте `fish --no-config` і очистіть ненадійні змінні шляхів XDG.

## References

- [1] [Файли запуску Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Виклик Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [Файли запуску/завершення zsh](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [Файли конфігурації fish](https://fishshell.com/docs/current/language.html#configuration-files)
{{#include ../../../banners/hacktricks-training.md}}
