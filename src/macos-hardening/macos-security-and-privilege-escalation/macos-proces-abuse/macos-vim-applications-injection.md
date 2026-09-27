# Ін’єкція в застосунки macOS Vim/Neovim

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Власна мова сценаріїв Vim (Vimscript) може запускати **довільні Ex-команди та shell-команди під час запуску** з environment variables. Якщо більш привілейований процес (workflow обслуговування/root, `sudo vim …`, редактор, запущений іншим інструментом, `crontab -e`, `visudo`, `git`/`less`, що викликають редактор, …) запускає Vim/Neovim з environment, на який впливає attacker, attacker отримує виконання коду в цьому контексті.

## `VIMINIT`

Під час ініціалізації Vim читає та виконує Ex-команди з **`VIMINIT`**. Ex-команди включають `:!cmd` (запуск shell-команди) і `:call system(...)`, тому одна змінна забезпечує довільне виконання ще до редагування будь-якого файлу.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```
`:qa!`, переданий через stdin у першому прикладі, лише закриває редактор після виконання payload; у реальному сценарії жертва може відкрити Vim звичайним способом.

`VIMINIT` обробляється як **один рядок команд Ex**. Розділяйте ланцюжок за допомогою `|` (або буквального переведення рядка). Він має пріоритет над vimrc користувача та `EXINIT`, тому для payload не потрібен шкідливий конфігураційний файл, і він виконується до звичайної конфігурації користувача.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Якщо `VIMINIT` не встановлено, Vim (а також бінарні файли сумісності `vi`/`ex`) використовує **`EXINIT`**, який виконується так само. Це класичний варіант тієї самої примітивної можливості з епохи vi.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Придушення запуску та можливість експлуатації

Цей примітив залежить від **звичайного запуску**. `vim -u NONE` / `nvim -u NONE` пропускають ініціалізацію середовища/користувача (і plugins), тоді як `-u <file>` використовує вказаний файл. Vim `-es`/`-Es` і Neovim `-es`, `-Es` або `-l` також пропускають ці кроки ініціалізації. Не вважайте `--headless` безпечним режимом: звичайний headless-запуск Neovim все одно обробляє `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Отже, перевіряйте весь ланцюжок запуску: змінна має пройти через wrapper, політику `sudo`, job runner і вибір редактора, а фінальна команда не повинна примусово вмикати `-u NONE`/`NORC` або batch mode. Надійний payload може завершити себе за допомогою `|qall!`, що також спрощує тестування wrapper-ів, які не надають TTY.<sup>[[1]](#references)[[2]](#references)</sup>

## Перехоплення Lua-модулів із поточного каталогу Neovim

Окремий примітив ін’єкції Neovim впливає на збірки, у яких Lua `package.path`/`package.cpath` усе ще містять шаблони поточного каталогу, такі як `./?.lua` або `./?.so`. Самого запуску Neovim недостатньо: конфігурація або plugin мають викликати `require("name")`, і жоден попередній loader не повинен розв’язати це ім’я. Поширеним trigger є **перевірка optional dependency**, наприклад `pcall(require, "optional_dep")`; розміщення `optional_dep.lua` у контрольованому атакувальником робочому каталозі запускає його без увімкнення окремої функції локальної конфігурації `'exrc'`. Основні модулі `vim.*` і модулі, які вже знайдено в `'runtimepath'`, зазвичай не можна shadow-ити, тому слід перелічити фактичні відсутні/optional виклики `require()`, а не вгадувати імена.<sup>[[3]](#references)</sup>

Наведене нижче відтворює loader-примітив за допомогою нешкідливого маркера:<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/nvim-cwd-hijack
cat > /tmp/nvim-cwd-hijack/optional_dep.lua <<'LUA'
vim.fn.writefile({"loaded"}, "/tmp/nvim-cwd-hit")
return {}
LUA

cd /tmp/nvim-cwd-hijack
nvim --clean --headless '+lua require("optional_dep")' +qa
cat /tmp/nvim-cwd-hit
```
Перевірте запущену збірку замість того, щоб покладатися лише на рядок версії:<sup>[[3]](#references)</sup>
```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```
Upstream відстежує видалення резервного варіанта з поточним каталогом під час звичайного запуску редактора, водночас зберігаючи поведінку Lua-скриптів (`nvim -l`). Поки встановлена збірка все ще надає його, розмістіть це на **початку** `init.lua` (це навмисно видаляє шаблони Lua/C-модулів із відносного поточного каталогу, тому не застосовуйте це до робочих процесів, яким вони потрібні):<sup>[[3]](#references)</sup>
```lua
local function drop_cwd(path)
local keep = {}
for entry in path:gmatch("[^;]+") do
if not entry:match("^%./") then keep[#keep + 1] = entry end
end
return table.concat(keep, ";")
end
package.path = drop_cwd(package.path)
package.cpath = drop_cwd(package.cpath)
```
## Примітки та застереження

- **Neovim** враховує як `VIMINIT`, так і резервний варіант `EXINIT`, але його стандартною конфігурацією користувача є `init.vim` або `init.lua`.<sup>[[2]](#references)</sup>
- Для шляху через змінну середовища не потрібен доступний для запису файл. Локальний rc і hijacking модулів у поточному каталозі є окремими file-backed примітивами.<sup>[[1]](#references)[[3]](#references)</sup>
- Локальна конфігурація проєкту є окремою поверхнею від modelines. Якщо у Vim увімкнено `'exrc'`, локальний vimrc/exrc, власником якого є інший користувач, запускається з обмеженнями `'secure'`; однак під час розпакування архіву створений файл зазвичай стає власністю жертви, що обходить цей захист на основі власника. Neovim також шукає `.nvim.lua`, `.nvimrc` або `.exrc`, коли `'exrc'` увімкнено — не плутайте цей механізм, який потребує явного ввімкнення, із наведеним вище fallback `require()` у поточному каталозі.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Змінні вибору редактора лише визначають, яку програму буде запущено; вони не гарантують, що `VIMINIT` потрапить до кінцевого процесу. Перевіряйте точне середовище та аргументи на межі exec Vim/Neovim.<sup>[[1]](#references)[[2]](#references)</sup>

## Посилення захисту

- Явно видаляйте змінні перед привілейованим або автоматизованим запуском редактора: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` важливий, коли викликач має ігнорувати всі джерела запуску користувача.<sup>[[1]](#references)[[2]](#references)</sup>
- Встановлюйте `EDITOR`/`VISUAL` як довірені абсолютні шляхи, уникайте запуску інтерактивних редакторів від імені root із успадкованим середовищем користувача та переконайтеся, що wrappers не можуть відновити `VIMINIT`/`EXINIT` після санітизації.<sup>[[1]](#references)[[2]](#references)</sup>
- Для Neovim оновіть систему до build, який видаляє шаблони пошуку Lua/C у поточному каталозі під час роботи редактора, або видаліть їх перед завантаженням plugins. Перевіряйте код plugins на наявність необов'язкових викликів `pcall(require, ...)` під час відкриття недовірених репозиторіїв.<sup>[[3]](#references)</sup>
- Розглядайте контроль над середовищем редактора, робочим каталогом або конфігурацією запуску цілі як потенційний примітив виконання коду в контексті безпеки редактора.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Документація Vim — `starting.txt` (ініціалізація, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Документація Neovim — запуск та ініціалізація](https://neovim.io/doc/user/starting/)
- [3] [Issue Neovim #38966 — fallback у поточному каталозі в `require()`](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}
