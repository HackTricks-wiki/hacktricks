# Ін’єкція в застосунки macOS Vim/Neovim

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Власна скриптова мова Vim (Vimscript) може запускати **довільні Ex-команди та shell-команди під час запуску** з environment variables. Якщо процес із вищими привілеями (workflow обслуговування/root, `sudo vim …`, редактор, запущений іншим інструментом, `crontab -e`, `visudo`, `git`/`less`, що викликають редактор, …) запускає Vim/Neovim з environment, на який впливає attacker, attacker отримує виконання коду в цьому контексті.

## `VIMINIT`

Під час ініціалізації Vim читає та виконує Ex-команди з **`VIMINIT`**. Ex-команди включають `:!cmd` (запуск shell-команди) і `:call system(...)`, тому одна змінна забезпечує довільне виконання до редагування будь-якого файлу.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript (no external process, e.g. write a file)
printf ':qa!\n' | VIMINIT='call writefile(["x"],"/tmp/vim-vimscript")' vim /tmp/victim.txt
```
Рядок `:qa!`, переданий через stdin, лише закриває редактор після того, як payload уже виконано; у реальному сценарії жертва просто відкриває Vim у звичайний спосіб.

## `EXINIT`

Якщо `VIMINIT` не встановлено, Vim (а також сумісні бінарні файли `vi`/`ex`) використовує **`EXINIT`**, який виконується так само. Це класичний варіант тієї самої primitive з епохи vi.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Примітки та застереження

- **Neovim** також враховує `VIMINIT` (його перевіряють перед користувацькими `init.vim`/`init.lua`).
- Пакетний/Ex-режим (`vim -es` / `vim -Es`) **не** завантажує `VIMINIT`/`EXINIT`; ці змінні виконуються під час звичайного (інтерактивного) запуску, що є типовим сценарієм для жертви.
- Пов’язані вектори на основі файлів — це функції `exrc`/`.nvimrc` «modeline»/локального rc для кожного каталогу та `-u <vimrc>`; описаний вище шлях через змінні середовища взагалі не потребує доступного для запису файлу.

## Посилення захисту

- Очищайте середовище (видаляйте `VIMINIT`/`EXINIT`) перед запуском редакторів із привілейованих або автоматизованих контекстів і надавайте перевагу обгорткам `sudo -i`/`env -i`, які скидають середовище.
- Встановлюйте `EDITOR`/`VISUAL` на надійні абсолютні шляхи та уникайте запуску редакторів від root з успадкованим середовищем користувача.
- Розглядайте контроль над середовищем цілі як еквівалент виконання коду для будь-якого запущеного нею Vim/Neovim.

## References

- [1] [Документація Vim — `starting.txt` (ініціалізація, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
{{#include ../../../banners/hacktricks-training.md}}
