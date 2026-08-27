# macOS Lua 应用程序注入

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

在处理命令行选项或目标脚本之前，独立的 Lua interpreter 会执行 `LUA_INIT_<major>_<minor>`；如果版本化变量不存在，则执行 `LUA_INIT`。以 `@` 开头的值表示文件名；其他值则直接作为 Lua code 求值。这同时支持基于文件和无文件的启动执行。<sup>[[1]](#references)</sup>
```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```
具体的版本化名称会随解释器而变化，例如 `LUA_INIT_5_4`。`lua -E` 会忽略所有环境变量，包括启动代码和 Lua 模块路径。

## References

- [1] [Lua 5.4 standalone interpreter](https://www.lua.org/manual/5.4/manual.html#7)
{{#include ../../../banners/hacktricks-training.md}}
