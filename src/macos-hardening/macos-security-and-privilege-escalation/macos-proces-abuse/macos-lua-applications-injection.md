# macOS Lua Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

コマンドラインオプションまたは対象スクリプトを処理する前に、standalone Lua interpreter は `LUA_INIT_<major>_<minor>` を実行します。versioned variable が存在しない場合は `LUA_INIT` を実行します。`@` で始まる値はファイルを指定し、それ以外の値は Lua code として直接評価されます。これにより、file-backed と fileless の両方の startup execution が可能になります。<sup>[[1]](#references)</sup>
```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```
インタープリタによって正確なバージョン付きの名前が変わります。たとえば `LUA_INIT_5_4` です。`lua -E` は、startup code や Lua module paths を含むすべての環境変数を無視します。

## References

- [1] [Lua 5.4 スタンドアロンインタープリタ](https://www.lua.org/manual/5.4/manual.html#7)
{{#include ../../../banners/hacktricks-training.md}}
