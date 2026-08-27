# macOS Lua Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

Voordat die selfstandige Lua-interpreter opdragreëlopsies of die teikenskrip verwerk, voer dit `LUA_INIT_<major>_<minor>` uit, of, indien die weergaweveranderlike ontbreek, `LUA_INIT`. ’n Waarde wat met `@` begin, verwys na ’n lêer; enige ander waarde word direk as Lua-kode geëvalueer. Dit bied dus beide lêergebaseerde en lêerlose uitvoering tydens opstart.<sup>[[1]](#references)</sup>
```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```
Die presiese weergawe-spesifieke naam verander volgens die interpreter, byvoorbeeld `LUA_INIT_5_4`. `lua -E` ignoreer alle omgewingsveranderlikes, insluitend opstartkode en Lua-modulepaaie.

## References

- [1] [Lua 5.4 standalone interpreter](https://www.lua.org/manual/5.4/manual.html#7)
{{#include ../../../banners/hacktricks-training.md}}
