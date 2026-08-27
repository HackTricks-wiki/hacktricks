# Injection ya Applications za Lua kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

Kabla ya kuchakata chaguo za mstari wa amri au script inayolengwa, standalone Lua interpreter hutekeleza `LUA_INIT_<major>_<minor>` au, ikiwa variable yenye version haipo, `LUA_INIT`. Thamani inayoanza na `@` hutaja file; thamani nyingine yoyote hutathminiwa moja kwa moja kama code ya Lua. Hii hutoa utekelezaji wa kuanzia unaotegemea file na usiotegemea file.<sup>[[1]](#references)</sup>
```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```
Jina kamili lenye nambari ya toleo hubadilika kulingana na interpreter, kwa mfano `LUA_INIT_5_4`. `lua -E` hupuuza environment variables zote, ikiwemo code ya kuanzisha na njia za Lua modules.

## References

- [1] [Interpreter ya kujitegemea ya Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
{{#include ../../../banners/hacktricks-training.md}}
