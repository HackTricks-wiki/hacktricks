# Injection in macOS-Lua-Anwendungen

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

Bevor der eigenständige Lua-Interpreter Befehlszeilenoptionen oder das Ziels script verarbeitet, führt er `LUA_INIT_<major>_<minor>` aus oder, falls die versionierte Variable nicht vorhanden ist, `LUA_INIT`. Ein mit `@` beginnender Wert bezeichnet eine Datei; jeder andere Wert wird direkt als Lua-Code ausgewertet. Dies ermöglicht sowohl dateibasierte als auch dateilose Startup-Ausführung.<sup>[[1]](#references)</sup>
```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```
Der genaue versionsabhängige Name ändert sich je nach Interpreter, zum Beispiel `LUA_INIT_5_4`. `lua -E` ignoriert alle Umgebungsvariablen, einschließlich des Startcodes und der Lua-Modulpfade.

## References

- [1] [Eigenständiger Lua-5.4-Interpreter](https://www.lua.org/manual/5.4/manual.html#7)
{{#include ../../../banners/hacktricks-training.md}}
