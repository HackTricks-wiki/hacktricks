# macOS Lua Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

Antes de procesar las opciones de la línea de comandos o el script objetivo, el intérprete independiente de Lua ejecuta `LUA_INIT_<major>_<minor>` o, si la variable versionada no está definida, `LUA_INIT`. Un valor que comienza con `@` indica un archivo; cualquier otro valor se evalúa directamente como código Lua. Esto permite la ejecución de inicio tanto respaldada por archivos como fileless.<sup>[[1]](#references)</sup>
```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```
El nombre exacto con versión cambia según el intérprete, por ejemplo `LUA_INIT_5_4`. `lua -E` ignora todas las variables de entorno, incluido el código de inicio y las rutas de módulos de Lua.

## References

- [1] [Intérprete independiente de Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
{{#include ../../../banners/hacktricks-training.md}}
