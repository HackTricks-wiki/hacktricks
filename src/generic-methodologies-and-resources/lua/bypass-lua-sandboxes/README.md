# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Esta página recopila técnicas prácticas para enumerar y escapar de "sandboxes" de Lua integrados en aplicaciones (especialmente game clients, plugins o scripting engines dentro de aplicaciones). Muchos engines exponen un entorno Lua restringido, pero dejan accesibles globals potentes que permiten la ejecución arbitraria de comandos o incluso la corrupción de memoria nativa cuando los bytecode loaders están expuestos.

Ideas clave:
- Trata la VM como un entorno desconocido: enumera _G y descubre qué primitives peligrosos son accesibles.
- Cuando stdout/print está bloqueado, abusa de cualquier canal de UI/IPC dentro de la VM como output sink para observar los resultados.
- Si io/os está expuesto, normalmente tienes ejecución directa de comandos (io.popen, os.execute).
- Si load/loadstring/loadfile están expuestos, ejecutar Lua bytecode preparado puede subvertir la memory safety en algunas versiones (los verifiers de ≤5.1 se pueden evadir; 5.2 eliminó el verifier), lo que permite advanced exploitation.

## Enumerar el entorno sandboxed

- Vuelca el entorno global para inventariar las tablas/funciones accesibles:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Si no hay print() disponible, reutiliza canales dentro de la VM. Ejemplo de una VM de script de housing de un MMO, donde la salida del chat solo funciona después de una llamada de sonido; lo siguiente crea una función de salida fiable:<sup>[[1]](#references)</sup>
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
Generaliza este patrón para tu objetivo: cualquier textbox, toast, logger o callback de UI que acepte strings puede actuar como stdout para reconnaissance.

## Ejecución directa de comandos si io/os está expuesto

Si el sandbox todavía expone las librerías estándar io u os, probablemente tengas ejecución inmediata de comandos:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notas:

- La ejecución ocurre dentro del proceso del cliente; muchas capas anti-cheat/antidebug que bloquean depuradores externos no impedirán la creación de procesos in-VM.
- Comprueba también: package.loadlib (carga arbitraria de DLL/.so), require con módulos nativos, ffi de LuaJIT (si está presente) y la debug library (puede elevar privilegios dentro de la VM).

## Triggers zero-click mediante auto-run callbacks

Si la aplicación host envía scripts a los clientes y la VM expone hooks auto-run (p. ej., OnInit/OnLoad/OnEnter), coloca ahí tu payload para lograr un drive-by compromise en cuanto se cargue el script:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Cualquier callback equivalente (OnLoad, OnEnter, etc.) generaliza esta técnica cuando los scripts se transmiten y ejecutan automáticamente en el cliente.

## Primitivas peligrosas que se deben buscar durante el recon

Durante la enumeración de _G, busca específicamente:
- io, os: io.popen, os.execute, E/S de archivos, acceso al entorno.
- load, loadstring, loadfile, dofile: ejecutan código fuente o bytecode; permiten cargar bytecode no confiable.
- package, package.loadlib, require: carga de librerías dinámicas y superficie de módulos.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo y hooks.
- Solo LuaJIT: ffi.cdef, ffi.load para llamar directamente a código nativo.

Ejemplos mínimos de uso (si son accesibles):
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
## Escalada opcional: abuso de cargadores de bytecode de Lua

Cuando load/loadstring/loadfile son accesibles, pero io/os están restringidos, la ejecución de bytecode de Lua diseñado específicamente puede permitir la divulgación y corrupción de memoria. Datos clave:
- Lua ≤ 5.1 incluía un verificador de bytecode con bypasses conocidos.<sup>[[4]](#references)</sup>
- Lua 5.2 eliminó por completo el verificador (la postura oficial: las aplicaciones simplemente deberían rechazar los chunks precompilados), ampliando la superficie de ataque si no se prohíbe la carga de bytecode.<sup>[[2]](#references)[[3]](#references)</sup>
- Los workflows suelen consistir en: filtrar punteros mediante output dentro de la VM, crear bytecode para generar confusiones de tipos (por ejemplo, alrededor de FORLOOP u otros opcodes) y después pivotar hacia lectura/escritura arbitraria o ejecución de código nativo.<sup>[[2]](#references)[[4]](#references)</sup>

Este camino es específico del engine y de la versión, y requiere RE. Consulta las referencias para obtener análisis detallados, primitivas de explotación y ejemplos de gadgets en games.

## Notas de detección y hardening (para defenders)

- Server side: rechazar o reescribir los scripts de usuario; permitir únicamente APIs seguras mediante allowlist; eliminar o vincular a valores vacíos io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: ejecutar Lua con un _ENV mínimo, prohibir la carga de bytecode, reintroducir un verificador estricto de bytecode o comprobaciones de firmas, y bloquear la creación de procesos desde el proceso del cliente.
- Telemetry: generar alertas cuando gameclient cree un proceso hijo poco después de la carga de un script; correlacionarlo con eventos de UI/chat/script.

## Referencias

- [1] [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
