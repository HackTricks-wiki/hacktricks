# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Ta strona zawiera praktyczne techniki enumeracji i escape z „sandboxów” Lua osadzonych w aplikacjach (zwłaszcza klientach gier, pluginach lub silnikach skryptowych w aplikacjach). Wiele silników udostępnia ograniczone środowisko Lua, ale pozostawia dostęp do potężnych globali, które umożliwiają wykonanie dowolnych poleceń, a nawet natywne uszkodzenie pamięci, gdy dostępne są loadery bytecode.

Najważniejsze idee:
- Traktuj VM jako nieznane środowisko: przeprowadź enumerację _G i sprawdź, do których niebezpiecznych prymitywów można uzyskać dostęp.
- Gdy stdout/print jest zablokowane, wykorzystaj dowolny kanał UI/IPC w VM jako sink wyjścia, aby obserwować wyniki.
- Jeśli io/os jest dostępne, często otrzymujesz bezpośrednie wykonanie poleceń (io.popen, os.execute).
- Jeśli load/loadstring/loadfile są dostępne, wykonywanie spreparowanego Lua bytecode może w niektórych wersjach naruszyć bezpieczeństwo pamięci (weryfikatory ≤5.1 można obejść; w 5.2 weryfikator usunięto), umożliwiając zaawansowany exploitation.

## Enumerate the sandboxed environment

- Zrzuć globalne środowisko, aby zinwentaryzować dostępne tabele/funkcje:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Jeśli print() nie jest dostępne, wykorzystaj ponownie kanały in-VM. Przykład z VM skryptu systemu mieszkań w MMO, gdzie wyjście czatu działa dopiero po wywołaniu dźwięku; poniższy kod tworzy niezawodną funkcję wyjścia:<sup>[[1]](#references)</sup>
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
Uogólnij ten wzorzec dla swojego celu: dowolne pole tekstowe, toast, logger lub callback UI, który akceptuje ciągi znaków, może służyć jako stdout do rekonesansu.

## Bezpośrednie wykonywanie poleceń, jeśli io/os są dostępne

Jeśli sandbox nadal udostępnia standardowe biblioteki io lub os, prawdopodobnie masz natychmiastową możliwość wykonywania poleceń:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notatki:

- Wykonanie odbywa się wewnątrz procesu klienta; wiele warstw anti-cheat/antidebug, które blokują zewnętrzne debugery, nie zapobiegnie tworzeniu procesu w VM.
- Sprawdź również: package.loadlib (ładowanie dowolnych bibliotek DLL/.so), require z native modules, ffi LuaJIT (jeśli jest dostępne) oraz bibliotekę debug (może podnosić uprawnienia wewnątrz VM).

## Zero-click triggers przez auto-run callbacks

Jeśli aplikacja hosta wysyła skrypty do klientów, a VM udostępnia auto-run hooks (np. OnInit/OnLoad/OnEnter), umieść tam swój payload, aby przeprowadzić drive-by compromise natychmiast po załadowaniu skryptu:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Każdy równoważny callback (OnLoad, OnEnter itd.) uogólnia tę technikę, gdy skrypty są automatycznie przesyłane i wykonywane po stronie klienta.

## Niebezpieczne prymitywy do wyszukania podczas recon

Podczas wyliczania elementów `_G` zwróć szczególną uwagę na:
- io, os: io.popen, os.execute, file I/O, dostęp do env.
- load, loadstring, loadfile, dofile: wykonywanie source lub bytecode; obsługa ładowania niezaufanego bytecode.
- package, package.loadlib, require: dynamiczne ładowanie bibliotek i powierzchnia modułów.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo oraz hooks.
- Tylko LuaJIT: ffi.cdef, ffi.load do bezpośredniego wywoływania native code.

Minimalne przykłady użycia (jeśli są dostępne):

API loadera Lua zmieniało się między wersjami: w Lua 5.1 `load` odczytuje dane z funkcji reader, a `loadstring` odczytuje je z stringa; `load` w Lua 5.2 przyjmuje zarówno string, jak i funkcję reader, a `loadstring` jest przestarzałym odpowiednikiem.<sup>[[5]](#references)[[6]](#references)</sup>
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
## Opcjonalna eskalacja: wykorzystywanie loaderów Lua bytecode

Gdy load/loadstring/loadfile są dostępne, ale io/os są ograniczone, wykonanie spreparowanego Lua bytecode może prowadzić do ujawnienia pamięci i uzyskania prymitywów jej modyfikacji. Najważniejsze fakty:
- Lua ≤ 5.1 zawierała bytecode verifier, który ma znane obejścia.<sup>[[4]](#references)</sup>
- Lua 5.2 całkowicie usunęła verifier (oficjalne stanowisko: aplikacje powinny po prostu odrzucać precompiled chunks), co poszerza attack surface, jeśli ładowanie bytecode nie jest zablokowane.<sup>[[2]](#references)[[3]](#references)</sup>
- Typowy przebieg obejmuje: wyciek pointerów za pośrednictwem danych wyjściowych w VM, spreparowanie bytecode w celu wywołania type confusion (np. wokół FORLOOP lub innych opcode'ów), a następnie przejście do arbitrary read/write lub native code execution.<sup>[[2]](#references)[[4]](#references)</sup>

Ta ścieżka zależy od engine/version i wymaga RE. Zobacz referencje, aby zapoznać się z dogłębnymi analizami, exploitation primitives oraz przykładami gadgetów w grach.

## Uwagi dotyczące wykrywania i hardeningu (dla defenderów)

- Po stronie serwera: odrzucaj lub przepisuj user scripts; stosuj allowlistę bezpiecznych API; usuwaj io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi albo wiąż je z pustymi wartościami.
- Po stronie klienta: uruchamiaj Lua z minimalnym _ENV, zabroń ładowania bytecode, ponownie wprowadź ścisły bytecode verifier lub signature checks i zablokuj tworzenie procesów z procesu klienta.
- Telemetria: generuj alerty dotyczące tworzenia child process przez gameclient wkrótce po załadowaniu scriptu; koreluj je ze zdarzeniami UI/chat/script.

## References

- [1] [Ten dom jest nawiedzony: RCE sprzed dekady w kliencie AION (zawierającym Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Analiza bytecode: odkrywanie luk bezpieczeństwa Lua w Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Dyskusja na temat usunięcia bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist z obejściami verifiera/notatkami)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Dokumentacja referencyjna Lua 5.1](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Dokumentacja referencyjna Lua 5.2](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}
