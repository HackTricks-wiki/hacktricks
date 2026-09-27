# Injection aplikacji Vim/Neovim w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Własny język skryptowy Vima (Vimscript) może uruchamiać **dowolne polecenia Ex i polecenia powłoki podczas uruchamiania** na podstawie zmiennych środowiskowych. Jeśli proces z większymi uprawnieniami (workflow konserwacyjny/root, `sudo vim …`, edytor uruchamiany przez inne narzędzie, `crontab -e`, `visudo`, `git`/`less` wywołujący edytor itd.) uruchomi Vim/Neovim ze środowiskiem kontrolowanym przez atakującego, atakujący uzyska code execution w tym kontekście.

## `VIMINIT`

Podczas inicjalizacji Vim odczytuje i wykonuje polecenia Ex znajdujące się w **`VIMINIT`**. Polecenia Ex obejmują `:!cmd` (uruchomienie polecenia powłoki) oraz `:call system(...)`, więc pojedyncza zmienna zapewnia dowolne wykonanie poleceń, zanim jakikolwiek plik zostanie poddany edycji.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```
` :qa!` podane przez stdin w pierwszym przykładzie zamyka edytor dopiero po wykonaniu payloadu; w rzeczywistym scenariuszu ofiara może normalnie otworzyć Vim.

`VIMINIT` jest analizowane jako **pojedynczy wiersz poleceń Ex**. Łańcuch należy rozdzielać za pomocą `|` (lub dosłownego znaku nowej linii). Ma pierwszeństwo przed vimrc użytkownika i `EXINIT`, więc payload nie wymaga złośliwego pliku konfiguracyjnego i jest uruchamiany przed standardową konfiguracją użytkownika.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Jeśli `VIMINIT` nie jest ustawione, Vim (oraz binaria zgodności `vi`/`ex`) przechodzi do **`EXINIT`**, które jest wykonywane w ten sam sposób. Jest to klasyczny wariant z czasów vi tego samego prymitywu.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Ograniczenie uruchamiania i podatność na exploitację

Ten primitive zależy od **normalnego uruchomienia**. `vim -u NONE` / `nvim -u NONE` pomijają inicjalizację środowiska/użytkownika (oraz plugins), podczas gdy `-u <file>` używa zamiast tego wskazanego pliku. Vim `-es`/`-Es` oraz Neovim `-es`, `-Es` lub `-l` również pomijają te kroki inicjalizacji. Nie należy mylić `--headless` z safe mode: normalne uruchomienie Neovim w trybie headless nadal przetwarza `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

W związku z tym należy zweryfikować kompletny łańcuch uruchamiania: zmienna musi przetrwać wrapper, politykę `sudo`, job runner oraz wybór edytora, a końcowa komenda nie może wymuszać `-u NONE`/`NORC` ani batch mode. Niezawodny payload może zakończyć działanie za pomocą `|qall!`, co ułatwia również testowanie wrapperów, które nie udostępniają TTY.<sup>[[1]](#references)[[2]](#references)</sup>

## Hijacking modułu Lua z bieżącego katalogu w Neovim

Oddzielny primitive injection w Neovim dotyczy buildów, w których `package.path`/`package.cpath` Lua nadal zawierają templates bieżącego katalogu, takie jak `./?.lua` lub `./?.so`. Samo uruchomienie Neovim jest niewystarczające: konfiguracja lub plugin musi wywołać `require("name")`, a żaden wcześniejszy loader nie może rozwiązać tej nazwy. Częstym triggerem jest **optional dependency check**, taki jak `pcall(require, "optional_dep")`; umieszczenie `optional_dep.lua` w kontrolowanym przez atakującego katalogu roboczym powoduje następnie jego wykonanie bez włączania oddzielnej funkcji lokalnej konfiguracji `'exrc'`. Podstawowe moduły `vim.*` oraz moduły już znalezione w `'runtimepath'` zasadniczo nie mogą być shadowed, dlatego należy wyliczyć rzeczywiste brakujące/optional wywołania `require()`, zamiast zgadywać nazwy.<sup>[[3]](#references)</sup>

Poniższy przykład odtwarza loader primitive za pomocą nieszkodliwego markera:<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/nvim-cwd-hijack
cat > /tmp/nvim-cwd-hijack/optional_dep.lua <<'LUA'
vim.fn.writefile({"loaded"}, "/tmp/nvim-cwd-hit")
return {}
LUA

cd /tmp/nvim-cwd-hijack
nvim --clean --headless '+lua require("optional_dep")' +qa
cat /tmp/nvim-cwd-hit
```
Sprawdź działającą kompilację zamiast polegać wyłącznie na ciągu wersji:<sup>[[3]](#references)</sup>
```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```
Upstream śledzi usunięcie mechanizmu awaryjnego dla bieżącego katalogu podczas normalnego uruchamiania edytora, zachowując jednocześnie działanie skryptów Lua (`nvim -l`). Do czasu, aż zainstalowany build przestanie go udostępniać, umieść to na **początku** `init.lua` (celowo usuwa względne szablony modułów Lua/C z bieżącego katalogu, dlatego nie stosuj tego w workflow wymagających tych modułów):<sup>[[3]](#references)</sup>
```lua
local function drop_cwd(path)
local keep = {}
for entry in path:gmatch("[^;]+") do
if not entry:match("^%./") then keep[#keep + 1] = entry end
end
return table.concat(keep, ";")
end
package.path = drop_cwd(package.path)
package.cpath = drop_cwd(package.cpath)
```
## Uwagi i zastrzeżenia

- **Neovim** uwzględnia zarówno `VIMINIT`, jak i fallback `EXINIT`, ale jego standardową konfiguracją użytkownika jest `init.vim` lub `init.lua`.<sup>[[2]](#references)</sup>
- Ścieżka zmiennej środowiskowej nie wymaga zapisywalnego pliku. Lokalne rc oraz przejęcie modułu z bieżącego katalogu to odrębne, oparte na plikach primitives.<sup>[[1]](#references)[[3]](#references)</sup>
- Konfiguracja lokalna projektu jest inną powierzchnią ataku niż modelines. Przy włączonej opcji Vim `'exrc'` lokalny vimrc/exrc należący do innego użytkownika jest uruchamiany z ograniczeniami `'secure'`; jednak wypakowanie archiwum zwykle powoduje, że podstawiony plik należy do ofiary, omijając tę ochronę opartą na własności. Neovim również wyszukuje `.nvim.lua`, `.nvimrc` lub `.exrc`, gdy włączona jest opcja `'exrc'` — nie należy mylić tego mechanizmu opt-in z opisanym wyżej fallbackiem `require()` dla bieżącego katalogu.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Zmienne wyboru edytora określają tylko, jaki program zostanie uruchomiony; nie gwarantują, że `VIMINIT` dotrze do końcowego procesu. Należy sprawdzić dokładne środowisko i argumenty na granicy exec Vim/Neovim.<sup>[[1]](#references)[[2]](#references)</sup>

## Wzmacnianie zabezpieczeń

- Jawnie usuń zmienne przed uruchomieniem uprzywilejowanego lub zautomatyzowanego edytora: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` jest istotne, gdy wywołujący musi zignorować wszystkie źródła konfiguracji startowej użytkownika.<sup>[[1]](#references)[[2]](#references)</sup>
- Ustaw `EDITOR`/`VISUAL` na zaufane ścieżki absolutne, unikaj uruchamiania interaktywnych edytorów jako root z odziedziczonym środowiskiem użytkownika oraz upewnij się, że wrappery nie mogą przywrócić `VIMINIT`/`EXINIT` po sanitizacji.<sup>[[1]](#references)[[2]](#references)</sup>
- W przypadku Neovim zaktualizuj go do builda, który usuwa szablony wyszukiwania Lua/C z bieżącego katalogu podczas pracy edytora, albo usuń je przed ładowaniem pluginów. Podczas otwierania niezaufanych repozytoriów przeprowadź audit kodu pluginów pod kątem opcjonalnych wywołań `pcall(require, ...)`.<sup>[[3]](#references)</sup>
- Traktuj kontrolę nad środowiskiem edytora, katalogiem roboczym lub konfiguracją startową celu jako potencjalny primitive umożliwiający code execution w kontekście bezpieczeństwa edytora.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Dokumentacja Vim — `starting.txt` (inicjalizacja, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Dokumentacja Neovim — uruchamianie i inicjalizacja](https://neovim.io/doc/user/starting/)
- [3] [Problem Neovim #38966 — fallback bieżącego katalogu w `require()`](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}
