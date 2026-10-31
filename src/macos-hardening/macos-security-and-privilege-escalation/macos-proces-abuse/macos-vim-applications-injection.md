# Wstrzykiwanie do aplikacji macOS Vim/Neovim

{{#include ../../../banners/hacktricks-training.md}}

## Omówienie

Własny język skryptowy Vima (Vimscript) może uruchamiać **dowolne polecenia Ex i polecenia powłoki podczas startu** na podstawie zmiennych środowiskowych. Jeśli proces z wyższymi uprawnieniami (procedura konserwacji lub workflow roota, `sudo vim …`, edytor uruchomiony przez inne narzędzie, `crontab -e`, `visudo`, `git`/`less` wywołujące edytor, …) uruchamia Vim/Neovim ze środowiskiem, na które wpływa atakujący, atakujący może wykonać kod w tym kontekście.

## `VIMINIT`

Podczas inicjalizacji Vim odczytuje i wykonuje polecenia Ex z **`VIMINIT`**. Polecenia Ex obejmują `:!cmd` (uruchomienie polecenia powłoki) oraz `:call system(...)`, więc pojedyncza zmienna umożliwia dowolne wykonanie kodu, zanim zostanie edytowany jakikolwiek plik.<sup>[[1]](#references)</sup>

```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```

`:qa!` przekazane przez stdin w pierwszym przykładzie zamyka edytor dopiero po uruchomieniu payloadu; w rzeczywistej sytuacji ofiara może normalnie otworzyć Vim.

`VIMINIT` jest parsowane jako **jeden wiersz poleceń Ex**. Łańcuch poleceń należy rozdzielić za pomocą `|` (lub dosłownego znaku nowej linii). Ma pierwszeństwo przed vimrc użytkownika i `EXINIT`, więc payload nie wymaga złośliwego pliku konfiguracyjnego i uruchamia się przed normalną konfiguracją użytkownika.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Jeśli `VIMINIT` nie jest ustawione, Vim (oraz pliki binarne zgodności `vi`/`ex`) używa **`EXINIT`**, które jest wykonywane w ten sam sposób. To klasyczny wariant tego samego prymitywu z czasów vi.<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## Lokalny dla projektu rc z Vim `exrc`

To alternatywa dla `VIMINIT` oparta na pliku. Jeśli poszkodowany włączył `set exrc` w konfiguracji użytkownika, Vim wczytuje również `.vimrc` (a następnie `_vimrc` lub `.exrc`) z **katalogu roboczego**, a nie tylko z katalogu edytowanego pliku. Umieść lokalny dla projektu plik `.vimrc` i spraw, by poszkodowany uruchomił Vim z tego projektu. W systemie Unix Vim nakłada ograniczenia `secure` na lokalny rc należący do innego użytkownika, ale archiwum rozpakowane przez poszkodowanego zwykle przypisuje umieszczonemu w nim plikowi własność poszkodowanego i pozwala uniknąć tej kontroli.<sup>[[1]](#references)</sup>

Ten odizolowany znacznik pokazuje wyzwalacz przy uruchamianiu bez modyfikowania rzeczywistej konfiguracji użytkownika:<sup>[[1]](#references)</sup>

```bash
lab=$(mktemp -d)
mkdir -p "$lab/home" "$lab/project"
printf 'set exrc\n' > "$lab/home/.vimrc"
printf 'call writefile(["loaded"], "%s/hit")\n' "$lab" > "$lab/project/.vimrc"
(cd "$lab/project" && env -u VIMINIT -u EXINIT HOME="$lab/home" vim -c 'qa!' >/dev/null 2>&1)
test -e "$lab/hit" && echo 'project rc loaded'
rm -r "$lab"
```

Neovim działa inaczej: obecne kompilacje wymagają, aby przed wykonaniem zaufać projektowemu plikowi `.nvim.lua`, `.nvimrc` lub `.exrc`. Zaufanie jest powiązane z hashem zawartości pliku, więc zmiana już zaufanego pliku wymaga ponownej decyzji o zaufaniu. Atakujący, który może jedynie umieścić plik w repozytorium, nie może zakładać cichego wykonania przez `exrc`; należy odróżnić tę wymagającą zgody i zaufania ścieżkę od opisanej niżej ścieżki Lua `require()` z bieżącego katalogu.<sup>[[4]](#references)[[5]](#references)</sup>

Informacje o zapisywalnym pliku vimrc **użytkownika**, a nie projektowym, znajdziesz w sekcji [Konfiguracja startowa macOS Vim](../../macos-auto-start-locations.md#vim-startup-configuration).

## Pominięcie inicjalizacji i możliwość wykorzystania

Ten prymityw wymaga **normalnego uruchomienia**. `vim -u NONE` / `nvim -u NONE` pomijają inicjalizację środowiska/użytkownika (oraz wtyczki), natomiast `-u <file>` używa wskazanego pliku. Vim `-es`/`-Es` oraz Neovim `-es`, `-Es` lub `-l` również pomijają te kroki inicjalizacji. Nie uznawaj `--headless` za bezpieczny tryb: normalne uruchomienie Neovim w trybie headless nadal przetwarza `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Dlatego zweryfikuj cały łańcuch uruchamiania: zmienna musi przetrwać działanie wrappera, politykę `sudo`, runnera zadań i wybór edytora, a końcowe polecenie nie może wymuszać `-u NONE`/`NORC` ani trybu wsadowego. Niezawodny payload może zakończyć działanie poleceniem `|qall!`, co ułatwia również testowanie wrapperów, które nie udostępniają TTY.<sup>[[1]](#references)[[2]](#references)</sup>

## Przechwytywanie modułów Lua z bieżącego katalogu w Neovim

Osobny prymityw wstrzykiwania Neovim dotyczy kompilacji, w których `package.path`/`package.cpath` Lua nadal zawierają szablony bieżącego katalogu, takie jak `./?.lua` lub `./?.so`. Samo uruchomienie Neovim nie wystarczy: konfiguracja lub wtyczka musi wywołać `require("name")`, a wcześniejszy loader nie może znaleźć tego modułu. Częstym wyzwalaczem jest **sprawdzenie opcjonalnej zależności**, takie jak `pcall(require, "optional_dep")`; umieszczenie pliku `optional_dep.lua` w katalogu roboczym kontrolowanym przez atakującego powoduje wtedy jego wykonanie bez włączania osobnej funkcji lokalnej konfiguracji `'exrc'`. Podstawowych modułów `vim.*` ani modułów znalezionych już w `'runtimepath'` zazwyczaj nie da się przesłonić, dlatego należy wyliczyć rzeczywiste wywołania `require()` dla brakujących/opcjonalnych modułów, zamiast zgadywać ich nazwy.<sup>[[3]](#references)</sup>

Poniższy przykład odtwarza działanie tego loadera, używając nieszkodliwego znacznika:<sup>[[3]](#references)</sup>

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

Sprawdź działającą kompilację, zamiast polegać wyłącznie na ciągu znaków wersji:<sup>[[3]](#references)</sup>

```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```

Upstream śledzi usuwanie mechanizmu awaryjnego korzystającego z bieżącego katalogu podczas zwykłego uruchamiania edytora, zachowując działanie skryptów Lua (`nvim -l`). Dopóki zainstalowana kompilacja nadal go udostępnia, umieść to na **początku** `init.lua` (celowo usuwa względne szablony modułów Lua/C z bieżącego katalogu, więc nie stosuj tego w przepływach pracy, które ich wymagają):<sup>[[3]](#references)</sup>

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

- **Neovim** obsługuje zarówno `VIMINIT`, jak i zmienną zapasową `EXINIT`, ale jego standardowym plikiem konfiguracyjnym użytkownika jest `init.vim` lub `init.lua`.<sup>[[2]](#references)</sup>
- Ścieżka wykorzystująca zmienną środowiskową nie wymaga zapisywalnego pliku. Przejęcie lokalnego pliku rc i modułu z bieżącego katalogu to osobne mechanizmy oparte na plikach.<sup>[[1]](#references)[[3]](#references)</sup>
- Pliki rc specyficzne dla projektu różnią się od modelines i opisanego wyżej mechanizmu zapasowego `require()` dla bieżącego katalogu. Vim i Neovim sprawdzają je w różny sposób; zobacz opisany wyżej przepływ pracy z projektowym `exrc`.<sup>[[1]](#references)[[4]](#references)</sup>
- Zmienne wyboru edytora określają tylko, jaki program zostanie uruchomiony; nie gwarantują, że `VIMINIT` dotrze do końcowego procesu. Sprawdź dokładne zmienne środowiskowe i argumenty na granicy wywołania exec Vim/Neovim.<sup>[[1]](#references)[[2]](#references)</sup>

## Zabezpieczenia

- Jawnie usuń te zmienne przed uruchomieniem edytora z podwyższonymi uprawnieniami lub w trybie automatycznym: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` jest ważne, gdy wywołujący musi pominąć wszystkie źródła konfiguracji startowej użytkownika.<sup>[[1]](#references)[[2]](#references)</sup>
- Ustaw `EDITOR`/`VISUAL` na zaufane ścieżki bezwzględne, unikaj uruchamiania interaktywnych edytorów jako root z odziedziczonym środowiskiem użytkownika i dopilnuj, by wrappery nie mogły przywrócić `VIMINIT`/`EXINIT` po oczyszczeniu środowiska.<sup>[[1]](#references)[[2]](#references)</sup>
- W przypadku Neovim zaktualizuj wersję do takiej, która usuwa szablony wyszukiwania Lua/C z bieżącego katalogu w trybie edytora, albo usuń je przed załadowaniem pluginów. Podczas otwierania niezaufanych repozytoriów sprawdź kod pluginów pod kątem opcjonalnych wywołań `pcall(require, ...)`.<sup>[[3]](#references)</sup>
- Traktuj możliwość kontrolowania środowiska edytora, katalogu roboczego lub konfiguracji startowej celu jako potencjalny mechanizm wykonania kodu w kontekście bezpieczeństwa edytora.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Dokumentacja Vim — `starting.txt` (inicjalizacja, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Dokumentacja Neovim — uruchamianie i inicjalizacja](https://neovim.io/doc/user/starting/)
- [3] [Zgłoszenie Neovim nr 38966 — mechanizm zapasowy `require()` dla bieżącego katalogu](https://github.com/neovim/neovim/issues/38966)
- [4] [Opcje Neovim — projektowy `exrc` i wymóg zaufania](https://neovim.io/doc/user/options/#%27exrc%27)
- [5] [Edycja w Neovim — zaufane pliki i `:trust`](https://neovim.io/doc/user/editing/#trust)
{{#include ../../../banners/hacktricks-training.md}}
