# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Omówienie

Własny język skryptowy Vima (Vimscript) może uruchamiać **dowolne polecenia Ex i polecenia powłoki podczas uruchamiania** na podstawie zmiennych środowiskowych. Jeśli proces o wyższych uprawnieniach (workflow konserwacyjny/root, `sudo vim …`, edytor uruchamiany przez inne narzędzie, `crontab -e`, `visudo`, `git`/`less` wywołujące edytor itd.) uruchamia Vim/Neovim ze środowiskiem kontrolowanym przez atakującego, atakujący uzyskuje code execution w tym kontekście.

## `VIMINIT`

Podczas inicjalizacji Vim odczytuje i wykonuje polecenia Ex z **`VIMINIT`**. Polecenia Ex obejmują `:!cmd` (uruchomienie polecenia powłoki) oraz `:call system(...)`, więc pojedyncza zmienna zapewnia arbitrary execution przed edycją jakiegokolwiek pliku.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript (no external process, e.g. write a file)
printf ':qa!\n' | VIMINIT='call writefile(["x"],"/tmp/vim-vimscript")' vim /tmp/victim.txt
```
`:qa!` przekazane przez stdin po prostu zamyka edytor po tym, jak payload został już wykonany; w rzeczywistym scenariuszu ofiara po prostu normalnie otwiera Vim.

## `EXINIT`

Jeśli `VIMINIT` nie jest ustawiona, Vim (oraz binaria zgodności `vi`/`ex`) używa w zastępstwie **`EXINIT`**, które jest wykonywane w ten sam sposób. Jest to klasyczny wariant z ery vi tego samego primitive.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Uwagi i zastrzeżenia

- **Neovim** również respektuje `VIMINIT` (jest ono sprawdzane przed plikiem użytkownika `init.vim`/`init.lua`).
- Tryb Batch/Ex (`vim -es` / `vim -Es`) **nie** ładuje `VIMINIT`/`EXINIT`; zmienne są używane podczas zwykłego uruchamiania (interaktywnego), co jest typowym scenariuszem ofiary.
- Powiązane wektory oparte na plikach to funkcje `exrc`/`.nvimrc` „modeline”/local-rc dla poszczególnych katalogów oraz `-u <vimrc>`; opisana powyżej ścieżka wykorzystująca zmienne środowiskowe nie wymaga żadnego zapisywalnego pliku.

## Wzmacnianie zabezpieczeń

- Oczyść środowisko (usuń `VIMINIT`/`EXINIT`) przed uruchamianiem edytorów z uprzywilejowanych lub zautomatyzowanych kontekstów i preferuj opakowania `sudo -i`/`env -i`, które resetują środowisko.
- Ustaw `EDITOR`/`VISUAL` na zaufane ścieżki bezwzględne i unikaj uruchamiania edytorów jako root z odziedziczonym środowiskiem użytkownika.
- Traktuj kontrolę nad środowiskiem celu jako równoważną wykonywaniu kodu dla każdego uruchamianego przez niego Vim/Neovim.

## References

- [1] [Dokumentacja Vim — `starting.txt` (inicjalizacja, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
{{#include ../../../banners/hacktricks-training.md}}
