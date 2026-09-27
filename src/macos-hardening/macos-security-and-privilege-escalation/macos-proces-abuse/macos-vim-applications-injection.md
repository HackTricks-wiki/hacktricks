# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Vim-ov sopstveni scripting jezik (Vimscript) može da pokrene **proizvoljne Ex commands i shell commands pri pokretanju** iz environment variables. Ako proces sa većim privilegijama (maintenance/root workflow, `sudo vim …`, editor koji pokreće drugi alat, `crontab -e`, `visudo`, `git`/`less` koji poziva editor, …) pokrene Vim/Neovim sa environment-om na koji napadač može da utiče, napadač dobija code execution u tom kontekstu.

## `VIMINIT`

Tokom inicijalizacije Vim čita i izvršava Ex commands u **`VIMINIT`**. Ex commands uključuju `:!cmd` (pokretanje shell command-a) i `:call system(...)`, tako da jedna promenljiva omogućava proizvoljno izvršavanje pre nego što se otvori bilo koji fajl.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```
`:qa!` prosleđen putem stdin-a u prvom primeru samo zatvara editor nakon izvršavanja payload-a; u stvarnom scenariju žrtva može normalno da otvori Vim.

`VIMINIT` se parsira kao **jedna Ex komandna linija**. Lanac se razdvaja pomoću `|` (ili doslovnim novim redom). Ima prednost nad korisničkim vimrc-om i `EXINIT`-om, tako da payload-u nije potreban malicious configuration file i izvršava se pre uobičajene korisničke konfiguracije.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Ako `VIMINIT` nije postavljen, Vim (kao i `vi`/`ex` compatibility binaries) prelazi na **`EXINIT`**, koji se izvršava na isti način. To je klasična vi-era varijanta istog primitive-a.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Potiskivanje pokretanja i exploitability

Ovaj primitive zavisi od **normalnog pokretanja**. `vim -u NONE` / `nvim -u NONE` preskaču inicijalizaciju okruženja/korisnika (i plugins), dok `-u <file>` umesto toga koristi tu datoteku. Vim `-es`/`-Es` i Neovim `-es`, `-Es` ili `-l` takođe preskaču ove korake inicijalizacije. Nemojte mešati `--headless` sa bezbednim režimom: normalno Neovim headless pokretanje i dalje obrađuje `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Zato proverite kompletan lanac pokretanja: promenljiva mora proći kroz wrapper, `sudo` politiku, job runner i izbor editora, a konačna komanda ne sme nametnuti `-u NONE`/`NORC` ili batch mode. Pouzdan payload može sam sebe završiti pomoću `|qall!`, što takođe olakšava testiranje wrappera koji ne obezbeđuju TTY.<sup>[[1]](#references)[[2]](#references)</sup>

## Otmica Lua modula iz trenutnog direktorijuma u Neovim-u

Zaseban Neovim injection primitive pogađa buildove čiji Lua `package.path`/`package.cpath` i dalje sadrže templejte trenutnog direktorijuma kao što su `./?.lua` ili `./?.so`. Samo pokretanje Neovim-a nije dovoljno: config ili plugin mora pozvati `require("name")`, a nijedan raniji loader ne sme razrešiti to ime. Čest trigger je provera **opcione dependency** kao što je `pcall(require, "optional_dep")`; postavljanjem `optional_dep.lua` u radni direktorijum pod kontrolom napadača izvršava se taj fajl bez omogućavanja zasebne funkcije lokalne konfiguracije `'exrc'`. Osnovni `vim.*` moduli i moduli koji su već pronađeni na `'runtimepath'` uglavnom ne mogu da se shadow-uju, zato enumerišite stvarne nedostajuće/opcione `require()` pozive umesto nagađanja imena.<sup>[[3]](#references)</sup>

Sledeće reprodukuje loader primitive pomoću bezopasnog markera:<sup>[[3]](#references)</sup>
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
Proverite pokrenuti build umesto da se oslanjate samo na string verzije:<sup>[[3]](#references)</sup>
```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```
Upstream prati uklanjanje rezervne opcije za trenutni direktorijum tokom uobičajenog pokretanja editora, uz zadržavanje ponašanja Lua skripti (`nvim -l`). Dok instalirana verzija više ne bude izlagala ovu opciju, postavite sledeće na **početak** fajla `init.lua` (namerno uklanja relativne predloške Lua/C modula iz trenutnog direktorijuma, zato ga nemojte primenjivati u workflow-ovima koji ih zahtevaju):<sup>[[3]](#references)</sup>
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
## Napomene i ograničenja

- **Neovim** poštuje i `VIMINIT` i rezervni `EXINIT`, ali njegova uobičajena korisnička konfiguracija je `init.vim` ili `init.lua`.<sup>[[2]](#references)</sup>
- Putanja promenljive okruženja ne zahteva fajl sa dozvolom upisivanja. Lokalni rc i hijacking modula iz trenutnog direktorijuma su odvojeni primitivni mehanizmi zasnovani na fajlovima.<sup>[[1]](#references)[[3]](#references)</sup>
- Konfiguracija specifična za projekat predstavlja drugačiju površinu napada od modelina. Kada je Vim-ov `'exrc'` omogućen, lokalni vimrc/exrc u vlasništvu drugog korisnika izvršava se uz ograničenja `'secure'`; međutim, raspakivanje arhive obično postavlja zasađeni fajl u vlasništvo žrtve i zaobilazi ovu zaštitu zasnovanu na vlasništvu. Neovim takođe pretražuje `.nvim.lua`, `.nvimrc` ili `.exrc` kada je `'exrc'` omogućen — ne mešajte ovaj mehanizam koji zahteva eksplicitno uključivanje sa prethodno navedenim `require()` rezervnim mehanizmom za trenutni direktorijum.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Promenljive za izbor editora samo određuju koji će program biti pokrenut; one ne garantuju da će `VIMINIT` stići do krajnjeg procesa. Proverite tačno okruženje i argumente na granici izvršavanja Vim/Neovim procesa.<sup>[[1]](#references)[[2]](#references)</sup>

## Ojačavanje

- Eksplicitno uklonite promenljive pre pokretanja editora sa privilegijama ili automatizovanog pokretanja editora: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` je važno kada pozivalac mora da ignoriše svaki korisnički izvor pri pokretanju.<sup>[[1]](#references)[[2]](#references)</sup>
- Postavite `EDITOR`/`VISUAL` na pouzdane apsolutne putanje, izbegavajte pokretanje interaktivnih editora kao root sa nasleđenim korisničkim okruženjem i obezbedite da wrapper-i ne mogu da vrate `VIMINIT`/`EXINIT` nakon sanitizacije.<sup>[[1]](#references)[[2]](#references)</sup>
- Za Neovim ažurirajte na build koji uklanja Lua/C search templates iz trenutnog direktorijuma tokom režima editora ili ih uklonite pre učitavanja plugin-ova. Proverite kod plugin-ova da li sadrži opcione pozive `pcall(require, ...)` prilikom otvaranja nepouzdanih repozitorijuma.<sup>[[3]](#references)</sup>
- Kontrolu nad okruženjem editora, radnim direktorijumom ili konfiguracijom pri pokretanju cilja tretirajte kao potencijalni primitiv za izvršavanje koda u bezbednosnom kontekstu editora.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim dokumentacija — `starting.txt` (inicijalizacija, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim dokumentacija — pokretanje i inicijalizacija](https://neovim.io/doc/user/starting/)
- [3] [Neovim issue #38966 — rezervni mehanizam trenutnog direktorijuma u `require()`](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}
