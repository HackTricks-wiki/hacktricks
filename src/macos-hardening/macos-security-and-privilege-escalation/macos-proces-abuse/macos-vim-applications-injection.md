# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Vim-ov sopstveni skriptni jezik (Vimscript) može da pokrene **proizvoljne Ex komande i shell komande pri pokretanju** iz promenljivih okruženja. Ako privilegovaniji proces (tok održavanja/root, `sudo vim …`, editor koji pokreće drugi alat, `crontab -e`, `visudo`, `git`/`less` koji pozivaju editor, …) pokrene Vim/Neovim sa okruženjem na koje napadač može da utiče, napadač dobija izvršavanje koda u tom kontekstu.

## `VIMINIT`

Tokom inicijalizacije Vim čita i izvršava Ex komande iz **`VIMINIT`**. Ex komande obuhvataju `:!cmd` (pokretanje shell komande) i `:call system(...)`, tako da jedna promenljiva omogućava proizvoljno izvršavanje pre nego što se izmeni bilo koja datoteka.<sup>[[1]](#references)</sup>

```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```

`:qa!` prosleđen preko stdin-a u prvom primeru samo zatvara editor nakon izvršavanja payload-a; u stvarnom scenariju žrtva može normalno da otvori Vim.

`VIMINIT` se parsira kao **jedna Ex komandna linija**. Niz komandi razdvojite znakom `|` (ili doslovnim novim redom). Ima prednost nad korisnikovim vimrc-om i `EXINIT`-om, pa payload-u nije potrebna zlonamerna konfiguraciona datoteka i izvršava se pre uobičajene korisničke konfiguracije.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Ako `VIMINIT` nije postavljen, Vim (i binarne datoteke kompatibilne sa `vi`/`ex`) koristi **`EXINIT`** kao rezervnu opciju, a ono se izvršava na isti način. To je klasična varijanta istog primitiva iz ere vi-ja.<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## Projektni rc sa Vim `exrc`

Ovo je alternativa za `VIMINIT` zasnovana na datoteci. Ako je žrtva u korisničkoj konfiguraciji omogućila `set exrc`, Vim učitava i `.vimrc` (zatim `_vimrc` ili `.exrc`) iz svog **radnog direktorijuma**, a ne samo iz direktorijuma datoteke koja se uređuje. Postavite projektni `.vimrc` i navedite žrtvu da pokrene Vim iz tog projekta. Na Unixu, Vim primenjuje ograničenja `secure` na lokalni rc čiji je vlasnik neko drugi, ali datoteka izdvojena iz arhive obično postaje vlasništvo žrtve i time se zaobilazi ta provera.<sup>[[1]](#references)</sup>

Ovaj izolovani marker prikazuje okidač pri pokretanju bez menjanja stvarne korisničke konfiguracije:<sup>[[1]](#references)</sup>

```bash
lab=$(mktemp -d)
mkdir -p "$lab/home" "$lab/project"
printf 'set exrc\n' > "$lab/home/.vimrc"
printf 'call writefile(["loaded"], "%s/hit")\n' "$lab" > "$lab/project/.vimrc"
(cd "$lab/project" && env -u VIMINIT -u EXINIT HOME="$lab/home" vim -c 'qa!' >/dev/null 2>&1)
test -e "$lab/hit" && echo 'project rc loaded'
rm -r "$lab"
```

Neovim se razlikuje: aktuelne verzije zahtevaju da se projektni `.nvim.lua`, `.nvimrc` ili `.exrc` označi kao pouzdan pre izvršavanja. Poverenje se vezuje za hash sadržaja datoteke, pa izmena već pouzdane datoteke zahteva novu odluku o poverenju. Napadač koji može samo da postavi datoteku u repozitorijum ne može da računa na tiho izvršavanje preko `exrc`; razlikujte ovaj pristup, koji zahteva eksplicitno uključivanje i poverenje, od Lua `require()` pristupa iz trenutnog direktorijuma opisanog ispod.<sup>[[4]](#references)[[5]](#references)</sup>

Za upisiv korisnički vimrc, umesto projektnog, pogledajte [macOS Vim startup configuration](../../macos-auto-start-locations.md#vim-startup-configuration).

## Onemogućavanje pokretanja i mogućnost eksploatacije

Ovaj primitiv zavisi od **uobičajenog pokretanja**. `vim -u NONE` / `nvim -u NONE` preskaču inicijalizaciju okruženja/korisnika (i dodatke), dok `-u <file>` koristi tu datoteku umesto njih. Vim `-es`/`-Es` i Neovim `-es`, `-Es` ili `-l` takođe preskaču ove korake inicijalizacije. Nemojte `--headless` smatrati bezbednim režimom: pri uobičajenom pokretanju Neovim u headless režimu i dalje obrađuje `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Zato proverite ceo lanac pokretanja: promenljiva mora da preživi wrapper, `sudo` pravila, izvršilac poslova i izbor editora, a završna komanda ne sme da forsira `-u NONE`/`NORC` ili batch režim. Pouzdan payload može da se završi komandom `|qall!`, što olakšava i testiranje wrappera koji ne obezbeđuju TTY.<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim: Lua module hijacking iz trenutnog direktorijuma

Zaseban Neovim injection primitiv utiče na verzije čiji `package.path`/`package.cpath` za Lua i dalje sadrži šablone za trenutni direktorijum, kao što su `./?.lua` ili `./?.so`. Samo pokretanje Neovim nije dovoljno: konfiguracija ili dodatak mora da pozove `require("name")`, a nijedan raniji loader ne sme da razreši to ime. Čest okidač je **provera opcionе zavisnosti**, kao što je `pcall(require, "optional_dep")`; postavljanjem `optional_dep.lua` u radni direktorijum pod kontrolom napadača izvršava se njen sadržaj bez uključivanja zasebne funkcije lokalne konfiguracije `'exrc'`. Osnovne `vim.*` module i module koji su već pronađeni na `'runtimepath'` uglavnom nije moguće zaseniti, zato popišite stvarne pozive `require()` za nedostajuće/opcione module umesto da nagađate njihova imena.<sup>[[3]](#references)</sup>

Sledeći primer reprodukuje loader primitiv pomoću bezopasnog markera:<sup>[[3]](#references)</sup>

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

Proverite pokrenuti build umesto da se oslanjate samo na niz verzije:<sup>[[3]](#references)</sup>

```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```

Upstream prati uklanjanje rezervnog učitavanja iz trenutnog direktorijuma tokom uobičajenog pokretanja editora, uz očuvanje ponašanja Lua skripti (`nvim -l`). Dok instalirana verzija još uvek podržava ovu mogućnost, postavite ovo na **početak** fajla `init.lua` (namerno uklanja predloške Lua/C modula sa relativnim putanjama iz trenutnog direktorijuma, zato nemojte da ga primenjujete u radnim tokovima koji ih zahtevaju):<sup>[[3]](#references)</sup>

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

- **Neovim** koristi i `VIMINIT` i rezervnu opciju `EXINIT`, ali njegova uobičajena korisnička konfiguracija je `init.vim` ili `init.lua`.<sup>[[2]](#references)</sup>
- Putanja preko promenljive okruženja ne zahteva upisiv fajl. Otimanje lokalnog rc fajla i modula iz trenutnog direktorijuma zasebni su mehanizmi zasnovani na fajlovima.<sup>[[1]](#references)[[3]](#references)</sup>
- Projektni lokalni rc fajlovi razlikuju se od modelines i rezervne opcije `require()` za trenutni direktorijum navedene iznad. Vim i Neovim ih proveravaju na različite načine; pogledajte prethodni postupak za projektni lokalni `exrc`.<sup>[[1]](#references)[[4]](#references)</sup>
- Promenljive za izbor editora određuju samo koji će se program pokrenuti; one ne garantuju da će `VIMINIT` stići do konačnog procesa. Proverite tačno okruženje i argumente na granici `exec` poziva Vima/Neovima.<sup>[[1]](#references)[[2]](#references)</sup>

## Ojačavanje bezbednosti

- Eksplicitno uklonite promenljive pre pokretanja editora sa privilegijama ili u automatizovanom okruženju: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` je važan kada pozivalac mora da zanemari sve izvore korisničkog pokretanja.<sup>[[1]](#references)[[2]](#references)</sup>
- Podesite `EDITOR`/`VISUAL` na pouzdane apsolutne putanje, izbegavajte pokretanje interaktivnih editora kao root sa nasleđenim korisničkim okruženjem i osigurajte da omotači ne mogu ponovo da postave `VIMINIT`/`EXINIT` nakon čišćenja.<sup>[[1]](#references)[[2]](#references)</sup>
- Za Neovim, ažurirajte na verziju koja uklanja Lua/C šablone za pretragu u trenutnom direktorijumu tokom režima editora ili ih uklonite pre učitavanja dodataka. Proverite kod dodataka zbog opcionalnih poziva `pcall(require, ...)` pri otvaranju nepouzdanih repozitorijuma.<sup>[[3]](#references)</sup>
- Tretirajte kontrolu nad okruženjem editora, radnim direktorijumom ili konfiguracijom pokretanja cilja kao potencijalni mehanizam za izvršavanje koda u bezbednosnom kontekstu editora.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim dokumentacija — `starting.txt` (inicijalizacija, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim dokumentacija — pokretanje i inicijalizacija](https://neovim.io/doc/user/starting/)
- [3] [Neovim issue #38966 — rezervna opcija za trenutni direktorijum u `require()`](https://github.com/neovim/neovim/issues/38966)
- [4] [Neovim opcije — projektni lokalni `exrc` i zahtev za poverenjem](https://neovim.io/doc/user/options/#%27exrc%27)
- [5] [Neovim uređivanje — pouzdani fajlovi i `:trust`](https://neovim.io/doc/user/editing/#trust)
{{#include ../../../banners/hacktricks-training.md}}
