# macOS Vim/Neovim-toepassingsinspuiting

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Vim se eie skripttaal (Vimscript) kan **willekeurige Ex-opdragte en shell-opdragte tydens opstart uitvoer** vanuit omgewingsveranderlikes. As ’n meer bevoorregte proses (’n onderhoud-/root-werkvloei, ’n `sudo vim …`, ’n editor wat deur ’n ander nutsprogram begin word, `crontab -e`, `visudo`, `git`/`less` wat ’n editor aanroep, …) Vim/Neovim met ’n aanvallerbeïnvloede omgewing begin, kry die aanvaller kode-uitvoering in daardie konteks.

## `VIMINIT`

Tydens initialisering lees Vim die Ex-opdragte in **`VIMINIT`** en voer dit uit. Ex-opdragte sluit `:!cmd` (voer ’n shell-opdrag uit) en `:call system(...)` in, dus kan ’n enkele veranderlike arbitrêre uitvoering veroorsaak voordat enige lêer geredigeer word.<sup>[[1]](#references)</sup>

```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```

Die `:qa!` wat in die eerste voorbeeld via stdin ingevoer word, maak die redigeerder eers toe nadat die payload uitgevoer is; in ’n werklike scenario kan die slagoffer Vim normaalweg oopmaak.

`VIMINIT` word as **een Ex-opdragreël** ontleed. Skei ’n ketting met `|` (of ’n letterlike reëlbreuk). Dit geniet voorkeur bo die gebruiker se vimrc en `EXINIT`, dus het ’n payload nie ’n kwaadwillige konfigurasielêer nodig nie en loop dit voordat die normale gebruikerskonfigurasie gelaai word.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

As `VIMINIT` nie gestel is nie, val Vim (en die `vi`/`ex`-versoenbaarheidsbinaries) terug op **`EXINIT`**, wat op dieselfde manier uitgevoer word. Dit is die klassieke vi-era-variant van dieselfde primitief.<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## Projekplaaslike rc met Vim `exrc`

Dit is ’n lêergebaseerde alternatief vir `VIMINIT`. As die slagoffer `set exrc` in sy gebruikerskonfigurasie geaktiveer het, laai Vim ook `.vimrc` (dan `_vimrc` of `.exrc`) uit sy **werkgids**, nie net uit die gids van die lêer wat geredigeer word nie. Plaas ’n projekplaaslike `.vimrc` en laat die slagoffer Vim vanuit daardie projek begin. Op Unix pas Vim `secure`-beperkings toe op ’n plaaslike rc-lêer wat aan iemand anders behoort, maar ’n argief wat die slagoffer uitpak, gee gewoonlik die geplante lêer die slagoffer se eienaarskap en omseil dié kontrole.<sup>[[1]](#references)</sup>

Hierdie geïsoleerde merker wys die opstartsneller sonder om die werklike gebruikerskonfigurasie te wysig:<sup>[[1]](#references)</sup>

```bash
lab=$(mktemp -d)
mkdir -p "$lab/home" "$lab/project"
printf 'set exrc\n' > "$lab/home/.vimrc"
printf 'call writefile(["loaded"], "%s/hit")\n' "$lab" > "$lab/project/.vimrc"
(cd "$lab/project" && env -u VIMINIT -u EXINIT HOME="$lab/home" vim -c 'qa!' >/dev/null 2>&1)
test -e "$lab/hit" && echo 'project rc loaded'
rm -r "$lab"
```

Neovim is anders: huidige builds vereis dat projek-plaaslike `.nvim.lua`, `.nvimrc` of `.exrc` vertrou word voordat dit uitgevoer word. Vertroue word aan die lêer se inhoudhash gekoppel, dus vereis die verandering van ’n reeds vertroude lêer nog ’n vertrouensbesluit. ’n Aanvaller wat slegs ’n lêer in ’n repository kan plaas, kan nie aanneem dat dit stilweg deur `exrc` uitgevoer word nie; onderskei hierdie opsionele, vertrouensbeheerde roete van die Lua `require()`-roete vir die huidige gids hieronder.<sup>[[4]](#references)[[5]](#references)</sup>

Vir ’n skryfbare **user** vimrc eerder as ’n projek-plaaslike een, sien [macOS Vim startup configuration](../../macos-auto-start-locations.md#vim-startup-configuration).

## Onderdrukking van opstart en uitbuitbaarheid

Hierdie primitief is afhanklik van ’n **normale opstart**. `vim -u NONE` / `nvim -u NONE` slaan die omgewings-/gebruikerinitialisering (en plugins) oor, terwyl `-u <file>` daardie lêer in plaas daarvan gebruik. Vim `-es`/`-Es` en Neovim `-es`, `-Es` of `-l` slaan ook hierdie initialiseringstappe oor. Moenie `--headless` met ’n veilige modus verwar nie: ’n normale Neovim headless-opstart verwerk steeds `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Valideer gevolglik die volledige lanseringsketting: die veranderlike moet die wrapper, `sudo`-beleid, job runner en redigeerderkeuse oorleef, en die finale opdrag moenie `-u NONE`/`NORC` of bondelmodus afdwing nie. ’n Betroubare payload kan homself met `|qall!` beëindig, wat dit ook makliker maak om wrappers te toets wat nie ’n TTY verskaf nie.<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim-huidigegids-Lua-modulekaping

’n Afsonderlike Neovim-inspuitingsprimitief raak builds waarvan die Lua `package.path`/`package.cpath` steeds huidigegids-sjablone soos `./?.lua` of `./?.so` bevat. Om Neovim bloot te begin, is nie genoeg nie: ’n konfigurasie of plugin moet `require("name")` aanroep, en geen vroeëre laaier mag daardie naam oplos nie. ’n Algemene sneller is ’n **kontrole vir ’n opsionele afhanklikheid**, soos `pcall(require, "optional_dep")`; deur `optional_dep.lua` in ’n aanvaller-beheerde werkgids te plaas, word dit dan uitgevoer sonder om die afsonderlike `'exrc'`-funksie vir plaaslike konfigurasie te aktiveer. Kern-`vim.*`-modules en modules wat reeds op `'runtimepath'` gevind word, kan gewoonlik nie oorskadu word nie; lys dus werklike ontbrekende/opsionele `require()`-aanroepe eerder as om name te raai.<sup>[[3]](#references)</sup>

Die volgende reproduseer die laaierprimitief met ’n onskadelike merker:<sup>[[3]](#references)</sup>

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

Kontroleer die weergawe van die lopende bou eerder as om net op ’n weergawestring staat te maak:<sup>[[3]](#references)</sup>

```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```

Upstream volg die verwydering van die terugval na die huidige gids tydens normale redigeerderopstart, terwyl Lua-skripgedrag (`nvim -l`) behoue bly. Totdat die geïnstalleerde bouweergawe dit nie meer blootstel nie, plaas dit aan die **begin** van `init.lua` (dit verwyder doelbewus relatiewe Lua/C-module-sjablone in die huidige gids, dus moet dit nie toegepas word op werkvloeie wat dit vereis nie):<sup>[[3]](#references)</sup>

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

## Notas en voorbehoude

- **Neovim** respekteer beide `VIMINIT` en die `EXINIT`-terugvalopsie, maar sy gewone gebruikerskonfigurasie is `init.vim` of `init.lua`.<sup>[[2]](#references)</sup>
- Die omgewingsveranderlike-pad benodig geen skryfbare lêer nie. Plaaslike rc- en huidige-gidsmodulekaping is afsonderlike, lêergebaseerde primitives.<sup>[[1]](#references)[[3]](#references)</sup>
- Projekplaaslike rc-lêers verskil van modelines en van die `require()`-terugvalopsie vir die huidige gids hier bo. Vim en Neovim hanteer hulle met verskillende kontroles; sien die projekplaaslike `exrc`-werkvloei hier bo.<sup>[[1]](#references)[[4]](#references)</sup>
- Redigeerderkeuse-veranderlikes bepaal slegs watter program geloods word; hulle waarborg nie dat `VIMINIT` die finale proses bereik nie. Inspekteer die presiese omgewing en argumente by die Vim/Neovim-exec-grens.<sup>[[1]](#references)[[2]](#references)</sup>

## Verharding

- Verwyder die veranderlikes uitdruklik voordat bevoorregte of geoutomatiseerde redigeerders geloods word: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` is belangrik wanneer die oproeper alle gebruiker-opstartbronne moet ignoreer.<sup>[[1]](#references)[[2]](#references)</sup>
- Stel `EDITOR`/`VISUAL` op vertroude absolute paaie, vermy die gebruik van interaktiewe redigeerders as root met ’n oorgeërfde gebruikersomgewing, en sorg dat wrappers nie `VIMINIT`/`EXINIT` ná sanitering kan herstel nie.<sup>[[1]](#references)[[2]](#references)</sup>
- Dateer Neovim op na ’n weergawe wat huidige-gids Lua/C-soeksjablone in redigeerdermodus verwyder, of stroop hulle voordat plugins gelaai word. Gaan pluginkode na vir opsionele `pcall(require, ...)`-aanroepe wanneer onvertroude repositories oopgemaak word.<sup>[[3]](#references)</sup>
- Behandel beheer oor ’n teiken se redigeerderomgewing, werkgids of opstartkonfigurasie as ’n moontlike kode-uitvoeringsprimitive in die redigeerder se sekuriteitskonteks.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim-dokumentasie — `starting.txt` (inisialisering, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim-dokumentasie — opstart en inisialisering](https://neovim.io/doc/user/starting/)
- [3] [Neovim-kwessie #38966 — terugvalopsie vir huidige gids in `require()`](https://github.com/neovim/neovim/issues/38966)
- [4] [Neovim-opsies — projekplaaslike `exrc` en vertrouensvereiste](https://neovim.io/doc/user/options/#%27exrc%27)
- [5] [Neovim-redigering — vertroude lêers en `:trust`](https://neovim.io/doc/user/editing/#trust)
{{#include ../../../banners/hacktricks-training.md}}
