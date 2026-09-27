# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Vim se eie scripting-taal (Vimscript) kan **arbitrêre Ex commands en shell commands tydens startup** vanaf environment variables uitvoer. As ’n meer bevoorregte proses (’n maintenance/root workflow, ’n `sudo vim …`, ’n editor wat deur ’n ander tool gestart word, `crontab -e`, `visudo`, `git`/`less` wat ’n editor aanroep, …) Vim/Neovim met ’n aanvaller-beïnvloede environment launch, kry die aanvaller code execution in daardie konteks.

## `VIMINIT`

Tydens initialization lees en voer Vim die Ex commands in **`VIMINIT`** uit. Ex commands sluit `:!cmd` in (voer ’n shell command uit) en `:call system(...)`, dus lewer ’n enkele variable arbitrêre execution voordat enige file edited word.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```
Die `:qa!` wat in die eerste voorbeeld via stdin gevoer word, sluit die editor eers nadat die payload uitgevoer is; in ’n werklike scenario kan die slagoffer Vim normaalweg oopmaak.

`VIMINIT` word as **een Ex command line** ontleed. Skei ’n ketting met `|` (of ’n letterlike newline). Dit het voorrang bo die gebruiker se vimrc en `EXINIT`, dus het ’n payload nie ’n kwaadwillige konfigurasielêer nodig nie en loop dit vóór die normale gebruikerskonfigurasie.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

As `VIMINIT` nie gestel is nie, val Vim (en die `vi`/`ex`-versoenbaarheidsbinaries) terug op **`EXINIT`**, wat op dieselfde manier uitgevoer word. Dit is die klassieke vi-era-variant van dieselfde primitive.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Onderdrukking van opstart en uitbuitbaarheid

Hierdie primitief is afhanklik van ’n **normale opstart**. `vim -u NONE` / `nvim -u NONE` slaan die omgewings-/gebruikersinitialisering (en plugins) oor, terwyl `-u <file>` daardie lêer in plaas daarvan gebruik. Vim `-es`/`-Es` en Neovim `-es`, `-Es` of `-l` slaan ook hierdie initialiseringstappe oor. Moenie `--headless` met ’n veilige modus verwar nie: ’n normale Neovim headless-opstart verwerk steeds `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Valideer gevolglik die volledige launch chain: die veranderlike moet die wrapper, `sudo`-beleid, job runner en editor-keuse oorleef, en die finale opdrag mag nie `-u NONE`/`NORC` of batch mode afdwing nie. ’n Betroubare payload kan homself met `|qall!` beëindig, wat dit ook makliker maak om wrappers te toets wat nie ’n TTY verskaf nie.<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim current-directory Lua module hijacking

’n Afsonderlike Neovim injection primitive beïnvloed builds waarvan Lua se `package.path`/`package.cpath` steeds current-directory templates soos `./?.lua` of `./?.so` bevat. Om Neovim alleen te begin, is onvoldoende: ’n config of plugin moet `require("name")` aanroep, en geen vroeëre loader mag daardie naam resolve nie. ’n Algemene sneller is ’n **optional dependency check** soos `pcall(require, "optional_dep")`; deur `optional_dep.lua` in ’n aanvaller-beheerde werkgids te plaas, word dit uitgevoer sonder om die afsonderlike `'exrc'` local-configuration feature te aktiveer. Core `vim.*`-modules en modules wat reeds op `'runtimepath'` gevind word, kan oor die algemeen nie geshadow word nie; enumereer dus werklike ontbrekende/opsionele `require()`-aanroepe eerder as om name te raai.<sup>[[3]](#references)</sup>

Die volgende reproduseer die loader primitive met ’n onskadelike merker:<sup>[[3]](#references)</sup>
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
Gaan die lopende build na in plaas daarvan om slegs op ’n weergawestring staat te maak:<sup>[[3]](#references)</sup>
```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```
Upstream volg die verwydering van die huidige-gids-terugval tydens normale redigeerder-opstart, terwyl Lua-script (`nvim -l`)-gedrag behou word. Totdat die geïnstalleerde bouweergawe dit nie meer blootstel nie, plaas dit aan die **begin** van `init.lua` (dit verwyder doelbewus relatiewe huidige-gids Lua/C-module-sjablone, dus moenie dit toepas op werkvloeie wat dit benodig nie):<sup>[[3]](#references)</sup>
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
## Aantekeninge en voorbehoude

- **Neovim** respekteer beide `VIMINIT` en die `EXINIT`-fallback, maar sy normale gebruiker-konfigurasie is `init.vim` of `init.lua`.<sup>[[2]](#references)</sup>
- Die environment-variable-pad benodig geen skryfbare lêer nie. Local rc en current-directory module hijacking is afsonderlike, lêergebaseerde primitives.<sup>[[1]](#references)[[3]](#references)</sup>
- Project-local configuration is 'n ander oppervlak as modelines. Wanneer Vim se `'exrc'` enabled is, loop 'n local vimrc/exrc wat aan 'n ander gebruiker behoort met `'secure'`-beperkings; wanneer 'n archive egter normaalweg uitgepak word, word die geplante lêer gewoonlik deur die victim besit en word hierdie ownership-gebaseerde beskerming omseil. Neovim soek ook na `.nvim.lua`, `.nvimrc`, of `.exrc` wanneer `'exrc'` enabled is—moenie hierdie opt-in-meganisme met die `require()` current-directory fallback hierbo verwar nie.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Editor-selection variables kies slegs watter program geloods word; hulle waarborg nie dat `VIMINIT` die finale proses bereik nie. Inspekteer die presiese environment en arguments by die Vim/Neovim exec boundary.<sup>[[1]](#references)[[2]](#references)</sup>

## Verharding

- Verwyder die variables uitdruklik voor privileged of automated editor launches: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` is belangrik wanneer die caller elke user startup source moet ignoreer.<sup>[[1]](#references)[[2]](#references)</sup>
- Stel `EDITOR`/`VISUAL` op trusted absolute paths, vermy die loop van interactive editors as root met 'n geërfde user environment, en verseker dat wrappers nie `VIMINIT`/`EXINIT` ná sanitization kan herstel nie.<sup>[[1]](#references)[[2]](#references)</sup>
- Vir Neovim, update na 'n build wat current-directory Lua/C search templates tydens editor mode verwyder, of strip hulle voordat plugins gelaai word. Ouditeur plugin code vir optional `pcall(require, ...)` calls wanneer untrusted repositories oopgemaak word.<sup>[[3]](#references)</sup>
- Behandel beheer oor 'n target se editor environment, working directory, of startup configuration as 'n potensiële code-execution primitive in die editor se security context.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim-dokumentasie — `starting.txt` (initialisering, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim-dokumentasie — startup en initialisering](https://neovim.io/doc/user/starting/)
- [3] [Neovim issue #38966 — current-directory fallback in `require()`](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}
