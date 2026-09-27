# Udukuzi wa Applications za Vim/Neovim kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Lugha ya scripting ya Vim yenyewe (Vimscript) inaweza kuendesha **amri za Ex na amri za shell kiholela wakati wa kuanzisha** kupitia environment variables. Ikiwa mchakato wenye privileges zaidi (workflow ya maintenance/root, `sudo vim …`, editor iliyoanzishwa na tool nyingine, `crontab -e`, `visudo`, `git`/`less` inayoanzisha editor, …) utaanzisha Vim/Neovim ikiwa na environment iliyoathiriwa na attacker, attacker hupata code execution katika context hiyo.

## `VIMINIT`

Wakati wa initialization, Vim husoma na kuendesha amri za Ex zilizomo kwenye **`VIMINIT`**. Amri za Ex zinajumuisha `:!cmd` (kuendesha shell command) na `:call system(...)`, hivyo variable moja inaweza kutoa arbitrary execution kabla ya faili lolote kuhaririwa.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```
`:qa!` iliyowekwa kupitia stdin katika mfano wa kwanza hufunga tu editor baada ya payload kutekelezwa; katika hali halisi victim anaweza kufungua Vim kwa kawaida.

`VIMINIT` huchanganuliwa kama **mstari mmoja wa Ex command**. Tenganisha mfululizo wa commands kwa `|` (au newline halisi). Ina precedence juu ya vimrc ya mtumiaji na `EXINIT`, hivyo payload haihitaji faili ya configuration yenye madhara na hutekelezwa kabla ya configuration ya kawaida ya mtumiaji.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Ikiwa `VIMINIT` haijawekwa, Vim (pamoja na binaries za compatibility za `vi`/`ex`) hutumia **`EXINIT`** kama fallback, ambayo hutekelezwa kwa njia hiyo hiyo. Hii ni variant ya enzi za vi ya primitive hiyo hiyo.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Startup suppression and exploitability

This primitive inategemea **normal startup**. `vim -u NONE` / `nvim -u NONE` huruka uanzishaji wa environment/user (pamoja na plugins), huku `-u <file>` ikitumia file hiyo badala yake. Vim `-es`/`-Es` na Neovim `-es`, `-Es`, au `-l` pia huruka hatua hizi za uanzishaji. Usichukulie `--headless` kuwa safe mode: normal Neovim headless startup bado huchakata `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Kwa hivyo, thibitisha launch chain nzima: variable lazima ipite kwenye wrapper, `sudo` policy, job runner, na editor selection, na command ya mwisho isiweke kwa lazima `-u NONE`/`NORC` au batch mode. Payload inayotegemeka inaweza kujikomesha kwa `|qall!`, jambo ambalo pia hurahisisha testing ya wrappers zisizotoa TTY.<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim current-directory Lua module hijacking

Neovim injection primitive tofauti huathiri builds ambazo `package.path`/`package.cpath` za Lua bado zina current-directory templates kama `./?.lua` au `./?.so`. Kuanzisha Neovim pekee hakutoshi: config au plugin lazima iite `require("name")`, na hakuna loader wa awali anayepaswa kutatua jina hilo. Trigger ya kawaida ni **optional dependency check** kama `pcall(require, "optional_dep")`; kuweka `optional_dep.lua` katika working directory inayodhibitiwa na attacker kisha hui-execute bila kuwezesha feature tofauti ya local-configuration ya `'exrc'`. Core `vim.*` modules na modules ambazo tayari zinapatikana kwenye `'runtimepath'` kwa ujumla haziwezi kushadowiwa, kwa hivyo orodhesha calls halisi za `require()` ambazo hazipo au ni optional badala ya kubashiri majina.<sup>[[3]](#references)</sup>

Ifuatayo inazalisha tena loader primitive kwa marker isiyo na madhara:<sup>[[3]](#references)</sup>
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
Kagua build inayoendeshwa badala ya kutegemea tu string ya toleo:<sup>[[3]](#references)</sup>
```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```
Upstream inafuatilia kuondolewa kwa fallback ya current-directory wakati wa uanzishaji wa kawaida wa editor, huku ikihifadhi tabia ya Lua-script (`nvim -l`). Hadi build iliyosakinishwa isiiweke tena wazi, weka hii **mwanzoni mwa** `init.lua` (inaondoa kwa makusudi templates za Lua/C module za current-directory zilizo relative, kwa hivyo usiitumie kwenye workflows zinazozihitaji):<sup>[[3]](#references)</sup>
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
## Maelezo na tahadhari

- **Neovim** inaheshimu `VIMINIT` na fallback ya `EXINIT`, lakini configuration yake ya kawaida ya mtumiaji ni `init.vim` au `init.lua`.<sup>[[2]](#references)</sup>
- Njia ya environment variable haihitaji file inayoweza kuandikwa. Local rc na current-directory module hijacking ni primitives tofauti zinazotegemea files.<sup>[[1]](#references)[[3]](#references)</sup>
- Configuration ya project-local ni surface tofauti na modelines. `exrc` ya Vim ikiwa imewezeshwa, vimrc/exrc ya ndani inayomilikiwa na mtumiaji mwingine huendeshwa ikiwa na restrictions za `secure`; hata hivyo, kutoa archive kwa kawaida hufanya file iliyopandikizwa imilikiwe na victim na kubatilisha ulinzi huo unaotegemea ownership. Neovim pia hutafuta `.nvim.lua`, `.nvimrc`, au `.exrc` wakati `exrc` imewezeshwa—usichanganye mechanism hiyo ya opt-in na fallback ya `require()` ya current-directory iliyoelezwa hapo juu.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Editor-selection variables huchagua tu program itakayoanzishwa; hazihakikishi kuwa `VIMINIT` itafika kwenye process ya mwisho. Kagua environment na arguments halisi kwenye exec boundary ya Vim/Neovim.<sup>[[1]](#references)[[2]](#references)</sup>

## Uimarishaji

- Ondoa variables hizo waziwazi kabla ya editor launches zenye privileged au automated: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` ni muhimu wakati caller lazima apuuze kila user startup source.<sup>[[1]](#references)[[2]](#references)</sup>
- Weka `EDITOR`/`VISUAL` ziwe absolute paths zinazoaminika, epuka kuendesha interactive editors kama root ikiwa na user environment iliyorithiwa, na hakikisha wrappers haziwezi kurejesha `VIMINIT`/`EXINIT` baada ya sanitization.<sup>[[1]](#references)[[2]](#references)</sup>
- Kwa Neovim, update hadi build inayoondoa current-directory Lua/C search templates wakati wa editor mode, au ziondoe kabla ya kupakia plugins. Kagua plugin code kwa calls za hiari za `pcall(require, ...)` wakati wa kufungua repositories zisizoaminika.<sup>[[3]](#references)</sup>
- Chukulia udhibiti wa editor environment, working directory, au startup configuration ya target kama potential code-execution primitive ndani ya security context ya editor.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim documentation — `starting.txt` (initialization, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim documentation — startup and initialization](https://neovim.io/doc/user/starting/)
- [3] [Neovim issue #38966 — current-directory fallback in `require()`](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}
