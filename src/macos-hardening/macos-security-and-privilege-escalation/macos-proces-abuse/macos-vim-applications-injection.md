# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Lugha ya Vim ya scripting (Vimscript) inaweza kuendesha **Ex commands na shell commands kiholela wakati wa kuwasha** kupitia environment variables. Ikiwa mchakato wenye privileges zaidi (mtiririko wa matengenezo/root, `sudo vim …`, editor inayoanzishwa na tool nyingine, `crontab -e`, `visudo`, `git`/`less` inayoanzisha editor, …) utaanzisha Vim/Neovim ikiwa na environment inayodhibitiwa na mshambuliaji, mshambuliaji anaweza kutekeleza code katika muktadha huo.

## `VIMINIT`

Wakati wa kuanzishwa, Vim husoma na kuendesha Ex commands zilizo katika **`VIMINIT`**. Ex commands zinajumuisha `:!cmd` (kuendesha shell command) na `:call system(...)`, kwa hiyo variable moja tu inaruhusu execution yoyote kabla faili lolote halijahaririwa.<sup>[[1]](#references)</sup>

```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```

`:qa!` iliyotumwa kupitia stdin katika mfano wa kwanza hufunga tu editor baada ya payload kutekelezwa; katika hali halisi, mwathiriwa anaweza kufungua Vim kawaida.

`VIMINIT` huchanganuliwa kama **mstari mmoja wa amri za Ex**. Tenganisha mfululizo wa amri kwa `|` (au newline halisi). Ina kipaumbele kuliko vimrc ya mtumiaji na `EXINIT`, kwa hivyo payload haihitaji faili hasidi ya usanidi na hutekelezwa kabla ya usanidi wa kawaida wa mtumiaji.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Ikiwa `VIMINIT` haijawekwa, Vim (na binaries za uoanifu za `vi`/`ex`) hutumia **`EXINIT`** badala yake, nayo hutekelezwa vivyo hivyo. Hii ndiyo toleo la zamani la enzi ya vi la primitive hiyo hiyo.<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## rc ya ndani ya project kwa kutumia Vim `exrc`

Hii ni njia mbadala inayotegemea faili kwa `VIMINIT`. Ikiwa mwathiriwa amewasha `set exrc` kwenye usanidi wake wa mtumiaji, Vim pia hupakia `.vimrc` (kisha `_vimrc` au `.exrc`) kutoka kwenye **working directory** yake, wala si kutoka tu kwenye directory ya faili inayohaririwa. Weka `.vimrc` ya ndani ya project na mwathiriwa aanzishe Vim akiwa ndani ya project hiyo. Kwenye Unix, Vim hutumia vizuizi vya `secure` kwa rc ya ndani inayomilikiwa na mtu mwingine, lakini kwa kawaida faili iliyowekwa ndani ya archive inayotolewa na mwathiriwa humilikiwa naye na huepusha ukaguzi huo.<sup>[[1]](#references)</sup>

Alama hii iliyotengwa huonyesha kichochezi cha uanzishaji bila kubadilisha usanidi halisi wa mtumiaji:<sup>[[1]](#references)</sup>

```bash
lab=$(mktemp -d)
mkdir -p "$lab/home" "$lab/project"
printf 'set exrc\n' > "$lab/home/.vimrc"
printf 'call writefile(["loaded"], "%s/hit")\n' "$lab" > "$lab/project/.vimrc"
(cd "$lab/project" && env -u VIMINIT -u EXINIT HOME="$lab/home" vim -c 'qa!' >/dev/null 2>&1)
test -e "$lab/hit" && echo 'project rc loaded'
rm -r "$lab"
```

Neovim ni tofauti: builds za sasa zinahitaji `.nvim.lua`, `.nvimrc`, au `.exrc` iliyo ndani ya project iaminike kabla ya kutekelezwa. Uaminifu huhusishwa na hash ya maudhui ya faili, kwa hivyo kubadilisha faili ambayo tayari imeaminiwa kunahitaji uamuzi mwingine wa kuamini. Mshambuliaji anayeweza tu kuweka faili kwenye repository hawezi kudhani kuwa faili itatekelezwa kimyakimya kupitia `exrc`; tofautisha njia hii ya hiari inayohitaji kuaminiwa na njia ya sasa ya `require()` ya Lua iliyo hapa chini.<sup>[[4]](#references)[[5]](#references)</sup>

Kwa vimrc ya **mtumiaji** inayoweza kuandikwa badala ya iliyo ndani ya project, angalia [macOS Vim startup configuration](../../macos-auto-start-locations.md#vim-startup-configuration).

## Kuzuia startup na uwezekano wa exploit

Primitive hii hutegemea **startup ya kawaida**. `vim -u NONE` / `nvim -u NONE` huruka uanzishaji wa mazingira/mtumiaji (na plugins), ilhali `-u <file>` hutumia faili hiyo badala yake. Vim `-es`/`-Es` na Neovim `-es`, `-Es`, au `-l` pia huruka hatua hizi za uanzishaji. Usichukulie `--headless` kuwa hali salama: startup ya kawaida ya Neovim headless bado huchakata `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Kwa hivyo, thibitisha mnyororo mzima wa uanzishaji: kigezo lazima kipite kwenye wrapper, sera ya `sudo`, job runner, na uteuzi wa editor, na amri ya mwisho haipaswi kulazimisha `-u NONE`/`NORC` au batch mode. Payload ya kuaminika inaweza kujizima kwa `|qall!`, jambo ambalo pia hurahisisha kupima wrappers zisizotoa TTY.<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim current-directory Lua module hijacking

Primitive tofauti ya injection katika Neovim huathiri builds ambazo `package.path`/`package.cpath` za Lua bado zina templates za current directory kama `./?.lua` au `./?.so`. Kuanzisha Neovim pekee hakutoshi: config au plugin lazima iite `require("name")`, na loader yoyote iliyotangulia isiweze kutatua jina hilo. Kichocheo cha kawaida ni ukaguzi wa dependency ya hiari kama `pcall(require, "optional_dep")`; kuweka `optional_dep.lua` kwenye working directory inayodhibitiwa na mshambuliaji kisha huiendesha bila kuwasha kipengele tofauti cha local configuration cha `'exrc'`. Modules za msingi za `vim.*` na modules ambazo tayari zimepatikana kwenye `'runtimepath'` kwa kawaida haziwezi kufunikwa, kwa hiyo orodhesha miito halisi ya `require()` ya modules zinazokosekana/za hiari badala ya kubahatisha majina.<sup>[[3]](#references)</sup>

Haya yafuatayo yanaonyesha upya primitive ya loader kwa kutumia marker isiyo na madhara:<sup>[[3]](#references)</sup>

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

Kagua build inayoendeshwa badala ya kutegemea tu mfuatano wa toleo:<sup>[[3]](#references)</sup>

```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```

Upstream inafuatilia kuondoa fallback ya current-directory wakati wa kuwasha editor kwa kawaida, huku ikihifadhi tabia ya Lua-script (`nvim -l`). Hadi build iliyosakinishwa isiionyeshe tena, weka hii **mwanzoni** mwa `init.lua` (inaondoa kwa makusudi violezo vya Lua/C module vinavyotumia current-directory relative, kwa hivyo usiitumie kwenye workflows zinazohitaji violezo hivyo):<sup>[[3]](#references)</sup>

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

- **Neovim** hutumia `VIMINIT` na pia `EXINIT` kama fallback, lakini usanidi wake wa kawaida wa mtumiaji ni `init.vim` au `init.lua`.<sup>[[2]](#references)</sup>
- Njia ya kigezo cha mazingira haihitaji faili inayoweza kuandikwa. Utekaji wa rc ya ndani na wa moduli katika saraka ya sasa ni mbinu tofauti zinazotegemea faili.<sup>[[1]](#references)[[3]](#references)</sup>
- Faili za rc za ndani ya mradi ni tofauti na modelines na fallback ya `require()` katika saraka ya sasa iliyoelezwa hapo juu. Vim na Neovim zina ukaguzi tofauti kwa faili hizo; angalia mtiririko wa kazi wa `exrc` ya ndani ya mradi ulioelezwa hapo juu.<sup>[[1]](#references)[[4]](#references)</sup>
- Vigezo vya kuchagua editor huchagua tu programu itakayozinduliwa; havihakikishi kwamba `VIMINIT` itafika kwenye mchakato wa mwisho. Kagua mazingira na hoja halisi kwenye mpaka wa exec wa Vim/Neovim.<sup>[[1]](#references)[[2]](#references)</sup>

## Kuimarisha usalama

- Ondoa vigezo hivyo waziwazi kabla ya uzinduzi wa editor wenye upendeleo au wa kiotomatiki: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` ni muhimu pale mpigaji anapohitaji kupuuza vyanzo vyote vya uanzishaji wa mtumiaji.<sup>[[1]](#references)[[2]](#references)</sup>
- Weka `EDITOR`/`VISUAL` kwenye njia kamili zinazoaminika, epuka kuendesha editor shirikishi kama root ikiwa imepokea mazingira ya mtumiaji, na hakikisha wrappers haziwezi kurejesha `VIMINIT`/`EXINIT` baada ya usafishaji.<sup>[[1]](#references)[[2]](#references)</sup>
- Kwa Neovim, sasisha hadi build inayoondoa templates za utafutaji wa Lua/C kwenye saraka ya sasa wakati wa editor mode, au ziondoe kabla ya kupakia plugins. Kagua msimbo wa plugins ili kutafuta miito ya hiari ya `pcall(require, ...)` unapofungua repositori zisizoaminika.<sup>[[3]](#references)</sup>
- Chukulia udhibiti wa mazingira ya editor, saraka ya kazi, au usanidi wa uanzishaji wa lengo kama mbinu inayoweza kusababisha utekelezaji wa msimbo katika muktadha wa usalama wa editor.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Nyaraka za Vim — `starting.txt` (uanzishaji, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Nyaraka za Neovim — uzinduzi na uanzishaji](https://neovim.io/doc/user/starting/)
- [3] [Suala la Neovim #38966 — fallback ya saraka ya sasa katika `require()`](https://github.com/neovim/neovim/issues/38966)
- [4] [Chaguo za Neovim — `exrc` ya ndani ya mradi na hitaji la kuamini](https://neovim.io/doc/user/options/#%27exrc%27)
- [5] [Uhariri katika Neovim — faili zinazoaminika na `:trust`](https://neovim.io/doc/user/editing/#trust)
{{#include ../../../banners/hacktricks-training.md}}
