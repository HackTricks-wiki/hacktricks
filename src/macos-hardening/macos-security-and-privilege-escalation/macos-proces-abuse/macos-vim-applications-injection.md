# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Lugha ya scripting ya Vim (Vimscript) inaweza kuendesha **Ex commands na shell commands kiholela wakati wa kuanza** kutoka kwa environment variables. Ikiwa mchakato wenye privilege zaidi (maintenance/root workflow, `sudo vim …`, editor iliyoanzishwa na tool nyingine, `crontab -e`, `visudo`, `git`/`less` inayoanzisha editor, …) utaanzisha Vim/Neovim ikiwa na environment inayodhibitiwa na attacker, attacker hupata code execution katika context hiyo.

## `VIMINIT`

Wakati wa initialization, Vim husoma na kutekeleza Ex commands zilizo katika **`VIMINIT`**. Ex commands zinajumuisha `:!cmd` (kuendesha shell command) na `:call system(...)`, hivyo variable moja inaweza kutoa arbitrary execution kabla ya file yoyote kuhaririwa.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript (no external process, e.g. write a file)
printf ':qa!\n' | VIMINIT='call writefile(["x"],"/tmp/vim-vimscript")' vim /tmp/victim.txt
```
` :qa!` iliyowekwa kwenye stdin hufunga tu editor baada ya payload kutekelezwa; katika hali halisi mwathiriwa hufungua Vim kama kawaida.

## `EXINIT`

Ikiwa `VIMINIT` haijawekwa, Vim (pamoja na binary za uoanifu za `vi`/`ex`) hutumia **`EXINIT`** kama njia mbadala, ambayo hutekelezwa kwa njia ileile. Hii ni toleo la enzi za vi la primitive hiyo hiyo.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Maelezo na tahadhari

- **Neovim** pia huheshimu `VIMINIT` (hukaguliwa kabla ya `init.vim`/`init.lua` ya mtumiaji).
- Batch/Ex mode (`vim -es` / `vim -Es`) **haisource** `VIMINIT`/`EXINIT`; variables hizi hutumika wakati wa startup ya kawaida (interactive), ambayo ndiyo hali ya kawaida ya victim.
- Vectors zinazohusiana na file ni features za `exrc`/`.nvimrc` za kila directory, "modeline"/local-rc na `-u <vimrc>`; njia ya environment-variable hapo juu haihitaji file yoyote inayoweza kuandikwa.

## Hardening

- Safisha environment (ondoa `VIMINIT`/`EXINIT`) kabla ya kuanzisha editors kutoka kwenye contexts zenye privileges au automated, na pendelea wrappers za `sudo -i`/`env -i` zinazo-reset environment.
- Weka `EDITOR`/`VISUAL` kwenye absolute paths zinazoaminika na epuka kuendesha editors kama root ikiwa na user environment iliyorithiwa.
- Chukulia control ya environment ya target kuwa sawa na code execution kwa Vim/Neovim yoyote itakayoianzisha.

## References

- [1] [Vim documentation — `starting.txt` (initialization, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
{{#include ../../../banners/hacktricks-training.md}}
