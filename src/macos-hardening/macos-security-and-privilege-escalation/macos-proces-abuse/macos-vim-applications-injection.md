# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Vim se eie scripting language (Vimscript) kan **arbitrêre Ex commands en shell commands by opstart uitvoer** vanuit environment variables. Indien ’n meer bevoorregte proses (’n maintenance/root workflow, ’n `sudo vim …`, ’n editor wat deur ’n ander tool gestart word, `crontab -e`, `visudo`, `git`/`less` wat ’n editor invoke, …) Vim/Neovim met ’n aanvaller-beïnvloede environment launch, kry die aanvaller code execution in daardie context.

## `VIMINIT`

Tydens initialisering lees en execute Vim die Ex commands in **`VIMINIT`**. Ex commands sluit `:!cmd` in (run ’n shell command) en `:call system(...)`, dus lewer ’n enkele variable arbitrary execution voordat enige file edited word.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript (no external process, e.g. write a file)
printf ':qa!\n' | VIMINIT='call writefile(["x"],"/tmp/vim-vimscript")' vim /tmp/victim.txt
```
Die `:qa!` wat via stdin ingevoer word, sluit die editor net nadat die payload reeds uitgevoer is; in ’n werklike scenario maak die slagoffer Vim eenvoudig normaalweg oop.

## `EXINIT`

As `VIMINIT` nie gestel is nie, val Vim (en die `vi`/`ex`-versoenbaarheidsbinaries) terug na **`EXINIT`**, wat op dieselfde manier uitgevoer word. Dit is die klassieke vi-era-variant van dieselfde primitive.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Notas en voorbehoude

- **Neovim** respekteer ook `VIMINIT` (dit word vóór die gebruiker se `init.vim`/`init.lua` nagegaan).
- Batch/Ex-modus (`vim -es` / `vim -Es`) source nie `VIMINIT`/`EXINIT` nie; die veranderlikes word tydens normale (interaktiewe) opstart gebruik, wat die algemene slagoffer-scenario is.
- Verwante lêergebaseerde vectors is die per-gids `exrc`/`.nvimrc`-"modeline"/local-rc-features en `-u <vimrc>`; die omgewingsveranderlike-pad hierbo benodig glad nie ’n skryfbare lêer nie.

## Verharding

- Saniteer die omgewing (verwyder `VIMINIT`/`EXINIT`) voordat editors vanuit bevoorregte of geoutomatiseerde kontekste geloods word, en verkies `sudo -i`/`env -i`-wrappers wat die omgewing terugstel.
- Stel `EDITOR`/`VISUAL` op vertroude absolute paaie en vermy dit om editors as root met ’n geërfde gebruiker-omgewing te laat loop.
- Behandel beheer oor ’n teiken se omgewing as gelykstaande aan code execution vir enige Vim/Neovim wat dit spawn.

## References

- [1] [Vim-dokumentasie — `starting.txt` (initialisering, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
{{#include ../../../banners/hacktricks-training.md}}
