# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Vim-ov sopstveni scripting language (Vimscript) može da pokrene **proizvoljne Ex commands i shell commands pri pokretanju** iz environment variables. Ako proces sa višim privilegijama (workflow za održavanje/root, `sudo vim …`, editor koji pokreće drugi alat, `crontab -e`, `visudo`, `git`/`less` koji pozivaju editor, …) pokrene Vim/Neovim sa environment-om pod uticajem napadača, napadač dobija izvršavanje koda u tom kontekstu.

## `VIMINIT`

Tokom inicijalizacije Vim čita i izvršava Ex commands u **`VIMINIT`**. Ex commands uključuju `:!cmd` (pokretanje shell command-a) i `:call system(...)`, tako da jedna promenljiva omogućava proizvoljno izvršavanje pre nego što se uredi bilo koja datoteka.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript (no external process, e.g. write a file)
printf ':qa!\n' | VIMINIT='call writefile(["x"],"/tmp/vim-vimscript")' vim /tmp/victim.txt
```
`:qa!` prosleđen putem stdin-a samo zatvara editor nakon što je payload već izvršen; u stvarnom scenariju žrtva jednostavno normalno otvara Vim.

## `EXINIT`

Ako `VIMINIT` nije postavljen, Vim (kao i binarni fajlovi kompatibilni sa `vi`/`ex`) koristi **`EXINIT`** kao rezervnu opciju, koja se izvršava na isti način. To je klasična varijanta iz ere vi-ja istog primitiva.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Napomene i ograničenja

- **Neovim** takođe poštuje `VIMINIT` (proverava se pre korisničkog `init.vim`/`init.lua`).
- Batch/Ex mode (`vim -es` / `vim -Es`) **ne** učitava `VIMINIT`/`EXINIT`; promenljive se izvršavaju pri normalnom (interaktivnom) pokretanju, što je uobičajeni scenario za žrtvu.
- Povezani vektori zasnovani na datotekama obuhvataju `exrc`/`.nvimrc` funkcije "modeline"/local-rc po direktorijumu i `-u <vimrc>`; prethodno opisan put preko environment promenljive ne zahteva nikakvu writable datoteku.

## Ojačavanje bezbednosti

- Sanitizujte environment (uklonite `VIMINIT`/`EXINIT`) pre pokretanja editora iz privilegovanih ili automatizovanih konteksta i preferirajte `sudo -i`/`env -i` omotače koji resetuju environment.
- Postavite `EDITOR`/`VISUAL` na pouzdane apsolutne putanje i izbegavajte pokretanje editora kao root sa nasleđenim korisničkim environment-om.
- Kontrolu nad environment-om mete tretirajte kao ekvivalent izvršavanju koda za svaki Vim/Neovim koji ona pokrene.

## References

- [1] [Vim dokumentacija — `starting.txt` (inicijalizacija, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
{{#include ../../../banners/hacktricks-training.md}}
