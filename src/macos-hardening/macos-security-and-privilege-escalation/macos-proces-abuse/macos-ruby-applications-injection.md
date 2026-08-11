# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby किसी script को चलाने से पहले `RUBYOPT` environment variable से supported command-line switches को parse करता है। हालांकि Ruby वहाँ कुछ switches को अस्वीकार करता है, `-I` किसी library-search directory को prepend कर सकता है और `-r` किसी library को require कर सकता है। इसलिए, attacker-controlled environment variables के साथ Ruby launch करने वाली process को attacker-controlled Ruby code load करने के लिए बाध्य किया जा सकता है।<sup>[[1]](#references)</sup>

`/tmp/inject.rb` बनाएँ:
```ruby:inject.rb
puts `whoami`
```
`hello.rb` जैसी एक harmless Ruby script बनाएँ:
```ruby:hello.rb
puts 'Hello, World!'
```
इसे नियंत्रित `RUBYOPT` मान के साथ चलाएँ:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
इस व्यवहार को disable करने के लिए, script name से **पहले** `--disable=rubyopt` (या `--disable-rubyopt`) पास करें:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
`hello.rb` के बाद लिखा गया कोई विकल्प script को `ARGV` में पास किया जाता है; यह Ruby द्वारा `RUBYOPT` की पहले की processing को disable नहीं करता।<sup>[[1]](#references)</sup>

## References

- [1] [Ruby documentation - Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
