# Injection ya Ruby Applications katika macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby huchanganua switches za command-line zinazotumika kutoka kwenye environment variable ya `RUBYOPT` kabla ya kuendesha script. Ingawa Ruby hukataa baadhi ya switches humo, `-I` inaweza kuongeza directory ya library-search na `-r` inaweza ku-require library. Kwa hivyo, process inayoanzisha Ruby ikiwa na environment variables zinazodhibitiwa na attacker inaweza kulazimishwa kupakia Ruby code inayodhibitiwa na attacker.<sup>[[1]](#references)</sup>

Unda `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Unda hati ya Ruby isiyo na madhara kama `hello.rb`:
```ruby:hello.rb
puts 'Hello, World!'
```
Iendeshe kwa thamani iliyodhibitiwa ya `RUBYOPT`:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Ili kuzima tabia hii, pitisha `--disable=rubyopt` (au `--disable-rubyopt`) **kabla** ya jina la script:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
Chaguo lililoandikwa baada ya `hello.rb` hupitishwa kwa script katika `ARGV`; haliwezi kuzima uchakataji wa awali wa Ruby wa `RUBYOPT`.<sup>[[1]](#references)</sup>

## References

- [1] [Nyaraka za Ruby - Chaguo za mstari wa amri za Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
