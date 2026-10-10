# Démarrage du shell, alias et historique

{{#include ../../banners/hacktricks-training.md}}

Une commande du shell peut se comporter différemment de l’exécutable portant le même nom si un alias, une fonction, un fichier de démarrage ou une variable d’environnement modifie son fonctionnement. Vérifiez ces éléments avant de vous fier à la sortie d’une commande ou de supposer qu’un script utilise le même PATH qu’une session interactive.

## Inspecter le shell actuel

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` et `command -V` indiquent si un nom correspond à un alias, une fonction, une commande intégrée ou un fichier. `command -v` et `which` ne donnent pas toujours les mêmes résultats pour les alias et les fonctions. L’historique du shell peut révéler des commandes ou des identifiants, mais il peut être incomplet, désactivé ou conservé en mémoire jusqu’à la fermeture de la session.

## Examiner les fichiers de démarrage et d’historique

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Un fichier de démarrage modifiable par un utilisateur peut exécuter des commandes lors du lancement ultérieur d’un shell. Un fichier de démarrage global ou celui d’un utilisateur privilégié est plus sensible si un compte moins privilégié peut le modifier. Bash non interactif peut également lire le fichier indiqué par `BASH_ENV` ; la page sur les [variables d’environnement](linux-environment-variables.md#bash_env--env) explique ce comportement et d’autres hooks d’interpréteur. Vérifiez quels fichiers le shell lit réellement pour les sessions de connexion, interactives et non interactives avant d’affirmer qu’il s’agit d’un mécanisme de persistance.

Inspectez également les fichiers chargés par un fichier de démarrage global. Par exemple, un `source /opt/app/venv/bin/activate` littéral dans `/etc/bash.bashrc` exécute le fichier d’activation comme du code shell lorsqu’un shell lit effectivement ce fichier de démarrage. Examinez le fichier d’activation, les permissions des liens symboliques et des répertoires parents, ainsi que les ACL ; un utilisateur moins privilégié ne peut affecter un shell privilégié que si ce shell ou une tâche privilégiée charge ensuite ce fichier. Si l’accès en écriture dépend de `sudoedit`, vérifiez d’abord la règle sudoers exacte et le paquet sudo installé, corrigé par le fournisseur ; une chaîne de version amont ne suffit pas à établir une [exposition à l’injection d’arguments sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Vérifiez l’historique, les fichiers cachés et les sauvegardes pour y rechercher des secrets, comme décrit dans [utilisateurs et sessions](../user-information/user-and-session-triage.md). Si un script privilégié résout les commandes par leur nom, complétez cet examen avec les [conseils sur le détournement de PATH](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
