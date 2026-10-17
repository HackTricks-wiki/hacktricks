# Démarrage du shell, alias et historique

{{#include ../../banners/hacktricks-training.md}}

Une commande du shell peut se comporter différemment de l’exécutable portant le même nom si un alias, une fonction, un fichier de démarrage ou une variable d’environnement modifie son exécution. Vérifiez ces éléments avant de vous fier au résultat d’une commande ou de supposer qu’un script utilise le même PATH qu’une session interactive.

## Inspecter le shell actuel

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` et `command -V` indiquent si un nom correspond à un alias, une fonction, une commande intégrée ou un fichier. `command -v` et `which` peuvent donner des résultats différents pour les alias et les fonctions. L’historique du shell peut révéler des commandes ou des identifiants, mais il peut être incomplet, désactivé ou conservé en mémoire jusqu’à la fermeture de la session.

## Examiner les fichiers de démarrage et d’historique

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Un fichier de démarrage modifiable par un utilisateur peut exécuter des commandes lors d’un prochain lancement du shell. Un fichier de démarrage global ou celui d’un utilisateur privilégié est plus sensible si un compte moins privilégié peut le modifier. Bash non interactif peut aussi lire le fichier indiqué par `BASH_ENV` ; la page sur les [variables d’environnement](linux-environment-variables.md#bash_env--env) explique ce comportement et d’autres hooks d’interpréteur. Vérifiez quels fichiers le shell lit réellement pour les sessions de connexion, interactives et non interactives avant de conclure qu’il s’agit d’un mécanisme de persistance.

Inspectez aussi les fichiers chargés par un fichier de démarrage global. Par exemple, un `source /opt/app/venv/bin/activate` littéral dans `/etc/bash.bashrc` exécute le fichier d’activation comme du code shell lorsqu’un shell lit effectivement ce fichier de démarrage. Examinez le fichier d’activation, les permissions des liens symboliques et des répertoires parents, ainsi que les ACL ; un utilisateur moins privilégié ne peut affecter un shell privilégié que si ce shell ou une tâche privilégiée charge ensuite ce fichier. Si l’accès en écriture dépend de `sudoedit`, vérifiez d’abord la règle sudoers exacte et le paquet sudo installé, avec ses correctifs du fournisseur ; une chaîne de version en amont ne suffit pas à établir une [exposition à l’injection d’arguments sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Vérifiez l’historique, les fichiers cachés et les sauvegardes pour y rechercher des secrets, comme décrit dans [utilisateurs et sessions](../user-information/user-and-session-triage.md). Si un script privilégié résout les commandes par leur nom, complétez cet examen avec les [recommandations sur le détournement de PATH](linux-environment-variables.md#path).

## Redirection du démarrage de Zsh et fichiers compilés

Avec ses paramètres `RCS` par défaut, zsh lit `$ZDOTDIR/.zshenv` avant les invocations normales, y compris `zsh -c` et les scripts ; si `ZDOTDIR` n’est pas défini, il utilise `$HOME`. Lorsqu’un lanceur de commandes accepte une map d’environnement, vérifiez s’il transmet l’une ou l’autre de ces variables à un processus zsh privilégié. Un fichier `.zshenv` modifiable peut alors s’exécuter **avant** le corps de la commande que le lanceur vérifie ou autorise. Cela nécessite que le processus privilégié hérite du répertoire redirigé ; `zsh -f` ignore les fichiers de démarrage utilisateur, mais pas le `zshenv` global (souvent `/etc/zshenv`, mais les chemins varient selon la distribution). La [page sur l’injection zsh dans macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) présente un exemple minimal avec `ZDOTDIR`.<sup>[[1]](#references)[[2]](#references)</sup>

Un fichier `.zshenv.zwc` ou `.zshrc.zwc` plus récent et valide est exécuté à la place du fichier de démarrage en texte brut correspondant. Si vous pouvez écrire dans le répertoire de démarrage, compiler un fichier modifié puis rétablir un fichier texte d’apparence inoffensive peut laisser du code exécutable dans la copie compilée. Il s’agit d’obscurcissement, pas de chiffrement. Le test jetable ci-dessous montre pourquoi inspecter uniquement le fichier texte ne suffit pas ; il ne touche pas à un vrai répertoire personnel.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
lab=$(mktemp -d)
printf '%s\n' 'print -r -- compiled > "$ZDOTDIR/result"' > "$lab/.zshenv"
zsh -f -c 'zcompile -R "$1"' _ "$lab/.zshenv"
printf '%s\n' 'print -r -- plaintext > "$ZDOTDIR/result"' > "$lab/.zshenv"
touch -d '2 minutes ago' "$lab/.zshenv"  # ensure the .zwc is newer
ZDOTDIR="$lab" zsh -c :
cat "$lab/result"  # compiled
zsh -f -c 'zcompile -t "$1"' _ "$lab/.zshenv.zwc"
```

Pour une cible réelle, déterminez son `ZDOTDIR`/`HOME` effectif, inspectez les fichiers texte et `.zwc`, et vérifiez les horodatages, la propriété et les répertoires parents accessibles en écriture. Un fichier `.zwc` doit correspondre au fichier source et être plus récent pour prendre le dessus.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Fichiers de démarrage et d’arrêt de Zsh](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Avis sur l’injection dans l’environnement de démarrage du shell](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Commandes intégrées du shell Zsh : zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [Le fichier .zshrc.zwc que vous avez oublié de vérifier](https://dfir.ch/posts/compiled_zsh/)
{{#include ../../banners/hacktricks-training.md}}
