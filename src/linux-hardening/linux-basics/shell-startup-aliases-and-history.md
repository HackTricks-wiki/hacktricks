# Démarrage du shell, alias et historique

{{#include ../../banners/hacktricks-training.md}}

Une commande shell peut se comporter différemment de l’exécutable portant le même nom si un alias, une fonction, un fichier de démarrage ou une variable d’environnement modifie son exécution. Vérifiez ces éléments avant de vous fier au résultat d’une commande ou de supposer qu’un script utilise le même PATH qu’une session interactive.

## Examiner le shell actuel

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` et `command -V` indiquent si un nom correspond à un alias, une fonction, une commande intégrée ou un fichier. `command -v` et `which` peuvent donner des résultats différents pour les alias et les fonctions. L’historique du shell peut révéler des commandes ou des identifiants, mais il peut être incomplet, désactivé ou conservé en mémoire jusqu’à la fermeture de la session.

Un fichier `.bashrc` modifié peut définir un alias `sudo` qui imite une invite de mot de passe, enregistre la réponse et la transmet à la commande réelle. Cela peut dissimuler l’interception d’identifiants sans modifier l’exécutable `sudo` ni le `PATH`.<sup>[[5]](#references)</sup> Le shell doit lire le fichier de démarrage modifié et développer l’alias.<sup>[[7]](#references)</sup> Par défaut, Bash non interactif ne développe pas les alias, sauf si `expand_aliases` est activé.<sup>[[6]](#references)</sup>

## Examiner les fichiers de démarrage et d’historique

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Un fichier de démarrage modifiable par un utilisateur peut exécuter des commandes au prochain lancement d’un shell. Un fichier de démarrage à l’échelle du système ou le fichier de démarrage d’un utilisateur privilégié est plus sensible si un compte moins privilégié peut le modifier. Bash non interactif peut également lire le fichier indiqué par `BASH_ENV` ; la page sur les [variables d’environnement](linux-environment-variables.md#bash_env--env) explique ce comportement et d’autres hooks d’interpréteur. Vérifiez quels fichiers le shell réel lit lors des sessions de connexion, interactives et non interactives avant d’affirmer qu’il s’agit d’un vecteur de persistance.

Inspectez également les fichiers appelés par un fichier de démarrage global. Par exemple, un `source /opt/app/venv/bin/activate` littéral dans `/etc/bash.bashrc` exécute le fichier d’activation comme du code shell lorsqu’un shell lit effectivement ce fichier de démarrage. Examinez le fichier d’activation, les permissions des liens symboliques et des répertoires parents, ainsi que les ACL ; un utilisateur moins privilégié ne peut affecter un shell privilégié que si ce shell ou une tâche privilégiée appelle ensuite ce fichier. Si l’accès en écriture dépend de `sudoedit`, vérifiez d’abord la règle sudoers exacte et le paquet sudo installé et corrigé par le fournisseur ; une simple chaîne de version en amont ne suffit pas à établir une [exposition à l’injection d’arguments sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Examinez l’historique, les dotfiles et les sauvegardes à la recherche de secrets, comme décrit dans [utilisateurs et sessions](../user-information/user-and-session-triage.md). Si un script privilégié résout les commandes par leur nom, associez cet examen aux [conseils sur le détournement de PATH](linux-environment-variables.md#path).

## Redirection du démarrage de Zsh et fichiers compilés

Avec ses paramètres `RCS` par défaut, zsh lit `$ZDOTDIR/.zshenv` avant les invocations normales, y compris `zsh -c` et les scripts ; si `ZDOTDIR` n’est pas défini, il utilise `$HOME`. Lorsqu’un exécuteur de commandes accepte une map d’environnement, vérifiez s’il transmet l’une ou l’autre de ces variables à un processus zsh privilégié. Un `.zshenv` modifiable peut alors s’exécuter **avant** le corps de commande vérifié ou placé sur liste d’autorisation par l’exécuteur. Cela nécessite que le processus privilégié hérite du répertoire redirigé ; `zsh -f` ignore les fichiers de démarrage utilisateur, mais pas le `zshenv` global (souvent `/etc/zshenv`, mais les chemins varient selon la distribution). La [page sur l’injection Zsh de macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) présente un exemple minimal de `ZDOTDIR`.<sup>[[1]](#references)[[2]](#references)</sup>

Un `.zshenv.zwc` ou `.zshrc.zwc` valide et plus récent est exécuté à la place de son fichier de démarrage en texte brut. Si vous pouvez écrire dans le répertoire de démarrage, compiler un fichier modifié puis restaurer un fichier texte d’apparence inoffensive peut laisser du code exécutable dans la copie compilée. Il s’agit d’obfuscation, pas de chiffrement. Le test jetable ci-dessous montre pourquoi inspecter uniquement le fichier texte ne suffit pas ; il ne touche pas à un véritable répertoire personnel.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

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

Pour une cible réelle, déterminez son ZDOTDIR/HOME effectif, inspectez à la fois les fichiers texte et les fichiers .zwc, et vérifiez les horodatages, la propriété et les droits d’écriture des répertoires parents. Un fichier .zwc doit correspondre au fichier source et être plus récent pour prendre le dessus.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Fichiers de démarrage et d'arrêt de Zsh](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Avis sur l'injection de l'environnement de démarrage du shell](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Commandes intégrées du shell Zsh : zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [Le fichier .zshrc.zwc que vous avez oublié de vérifier](https://dfir.ch/posts/compiled_zsh/)
- [5] [Une campagne d'espionnage alimentée par l'IA cible l'infrastructure Linux gouvernementale](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/)
- [6] [Manuel de Bash : alias](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)
- [7] [Manuel de Bash : fichiers de démarrage de Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
{{#include ../../banners/hacktricks-training.md}}
