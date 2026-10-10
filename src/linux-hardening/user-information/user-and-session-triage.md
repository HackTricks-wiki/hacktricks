# Utilisateurs, sessions et artefacts d’identification

{{#include ../../banners/hacktricks-training.md}}

Commencez par identifier le propriétaire du shell actuel, puis énumérez les autres utilisateurs, les groupes, les sessions actives et les magasins d’identifiants. La page sur les [ID utilisateur réel, effectif et sauvegardé](euid-ruid-suid.md) explique pourquoi les privilèges effectifs d’un processus peuvent différer de ceux de son compte de connexion.

## Énumérer les identités et les accès fondés sur les groupes

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` inclut les comptes issus d’un annuaire qu’une simple lecture de `/etc/passwd` peut ne pas détecter. Examinez les comptes avec un UID 0, les shells de connexion, les répertoires personnels, les groupes supplémentaires et les comptes dont la configuration autorise de manière inattendue une connexion interactive. La page sur les [groupes intéressants](interesting-groups-linux-pe/README.md) traite des accès délégués tels que `sudo`, `docker`, `disk` et `shadow`. Vérifiez les ACL réelles du système de fichiers et les règles locales avant d’associer des privilèges à un nom de groupe.

Si [NSS redirige les recherches dans `passwd`, `group` ou `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) vers une base de données, examinez le fournisseur actif et son chemin de configuration avant d’évaluer les identités issues de cette base. Pour les déploiements PostgreSQL de NSS, `/etc/nss-pgsql.conf` et `/etc/nss-pgsql-root.conf` sont des pistes qui indiquent uniquement des chemins, car les paramètres de connexion peuvent contenir des identifiants. Un rôle de base de données n’a d’importance que s’il peut modifier les enregistrements effectivement renvoyés par le fournisseur NSS actif et qu’un compte peut s’authentifier avec ces informations. Un GID primaire de 0 confère l’appartenance au groupe root, pas un UID 0 ; une association au groupe sudo nécessite une [règle de groupe sudoers](https://man7.org/linux/man-pages/man5/sudoers.5.html) effective ainsi que toute authentification requise. Une association à un UID 0 constitue une frontière d’identité différente. N’affichez pas les chaînes de connexion et ne modifiez pas les enregistrements de comptes lors d’une énumération passive.

Comparez également les UID numériques entre les noms de comptes locaux. Deux noms dans [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) peuvent désigner la même identité de fichier Unix, alors que leurs enregistrements d’authentification peuvent différer. Un alias récemment ajouté avec un UID non nul partagé peut donc donner accès aux fichiers ou processus d’un autre utilisateur après une authentification réussie ; il ne confère pas les privilèges root, sauf si cet UID ou une voie distincte le permet. Les UID partagés peuvent être intentionnels. Vérifiez la source des comptes (`/etc/passwd` ou NSS), l’historique de création, le shell et le répertoire personnel, la politique d’authentification effective, ainsi que l’autorisation de partager cette identité entre les comptes. Une vérification limitée aux doublons locaux ne permet pas d’exclure un alias issu d’un annuaire.

## Rechercher les sessions actives et récentes

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

Un socket `screen` ou `tmux` peut exposer un shell existant si ses permissions permettent à l’utilisateur actuel de s’y connecter. Vérifiez le propriétaire et le mode du socket avant de tenter d’y accéder ; la session d’un autre utilisateur n’est pas automatiquement accessible. Un timestamp sudo actif ou un socket d’agent SSH peut également être pertinent, mais leur réutilisation dépend de l’identité de l’utilisateur, des permissions et de la policy. Pour l’abus de l’agent forwarding, consultez [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Un [socket de contrôle OpenSSH multiplexé](https://man.openbsd.org/ssh_config#ControlMaster) est distinct de `SSH_AUTH_SOCK` : `ControlMaster` et `ControlPath` permettent aux clients SSH ultérieurs de partager une connexion déjà authentifiée, tandis que `ControlPersist` peut maintenir le master disponible après la fin de la première session. Inspectez le fichier `.ssh/config` de l’utilisateur actuel et les chemins de socket `.ssh` peu profonds, notamment leur propriétaire et leurs permissions. Le nom d’un socket ne prouve pas à lui seul que le master est actif, que l’utilisateur actuel peut s’y connecter ou quel compte distant il utilise.

## Examiner les artefacts utilisateur

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

L’historique du shell, les fichiers de démarrage, les clés SSH, la configuration des applications, les porte-clés GPG et les caches Kerberos peuvent révéler des identifiants ou des points de persistance modifiables. Un fichier `authorized_keys` ou un fichier de démarrage du shell modifiable pour un compte plus privilégié mérite d’être examiné. La [page de post-exploitation](../post-exploitation/README.md) couvre le déplacement du répertoire personnel GPG et la recherche d’identifiants ; [Linux Active Directory](linux-active-directory.md) couvre la réutilisation des caches Kerberos et des keytabs. La [page PAM](../software-information/pam-pluggable-authentication-modules.md) explique les risques liés aux politiques d’authentification.
{{#include ../../banners/hacktricks-training.md}}
