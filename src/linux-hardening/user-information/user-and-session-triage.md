# Utilisateurs, sessions et artefacts d’identification

{{#include ../../banners/hacktricks-training.md}}

Commencez par identifier l’utilisateur auquel appartient le shell actuel, puis recensez les autres utilisateurs, les groupes, les sessions actives et les magasins d’identifiants. La page sur les [identifiants utilisateur réel, effectif et sauvegardé](euid-ruid-suid.md) explique pourquoi les privilèges effectifs d’un processus peuvent différer de ceux de son compte de connexion.

## Recenser les identités et les accès basés sur les groupes

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` inclut les comptes adossés à un annuaire, qui peuvent ne pas apparaître lors d’une simple lecture de `/etc/passwd`. Examinez les comptes avec un UID 0, les shells de connexion, les répertoires personnels, les groupes supplémentaires et les comptes dont la configuration autorise de façon inattendue une connexion interactive. La page [interesting groups](interesting-groups-linux-pe/README.md) traite des accès délégués tels que `sudo`, `docker`, `disk` et `shadow`. Vérifiez les ACL réelles du système de fichiers et la politique locale avant de considérer un nom de groupe comme un privilège.

Si [NSS associe les recherches `passwd`, `group` ou `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) à une base de données, examinez le fournisseur actif et le chemin de sa configuration avant d’évaluer les identités provenant de la base. Pour les déploiements PostgreSQL NSS, `/etc/nss-pgsql.conf` et `/etc/nss-pgsql-root.conf` sont uniquement des pistes vers des chemins, car les paramètres de connexion peuvent contenir des identifiants. Un rôle de base de données n’a d’importance que s’il peut modifier les enregistrements réellement renvoyés par le fournisseur NSS actif et si un compte peut s’authentifier à l’aide de ces enregistrements. Un GID primaire de 0 donne l’appartenance au groupe root, pas un UID 0 ; une association au groupe sudo nécessite une [règle de groupe sudoers](https://man7.org/linux/man-pages/man5/sudoers.5.html) effective et toute authentification requise. Une association à un UID 0 constitue une frontière d’identité différente. N’affichez pas les chaînes de connexion et ne modifiez pas les enregistrements des comptes lors d’une énumération passive.

Comparez également les UID numériques entre les noms de comptes locaux. Deux noms dans [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) peuvent désigner la même identité de fichier Unix, même si leurs enregistrements d’authentification de connexion diffèrent. Un alias récemment ajouté partageant un UID non nul peut ainsi donner accès aux fichiers ou aux processus d’un autre utilisateur après une authentification réussie ; il ne confère pas les privilèges root, sauf si cet UID ou une autre voie d’élévation de privilèges le permet. Des UID partagés peuvent être intentionnels. Vérifiez la source du compte (`/etc/passwd` ou NSS), l’historique de création, le shell et le répertoire personnel, la politique d’authentification effective, ainsi que l’autorisation des comptes à partager cette identité. Une vérification des doublons limitée aux comptes locaux ne permet pas d’exclure un alias adossé à un annuaire.

## Trouver les sessions actives et récentes

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

Un socket `screen` ou `tmux` peut exposer un shell existant si ses permissions permettent à l’utilisateur actuel de s’y connecter. Vérifiez le propriétaire et le mode du socket avant toute tentative d’accès ; une session appartenant à un autre utilisateur n’est pas automatiquement accessible. Un timestamp sudo actif ou un socket SSH agent peut également être pertinent, mais leur réutilisation dépend de l’identité de l’utilisateur, des permissions et de la politique en vigueur. Pour l’exploitation de l’agent forwarding, voir [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Un [socket de contrôle du multiplexage OpenSSH](https://man.openbsd.org/ssh_config#ControlMaster) est distinct de `SSH_AUTH_SOCK` : `ControlMaster` et `ControlPath` permettent aux clients SSH ultérieurs de partager une connexion déjà authentifiée, tandis que `ControlPersist` peut maintenir le master disponible après la fin de la première session. Examinez le fichier `.ssh/config` de l’utilisateur actuel et les chemins de socket peu profonds dans `.ssh`, notamment le propriétaire et les permissions. Le nom d’un socket ne prouve pas à lui seul que le master est actif, que l’utilisateur actuel peut s’y connecter, ni quel compte distant il utilise.

## Examiner les artefacts utilisateur

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

L’historique du shell, les fichiers de démarrage, les clés SSH, la configuration des applications, les trousseaux GPG et les caches Kerberos peuvent révéler des identifiants ou des points de persistance accessibles en écriture. Un fichier `authorized_keys` ou de démarrage du shell accessible en écriture pour un compte plus privilégié mérite d’être examiné. La [page sur le post-exploitation](../post-exploitation/README.md) couvre le déplacement du répertoire personnel GPG et la recherche d’identifiants ; [Linux Active Directory](linux-active-directory.md) couvre la réutilisation des caches Kerberos et des keytabs. La [page PAM](../software-information/pam-pluggable-authentication-modules.md) explique les risques liés aux politiques d’authentification.
{{#include ../../banners/hacktricks-training.md}}
