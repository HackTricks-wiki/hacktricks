# फ़ाइलसिस्टम, इनोड्स और रिकवरी

{{#include ../../banners/hacktricks-training.md}}

फ़ाइलसिस्टम abuse अक्सर visible path और उसके पीछे मौजूद object के संबंध को भ्रमित करने से संबंधित होता है।

Disk images किसी अन्य फ़ाइलसिस्टम को छिपा सकती हैं।<sup>[[1]](#references)</sup> Writable mounts को privileged jobs द्वारा consume किया जा सकता है।

Hardlinks अलग नाम के माध्यम से उसी inode को expose कर सकते हैं।<sup>[[3]](#references)</sup> Deleted files अभी भी open file descriptor के माध्यम से पढ़ी जा सकती हैं।<sup>[[5]](#references)[[6]](#references)</sup>

यह पेज किसी एक specific lab या target पर नहीं, बल्कि technique पर केंद्रित है।

## Disk Images और Loop Mounts

एक regular file में complete फ़ाइलसिस्टम हो सकता है, इसलिए mount किए जाने पर disk image दूसरा फ़ाइलसिस्टम tree expose कर सकती है।<sup>[[1]](#references)</sup>

Backup images, copied block devices, VM artifacts या renamed blobs में credentials, scripts, SSH keys, configuration files या flags हो सकते हैं, भले ही वे बाहर से useful न दिखें।

संभावित images की पहचान करने के लिए candidate को classify करने हेतु `file`, recognized फ़ाइलसिस्टम metadata की जाँच के लिए `blkid`, और पूरे file को printable sequences के लिए scan करने हेतु `strings -a` का उपयोग करें।<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
जब mounting की अनुमति हो, तो `ro` के साथ loop mount का उपयोग करें ताकि image read-only रूप से attach हो; नीचे दिया गया `find` command inspection की depth और file type को सीमित करता है।<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
यदि mounting उपलब्ध नहीं है और image ext2/ext3/ext4 है, तो `debugfs` के साथ इसके metadata का सीधे निरीक्षण करें।<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
यह technique उपयोगी है क्योंकि यह सामान्य दिखने वाली file को दूसरी filesystem tree में बदल देती है।<sup>[[1]](#references)</sup> इसे hidden data recover करने के तरीके के रूप में देखें, न कि अपने-आप में privilege escalation के रूप में।

## Writable Mount Abuse

Writable mount तब खतरनाक हो जाता है जब कोई अधिक privileged context बाद में उसके अंदर मौजूद किसी चीज़ पर भरोसा करता है। महत्वपूर्ण प्रश्न केवल यह नहीं है कि "क्या मैं यहाँ write कर सकता हूँ?", बल्कि यह है कि "बाद में यहाँ से कौन read, execute, import या load करता है?"

Mounted filesystems और उनके options की जाँच करने के लिए `findmnt` का उपयोग करें।<sup>[[9]](#references)</sup>

Documented `find` permission, type और filesystem-boundary predicates के साथ writable mounts और suspicious consumers खोजें, फिर संभावित consumer configuration को search करने के लिए recursive `grep` का उपयोग करें।<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
सामान्य abuse patterns:

- कोई cron job या systemd service mount से writable script चलाती है।<sup>[[13]](#references)[[14]](#references)</sup>
- कोई privileged service mount से plugins, config, templates या helper binaries लोड करती है।
- किसी mount में SUID files होती हैं और वह modification, replacement या path manipulation की अनुमति देता है।
- कोई container या chroot ऐसा host-backed path expose करता है जो restricted environment से writable होता है। Mount namespaces अलग-अलग mount hierarchies प्रदान करते हैं, जबकि `chroot()` केवल pathname resolution बदलता है और पूर्ण sandbox नहीं है।<sup>[[15]](#references)[[16]](#references)</sup>

उन्हीं `find` predicates का उपयोग करने वाला सामान्य validation pattern।<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
अधिकृत lab में impact सिद्ध करते समय, payload को observable और minimal रखें, उदाहरण के लिए `id` के output को किसी temporary file में लिखें।<sup>[[23]](#references)</sup> मुख्य technique trusted writable location के माध्यम से delayed execution है।

## Inodes और Path Confusion

inode filesystem object होता है; path केवल उसकी ओर संकेत करने वाला नाम होता है। Device और inode metadata आपको अलग-अलग filesystems में objects को अलग पहचानने देते हैं, जबकि link counts कई hard links को उजागर करते हैं।<sup>[[3]](#references)</sup> जब तक कोई process file को open रखता है, तब तक deleted pathname का अर्थ हमेशा यह नहीं होता कि data समाप्त हो गया है।<sup>[[5]](#references)</sup>

नीचे दिए गए `find` predicates inode identity, link counts, device boundaries और timestamps की तुलना करते हैं।<sup>[[4]](#references)</sup>

`ls -i` और `stat` metadata formats का उपयोग करके files की तुलना inode और device के आधार पर करें।<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
`find -samefile` के साथ उसी inode के लिए हर visible pathname खोजें।<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
जब आपके पास केवल metadata हो, तो `find -inum` के साथ सीधे inode number द्वारा खोजें।<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
यह technique तब उपयोगी होती है जब कोई file किसी अप्रत्याशित नाम के अंतर्गत दिखाई देती है, जब कोई application एक path को validate करती है लेकिन दूसरे का उपयोग करती है, या जब कोई privileged wrapper ऐसे inode के साथ interact करता है, जो किसी अन्य स्थान से भी reachable है।

## Hardlink Abuse

Hardlinks एक ही inode के लिए कई names बनाते हैं। वे symlinks की तरह किसी target path की ओर point नहीं करते; वे उसी file object के लिए समान names होते हैं।<sup>[[3]](#references)</sup>

`find` के permission और link-count predicates का उपयोग करके कई hardlinks वाली SUID files खोजें।<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
एक संदिग्ध फ़ाइल का `stat` और `find -samefile` से निरीक्षण करें।<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
क्यों महत्वपूर्ण है:

- एक sensitive file कम स्पष्ट path के माध्यम से accessible हो सकती है।
- एक SUID wrapper ऐसे नाम के पीछे छिपा हो सकता है जो privileged नहीं लगता।
- एक pathname को हटाने वाली cleanup किसी अन्य hardlink को active छोड़ सकती है।

Linux का `fs.protected_hardlinks` sysctl privilege boundaries के पार hardlink creation को restrict कर सकता है।<sup>[[7]](#references)</sup> Existing hardlinks की अभी भी समीक्षा की जानी चाहिए।

## Open FDs के माध्यम से Deleted File Recovery

जब कोई process किसी file को open रखता है, तो उसके अंतिम pathname को unlink करने पर file अंतिम descriptor के close होने तक मौजूद रहती है; Linux उन descriptors को `/proc/<pid>/fd/` के अंतर्गत expose करता है।<sup>[[5]](#references)[[6]](#references)</sup>

`/proc` descriptors को list करके और open-file output को filter करके deleted open files खोजें।<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
इन links के माध्यम से recovery permission पर निर्भर करती है, क्योंकि `/proc/<pid>/fd` को dereference करना ptrace access checks और file permissions के अधीन है।<sup>[[6]](#references)</sup>

जब अनुमति होती है, `readlink` descriptor target दिखाता है और `cp` इसकी contents को copy करता है।<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
यह deleted logs, temporary secrets, dropped binaries, rotated files या execution के बाद हटाई गई scripts को recover करने की practical technique है।

## ext Recovery With debugfs

ext2/ext3/ext4 filesystems पर, `debugfs` block device या image से inode metadata inspect और inode contents dump कर सकता है; `-w` के बिना, यह filesystem को read-only खोलता है।<sup>[[2]](#references)</sup> जब भी संभव हो, copy या read-only image पर काम करें।

Directory listings, inode status और inode-to-path checks के लिए `debugfs` requests के साथ entries list करें और inodes inspect करें।<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
ज्ञात inode को `debugfs dump` कमांड से dump करें, फिर recovered output को `file` से classify करें।<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
यह guaranteed recovery नहीं है। यह filesystem की स्थिति, blocks के दोबारा उपयोग किए गए हैं या नहीं, और metadata अभी मौजूद है या नहीं, इन बातों पर निर्भर करता है। ext3/ext4 के लिए, `debugfs` manual में बताया गया है कि deleted-inode recovery विफल हो सकती है, क्योंकि released inode data blocks अब उपलब्ध नहीं होते।<sup>[[2]](#references)</sup> यह technique फिर भी उपयोगी है, क्योंकि इससे normal path traversal पर निर्भर हुए बिना inode-level state का निरीक्षण किया जा सकता है।

## Inode Exhaustion और Ordering

Inode exhaustion तब होता है जब filesystem में file nodes समाप्त हो जाते हैं, भले ही free disk space बची हुई हो।<sup>[[8]](#references)[[17]](#references)</sup> इससे आमतौर पर reliability failures होती हैं, लेकिन incident response या lab triage के दौरान यह अजीब behavior को समझाने में भी मदद कर सकता है।

Block usage के बजाय inode information report करने के लिए `df -i` का उपयोग करें।<sup>[[8]](#references)</sup>

`df` और directory parents की `find` count से inode pressure जांचें।<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode numbers और timestamps सरल lab environments में activity को reconstruct करने में भी मदद कर सकते हैं।

नीचे दिए गए `find` format directives इन fields को दिखाते हैं।<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Ordering को प्रमाण नहीं, बल्कि एक संकेत मानें। Copy operations, archive extraction, filesystem type, restores और concurrent writes सभी allocation patterns को बदल सकते हैं।

## Defensive Notes

- Analysis के दौरान अज्ञात images को read-only रूप में mount करें।<sup>[[1]](#references)</sup>
- Privileged scripts, service units, plugins और helper paths को user-writable mounts के बाहर रखें।
- जहाँ operational रूप से उपयुक्त हो, `nosuid`, `nodev` और `noexec` का उपयोग करें; ये options set-ID/capability execution, device interpretation या mount पर direct binary execution को disable करते हैं।<sup>[[1]](#references)</sup> इन्हें complete boundary न मानें।
- `/proc/<pid>/fd` तक access को restrict करें; इन links को dereference करना ptrace access checks और file permissions द्वारा नियंत्रित होता है।<sup>[[6]](#references)</sup> जहाँ संभव हो, व्यापक process metadata और cross-user inspection को restrict करें।
- Writable mount points, privileged files के unexpected hardlinks और deleted-but-open sensitive files को monitor करें।

## References

- [1] [mount(8) — Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — Linux manual page](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — Linux manual page](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — Linux manual page](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — Linux manual page](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [/proc/sys/fs/ के लिए Documentation — Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — Linux manual page](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — Linux manual page](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — Linux manual page](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — Linux manual page](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — Linux manual page](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — Linux manual page](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — Linux manual page](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — Linux manual page](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — Linux manual page](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — Linux manual page](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — Linux manual page](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — Linux manual page](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
