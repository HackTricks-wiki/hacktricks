# Filesystem, Inodes और Recovery

{{#include ../../banners/hacktricks-training.md}}

Filesystem abuse अक्सर visible path और उसके पीछे मौजूद object के बीच के संबंध को भ्रमित करने के बारे में होता है। Disk images किसी अन्य filesystem को छिपा सकती हैं, writable mounts का उपयोग privileged jobs द्वारा किया जा सकता है, hardlinks किसी अलग नाम के माध्यम से उसी inode को expose कर सकते हैं, और deleted files को open file descriptor के माध्यम से अब भी पढ़ा जा सकता है।

यह page किसी एक विशिष्ट lab या target पर नहीं, बल्कि technique पर केंद्रित है।

## Disk Images और Loop Mounts

एक regular file में पूरा filesystem हो सकता है। इसलिए backup images, copied block devices, VM artifacts या renamed blobs में credentials, scripts, SSH keys, configuration files या flags हो सकते हैं, भले ही वे बाहर से उपयोगी न दिखें।

संभावित images की पहचान करें:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
यदि mounting की अनुमति हो, तो अज्ञात images को पहले read-only रूप में mount करें:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
यदि mounting उपलब्ध न हो, तो filesystem metadata का सीधे निरीक्षण करें:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
यह technique उपयोगी है क्योंकि यह सामान्य दिखने वाली file को दूसरी filesystem tree में बदल देती है। इसे hidden data recover करने के तरीके के रूप में देखें, न कि अपने-आप में privilege escalation के रूप में।

## Writable Mount Abuse

Writable mount तब खतरनाक बन जाता है जब बाद में कोई अधिक privileged context उसके अंदर मौजूद किसी चीज़ पर भरोसा करता है। महत्वपूर्ण सवाल केवल यह नहीं है कि "क्या मैं यहाँ write कर सकता हूँ?", बल्कि यह है कि "बाद में यहाँ से कौन read, execute, import या load करेगा?"।

Writable mounts और suspicious consumers खोजें:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
सामान्य abuse patterns:

- एक privileged cron या systemd unit mount से writable script चलाता है।
- एक privileged service mount से plugins, config, templates या helper binaries load करती है।
- एक mount में SUID files होती हैं और modification, replacement या path manipulation की अनुमति होती है।
- कोई container या chroot host-backed path को expose करता है, जो restricted environment से writable होता है।

सामान्य validation pattern:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Authorized lab में impact साबित करते समय payload को observable और minimal रखें, उदाहरण के लिए `id` का output किसी temporary file में लिखें। Core technique एक trusted writable location के माध्यम से delayed execution है।

## Inodes और Path Confusion

एक inode filesystem object होता है; path केवल उसकी ओर संकेत करने वाला नाम होता है। यह महत्वपूर्ण है क्योंकि दो अलग-अलग paths एक ही inode की ओर संकेत कर सकते हैं, और किसी deleted pathname का अर्थ हमेशा यह नहीं होता कि data समाप्त हो गया है।

Files की तुलना inode और device के आधार पर करें:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
एक ही inode के लिए सभी दृश्यमान pathname खोजें:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
जब आपके पास केवल metadata हो, तो सीधे inode number से खोजें:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
यह technique तब उपयोगी होती है जब कोई file किसी अप्रत्याशित नाम के अंतर्गत दिखाई देती है, जब कोई application एक path को validate करती है लेकिन दूसरे का उपयोग करती है, या जब कोई privileged wrapper ऐसे inode के साथ interact करता है जो किसी अन्य स्थान से भी reachable है।

## Hardlink Abuse

Hardlinks एक ही inode के लिए कई names बनाते हैं। वे symlinks की तरह किसी target path की ओर point नहीं करते; वे उसी file object के लिए समान names होते हैं।

Multiple hardlinks वाली SUID files खोजें:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
एक संदिग्ध फ़ाइल का निरीक्षण करें:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
यह क्यों महत्वपूर्ण है:

- एक sensitive file कम स्पष्ट path के माध्यम से accessible हो सकती है।
- एक SUID wrapper ऐसे नाम के पीछे छिपा हो सकता है जो privileged नहीं दिखता।
- एक pathname को हटाने वाली cleanup प्रक्रिया किसी अन्य hardlink को सक्रिय छोड़ सकती है।

Modern kernels और mount options इस प्रकार के abuse को कम करने के लिए hardlink creation को प्रतिबंधित कर सकते हैं, लेकिन existing hardlinks की समीक्षा करना अभी भी उपयोगी है।

## Open FDs के माध्यम से Deleted File Recovery

जब कोई process किसी file को open रखता है, तो pathname delete किए जाने के बाद भी file data उपलब्ध रह सकता है। Linux इन open descriptors को `/proc/<pid>/fd/` के अंतर्गत expose करता है।

Deleted open files खोजें:
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
जब permissions अनुमति दें, तब data recover करें:
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
यह deleted logs, temporary secrets, dropped binaries, rotated files या execution के बाद हटाई गई scripts को recover करने की एक practical technique है।

## ext Recovery With debugfs

ext filesystems पर, `debugfs` inode metadata का निरीक्षण कर सकता है और कभी-कभी filesystem image से file contents को dump कर सकता है। जब भी संभव हो, किसी copy या read-only image पर काम करें।

Entries की सूची बनाएँ और inodes का निरीक्षण करें:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
ज्ञात inode को dump करें:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
यह guaranteed recovery नहीं है। यह filesystem की स्थिति, blocks के reuse होने और metadata के अभी भी मौजूद होने पर निर्भर करता है। यह technique अभी भी valuable है क्योंकि यह आपको normal path traversal पर निर्भर हुए बिना inode-level state inspect करने देती है।

## Inode Exhaustion और Ordering

Inode Exhaustion तब होता है जब filesystem में file objects समाप्त हो जाते हैं, भले ही free disk space मौजूद हो। आमतौर पर इससे reliability failures होते हैं, लेकिन यह incident response या lab triage के दौरान होने वाले अजीब behavior को भी समझा सकता है।

Inode pressure जांचें:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode numbers और timestamps simple lab environments में activity को reconstruct करने में भी मदद कर सकते हैं:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
क्रम को संकेत मानें, प्रमाण नहीं। Copy operations, archive extraction, filesystem type, restores और concurrent writes, सभी allocation patterns को बदल सकते हैं।

## Defensive Notes

- विश्लेषण के दौरान अज्ञात images को read-only रूप में mount करें।
- privileged scripts, service units, plugins और helper paths को user-writable mounts से बाहर रखें।
- जहाँ operational रूप से उचित हो, `nosuid`, `nodev` और `noexec` का उपयोग करें, लेकिन इन्हें complete boundary न मानें।
- जहाँ संभव हो, `/proc/<pid>/fd`, process metadata और cross-user process inspection तक पहुँच प्रतिबंधित करें।
- writable mount points, privileged files के unexpected hardlinks और deleted-but-open sensitive files की निगरानी करें।
{{#include ../../banners/hacktricks-training.md}}
