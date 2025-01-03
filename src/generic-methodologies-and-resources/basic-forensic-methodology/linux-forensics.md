# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## प्रारंभिक जानकारी संग्रहण

### बुनियादी जानकारी

सबसे पहले, यह अनुशंसा की जाती है कि आपके पास कुछ **USB** हो जिसमें **अच्छे ज्ञात बाइनरी और पुस्तकालय हों** (आप बस उबंटू ले सकते हैं और फ़ोल्डर _/bin_, _/sbin_, _/lib,_ और _/lib64_ की कॉपी कर सकते हैं), फिर USB को माउंट करें, और उन बाइनरी का उपयोग करने के लिए env वेरिएबल को संशोधित करें:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
एक बार जब आपने सिस्टम को अच्छे और ज्ञात बाइनरीज़ का उपयोग करने के लिए कॉन्फ़िगर कर लिया, तो आप **कुछ बुनियादी जानकारी निकालना शुरू कर सकते हैं**:
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### संदिग्ध जानकारी

बुनियादी जानकारी प्राप्त करते समय आपको अजीब चीजों की जांच करनी चाहिए जैसे:

- **रूट प्रक्रियाएँ** आमतौर पर कम PIDS के साथ चलती हैं, इसलिए यदि आप एक बड़े PID के साथ रूट प्रक्रिया पाते हैं तो आप संदेह कर सकते हैं
- `/etc/passwd` के अंदर बिना शेल वाले उपयोगकर्ताओं के **पंजीकृत लॉगिन** की जांच करें
- बिना शेल वाले उपयोगकर्ताओं के लिए `/etc/shadow` के अंदर **पासवर्ड हैश** की जांच करें

### मेमोरी डंप

चल रहे सिस्टम की मेमोरी प्राप्त करने के लिए, [**LiME**](https://github.com/504ensicsLabs/LiME) का उपयोग करने की सिफारिश की जाती है।\
इसे **संकलित** करने के लिए, आपको **उसी कर्नेल** का उपयोग करना होगा जो पीड़ित मशीन उपयोग कर रही है।

> [!NOTE]
> याद रखें कि आप **पीड़ित मशीन में LiME या कोई अन्य चीज़ स्थापित नहीं कर सकते** क्योंकि इससे इसमें कई परिवर्तन होंगे

तो, यदि आपके पास Ubuntu का एक समान संस्करण है तो आप `apt-get install lime-forensics-dkms` का उपयोग कर सकते हैं।\
अन्य मामलों में, आपको github से [**LiME**](https://github.com/504ensicsLabs/LiME) डाउनलोड करना होगा और इसे सही कर्नेल हेडर के साथ संकलित करना होगा। पीड़ित मशीन के **सटीक कर्नेल हेडर** प्राप्त करने के लिए, आप बस **डायरेक्टरी** `/lib/modules/<kernel version>` को अपनी मशीन पर **कॉपी** कर सकते हैं, और फिर उन्हें उपयोग करके LiME को **संकलित** कर सकते हैं:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME 3 **फॉर्मेट** का समर्थन करता है:

- कच्चा (हर खंड को एक साथ जोड़ा गया)
- पैडेड (कच्चे के समान, लेकिन दाहिने बिट्स में ज़ीरो के साथ)
- लाइम (मेटाडेटा के साथ अनुशंसित फॉर्मेट)

LiME का उपयोग **नेटवर्क के माध्यम से डंप भेजने** के लिए भी किया जा सकता है, इसे सिस्टम पर स्टोर करने के बजाय कुछ इस तरह: `path=tcp:4444`

### डिस्क इमेजिंग

#### सिस्टम को बंद करना

सबसे पहले, आपको **सिस्टम को बंद करना** होगा। यह हमेशा एक विकल्प नहीं होता क्योंकि कभी-कभी सिस्टम एक प्रोडक्शन सर्वर होता है जिसे कंपनी बंद नहीं कर सकती।\
सिस्टम को बंद करने के **2 तरीके** हैं, एक **सामान्य शटडाउन** और एक **"प्लग को खींचना" शटडाउन**। पहला तरीका **प्रक्रियाओं को सामान्य रूप से समाप्त** करने और **फाइल सिस्टम** को **सिंक्रनाइज़** करने की अनुमति देगा, लेकिन यह संभावित **मैलवेयर** को **साक्ष्य नष्ट** करने की भी अनुमति देगा। "प्लग को खींचने" का तरीका **कुछ जानकारी के नुकसान** को ले जा सकता है (जितनी जानकारी खोई नहीं जाएगी क्योंकि हमने पहले ही मेमोरी की एक इमेज ले ली है) और **मैलवेयर को इसके बारे में कुछ करने का कोई अवसर नहीं मिलेगा**। इसलिए, यदि आप **संदेह** करते हैं कि वहाँ **मैलवेयर** हो सकता है, तो बस सिस्टम पर **`sync`** **कमांड** चलाएँ और प्लग को खींचें।

#### डिस्क की इमेज लेना

यह महत्वपूर्ण है कि **आपके कंप्यूटर को मामले से संबंधित किसी भी चीज़ से कनेक्ट करने से पहले**, आपको यह सुनिश्चित करना होगा कि इसे **केवल पढ़ने के लिए माउंट किया जाएगा** ताकि किसी भी जानकारी को संशोधित करने से बचा जा सके।
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk Image pre-analysis

डिस्क इमेज को बिना किसी और डेटा के इमेज करना।
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
## ज्ञात मैलवेयर के लिए खोजें

### संशोधित सिस्टम फ़ाइलें

Linux सिस्टम घटकों की अखंडता सुनिश्चित करने के लिए उपकरण प्रदान करता है, जो संभावित रूप से समस्याग्रस्त फ़ाइलों को पहचानने के लिए महत्वपूर्ण है।

- **RedHat-आधारित सिस्टम**: व्यापक जांच के लिए `rpm -Va` का उपयोग करें।
- **Debian-आधारित सिस्टम**: प्रारंभिक सत्यापन के लिए `dpkg --verify` का उपयोग करें, इसके बाद `debsums | grep -v "OK$"` (जिसके लिए `debsums` को `apt-get install debsums` के साथ स्थापित करें) का उपयोग करें ताकि किसी भी समस्या की पहचान की जा सके।

### मैलवेयर/रूटकिट डिटेक्टर्स

मैलवेयर खोजने के लिए उपयोगी उपकरणों के बारे में जानने के लिए निम्नलिखित पृष्ठ पढ़ें:

{{#ref}}
malware-analysis.md
{{#endref}}

## स्थापित कार्यक्रमों की खोज करें

Debian और RedHat सिस्टम पर स्थापित कार्यक्रमों की प्रभावी खोज के लिए, सामान्य निर्देशिकाओं में मैनुअल जांच के साथ-साथ सिस्टम लॉग और डेटाबेस का उपयोग करने पर विचार करें।

- Debian के लिए, पैकेज इंस्टॉलेशन के बारे में विवरण प्राप्त करने के लिए _**`/var/lib/dpkg/status`**_ और _**`/var/log/dpkg.log`**_ की जांच करें, विशेष जानकारी के लिए `grep` का उपयोग करें।
- RedHat उपयोगकर्ता स्थापित पैकेजों की सूची के लिए `rpm -qa --root=/mntpath/var/lib/rpm` के साथ RPM डेटाबेस को क्वेरी कर सकते हैं।

इन पैकेज प्रबंधकों के बाहर या मैन्युअल रूप से स्थापित सॉफ़्टवेयर को उजागर करने के लिए, _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, और _**`/sbin`**_ जैसी निर्देशिकाओं का अन्वेषण करें। ज्ञात पैकेजों से संबंधित नहीं होने वाले निष्पादन योग्य फ़ाइलों की पहचान करने के लिए निर्देशिका लिस्टिंग को सिस्टम-विशिष्ट कमांड के साथ मिलाएं, जिससे सभी स्थापित कार्यक्रमों की खोज को बढ़ावा मिलेगा।
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
## हटाए गए चल रहे बाइनरी को पुनर्प्राप्त करें

कल्पना करें कि एक प्रक्रिया /tmp/exec से निष्पादित की गई थी और फिर हटा दी गई। इसे निकालना संभव है
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## ऑटॉस्टार्ट स्थानों का निरीक्षण करें

### अनुसूचित कार्य
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
### Services

एक पथ जहाँ एक मैलवेयर को सेवा के रूप में स्थापित किया जा सकता है:

- **/etc/inittab**: प्रारंभिक स्क्रिप्ट को कॉल करता है जैसे rc.sysinit, आगे स्टार्टअप स्क्रिप्ट की ओर निर्देशित करता है।
- **/etc/rc.d/** और **/etc/rc.boot/**: सेवा स्टार्टअप के लिए स्क्रिप्ट्स होते हैं, बाद वाला पुराने Linux संस्करणों में पाया जाता है।
- **/etc/init.d/**: कुछ Linux संस्करणों जैसे Debian में स्टार्टअप स्क्रिप्ट्स को संग्रहीत करने के लिए उपयोग किया जाता है।
- सेवाएँ **/etc/inetd.conf** या **/etc/xinetd/** के माध्यम से भी सक्रिय की जा सकती हैं, Linux के प्रकार के आधार पर।
- **/etc/systemd/system**: सिस्टम और सेवा प्रबंधक स्क्रिप्ट्स के लिए एक निर्देशिका।
- **/etc/systemd/system/multi-user.target.wants/**: उन सेवाओं के लिए लिंक होते हैं जिन्हें मल्टी-यूजर रनलेवल में शुरू किया जाना चाहिए।
- **/usr/local/etc/rc.d/**: कस्टम या तृतीय-पक्ष सेवाओं के लिए।
- **\~/.config/autostart/**: उपयोगकर्ता-विशिष्ट स्वचालित स्टार्टअप अनुप्रयोगों के लिए, जो उपयोगकर्ता-लक्षित मैलवेयर के लिए एक छिपने की जगह हो सकती है।
- **/lib/systemd/system/**: स्थापित पैकेजों द्वारा प्रदान की गई सिस्टम-व्यापी डिफ़ॉल्ट यूनिट फ़ाइलें।

### Kernel Modules

Linux कर्नेल मॉड्यूल, जिन्हें अक्सर मैलवेयर द्वारा रूटकिट घटकों के रूप में उपयोग किया जाता है, सिस्टम बूट पर लोड होते हैं। इन मॉड्यूल के लिए महत्वपूर्ण निर्देशिकाएँ और फ़ाइलें शामिल हैं:

- **/lib/modules/$(uname -r)**: चल रहे कर्नेल संस्करण के लिए मॉड्यूल रखता है।
- **/etc/modprobe.d**: मॉड्यूल लोडिंग को नियंत्रित करने के लिए कॉन्फ़िगरेशन फ़ाइलें होती हैं।
- **/etc/modprobe** और **/etc/modprobe.conf**: वैश्विक मॉड्यूल सेटिंग्स के लिए फ़ाइलें।

### Other Autostart Locations

Linux विभिन्न फ़ाइलों का उपयोग करता है जो उपयोगकर्ता लॉगिन पर स्वचालित रूप से कार्यक्रमों को निष्पादित करते हैं, जो संभावित रूप से मैलवेयर को आश्रय दे सकते हैं:

- **/etc/profile.d/**\*, **/etc/profile**, और **/etc/bash.bashrc**: किसी भी उपयोगकर्ता लॉगिन के लिए निष्पादित होते हैं।
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, और **\~/.config/autostart**: उपयोगकर्ता-विशिष्ट फ़ाइलें जो उनके लॉगिन पर चलती हैं।
- **/etc/rc.local**: सभी सिस्टम सेवाओं के शुरू होने के बाद चलती है, मल्टीयूजर वातावरण में संक्रमण के अंत को चिह्नित करती है।

## Examine Logs

Linux सिस्टम उपयोगकर्ता गतिविधियों और सिस्टम घटनाओं को विभिन्न लॉग फ़ाइलों के माध्यम से ट्रैक करता है। ये लॉग अनधिकृत पहुंच, मैलवेयर संक्रमण, और अन्य सुरक्षा घटनाओं की पहचान के लिए महत्वपूर्ण हैं। प्रमुख लॉग फ़ाइलें शामिल हैं:

- **/var/log/syslog** (Debian) या **/var/log/messages** (RedHat): सिस्टम-व्यापी संदेशों और गतिविधियों को कैप्चर करते हैं।
- **/var/log/auth.log** (Debian) या **/var/log/secure** (RedHat): प्रमाणीकरण प्रयासों, सफल और असफल लॉगिन को रिकॉर्ड करते हैं।
- प्रासंगिक प्रमाणीकरण घटनाओं को फ़िल्टर करने के लिए `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` का उपयोग करें।
- **/var/log/boot.log**: सिस्टम स्टार्टअप संदेशों को रखता है।
- **/var/log/maillog** या **/var/log/mail.log**: ईमेल सर्वर गतिविधियों को लॉग करता है, ईमेल-संबंधित सेवाओं को ट्रैक करने के लिए उपयोगी।
- **/var/log/kern.log**: कर्नेल संदेशों को संग्रहीत करता है, जिसमें त्रुटियाँ और चेतावनियाँ शामिल हैं।
- **/var/log/dmesg**: डिवाइस ड्राइवर संदेशों को रखता है।
- **/var/log/faillog**: असफल लॉगिन प्रयासों को रिकॉर्ड करता है, सुरक्षा उल्लंघन की जांच में मदद करता है।
- **/var/log/cron**: क्रोन जॉब निष्पादन को लॉग करता है।
- **/var/log/daemon.log**: पृष्ठभूमि सेवा गतिविधियों को ट्रैक करता है।
- **/var/log/btmp**: असफल लॉगिन प्रयासों का दस्तावेज़ीकरण करता है।
- **/var/log/httpd/**: Apache HTTPD त्रुटि और एक्सेस लॉग को रखता है।
- **/var/log/mysqld.log** या **/var/log/mysql.log**: MySQL डेटाबेस गतिविधियों को लॉग करता है।
- **/var/log/xferlog**: FTP फ़ाइल स्थानांतरणों को रिकॉर्ड करता है।
- **/var/log/**: यहाँ अप्रत्याशित लॉग के लिए हमेशा जाँच करें।

> [!NOTE]
> Linux सिस्टम लॉग और ऑडिट उपप्रणालियाँ एक घुसपैठ या मैलवेयर घटना में अक्षम या हटा दी जा सकती हैं। क्योंकि Linux सिस्टम पर लॉग आमतौर पर दुर्भावनापूर्ण गतिविधियों के बारे में कुछ सबसे उपयोगी जानकारी रखते हैं, घुसपैठिए नियमित रूप से उन्हें हटा देते हैं। इसलिए, उपलब्ध लॉग फ़ाइलों की जांच करते समय, यह महत्वपूर्ण है कि आप उन गैप्स या अनुक्रम से बाहर की प्रविष्टियों की तलाश करें जो हटाने या छेड़छाड़ का संकेत हो सकते हैं।

**Linux प्रत्येक उपयोगकर्ता के लिए एक कमांड इतिहास बनाए रखता है**, जो निम्नलिखित में संग्रहीत होता है:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

इसके अलावा, `last -Faiwx` कमांड उपयोगकर्ता लॉगिन की एक सूची प्रदान करता है। अज्ञात या अप्रत्याशित लॉगिन के लिए इसे जांचें।

अतिरिक्त rprivileges देने वाली फ़ाइलों की जाँच करें:

- अप्रत्याशित उपयोगकर्ता विशेषाधिकारों के लिए `/etc/sudoers` की समीक्षा करें जो दिए गए हो सकते हैं।
- अप्रत्याशित उपयोगकर्ता विशेषाधिकारों के लिए `/etc/sudoers.d/` की समीक्षा करें जो दिए गए हो सकते हैं।
- किसी भी असामान्य समूह सदस्यता या अनुमतियों की पहचान करने के लिए `/etc/groups` की जांच करें।
- किसी भी असामान्य समूह सदस्यता या अनुमतियों की पहचान करने के लिए `/etc/passwd` की जांच करें।

कुछ ऐप्स भी अपने स्वयं के लॉग उत्पन्न करते हैं:

- **SSH**: अनधिकृत दूरस्थ कनेक्शनों के लिए _\~/.ssh/authorized_keys_ और _\~/.ssh/known_hosts_ की जांच करें।
- **Gnome Desktop**: Gnome अनुप्रयोगों के माध्यम से हाल ही में एक्सेस की गई फ़ाइलों के लिए _\~/.recently-used.xbel_ में देखें।
- **Firefox/Chrome**: संदिग्ध गतिविधियों के लिए _\~/.mozilla/firefox_ या _\~/.config/google-chrome_ में ब्राउज़र इतिहास और डाउनलोड की जाँच करें।
- **VIM**: उपयोग विवरणों के लिए _\~/.viminfo_ की समीक्षा करें, जैसे एक्सेस की गई फ़ाइल पथ और खोज इतिहास।
- **Open Office**: हाल की दस्तावेज़ पहुंच की जांच करें जो समझौता की गई फ़ाइलों का संकेत दे सकती है।
- **FTP/SFTP**: अनधिकृत फ़ाइल स्थानांतरणों के लिए _\~/.ftp_history_ या _\~/.sftp_history_ में लॉग की समीक्षा करें।
- **MySQL**: संभावित रूप से अनधिकृत डेटाबेस गतिविधियों को प्रकट करने के लिए _\~/.mysql_history_ की जांच करें।
- **Less**: उपयोग इतिहास के लिए _\~/.lesshst_ का विश्लेषण करें, जिसमें देखी गई फ़ाइलें और निष्पादित कमांड शामिल हैं।
- **Git**: रिपॉजिटरी में परिवर्तनों के लिए _\~/.gitconfig_ और प्रोजेक्ट _.git/logs_ की जांच करें।

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) एक छोटा सा सॉफ़्टवेयर है जो शुद्ध Python 3 में लिखा गया है जो USB इवेंट इतिहास तालिकाओं का निर्माण करने के लिए Linux लॉग फ़ाइलों (`/var/log/syslog*` या `/var/log/messages*` वितरण के आधार पर) को पार्स करता है।

यह जानना दिलचस्प है कि **सभी USBs का उपयोग किया गया है** और यदि आपके पास "उल्लंघन घटनाओं" (उन USBs का उपयोग जो उस सूची में नहीं हैं) को खोजने के लिए USBs की एक अधिकृत सूची है तो यह अधिक उपयोगी होगा।

### Installation
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### उदाहरण
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## उपयोगकर्ता खातों और लॉगिन गतिविधियों की समीक्षा करें

असामान्य नामों या खातों के लिए _**/etc/passwd**_, _**/etc/shadow**_ और **सुरक्षा लॉग** की जांच करें जो ज्ञात अनधिकृत घटनाओं के निकटता में बनाए गए या उपयोग किए गए हैं। इसके अलावा, संभावित sudo ब्रूट-फोर्स हमलों की जांच करें।\
इसके अलावा, उपयोगकर्ताओं को दिए गए अप्रत्याशित विशेषाधिकारों के लिए _**/etc/sudoers**_ और _**/etc/groups**_ जैसी फ़ाइलों की जांच करें।\
अंत में, **कोई पासवर्ड नहीं** या **आसानी से अनुमानित** पासवर्ड वाले खातों की तलाश करें।

## फ़ाइल प्रणाली की जांच करें

### मैलवेयर जांच में फ़ाइल प्रणाली संरचनाओं का विश्लेषण

जब मैलवेयर घटनाओं की जांच की जाती है, तो फ़ाइल प्रणाली की संरचना जानकारी का एक महत्वपूर्ण स्रोत होती है, जो घटनाओं के अनुक्रम और मैलवेयर की सामग्री को प्रकट करती है। हालाँकि, मैलवेयर लेखक इस विश्लेषण को बाधित करने के लिए तकनीकें विकसित कर रहे हैं, जैसे फ़ाइल टाइमस्टैम्प को संशोधित करना या डेटा भंडारण के लिए फ़ाइल प्रणाली से बचना।

इन एंटी-फॉरेंसिक विधियों का मुकाबला करने के लिए, यह आवश्यक है:

- **घटनाओं के समयरेखा का गहन विश्लेषण करें** जैसे उपकरणों का उपयोग करके **Autopsy** घटनाओं की समयरेखा को दृश्य बनाने के लिए या **Sleuth Kit's** `mactime` विस्तृत समयरेखा डेटा के लिए।
- **सिस्टम के $PATH में अप्रत्याशित स्क्रिप्टों की जांच करें**, जिसमें हमलावरों द्वारा उपयोग किए गए शेल या PHP स्क्रिप्ट शामिल हो सकते हैं।
- **असामान्य फ़ाइलों के लिए `/dev` की जांच करें**, क्योंकि इसमें पारंपरिक रूप से विशेष फ़ाइलें होती हैं, लेकिन यह मैलवेयर से संबंधित फ़ाइलें भी रख सकता है।
- **छिपी हुई फ़ाइलों या निर्देशिकाओं की खोज करें** जिनके नाम ".. " (डॉट डॉट स्पेस) या "..^G" (डॉट डॉट कंट्रोल-G) हो सकते हैं, जो दुर्भावनापूर्ण सामग्री को छिपा सकते हैं।
- **setuid रूट फ़ाइलों की पहचान करें** कमांड का उपयोग करके: `find / -user root -perm -04000 -print` यह उन फ़ाइलों को खोजता है जिनके पास उच्च विशेषाधिकार होते हैं, जिन्हें हमलावरों द्वारा दुरुपयोग किया जा सकता है।
- **मास फ़ाइल हटाने को इंगित करने के लिए इनोड तालिकाओं में हटाने के टाइमस्टैम्प की समीक्षा करें**, जो संभवतः रूटकिट या ट्रोजन की उपस्थिति को इंगित कर सकते हैं।
- **एक बार पहचानने के बाद निकटवर्ती दुर्भावनापूर्ण फ़ाइलों के लिए लगातार इनोड की जांच करें**, क्योंकि उन्हें एक साथ रखा जा सकता है।
- **हाल ही में संशोधित फ़ाइलों के लिए सामान्य बाइनरी निर्देशिकाओं** (_/bin_, _/sbin_) की जांच करें, क्योंकि इन्हें मैलवेयर द्वारा संशोधित किया जा सकता है।
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!NOTE]
> ध्यान दें कि एक **हमलावर** **समय** को **संशोधित** कर सकता है ताकि **फाइलें वैध** **दिखें**, लेकिन वह **inode** को **संशोधित** नहीं कर सकता। यदि आप पाते हैं कि एक **फाइल** यह दर्शाती है कि इसे उसी **समय** में बनाया और संशोधित किया गया था जैसे कि उसी फ़ोल्डर में अन्य फ़ाइलें, लेकिन **inode** **अप्रत्याशित रूप से बड़ा** है, तो उस **फाइल के टाइमस्टैम्प को संशोधित किया गया था**।

## विभिन्न फाइल सिस्टम संस्करणों की तुलना करें

### फाइल सिस्टम संस्करण तुलना सारांश

फाइल सिस्टम संस्करणों की तुलना करने और परिवर्तनों को पहचानने के लिए, हम सरल `git diff` कमांड का उपयोग करते हैं:

- **नई फाइलें खोजने के लिए**, दो निर्देशिकाओं की तुलना करें:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **संशोधित सामग्री के लिए**, परिवर्तनों की सूची बनाएं जबकि विशिष्ट पंक्तियों की अनदेखी करें:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **हटाए गए फ़ाइलों का पता लगाने के लिए**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **फिल्टर विकल्प** (`--diff-filter`) विशिष्ट परिवर्तनों जैसे जोड़े गए (`A`), हटाए गए (`D`), या संशोधित (`M`) फ़ाइलों तक सीमित करने में मदद करते हैं।
- `A`: जोड़ी गई फ़ाइलें
- `C`: कॉपी की गई फ़ाइलें
- `D`: हटाई गई फ़ाइलें
- `M`: संशोधित फ़ाइलें
- `R`: नाम बदली गई फ़ाइलें
- `T`: प्रकार परिवर्तन (जैसे, फ़ाइल से सिम्लिंक)
- `U`: असंयुक्त फ़ाइलें
- `X`: अज्ञात फ़ाइलें
- `B`: टूटी हुई फ़ाइलें

## संदर्भ

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **पुस्तक: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

{{#include ../../banners/hacktricks-training.md}}
