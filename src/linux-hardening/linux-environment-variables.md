# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## Global variables

Global değişkenler **child processes** tarafından **miras alınacaktır**.

Mevcut oturumunuz için global bir değişken oluşturmak için şunu yapabilirsiniz:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Bu değişkene mevcut oturumlarınız ve onların alt süreçleri tarafından erişilebilir.

Bir değişkeni şu şekilde **kaldırabilirsiniz**:
```bash
unset MYGLOBAL
```
## Yerel değişkenler

**Yerel değişkenlere** yalnızca **geçerli shell/script** tarafından **erişilebilir**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Geçerli değişkenleri listele
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
`/proc/*/environ` içeriği **NUL-ayrımlıdır**, bu yüzden bu varyantlar genellikle daha kolay okunur:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
If you are looking for **credentials** or **interesting service configuration** inside inherited environments, also check [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X** tarafından kullanılan display. Bu değişken genellikle **:0.0** olarak ayarlanır; bu da geçerli bilgisayardaki ilk display anlamına gelir.
- **EDITOR** – kullanıcının tercih ettiği metin editörü.
- **HISTFILESIZE** – history file içinde bulunan maksimum satır sayısı.
- **HISTSIZE** – kullanıcı oturumunu bitirdiğinde history file’a eklenen satır sayısı
- **HOME** – home directory’niz.
- **HOSTNAME** – bilgisayarın hostname’i.
- **LANG** – geçerli diliniz.
- **MAIL** – kullanıcının mail spool konumu. Genellikle **/var/spool/mail/USER**.
- **MANPATH** – manual pages aramak için dizin listesi.
- **OSTYPE** – işletim sistemi türü.
- **PS1** – bash içindeki varsayılan prompt.
- **PATH** – çalıştırmak istediğiniz binary files’ların bulunduğu tüm dizinlerin yolunu saklar; dosya adını göreli veya mutlak path vermeden sadece adıyla belirterek çalıştırabilirsiniz.
- **PWD** – geçerli working directory.
- **SHELL** – geçerli command shell’in path’i (örneğin, **/bin/bash**).
- **TERM** – geçerli terminal türü (örneğin, **xterm**).
- **TZ** – time zone’unuz.
- **USER** – geçerli username’iniz.

## Interesting variables for hacking

Her variable aynı derecede faydalı değildir. Offensive açıdan, **search paths**, **startup files**, **dynamic linker davranışı** veya **audit/logging** değiştiren variable’lara öncelik verin.

### **HISTFILESIZE**

Bu variable’ın **değerini 0** yapın; böylece **oturumu bitirdiğinizde** **history file** (\~/.bash_history) **0 satıra kısaltılır**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

**Bu değişkenin değerini 0 olarak değiştirin**, böylece komutlar **bellek içi geçmişte tutulmaz** ve **history file** (\~/.bash_history) içine geri yazılmaz.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Eğer **bu değişkenin değeri `ignorespace` veya `ignoreboth` olarak ayarlanırsa**, başına ekstra bir boşluk eklenmiş herhangi bir komut geçmişe kaydedilmez.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

**history file**’ı **`/dev/null`**’a yönlendirin veya tamamen unset edin. Bu, genellikle yalnızca history boyutunu değiştirmekten daha güvenilirdir.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Processler, internete **http** veya **https** üzerinden bağlanmak için burada tanımlanan **proxy**’yi kullanacaktır.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: bunu destekleyen araçlar/protokoller için varsayılan proxy.
- `no_proxy`: doğrudan bağlanması gereken atlama listesi (hostlar/domainler/CIDR'ler).
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Araca bağlı olarak hem küçük harf hem de büyük harf varyantları kullanılabilir (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Süreçler, **bu env variables** içinde belirtilen sertifikalara güvenir. Bu, **`curl`**, **`git`**, Python HTTP clients veya package managers gibi araçların, saldırgan tarafından kontrol edilen bir CA’ya güvenmesini sağlamak için kullanışlıdır (örneğin, bir interception proxy’yi meşru göstermek için).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Eğer ayrıcalıklı bir wrapper/script komutları **mutlak path’ler olmadan** çalıştırırsa, `PATH` içindeki **ilk saldırgan kontrollü directory** kazanır. Bu, `sudo`, cron job’lar, shell wrapper’lar ve custom SUID helper’larda görülen birçok **PATH hijack**’in temelidir. `env_keep+=PATH`, zayıf `secure_path` veya `tar`, `service`, `cp`, `python` vb. komutları isimle çağıran wrapper’ları arayın.
```bash
mkdir -p /dev/shm/bin
cat > /dev/shm/bin/tar <<'EOF'
#!/bin/sh
echo '[+] PATH hijack reached' >&2
id
EOF
chmod +x /dev/shm/bin/tar
PATH=/dev/shm/bin:$PATH vulnerable-wrapper
```
Tam yetki yükseltme zincirlerinde `PATH` istismarı için [Linux Privilege Escalation](privilege-escalation/README.md) bölümüne bakın.

### **HOME & XDG_CONFIG_HOME**

`HOME` sadece bir dizin referansı değildir: birçok araç otomatik olarak **dotfiles**, **plugins** ve **per-user configuration** dosyalarını `$HOME` veya `$XDG_CONFIG_HOME` içinden yükler. Eğer ayrıcalıklı bir workflow bu değerleri korursa, **config injection** ikili dosya hijacking’den daha kolay olabilir.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
İlginç hedefler arasında `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` ve `.terraformrc` gibi araca özel dosyalar bulunur.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Bu değişkenler **dynamic linker** üzerinde etki yapar:

- `LD_PRELOAD`: ek shared objects dosyalarının önce yüklenmesini zorlar.
- `LD_LIBRARY_PATH`: library arama dizinlerini başa ekler.
- `LD_AUDIT`: library yüklenmesini ve symbol resolution işlemini gözlemleyen auditor libraries yükler.

Bunlar, bir yetkili komut bunları korursa, **hooking**, **instrumentation** ve **privilege escalation** için son derece değerlidir. **secure-execution** modunda (`AT_SECURE`, örn. setuid/setgid/capabilities), loader bu değişkenlerin çoğunu siler veya kısıtlar. Ancak, o erken loader aşamasındaki parser bug'ları yine de yüksek etkilidir çünkü **target program** çalışmadan önce çalışırlar.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` erken glibc davranışını değiştirir (örneğin, allocator tunables) ve exploit lab’lerinde çok kullanışlıdır. Güvenlik açısından da önemlidir çünkü **dynamic loader bunu çok erken parse eder**. 2023 **Looney Tunables** bug’ı, loader içinde parse edilen tek bir environment variable’ın SUID programlara karşı bir **local privilege-escalation primitive** haline gelebileceğini iyi bir şekilde hatırlattı.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Eğer **Bash** **non-interactively** başlatılırsa, `BASH_ENV` değerini kontrol eder ve target script çalıştırılmadan önce o dosyayı source eder. Bash `sh` olarak çağrıldığında veya POSIX-style interactive mode içinde çalıştığında, `ENV` de dikkate alınabilir. Bu, environment attacker-controlled olduğunda bir shell wrapper'ı code execution'a dönüştürmenin klasik bir yoludur.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash, **gerçek/etkin kimlikler farklı olduğunda** `-p` kullanılmadıkça bu başlangıç dosyalarını devre dışı bırakır; bu yüzden tam davranış, wrapper’ın shell’i nasıl çağırdığına bağlıdır.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Bu değişkenler Python’un nasıl başladığını değiştirir:

- `PYTHONPATH`: import arama yollarını başa ekler.
- `PYTHONHOME`: standart library ağacını başka bir yere taşır.
- `PYTHONSTARTUP`: interactive prompt’tan önce bir dosya çalıştırır.
- `PYTHONINSPECT=1`: bir script bittikten sonra interactive moda geçer.

Bunlar, Python’u kontrol edilebilir bir environment ile çağıran maintenance script’lere, debuggers’a, shell’lere ve wrapper’lara karşı kullanışlıdır. `python -E` ve `python -I` tüm `PYTHON*` değişkenlerini yok sayar.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl’in benzer şekilde kullanışlı startup variables vardır:

- `PERL5LIB`: library directories önüne ekler.
- `PERL5OPT`: sanki her `perl` command line’ında varmış gibi switches inject eder.

Bu, hedef script herhangi bir ilginç şey yapmadan önce **automatic module loading** zorlayabilir veya interpreter behavior’ını değiştirebilir. Perl bu variables’ı **taint / setuid / setgid** contexts içinde yok sayar, ancak normal root-run wrappers, CI jobs, installers ve custom sudoers rules için yine de çok önemlidir.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Aynı fikir diğer runtime’larda da görünür (`RUBYOPT`, `NODE_OPTIONS`, vb.): bir interpreter privileged wrapper tarafından başlatıldığında, **module loading** veya **startup behavior**’ı değiştiren env vars arayın.

Post-exploitation açısından, inherited environment’ların çoğu zaman **credentials**, **proxy settings**, **service tokens** veya **cloud keys** içerdiğini de unutmayın. `/proc/<PID>/environ` ve `systemd` `Environment=` avı için [Linux Post Exploitation](linux-post-exploitation/README.md) bölümüne bakın.

### PS1

Prompt’unuzun nasıl göründüğünü değiştirin.

[**This is an example**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Regular user:

![](<../images/image (740).png>)

One, two and three backgrounded jobs:

![](<../images/image (145).png>)

One background job, one stopped and last command didn't finish correctly:

![](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../banners/hacktricks-training.md}}
