# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## Global variables

Global değişkenler **child processes** tarafından **devralınacaktır**.

Mevcut oturumunuz için bir global değişken oluşturabilirsiniz:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Bu değişken, mevcut oturumlarınız ve onların alt süreçleri tarafından erişilebilir olacaktır.

Bir değişkeni şu şekilde **kaldırabilirsiniz**:
```bash
unset MYGLOBAL
```
## Yerel değişkenler

**Yerel değişkenlere** yalnızca **mevcut shell/script** tarafından **erişilebilir**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Mevcut değişkenleri listele
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
`/proc/*/environ` içeriği **NUL ile ayrılmıştır**, bu yüzden bu varyantlar genellikle daha kolay okunur:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Eğer devralınmış ortamlarda **credentials** veya **interesting service configuration** arıyorsanız, ayrıca [Linux Post Exploitation](linux-post-exploitation/README.md) kontrol edin.

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X** tarafından kullanılan display. Bu değişken genellikle **:0.0** olarak ayarlanır; bu da mevcut bilgisayardaki ilk display anlamına gelir.
- **EDITOR** – kullanıcının tercih ettiği metin editörü.
- **HISTFILESIZE** – history dosyasında bulunan satırların maksimum sayısı.
- **HISTSIZE** – kullanıcı oturumunu bitirdiğinde history dosyasına eklenen satır sayısı
- **HOME** – home dizininiz.
- **HOSTNAME** – bilgisayarın hostname’i.
- **LANG** – mevcut diliniz.
- **MAIL** – kullanıcının mail spool konumu. Genellikle **/var/spool/mail/USER**.
- **MANPATH** – manual pages için aranacak dizinlerin listesi.
- **OSTYPE** – operating system türü.
- **PS1** – bash içindeki varsayılan prompt.
- **PATH** – çalıştırmak istediğiniz binary dosyaların adını yalnızca belirterek, relative veya absolute path kullanmadan execute edilmesini sağlayan tüm dizinlerin path’ini saklar.
- **PWD** – mevcut working directory.
- **SHELL** – mevcut command shell’in path’i (örneğin, **/bin/bash**).
- **TERM** – mevcut terminal türü (örneğin, **xterm**).
- **TZ** – zaman diliminiz.
- **USER** – mevcut username’iniz.

## Interesting variables for hacking

Her variable eşit derecede useful değildir. Offensive perspektiften, **search paths**, **startup files**, **dynamic linker behavior** veya **audit/logging** değiştiren değişkenleri önceliklendirin.

### **HISTFILESIZE**

**End your session** sırasında **history file** (\~/.bash_history) **0 satıra kırpılacak** şekilde bu değişkenin **değerini 0 yapın**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Bu değişkenin **değerini 0** olarak değiştirin, böylece komutlar **in-memory history** içinde tutulmaz ve **history file** (\~/.bash_history) içine geri yazılmaz.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Eğer **bu değişkenin değeri `ignorespace` veya `ignoreboth` olarak ayarlanırsa**, başına ekstra bir boşluk eklenmiş herhangi bir komut history içinde kaydedilmez.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

**history file**'ı **`/dev/null`** olarak ayarlayın veya tamamen unset edin. Bu, genellikle yalnızca history boyutunu değiştirmekten daha güvenilirdir.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

İşlemler, internete **http** veya **https** üzerinden bağlanmak için burada tanımlanan **proxy**'yi kullanacaktır.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: bunu önemseyen araçlar/protokoller için varsayılan proxy.
- `no_proxy`: doğrudan bağlanması gereken atlama listesi (hostlar/domainler/CIDR'ler).
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Hem küçük hem büyük harfli varyantlar, kullanılan araca bağlı olarak kullanılabilir (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Process'ler, **bu env variables** içinde belirtilen sertifikalara güvenecektir. Bu, **`curl`**, **`git`**, Python HTTP clients veya package managers gibi araçların attacker tarafından kontrol edilen bir CA'ya güvenmesini sağlamak için kullanışlıdır (örneğin, bir interception proxy'nin meşru görünmesini sağlamak için).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Eğer ayrıcalıklı bir wrapper/script komutları **mutlak path’ler olmadan** çalıştırırsa, `PATH` içindeki **ilk saldırgan kontrollü directory** kazanır. Bu, `sudo`, cron jobs, shell wrappers ve custom SUID helpers içindeki birçok **PATH hijacks** için temel mekanizmadır. `env_keep+=PATH`, zayıf `secure_path`, veya `tar`, `service`, `cp`, `python` vb. komutları isimleriyle çağıran wrapper’ları arayın.
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
Tam yetki yükseltme zincirleri için `PATH` suistimali konusunda [Linux Privilege Escalation](privilege-escalation/README.md) bölümüne bakın.

### **HOME & XDG_CONFIG_HOME**

`HOME` yalnızca bir dizin referansı değildir: birçok araç `$HOME` veya `$XDG_CONFIG_HOME` üzerinden otomatik olarak **dotfiles**, **plugins** ve **kullanıcıya özel yapılandırma** yükler. Eğer ayrıcalıklı bir iş akışı bu değerleri koruyorsa, **config injection** binary hijacking'den daha kolay olabilir.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
İlginç hedefler arasında `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` ve `.terraformrc` gibi araca özel dosyalar bulunur.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Bu değişkenler **dynamic linker** üzerinde etkilidir:

- `LD_PRELOAD`: ekstra shared objects dosyalarının önce yüklenmesini zorlar.
- `LD_LIBRARY_PATH`: library arama dizinlerini başa ekler.
- `LD_AUDIT`: library yüklenmesini ve symbol resolution işlemlerini gözlemleyen auditor libraries yükler.

Bunlar, özellikle ayrıcalıklı bir komut bunları koruyorsa, **hooking**, **instrumentation** ve **privilege escalation** için son derece değerlidir. **secure-execution** modunda (`AT_SECURE`, örn. setuid/setgid/capabilities), loader bu değişkenlerin çoğunu siler veya kısıtlar. Ancak, o erken loader aşamasındaki parser bugs hâlâ yüksek etkilidir çünkü **target program** çalışmadan önce çalışırlar.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` erken glibc davranışını değiştirir (örneğin, allocator tunables) ve exploit lab’lerinde çok kullanışlıdır. Ayrıca güvenlik açısından da önemlidir çünkü **dynamic loader bunu çok erken ayrıştırır**. 2023 tarihli **Looney Tunables** bug’ı, loader’da ayrıştırılan tek bir environment variable’ın SUID programlara karşı bir **local privilege-escalation primitive** haline gelebileceğini hatırlatan iyi bir örnekti.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Eğer **Bash** **etkileşimli olmayan** şekilde başlatılırsa, `BASH_ENV` değerini kontrol eder ve hedef scripti çalıştırmadan önce o dosyayı source eder. Bash, `sh` olarak çağrıldığında veya POSIX tarzı etkileşimli modda, `ENV` de incelenebilir. Bu, ortam saldırgan tarafından kontrol ediliyorsa bir shell wrapper’ını code execution’a çevirmek için klasik bir yoldur.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash’in kendisi, `-p` kullanılmadığı sürece **gerçek/etkin kimlikler farklı olduğunda** bu başlangıç dosyalarını devre dışı bırakır; bu yüzden tam davranış, wrapper’ın shell’i nasıl çağırdığına bağlıdır.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Bu değişkenler Python’un nasıl başladığını değiştirir:

- `PYTHONPATH`: import arama yollarının başına ekler.
- `PYTHONHOME`: standart kütüphane ağacının yerini değiştirir.
- `PYTHONSTARTUP`: interactive prompt’tan önce bir dosyayı çalıştırır.
- `PYTHONINSPECT=1`: bir script bittikten sonra interactive mode’a geçer.

Bakım scriptleri, debugger’lar, shell’ler ve kontrol edilebilir bir environment ile Python çağıran wrapper’lara karşı faydalıdırlar. `python -E` ve `python -I` tüm `PYTHON*` değişkenlerini yok sayar.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl’in benzer derecede kullanışlı startup değişkenleri vardır:

- `PERL5LIB`: library dizinlerini öne ekler.
- `PERL5OPT`: sanki her `perl` command line’ında varmış gibi switches enjekte eder.

Bu, **automatic module loading** zorlayabilir veya target script bir şey yapmadan önce interpreter davranışını değiştirebilir. Perl bu değişkenleri **taint / setuid / setgid** context’lerinde görmezden gelir, ancak normal root-run wrappers, CI jobs, installers ve custom sudoers rules için yine de çok önemlidir.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Aynı fikir diğer runtime’larda da görünür (`RUBYOPT`, `NODE_OPTIONS`, vb.): bir interpreter ayrıcalıklı bir wrapper tarafından başlatıldığında, **module loading** veya **startup behavior**’ı değiştiren env vars arayın.

Post-exploitation açısından, miras alınan environment’ların çoğu zaman **credentials**, **proxy settings**, **service tokens** veya **cloud keys** içerdiğini de unutmayın. `/proc/<PID>/environ` ve `systemd` `Environment=` avı için [Linux Post Exploitation](linux-post-exploitation/README.md) bölümüne bakın.

### PS1

Prompt’unuzun nasıl göründüğünü değiştirin.

[**Bu bir örnektir**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Normal kullanıcı:

![](<../images/image (740).png>)

Bir, iki ve üç arka planda çalışan job:

![](<../images/image (145).png>)

Bir arka plan job’u, bir durmuş ve son komut doğru şekilde tamamlanmadı:

![](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../banners/hacktricks-training.md}}
